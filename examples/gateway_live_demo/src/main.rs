//! MoFA Cognitive Gateway — end-to-end live demo
//!
//! Wires together every kernel contract and foundation implementation:
//!
//! Kernel layer (traits / types)
//!   GatewayRoute, RouteRegistry, RequestEnvelope, AgentResponse
//!   AuthClaims, AuthProvider, ApiKeyStore, AuthError
//!   RoutingStrategy
//!
//! Foundation layer (concrete implementations)
//!   TokenBucketRateLimiter — per-client token-bucket quota
//!   WeightedRoundRobinRouter — proportional load balancing
//!   CapabilityMatchRouter + AgentScorer — semantic routing
//!   RouterRegistry — route-id → strategy map
//!
//! Endpoints
//!   GET  /                    live HTML dashboard (auto-refreshes every 500 ms)
//!   GET  /live/metrics        JSON metrics feed polled by the dashboard
//!   POST /v1/invoke/{path}    full dispatch pipeline (auth → rate-limit → route → strategy → echo)
//!   GET  /admin/health        health summary   (x-admin-key required)
//!   GET  /admin/routes        list routes      (x-admin-key required)
//!   POST /admin/routes        register route   (x-admin-key required)
//!   PATCH /admin/routes/{id}  toggle enabled   (x-admin-key required)
//!   DELETE /admin/routes/{id} deregister route (x-admin-key required)
//!   GET  /admin/keys          list issued keys (x-admin-key required)
//!   POST /admin/keys          issue new key    (x-admin-key required)
//!   DELETE /admin/keys/{key}  revoke key       (x-admin-key required)
//!
//! Run:
//!   cargo run -p gateway_live_demo
//!
//! Then open http://127.0.0.1:8080 in your browser.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

use mofa_foundation::{
    AgentScorer, CapabilityMatchRouter, RouterRegistry, TokenBucketRateLimiter,
    WeightedRoundRobinRouter,
};
use mofa_foundation::gateway::{KeyStrategy, RateLimitDecision, RateLimiter, RateLimiterConfig};
use mofa_kernel::{
    AgentResponse, ApiKeyStore, AuthClaims, AuthError, AuthProvider, GatewayRoute,
    HttpMethod, RegistryError, RequestEnvelope, RouteRegistry, RoutingStrategy,
};

// ─────────────────────────────────────────────────────────────────────────────
// Demo constants
// ─────────────────────────────────────────────────────────────────────────────

const ADMIN_KEY: &str = "admin-secret-2025";
const DEMO_KEY_ALICE: &str = "alice-key-abc123";
const DEMO_KEY_BOB: &str = "bob-key-xyz789";
const BIND_ADDR: &str = "127.0.0.1:8080";

// ─────────────────────────────────────────────────────────────────────────────
// L1 Cache — in-memory TTL cache for agent responses
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct CacheEntry {
    value: Value,
    inserted_at: Instant,
    ttl: Duration,
    hits: AtomicU64,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

#[derive(Debug)]
struct L1Cache {
    store: DashMap<String, CacheEntry>,
    hits: AtomicU64,
    misses: AtomicU64,
    default_ttl: Duration,
}

impl L1Cache {
    fn new(default_ttl_secs: u64) -> Self {
        Self {
            store: DashMap::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            default_ttl: Duration::from_secs(default_ttl_secs),
        }
    }

    /// Build a deterministic cache key from route + canonicalized body.
    fn make_key(route_id: &str, body: &Value) -> String {
        let canonical = body.to_string();
        let mut h = Sha256::new();
        h.update(route_id.as_bytes());
        h.update(b":");
        h.update(canonical.as_bytes());
        let digest = h.finalize();
        format!("{}:{}", route_id, hex::encode(&digest[..8]))
    }

    fn get(&self, key: &str) -> Option<Value> {
        if let Some(entry) = self.store.get(key) {
            if entry.is_expired() {
                drop(entry);
                self.store.remove(key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            entry.hits.fetch_add(1, Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.value.clone());
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn set(&self, key: String, value: Value, ttl: Option<Duration>) {
        self.store.insert(key, CacheEntry {
            value,
            inserted_at: Instant::now(),
            ttl: ttl.unwrap_or(self.default_ttl),
            hits: AtomicU64::new(0),
        });
    }

    fn invalidate(&self, key: &str) -> bool {
        self.store.remove(key).is_some()
    }

    fn clear(&self) {
        self.store.clear();
    }

    fn evict_expired(&self) {
        self.store.retain(|_, v| !v.is_expired());
    }

    fn stats(&self) -> CacheStats {
        self.evict_expired();
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 { hits * 100 / total } else { 0 };
        CacheStats {
            size: self.store.len(),
            hits,
            misses,
            hit_rate_pct: hit_rate,
        }
    }
}

#[derive(Debug, Serialize)]
struct CacheStats {
    size: usize,
    hits: u64,
    misses: u64,
    hit_rate_pct: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MQTT Adapter — in-process pub/sub bus simulating an MQTT broker + IoT devices
// ─────────────────────────────────────────────────────────────────────────────

/// An MQTT message on the internal bus.
#[derive(Debug, Clone)]
struct MqttMessage {
    topic: String,
    payload: Value,
    correlation_id: String,
}

/// A simulated IoT device that subscribes to a topic and replies on a response topic.
#[derive(Debug, Clone, Serialize)]
struct IoTDevice {
    id: String,
    topic: String,
    device_type: String,
    online: bool,
    messages_handled: u64,
}

/// In-process MQTT broker: routes messages to registered device handlers.
#[derive(Debug)]
struct MqttBroker {
    /// device_id → IoTDevice metadata
    devices: DashMap<String, IoTDevice>,
    /// topic → (device_id, reply_sender)
    subscriptions: DashMap<String, (String, tokio::sync::mpsc::Sender<MqttMessage>)>,
    published: AtomicU64,
    received: AtomicU64,
}

impl MqttBroker {
    fn new() -> Self {
        Self {
            devices: DashMap::new(),
            subscriptions: DashMap::new(),
            published: AtomicU64::new(0),
            received: AtomicU64::new(0),
        }
    }

    fn register_device(
        self: &Arc<Self>,
        id: &str,
        topic: &str,
        device_type: &str,
    ) -> tokio::sync::mpsc::Receiver<MqttMessage> {
        let (tx, rx) = tokio::sync::mpsc::channel::<MqttMessage>(64);
        self.devices.insert(id.to_string(), IoTDevice {
            id: id.to_string(),
            topic: topic.to_string(),
            device_type: device_type.to_string(),
            online: true,
            messages_handled: 0,
        });
        self.subscriptions.insert(topic.to_string(), (id.to_string(), tx));
        rx
    }

    /// Publish a message to a topic. Returns the response via a oneshot.
    async fn publish(
        self: &Arc<Self>,
        topic: &str,
        payload: Value,
        correlation_id: &str,
    ) -> Result<(), String> {
        self.published.fetch_add(1, Ordering::Relaxed);
        if let Some(sub) = self.subscriptions.get(topic) {
            let msg = MqttMessage {
                topic: topic.to_string(),
                payload,
                correlation_id: correlation_id.to_string(),
            };
            sub.1.send(msg).await.map_err(|e| e.to_string())?;
            self.received.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(format!("no subscriber on topic '{}'", topic))
        }
    }

    fn set_device_online(&self, device_id: &str, online: bool) {
        if let Some(mut d) = self.devices.get_mut(device_id) {
            d.online = online;
        }
    }

    fn broker_stats(&self) -> Value {
        json!({
            "devices": self.devices.len(),
            "subscriptions": self.subscriptions.len(),
            "published": self.published.load(Ordering::Relaxed),
            "received": self.received.load(Ordering::Relaxed),
        })
    }

    fn list_devices(&self) -> Vec<IoTDevice> {
        self.devices.iter().map(|e| e.value().clone()).collect()
    }
}

/// Spawn a simulated IoT device that handles requests and replies on a response channel.
fn spawn_iot_device(
    broker: Arc<MqttBroker>,
    device_id: String,
    subscribe_topic: String,
    response_map: Arc<DashMap<String, tokio::sync::oneshot::Sender<Value>>>,
) {
    let mut rx = broker.register_device(&device_id, &subscribe_topic, "simulated");
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // Update handled count
            if let Some(mut dev) = broker.devices.get_mut(&device_id) {
                dev.messages_handled += 1;
            }
            // Build a realistic device response
            let response = json!({
                "device_id": device_id,
                "topic": msg.topic,
                "correlation_id": msg.correlation_id,
                "status": "ok",
                "reading": {
                    "value": 42,
                    "unit": "celsius",
                    "timestamp_ms": SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                },
                "echo": msg.payload,
            });
            // Reply via the pending response map
            if let Some((_, tx)) = response_map.remove(&msg.correlation_id) {
                let _ = tx.send(response);
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Registry — Ed25519-signed plugin manifests with CRUD + verify
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginManifest {
    id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    capabilities: Vec<String>,
    entry_point: String,
    /// SHA-256 checksum of the plugin binary (hex)
    checksum: String,
    /// Ed25519 signature over `id|name|version|checksum` (hex), optional at publish time
    signature: Option<String>,
    /// Whether the signature has been verified against a trusted key
    verified: bool,
}

impl PluginManifest {
    /// The canonical bytes that get signed / verified.
    fn signable_bytes(&self) -> Vec<u8> {
        format!("{}|{}|{}|{}", self.id, self.name, self.version, self.checksum)
            .into_bytes()
    }
}

#[derive(Debug)]
struct PluginRegistry {
    plugins: DashMap<String, PluginManifest>,
    /// Trusted Ed25519 verifying keys (hex-encoded)
    trusted_keys: Mutex<Vec<String>>,
    /// The registry's own signing key (used in the demo to self-sign plugins)
    signing_key: SigningKey,
    installs: AtomicU64,
}

impl PluginRegistry {
    fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            plugins: DashMap::new(),
            trusted_keys: Mutex::new(vec![]),
            signing_key,
            installs: AtomicU64::new(0),
        }
    }

    /// Public key of this registry instance (hex).
    fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Register the registry's own public key as trusted.
    fn trust_self(&self) {
        self.trusted_keys
            .lock()
            .unwrap()
            .push(self.public_key_hex());
    }

    fn publish(&self, mut manifest: PluginManifest) -> Result<(), String> {
        if manifest.id.trim().is_empty() {
            return Err("id cannot be empty".into());
        }
        if self.plugins.contains_key(&manifest.id) {
            return Err(format!("plugin '{}' already exists", manifest.id));
        }
        manifest.verified = false;
        self.plugins.insert(manifest.id.clone(), manifest);
        Ok(())
    }

    /// Sign a manifest with the registry key and mark it verified.
    fn sign_and_verify(&self, plugin_id: &str) -> Result<String, String> {
        let mut manifest = self.plugins
            .get(plugin_id)
            .ok_or_else(|| format!("plugin '{}' not found", plugin_id))?
            .clone();

        let sig: Signature = self.signing_key.sign(&manifest.signable_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        manifest.signature = Some(sig_hex.clone());
        manifest.verified = true;
        self.plugins.insert(plugin_id.to_string(), manifest);
        Ok(sig_hex)
    }

    /// Verify an externally-provided signature against trusted keys.
    fn verify_signature(&self, plugin_id: &str, sig_hex: &str, pubkey_hex: &str) -> Result<(), String> {
        let trusted = self.trusted_keys.lock().unwrap();
        if !trusted.iter().any(|k| k == pubkey_hex) {
            return Err("public key is not in the trusted list".into());
        }
        let manifest = self.plugins
            .get(plugin_id)
            .ok_or_else(|| format!("plugin '{}' not found", plugin_id))?;

        let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "invalid signature length")?;
        let sig = Signature::from_bytes(&sig_arr);

        let key_bytes = hex::decode(pubkey_hex).map_err(|e| e.to_string())?;
        let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| "invalid key length")?;
        let vk = VerifyingKey::from_bytes(&key_arr).map_err(|e| e.to_string())?;

        vk.verify(&manifest.signable_bytes(), &sig).map_err(|e| e.to_string())?;

        drop(manifest);
        if let Some(mut m) = self.plugins.get_mut(plugin_id) {
            m.verified = true;
            m.signature = Some(sig_hex.to_string());
        }
        Ok(())
    }

    /// Simulate `mofa plugin install`: verify + increment install counter.
    fn install(&self, plugin_id: &str) -> Result<PluginManifest, String> {
        let manifest = self.plugins
            .get(plugin_id)
            .ok_or_else(|| format!("plugin '{}' not found", plugin_id))?
            .clone();
        if !manifest.verified {
            return Err(format!(
                "plugin '{}' has no verified signature — run verify first",
                plugin_id
            ));
        }
        self.installs.fetch_add(1, Ordering::Relaxed);
        Ok(manifest)
    }

    fn remove(&self, plugin_id: &str) -> bool {
        self.plugins.remove(plugin_id).is_some()
    }

    fn list(&self) -> Vec<PluginManifest> {
        self.plugins.iter().map(|e| e.value().clone()).collect()
    }

    fn search_by_capability(&self, cap: &str) -> Vec<PluginManifest> {
        self.plugins
            .iter()
            .filter(|e| e.capabilities.iter().any(|c| c.contains(cap)))
            .map(|e| e.value().clone())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryRouteRegistry — implements kernel RouteRegistry trait
// ─────────────────────────────────────────────────────────────────────────────

struct InMemoryRouteRegistry {
    routes: HashMap<String, GatewayRoute>,
}

impl InMemoryRouteRegistry {
    fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Find the highest-priority enabled route whose path_pattern matches
    /// `path` exactly.
    fn match_path(&self, path: &str, method: &HttpMethod) -> Option<&GatewayRoute> {
        let mut candidates: Vec<&GatewayRoute> = self
            .routes
            .values()
            .filter(|r| r.enabled && &r.method == method && r.path_pattern == path)
            .collect();
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        candidates.into_iter().next()
    }
}

impl RouteRegistry for InMemoryRouteRegistry {
    fn register(&mut self, route: GatewayRoute) -> Result<(), RegistryError> {
        route.validate()?;
        if self.routes.contains_key(&route.id) {
            return Err(RegistryError::DuplicateRouteId(route.id.clone()));
        }
        for existing in self.routes.values() {
            if existing.path_pattern == route.path_pattern
                && existing.method == route.method
                && existing.priority == route.priority
            {
                return Err(RegistryError::ConflictingRoutes(
                    existing.id.clone(),
                    route.id.clone(),
                ));
            }
        }
        self.routes.insert(route.id.clone(), route);
        Ok(())
    }

    fn deregister(&mut self, route_id: &str) -> Result<(), RegistryError> {
        self.routes
            .remove(route_id)
            .map(|_| ())
            .ok_or_else(|| RegistryError::RouteNotFound(route_id.to_string()))
    }

    fn lookup(&self, route_id: &str) -> Option<&GatewayRoute> {
        self.routes.get(route_id)
    }

    fn list_active(&self) -> Vec<&GatewayRoute> {
        let mut active: Vec<&GatewayRoute> =
            self.routes.values().filter(|r| r.enabled).collect();
        active.sort_by(|a, b| b.priority.cmp(&a.priority));
        active
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DemoApiKeyStore — implements kernel ApiKeyStore trait
// ─────────────────────────────────────────────────────────────────────────────

struct DemoApiKeyStore {
    keys: HashMap<String, AuthClaims>,
}

impl DemoApiKeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    fn all_keys(&self) -> Vec<(String, AuthClaims)> {
        self.keys
            .iter()
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect()
    }
}

impl ApiKeyStore for DemoApiKeyStore {
    fn lookup(&self, key: &str) -> Option<AuthClaims> {
        self.keys.get(key).cloned()
    }

    fn issue(&mut self, subject: impl Into<String>, scopes: Vec<String>) -> String {
        let key = format!("mk-{}", &Uuid::new_v4().to_string()[..12]);
        self.keys.insert(key.clone(), AuthClaims::new(subject, scopes));
        key
    }

    fn revoke(&mut self, key: &str) -> bool {
        self.keys.remove(key).is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DemoAuthProvider — implements kernel AuthProvider trait
// ─────────────────────────────────────────────────────────────────────────────

struct DemoAuthProvider {
    store: Arc<RwLock<DemoApiKeyStore>>,
}

impl DemoAuthProvider {
    fn new(store: Arc<RwLock<DemoApiKeyStore>>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AuthProvider for DemoAuthProvider {
    async fn authenticate(
        &self,
        headers: &HashMap<String, String>,
    ) -> Result<AuthClaims, AuthError> {
        let key = headers
            .get("x-api-key")
            .map(|s| s.as_str())
            .ok_or(AuthError::MissingCredentials)?;

        let store = self.store.read().unwrap();
        store.lookup(key).ok_or(AuthError::InvalidCredentials)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DemoAgentScorer — implements foundation AgentScorer trait
// ─────────────────────────────────────────────────────────────────────────────

struct DemoAgentScorer;

impl AgentScorer for DemoAgentScorer {
    fn score(&self, task: &str) -> Vec<(String, f64)> {
        let t = task.to_lowercase();
        let vision_score = if t.contains("image")
            || t.contains("vision")
            || t.contains("photo")
            || t.contains("picture")
            || t.contains("visual")
            || t.contains("diagram")
        {
            0.95
        } else {
            0.15
        };
        let text_score = if t.contains("text")
            || t.contains("write")
            || t.contains("summarize")
            || t.contains("translate")
            || t.contains("analyze")
            || t.contains("explain")
        {
            0.90
        } else {
            0.45
        };
        let code_score = if t.contains("code")
            || t.contains("debug")
            || t.contains("function")
            || t.contains("program")
        {
            0.92
        } else {
            0.20
        };
        vec![
            ("vision-agent".to_string(), vision_score),
            ("text-agent".to_string(), text_score),
            ("code-agent".to_string(), code_score),
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GatewayMetrics — live counters for the dashboard
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct GatewayMetrics {
    total: AtomicU64,
    rate_limited: AtomicU64,
    auth_rejected: AtomicU64,
    routed: AtomicU64,
    agent_hits: Mutex<HashMap<String, u64>>,
    recent: Mutex<std::collections::VecDeque<RecentReq>>,
}

#[derive(Debug, Clone, Serialize)]
struct RecentReq {
    ts_ms: u64,
    path: String,
    agent: String,
    status: u16,
    latency_ms: u64,
    subject: String,
}

impl GatewayMetrics {
    fn record_agent_hit(&self, agent_id: &str) {
        self.routed.fetch_add(1, Ordering::Relaxed);
        let mut hits = self.agent_hits.lock().unwrap();
        *hits.entry(agent_id.to_string()).or_insert(0) += 1;
    }

    fn push_recent(&self, req: RecentReq) {
        let mut deque = self.recent.lock().unwrap();
        if deque.len() >= 20 {
            deque.pop_front();
        }
        deque.push_back(req);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let rate_limited = self.rate_limited.load(Ordering::Relaxed);
        let auth_rejected = self.auth_rejected.load(Ordering::Relaxed);
        let routed = self.routed.load(Ordering::Relaxed);
        let agents = self.agent_hits.lock().unwrap().clone();
        let recent = self.recent.lock().unwrap().iter().cloned().collect();
        MetricsSnapshot {
            total,
            rate_limited,
            auth_rejected,
            routed,
            agents,
            recent,
        }
    }
}

#[derive(Serialize)]
struct MetricsSnapshot {
    total: u64,
    rate_limited: u64,
    auth_rejected: u64,
    routed: u64,
    agents: HashMap<String, u64>,
    recent: Vec<RecentReq>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AppState — axum shared state
// ─────────────────────────────────────────────────────────────────────────────

struct AppState {
    routes: RwLock<InMemoryRouteRegistry>,
    keys: Arc<RwLock<DemoApiKeyStore>>,
    auth: DemoAuthProvider,
    rate_limiter: TokenBucketRateLimiter,
    strategies: RwLock<RouterRegistry>,
    metrics: GatewayMetrics,
    started_at: Instant,
    admin_key: String,
    // L1 cache
    cache: L1Cache,
    // MQTT broker + pending response map
    mqtt: Arc<MqttBroker>,
    mqtt_pending: Arc<DashMap<String, tokio::sync::oneshot::Sender<Value>>>,
    // Plugin registry
    plugins: PluginRegistry,
}

impl AppState {
    fn new(admin_key: impl Into<String>) -> Self {
        let keys = Arc::new(RwLock::new(DemoApiKeyStore::new()));
        let auth = DemoAuthProvider::new(Arc::clone(&keys));

        // 10 burst, 2 req/sec sustained — easy to trigger with the stress test
        let rate_cfg = RateLimiterConfig {
            capacity: 10,
            refill_rate: 2,
            strategy: KeyStrategy::PerClient,
        };

        let plugins = PluginRegistry::new();
        plugins.trust_self();

        Self {
            routes: RwLock::new(InMemoryRouteRegistry::new()),
            keys,
            auth,
            rate_limiter: TokenBucketRateLimiter::new(&rate_cfg),
            strategies: RwLock::new(RouterRegistry::new()),
            metrics: GatewayMetrics::default(),
            started_at: Instant::now(),
            admin_key: admin_key.into(),
            cache: L1Cache::new(60),
            mqtt: Arc::new(MqttBroker::new()),
            mqtt_pending: Arc::new(DashMap::new()),
            plugins,
        }
    }

    fn verify_admin(&self, headers: &HeaderMap) -> bool {
        headers
            .get("x-admin-key")
            .and_then(|v| v.to_str().ok())
            .map(|k| k == self.admin_key)
            .unwrap_or(false)
    }
}

type SharedState = Arc<AppState>;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: convert HeaderMap → HashMap<String,String>
// ─────────────────────────────────────────────────────────────────────────────

fn header_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect()
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /
// ─────────────────────────────────────────────────────────────────────────────

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

static LOGO_PNG: &[u8] = include_bytes!("mofa-logo.png");

async fn logo_png() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        LOGO_PNG,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /live/metrics
// ─────────────────────────────────────────────────────────────────────────────

async fn live_metrics(State(state): State<SharedState>) -> Json<Value> {
    let snap = state.metrics.snapshot();
    let routes_active = state.routes.read().unwrap().list_active().len();
    let uptime = state.started_at.elapsed().as_secs();
    let cache_stats = state.cache.stats();
    let mqtt_stats = state.mqtt.broker_stats();
    let plugin_count = state.plugins.plugins.len();
    let plugin_installed = state.plugins.installs.load(Ordering::Relaxed);
    Json(json!({
        "total": snap.total,
        "rate_limited": snap.rate_limited,
        "auth_rejected": snap.auth_rejected,
        "routed": snap.routed,
        "routes_active": routes_active,
        "uptime_secs": uptime,
        "agents": snap.agents,
        "recent": snap.recent,
        "cache": {
            "size": cache_stats.size,
            "hits": cache_stats.hits,
            "misses": cache_stats.misses,
            "hit_rate_pct": cache_stats.hit_rate_pct,
        },
        "mqtt": mqtt_stats,
        "plugins": {
            "registered": plugin_count,
            "installed": plugin_installed,
        },
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/invoke/{path} — full dispatch pipeline
// ─────────────────────────────────────────────────────────────────────────────

async fn invoke(
    State(state): State<SharedState>,
    Path(invoke_path): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    state.metrics.total.fetch_add(1, Ordering::Relaxed);

    let path = format!("/v1/{}", invoke_path);
    let h_map = header_map(&headers);

    // ── 1. Auth ───────────────────────────────────────────────────────────────
    let claims = match state.auth.authenticate(&h_map).await {
        Ok(c) => c,
        Err(AuthError::MissingCredentials) => {
            state.metrics.auth_rejected.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing x-api-key header",
                    "hint": "add  -H 'x-api-key: alice-key-abc123'  to your request"
                })),
            )
                .into_response();
        }
        Err(AuthError::InvalidCredentials) => {
            state.metrics.auth_rejected.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid api key" })),
            )
                .into_response();
        }
        Err(e) => {
            state.metrics.auth_rejected.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // ── 2. Rate limit ─────────────────────────────────────────────────────────
    let client_key = claims.subject.clone();
    match state.rate_limiter.check_and_consume(&client_key) {
        RateLimitDecision::Denied { retry_after_ms } => {
            state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "rate limit exceeded",
                    "retry_after_ms": retry_after_ms,
                    "subject": claims.subject,
                })),
            )
                .into_response();
        }
        RateLimitDecision::Allowed { remaining } => {
            info!("rate ok for {}: {} tokens remaining", claims.subject, remaining);
        }
    }

    // ── 3. Route match ────────────────────────────────────────────────────────
    let envelope = RequestEnvelope::new("", payload.clone(), IpAddr::from_str("127.0.0.1").unwrap());
    let route_id = {
        let registry = state.routes.read().unwrap();
        match registry.match_path(&path, &HttpMethod::Post) {
            Some(r) => r.id.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": format!("no route matches path '{}'", path),
                        "registered_paths": registry.list_active()
                            .iter()
                            .map(|r| r.path_pattern.as_str())
                            .collect::<Vec<_>>(),
                    })),
                )
                    .into_response();
            }
        }
    };

    // ── 4. Cache check ────────────────────────────────────────────────────────
    let cache_key = L1Cache::make_key(&route_id, &payload);
    if let Some(cached) = state.cache.get(&cache_key) {
        state.metrics.record_agent_hit(
            cached.get("agent_id").and_then(|v| v.as_str()).unwrap_or("cached"),
        );
        state.metrics.push_recent(RecentReq {
            ts_ms: now_ms(),
            path: path.clone(),
            agent: format!("cached:{}", cached.get("agent_id").and_then(|v| v.as_str()).unwrap_or("?")),
            status: 200,
            latency_ms: 0,
            subject: claims.subject.clone(),
        });
        return (StatusCode::OK, Json(json!({
            "status": 200,
            "cache": "hit",
            "agent_id": cached.get("agent_id"),
            "route_id": route_id,
            "body": cached,
        }))).into_response();
    }

    // ── 5. Routing strategy ───────────────────────────────────────────────────
    let agent_id = {
        let strats = state.strategies.read().unwrap();
        strats
            .get(&route_id)
            .and_then(|s| s.select_agent(&envelope))
            .unwrap_or_else(|| "default-agent".to_string())
    };

    // ── 6. Dispatch: MQTT device, OpenAI, or echo ─────────────────────────────
    let t0 = Instant::now();
    let body = if state.mqtt.subscriptions.contains_key(&format!("mofa/requests/{}", route_id)) {
        // MQTT dispatch path
        let correlation_id = Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel::<Value>();
        state.mqtt_pending.insert(correlation_id.clone(), tx);
        let topic = format!("mofa/requests/{}", route_id);
        match state.mqtt.publish(&topic, payload.clone(), &correlation_id).await {
            Ok(()) => {
                match tokio::time::timeout(Duration::from_secs(5), rx).await {
                    Ok(Ok(resp)) => resp,
                    Ok(Err(_)) => json!({"error": "device channel closed"}),
                    Err(_) => {
                        state.mqtt_pending.remove(&correlation_id);
                        return (StatusCode::GATEWAY_TIMEOUT, Json(json!({
                            "error": "IoT device timeout",
                            "route_id": route_id,
                            "device_topic": topic,
                        }))).into_response();
                    }
                }
            }
            Err(e) => json!({"error": e, "route_id": route_id}),
        }
    } else if agent_id.starts_with("gpt-") || agent_id.starts_with("claude-") || agent_id.starts_with("gemini-") {
        // LLM routing path: real OpenAI call if key set, else realistic echo
        if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
            let model = if agent_id.starts_with("gpt-") { &agent_id } else { "gpt-3.5-turbo" };
            let user_msg = payload.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("hello");
            let openai_req = json!({
                "model": model,
                "messages": [{"role": "user", "content": user_msg}],
                "max_tokens": 256,
            });
            let client = reqwest::Client::new();
            match client
                .post("https://api.openai.com/v1/chat/completions")
                .bearer_auth(&api_key)
                .json(&openai_req)
                .timeout(Duration::from_secs(30))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    let resp_json: Value = r.json().await.unwrap_or_default();
                    let content = resp_json["choices"][0]["message"]["content"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    json!({
                        "agent_id": agent_id,
                        "route_id": route_id,
                        "subject": claims.subject,
                        "provider": "openai",
                        "model": model,
                        "content": content,
                        "echo": payload,
                        "usage": resp_json.get("usage"),
                    })
                }
                Ok(r) => {
                    let status = r.status().as_u16();
                    json!({"error": format!("OpenAI returned {}", status), "agent_id": agent_id})
                }
                Err(e) => json!({"error": e.to_string(), "agent_id": agent_id}),
            }
        } else {
            // No API key — realistic echo simulating LLM response shape
            json!({
                "agent_id": agent_id,
                "route_id": route_id,
                "subject": claims.subject,
                "provider": "echo (set OPENAI_API_KEY for real calls)",
                "model": agent_id,
                "content": format!("[simulated] {} processed: {}", agent_id, payload),
                "echo": payload,
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            })
        }
    } else {
        // Generic echo dispatch
        json!({
            "agent_id": agent_id,
            "route_id": route_id,
            "subject": claims.subject,
            "echo": payload,
            "message": format!("handled by {}", agent_id),
        })
    };

    let latency_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);

    // ── 7. Cache store ────────────────────────────────────────────────────────
    state.cache.set(cache_key, body.clone(), None);

    let resp = AgentResponse::new(200, body.clone(), &agent_id, &envelope);

    state.metrics.record_agent_hit(&agent_id);
    state.metrics.push_recent(RecentReq {
        ts_ms: now_ms(),
        path: path.clone(),
        agent: agent_id.clone(),
        status: 200,
        latency_ms,
        subject: claims.subject.clone(),
    });

    (StatusCode::OK, Json(json!({
        "status": resp.status_code,
        "agent_id": resp.agent_id,
        "route_id": route_id,
        "correlation_id": resp.correlation_id,
        "latency_ms": latency_ms,
        "subject": claims.subject,
        "cache": "miss",
        "body": body,
    })))
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn admin_health(State(state): State<SharedState>, headers: HeaderMap) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let snap = state.metrics.snapshot();
    (StatusCode::OK, Json(json!({
        "status": "healthy",
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "total_requests": snap.total,
        "routes_active": state.routes.read().unwrap().list_active().len(),
        "version": env!("CARGO_PKG_VERSION"),
        "rate_limiter": "token-bucket (10 burst, 2/s)",
    }))).into_response()
}

#[derive(Deserialize)]
struct RegisterRouteReq {
    id: String,
    path_pattern: String,
    agent_id: String,
    method: Option<String>,
    strategy: Option<String>,
    /// For weighted_round_robin: list of (agent_id, weight) pairs
    backends: Option<Vec<BackendWeight>>,
    /// For capability_match: fallback agent if score < threshold
    fallback_agent: Option<String>,
    /// Score threshold for capability_match (default 0.5)
    threshold: Option<f64>,
}

#[derive(Deserialize)]
struct BackendWeight {
    agent_id: String,
    weight: u32,
}

async fn admin_list_routes(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let routes: Vec<Value> = state
        .routes
        .read()
        .unwrap()
        .list_active()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "path_pattern": r.path_pattern,
                "agent_id": r.agent_id,
                "method": r.method.to_string(),
                "priority": r.priority,
                "enabled": r.enabled,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!(routes))).into_response()
}

async fn admin_register_route(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRouteReq>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }

    let method = req
        .method
        .as_deref()
        .and_then(HttpMethod::from_str_ci)
        .unwrap_or(HttpMethod::Post);

    let route = GatewayRoute::new(&req.id, &req.agent_id, &req.path_pattern, method);

    if let Err(e) = state.routes.write().unwrap().register(route) {
        let (code, msg) = match &e {
            RegistryError::DuplicateRouteId(_) => (StatusCode::CONFLICT, e.to_string()),
            RegistryError::ConflictingRoutes(_, _) => (StatusCode::CONFLICT, e.to_string()),
            _ => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        };
        return (code, Json(json!({"error": msg}))).into_response();
    }

    // Attach a routing strategy
    let strategy_name = req.strategy.as_deref().unwrap_or("weighted_round_robin");
    let strategy: Arc<dyn RoutingStrategy> = match strategy_name {
        "capability_match" => {
            let fallback = req
                .fallback_agent
                .clone()
                .unwrap_or_else(|| req.agent_id.clone());
            let threshold = req.threshold.unwrap_or(0.5);
            Arc::new(CapabilityMatchRouter::new(
                Arc::new(DemoAgentScorer),
                threshold,
                fallback,
                "task",
            ))
        }
        _ => {
            // weighted_round_robin (default)
            let backends: Vec<(String, u32)> = req
                .backends
                .map(|bs| bs.into_iter().map(|b| (b.agent_id, b.weight)).collect())
                .unwrap_or_else(|| vec![(req.agent_id.clone(), 1)]);
            Arc::new(WeightedRoundRobinRouter::new(backends))
        }
    };

    state
        .strategies
        .write()
        .unwrap()
        .register(req.id.clone(), strategy);

    info!("route '{}' registered with strategy '{}'", req.id, strategy_name);
    (StatusCode::CREATED, Json(json!({"registered": req.id, "strategy": strategy_name}))).into_response()
}

async fn admin_toggle_route(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(route_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let enabled = match body.get("enabled").and_then(|v| v.as_bool()) {
        Some(v) => v,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": "body must be {\"enabled\": true|false}"})),
            )
                .into_response();
        }
    };
    let mut registry = state.routes.write().unwrap();
    match registry.routes.get_mut(&route_id) {
        Some(r) => {
            r.enabled = enabled;
            (StatusCode::OK, Json(json!({"id": route_id, "enabled": enabled}))).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("route '{}' not found", route_id)})),
        )
            .into_response(),
    }
}

async fn admin_deregister_route(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(route_id): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    match state.routes.write().unwrap().deregister(&route_id) {
        Ok(()) => {
            // strategy entry for this route_id is left in place (harmless, no traffic will hit it)
            (StatusCode::OK, Json(json!({"deregistered": route_id}))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct IssueKeyReq {
    subject: String,
    scopes: Option<Vec<String>>,
}

async fn admin_list_keys(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let keys: Vec<Value> = state
        .keys
        .read()
        .unwrap()
        .all_keys()
        .into_iter()
        .map(|(k, c)| {
            json!({
                "key": k,
                "subject": c.subject,
                "scopes": c.scopes,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!(keys))).into_response()
}

async fn admin_issue_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<IssueKeyReq>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let scopes = req.scopes.unwrap_or_else(|| vec!["agents:invoke".to_string()]);
    let key = state.keys.write().unwrap().issue(req.subject.clone(), scopes);
    (StatusCode::CREATED, Json(json!({"key": key, "subject": req.subject}))).into_response()
}

async fn admin_revoke_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    if state.keys.write().unwrap().revoke(&key) {
        (StatusCode::OK, Json(json!({"revoked": key}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": format!("key '{}' not found", key)}))).into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache admin handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn admin_cache_stats(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let stats = state.cache.stats();
    (StatusCode::OK, Json(json!(stats))).into_response()
}

async fn admin_cache_clear(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    state.cache.clear();
    (StatusCode::OK, Json(json!({"cleared": true}))).into_response()
}

async fn admin_cache_invalidate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let removed = state.cache.invalidate(&key);
    if removed {
        (StatusCode::OK, Json(json!({"invalidated": key}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "key not found in cache"}))).into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MQTT admin handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn admin_mqtt_devices(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let devices = state.mqtt.list_devices();
    let stats = state.mqtt.broker_stats();
    (StatusCode::OK, Json(json!({"broker": stats, "devices": devices}))).into_response()
}

async fn admin_mqtt_device_toggle(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let online = match body.get("online").and_then(|v| v.as_bool()) {
        Some(v) => v,
        None => return (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "body must be {\"online\": true|false}"}))).into_response(),
    };
    if state.mqtt.devices.contains_key(&device_id) {
        state.mqtt.set_device_online(&device_id, online);
        (StatusCode::OK, Json(json!({"device_id": device_id, "online": online}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": format!("device '{}' not found", device_id)}))).into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin registry handlers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PublishPluginReq {
    id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    capabilities: Vec<String>,
    entry_point: String,
    checksum: String,
}

async fn admin_plugin_list(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let plugins = state.plugins.list();
    (StatusCode::OK, Json(json!(plugins))).into_response()
}

async fn admin_plugin_publish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<PublishPluginReq>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let manifest = PluginManifest {
        id: req.id.clone(),
        name: req.name,
        version: req.version,
        description: req.description,
        author: req.author,
        capabilities: req.capabilities,
        entry_point: req.entry_point,
        checksum: req.checksum,
        signature: None,
        verified: false,
    };
    match state.plugins.publish(manifest) {
        Ok(()) => (StatusCode::CREATED, Json(json!({"published": req.id}))).into_response(),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"error": e}))).into_response(),
    }
}

async fn admin_plugin_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(plugin_id): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    match state.plugins.plugins.get(&plugin_id) {
        Some(p) => (StatusCode::OK, Json(json!(p.clone()))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": format!("plugin '{}' not found", plugin_id)}))).into_response(),
    }
}

async fn admin_plugin_remove(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(plugin_id): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    if state.plugins.remove(&plugin_id) {
        (StatusCode::OK, Json(json!({"removed": plugin_id}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": format!("plugin '{}' not found", plugin_id)}))).into_response()
    }
}

/// POST /admin/plugins/:id/sign — sign a plugin with the registry key (demo: self-sign)
async fn admin_plugin_sign(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(plugin_id): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    match state.plugins.sign_and_verify(&plugin_id) {
        Ok(sig) => (StatusCode::OK, Json(json!({
            "plugin_id": plugin_id,
            "signature": sig,
            "verified": true,
            "public_key": state.plugins.public_key_hex(),
        }))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))).into_response(),
    }
}

/// POST /admin/plugins/:id/verify — verify an external signature
#[derive(Deserialize)]
struct VerifyPluginReq {
    signature: String,
    public_key: String,
}

async fn admin_plugin_verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(plugin_id): Path<String>,
    Json(req): Json<VerifyPluginReq>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    match state.plugins.verify_signature(&plugin_id, &req.signature, &req.public_key) {
        Ok(()) => (StatusCode::OK, Json(json!({"plugin_id": plugin_id, "verified": true}))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// POST /admin/plugins/:id/install — simulate `mofa plugin install`
async fn admin_plugin_install(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(plugin_id): Path<String>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    match state.plugins.install(&plugin_id) {
        Ok(manifest) => (StatusCode::OK, Json(json!({
            "installed": plugin_id,
            "version": manifest.version,
            "capabilities": manifest.capabilities,
            "verified": manifest.verified,
            "total_installs": state.plugins.installs.load(Ordering::Relaxed),
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// GET /admin/plugins/search?capability=mqtt
async fn admin_plugin_search(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if !state.verify_admin(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"invalid x-admin-key"}))).into_response();
    }
    let results = match params.get("capability") {
        Some(cap) => state.plugins.search_by_capability(cap),
        None => state.plugins.list(),
    };
    (StatusCode::OK, Json(json!(results))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────────────────────────────────────

fn seed_demo_data(state: &AppState) {
    // Pre-issue two API keys
    {
        let mut keys = state.keys.write().unwrap();
        keys.keys.insert(
            DEMO_KEY_ALICE.to_string(),
            AuthClaims::new("user:alice", vec!["agents:invoke".to_string()]),
        );
        keys.keys.insert(
            DEMO_KEY_BOB.to_string(),
            AuthClaims::new("user:bob", vec!["agents:invoke".to_string()]),
        );
    }

    // Route 1: /v1/chat → WeightedRoundRobin (gpt-4 70%, claude-3 30%)
    {
        let route = GatewayRoute::new("chat", "gpt-4", "/v1/chat", HttpMethod::Post);
        state.routes.write().unwrap().register(route).unwrap();
        let router = WeightedRoundRobinRouter::new(vec![
            ("gpt-4".to_string(), 7u32),
            ("claude-3".to_string(), 3u32),
        ]);
        state
            .strategies
            .write()
            .unwrap()
            .register("chat".to_string(), Arc::new(router));
    }

    // Route 2: /v1/vision → CapabilityMatchRouter (vision-agent / text-agent / code-agent)
    {
        let route = GatewayRoute::new("vision", "vision-agent", "/v1/vision", HttpMethod::Post);
        state.routes.write().unwrap().register(route).unwrap();
        let router = CapabilityMatchRouter::new(
            Arc::new(DemoAgentScorer),
            0.5,
            "text-agent".to_string(),
            "task",
        );
        state
            .strategies
            .write()
            .unwrap()
            .register("vision".to_string(), Arc::new(router));
    }

    // Route 3: /v1/code → CapabilityMatchRouter (code-agent preferred)
    {
        let route = GatewayRoute::new("code", "code-agent", "/v1/code", HttpMethod::Post);
        state.routes.write().unwrap().register(route).unwrap();
        let router = CapabilityMatchRouter::new(
            Arc::new(DemoAgentScorer),
            0.5,
            "code-agent".to_string(),
            "task",
        );
        state
            .strategies
            .write()
            .unwrap()
            .register("code".to_string(), Arc::new(router));
    }

    // Route 4: /v1/sensor → MQTT IoT device (temperature sensor)
    {
        let route = GatewayRoute::new("sensor", "iot-sensor", "/v1/sensor", HttpMethod::Post);
        state.routes.write().unwrap().register(route).unwrap();
        // Register the device on the broker (topic = mofa/requests/sensor)
        spawn_iot_device(
            Arc::clone(&state.mqtt),
            "temp-sensor-01".to_string(),
            "mofa/requests/sensor".to_string(),
            Arc::clone(&state.mqtt_pending),
        );
    }

    // Route 5: /v1/actuator → MQTT IoT actuator (smart light)
    {
        let route = GatewayRoute::new("actuator", "iot-actuator", "/v1/actuator", HttpMethod::Post);
        state.routes.write().unwrap().register(route).unwrap();
        spawn_iot_device(
            Arc::clone(&state.mqtt),
            "smart-light-01".to_string(),
            "mofa/requests/actuator".to_string(),
            Arc::clone(&state.mqtt_pending),
        );
    }

    // Seed demo plugins
    {
        let plugins = [
            PluginManifest {
                id: "mqtt-adapter".to_string(),
                name: "MQTT Transport Adapter".to_string(),
                version: "1.0.0".to_string(),
                description: "Bridges MQTT broker to gateway agent routes".to_string(),
                author: "mugiwaraluffy56".to_string(),
                capabilities: vec!["mqtt".to_string(), "iot".to_string(), "transport".to_string()],
                entry_point: "lib.so".to_string(),
                checksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
                signature: None,
                verified: false,
            },
            PluginManifest {
                id: "openai-provider".to_string(),
                name: "OpenAI LLM Provider".to_string(),
                version: "1.2.0".to_string(),
                description: "Routes requests to OpenAI GPT models with token telemetry".to_string(),
                author: "mugiwaraluffy56".to_string(),
                capabilities: vec!["llm".to_string(), "openai".to_string(), "streaming".to_string()],
                entry_point: "lib.so".to_string(),
                checksum: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".to_string(),
                signature: None,
                verified: false,
            },
            PluginManifest {
                id: "ha-adapter".to_string(),
                name: "Home Assistant Adapter".to_string(),
                version: "0.9.0".to_string(),
                description: "Integrates Home Assistant REST and WebSocket APIs as gateway agents".to_string(),
                author: "mugiwaraluffy56".to_string(),
                capabilities: vec!["iot".to_string(), "home-assistant".to_string(), "webhook".to_string()],
                entry_point: "lib.so".to_string(),
                checksum: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
                signature: None,
                verified: false,
            },
        ];
        for p in plugins {
            let id = p.id.clone();
            state.plugins.publish(p).ok();
            // Auto-sign each seeded plugin so it's ready to install
            state.plugins.sign_and_verify(&id).ok();
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let state = Arc::new(AppState::new(ADMIN_KEY));
    seed_demo_data(&state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/logo.png", get(logo_png))
        .route("/live/metrics", get(live_metrics))
        .route("/v1/invoke/:path", post(invoke))
        .route("/admin/health", get(admin_health))
        .route(
            "/admin/routes",
            get(admin_list_routes).post(admin_register_route),
        )
        .route(
            "/admin/routes/:id",
            patch(admin_toggle_route).delete(admin_deregister_route),
        )
        .route("/admin/keys", get(admin_list_keys).post(admin_issue_key))
        .route("/admin/keys/:key", delete(admin_revoke_key))
        // Cache admin
        .route("/admin/cache", get(admin_cache_stats).delete(admin_cache_clear))
        .route("/admin/cache/:key", delete(admin_cache_invalidate))
        // MQTT admin
        .route("/admin/mqtt", get(admin_mqtt_devices))
        .route("/admin/mqtt/:id", patch(admin_mqtt_device_toggle))
        // Plugin registry
        .route("/admin/plugins", get(admin_plugin_list).post(admin_plugin_publish))
        .route("/admin/plugins/search", get(admin_plugin_search))
        .route("/admin/plugins/:id", get(admin_plugin_get).delete(admin_plugin_remove))
        .route("/admin/plugins/:id/sign", post(admin_plugin_sign))
        .route("/admin/plugins/:id/verify", post(admin_plugin_verify))
        .route("/admin/plugins/:id/install", post(admin_plugin_install))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(Arc::clone(&state));

    let addr: SocketAddr = BIND_ADDR.parse().unwrap();

    info!("╔══════════════════════════════════════════════════╗");
    info!("║     MoFA Cognitive Gateway  —  live demo         ║");
    info!("╚══════════════════════════════════════════════════╝");
    info!("");
    info!("  Dashboard  →  http://{}", BIND_ADDR);
    info!("");
    info!("  Pre-seeded routes:");
    info!("    POST /v1/chat     → WeightedRoundRobin (gpt-4 70%, claude-3 30%)");
    info!("    POST /v1/vision   → CapabilityMatch    (vision/text/code agents)");
    info!("    POST /v1/code     → CapabilityMatch    (code agent preferred)");
    info!("    POST /v1/sensor   → MQTT IoT device    (temp-sensor-01)");
    info!("    POST /v1/actuator → MQTT IoT device    (smart-light-01)");
    info!("");
    info!("  Pre-seeded API keys:");
    info!("    alice:  {}", DEMO_KEY_ALICE);
    info!("    bob:    {}", DEMO_KEY_BOB);
    info!("");
    info!("  Admin key: {}", ADMIN_KEY);
    info!("");
    info!("  Quick test:");
    info!("    curl -s -X POST http://127.0.0.1:8080/v1/invoke/chat \\");
    info!("         -H 'x-api-key: {}' \\", DEMO_KEY_ALICE);
    info!("         -H 'content-type: application/json' \\");
    info!("         -d '{{\"message\":\"hello\"}}' | jq .");
    info!("");
    info!("  Rate-limit stress test (run 15 times in 1 second):");
    info!("    for i in $(seq 1 15); do curl -s -X POST http://127.0.0.1:8080/v1/invoke/chat \\");
    info!("         -H 'x-api-key: {}' \\", DEMO_KEY_ALICE);
    info!("         -H 'content-type: application/json' \\");
    info!("         -d '{{\"message\":\"ping\"}}' | jq .status; done");
    info!("");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Embedded HTML dashboard
// ─────────────────────────────────────────────────────────────────────────────


static DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MoFA Cognitive Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --red:    #D32F2F;
    --blue:   #1976D2;
    --yellow: #FFB300;
    --black:  #2D3748;
    --white:  #FFFFFF;
    --off:    #F7F8FA;
    --border: #2D3748;
    --g1:#FB6A58;--g2:#FD543F;--g3:#FFC63E;--g4:#6DCACE;
    --muted: #6b7280;
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--off);color:var(--black);font-family:'Inter',sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased;}

  /* ─── HEADER ─────────────────────────────────────────────── */
  header{
    background:var(--white);
    border-bottom:4px solid var(--black);
    height:72px;padding:0 2.5rem;
    display:flex;align-items:center;gap:1rem;
    position:sticky;top:0;z-index:200;
  }
  @keyframes gradient-flow{
    0%{background-position:0% 50%;}
    25%{background-position:100% 50%;}
    50%{background-position:100% 100%;}
    75%{background-position:0% 100%;}
    to{background-position:0% 50%;}
  }
  .brand{font-size:1.25rem;font-weight:900;letter-spacing:-0.5px;background:linear-gradient(120deg,#FB6A58,#FD543F,#FFC63E,#6DCACE);background-size:300% 300%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:gradient-flow 12s ease-in-out infinite;}
  .vsep{width:1px;height:22px;background:#d1d5db;margin:0 0.25rem;}
  .sub{font-size:0.82rem;font-weight:500;color:var(--muted);}

  .nav{display:flex;align-items:center;gap:0.4rem;margin-left:1rem;}
  .nav a{
    text-decoration:none;font-size:0.75rem;font-weight:700;letter-spacing:0.2px;
    padding:5px 11px;border:2px solid #d1d5db;color:var(--muted);background:var(--white);
    font-family:'JetBrains Mono',monospace;transition:all 0.12s;
  }
  .nav a:hover{color:var(--red);border-color:var(--red);transform:translate(-1px,-1px);box-shadow:2px 2px 0 var(--black);}
  .nav .ghbtn{
    display:inline-flex;align-items:center;gap:6px;
    background:linear-gradient(135deg,#FF5039,#FF6756);
    color:#fff!important;border:2px solid var(--black)!important;
    font-family:'Inter',sans-serif!important;font-weight:800!important;letter-spacing:0!important;
    padding:6px 14px!important;font-size:0.8rem!important;
  }
  .nav .ghbtn:hover{background:linear-gradient(135deg,#FFC938,#6ACFD1)!important;color:var(--black)!important;transform:translate(-2px,-2px)!important;box-shadow:3px 3px 0 var(--black)!important;}

  /* ─── DROPDOWN ───────────────────────────────────────────── */
  .dropdown{position:relative;}
  .dd-trigger{
    display:inline-flex;align-items:center;gap:5px;
    font-size:0.75rem;font-weight:700;letter-spacing:0.2px;
    padding:5px 11px;border:2px solid #d1d5db;color:var(--muted);background:var(--white);
    font-family:'JetBrains Mono',monospace;cursor:pointer;
    transition:all 0.12s;
  }
  .dd-trigger:hover,.dropdown.open .dd-trigger{
    color:var(--red);border-color:var(--red);
  }
  .dropdown.open .dd-trigger svg{transform:rotate(180deg);}
  .dd-trigger svg{transition:transform 0.15s;}

  .dd-menu{
    display:none;position:absolute;top:calc(100% + 6px);left:0;
    background:var(--white);border:2px solid var(--black);
    min-width:340px;z-index:500;
    box-shadow:4px 4px 0 var(--black);
    max-height:420px;overflow-y:auto;
  }
  .dropdown.open .dd-menu{display:block;}

  .dd-group-label{
    font-size:0.58rem;font-weight:800;text-transform:uppercase;letter-spacing:1.2px;
    color:var(--muted);padding:0.5rem 0.875rem 0.35rem;
    border-bottom:1px solid var(--gray2,#f1f5f9);
    background:var(--off);
  }
  .dd-item{
    display:flex;align-items:center;gap:0.6rem;
    padding:0.55rem 0.875rem;text-decoration:none;
    border-bottom:1px solid var(--off,#f7f8fa);
    transition:background 0.1s;
  }
  .dd-item:last-child{border-bottom:none;}
  .dd-item:hover{background:#f0f4ff;}
  .dd-num{
    font-family:'JetBrains Mono',monospace;font-size:0.68rem;font-weight:800;
    color:var(--red);width:32px;flex-shrink:0;
  }
  .dd-title{font-size:0.75rem;font-weight:500;color:var(--black);flex:1;}
  .dd-tag{
    font-size:0.58rem;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;
    padding:2px 6px;border:1.5px solid #d1d5db;color:var(--muted);
    font-family:'JetBrains Mono',monospace;flex-shrink:0;
  }

  .hdr-end{margin-left:auto;display:flex;align-items:center;gap:0.75rem;}
  .up-pill{font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:600;color:var(--muted);background:var(--off);border:1.5px solid #d1d5db;padding:4px 10px;}
  .live-btn{
    display:flex;align-items:center;gap:7px;
    font-size:0.72rem;font-weight:800;text-transform:uppercase;letter-spacing:1px;
    border:2px solid var(--black);padding:6px 13px;background:var(--white);color:var(--black);
  }
  .live-btn::before{content:'';width:8px;height:8px;border-radius:50%;background:#16a34a;animation:pulse 1.8s ease-in-out infinite;}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.4;transform:scale(0.8)}}

  /* ─── STATS STRIP ────────────────────────────────────────── */
  .stats-wrap{padding:1.5rem 1.75rem 0;max-width:1100px;margin:0 auto;}
  .stats{
    display:grid;grid-template-columns:repeat(4,1fr);
    border:2px solid var(--black);
  }
  .sp{
    background:var(--white);
    display:flex;flex-direction:column;justify-content:space-between;
    padding:1rem 1.25rem 0.875rem;
    border-right:2px solid var(--black);
    border-top:4px solid transparent;
    transition:background .12s;
    gap:0.5rem;
  }
  .sp:last-child{border-right:none;}
  .sp:hover{background:#fafafa;}
  .sp.sr{border-top-color:var(--red);}
  .sp.sb{border-top-color:var(--blue);}
  .sp.sy{border-top-color:var(--yellow);}
  .sp.sk{border-top-color:var(--black);}
  .sp-top{display:flex;align-items:center;justify-content:space-between;}
  .sp-label{font-size:0.58rem;font-weight:800;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);}
  .sp-badge{font-size:0.52rem;font-weight:700;font-family:'JetBrains Mono',monospace;padding:2px 5px;border:1.5px solid;}
  .sp.sr .sp-badge{color:var(--red);border-color:var(--red);}
  .sp.sb .sp-badge{color:var(--blue);border-color:var(--blue);}
  .sp.sy .sp-badge{color:#92400e;border-color:var(--yellow);}
  .sp.sk .sp-badge{color:var(--black);border-color:var(--black);}
  .sp-num{font-size:2rem;font-weight:900;line-height:1;letter-spacing:-1.5px;font-variant-numeric:tabular-nums;}
  .sp.sr .sp-num{color:var(--red);}
  .sp.sb .sp-num{color:var(--blue);}
  .sp.sy .sp-num{color:#92400e;}
  .sp.sk .sp-num{color:var(--black);}
  .sp-hint{font-size:0.6rem;color:var(--muted);font-weight:500;}

  /* ─── LAYOUT ─────────────────────────────────────────────── */
  .page{max-width:1100px;margin:0 auto;padding:1.75rem 1.75rem 3rem;}

  .sh{
    display:flex;align-items:center;gap:0.75rem;margin-bottom:1.1rem;
  }
  .sh span{
    font-size:0.62rem;font-weight:800;text-transform:uppercase;letter-spacing:1.6px;
    color:var(--black);background:var(--black);color:#fff;
    padding:3px 10px;
  }
  .sh::after{content:'';flex:1;height:3px;background:var(--black);}

  .g3{display:grid;grid-template-columns:5fr 3fr 3fr;gap:1.25rem;margin-bottom:1.5rem;}
  .g2{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;margin-bottom:1.5rem;}
  @media(max-width:1100px){.g3{grid-template-columns:1fr;}}
  @media(max-width:860px){.g2{grid-template-columns:1fr;}}

  /* ─── CARD ──────────────────────────────────────────────── */
  .card{background:var(--white);border:3px solid var(--black);display:flex;flex-direction:column;transition:transform .15s,box-shadow .15s;}
  .card:hover{transform:translate(-3px,-3px);box-shadow:5px 5px 0 var(--black);}

  .ch{
    padding:0.8rem 1.25rem;border-bottom:3px solid var(--black);
    background:var(--off);display:flex;align-items:center;gap:0.6rem;flex-shrink:0;
  }
  .ch-icon{
    width:28px;height:28px;background:var(--white);border:2px solid var(--black);
    display:flex;align-items:center;justify-content:center;font-size:0.8rem;flex-shrink:0;
  }
  .ch h3{font-size:0.8rem;font-weight:800;color:var(--black);letter-spacing:0.1px;}
  .ch-meta{margin-left:auto;font-size:0.62rem;font-weight:700;color:var(--muted);font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:0.5px;}

  .cb{padding:1.25rem;flex:1;}
  .cb.flush{padding:0;}

  /* ─── BAR CHART ─────────────────────────────────────────── */
  .arow{display:flex;align-items:center;gap:0.7rem;padding:0.45rem 0;border-bottom:1px solid var(--off);}
  .arow:last-child{border-bottom:none;}
  .aname{width:106px;font-size:0.7rem;font-weight:700;font-family:'JetBrains Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;color:var(--black);}
  .btrack{flex:1;background:#f1f5f9;border:2px solid var(--black);height:22px;overflow:hidden;}
  .bfill{height:100%;transition:width .45s cubic-bezier(.4,0,.2,1);display:flex;align-items:center;padding-left:6px;font-size:0.62rem;font-weight:800;color:#fff;white-space:nowrap;font-family:'JetBrains Mono',monospace;}
  .bfill.cr{background:var(--red);}
  .bfill.cp{background:#7c3aed;}
  .bfill.cy{background:var(--yellow);color:var(--black);}
  .bfill.cb2{background:var(--blue);}
  .bfill.ct{background:var(--g4);color:var(--black);}
  .bfill.cg{background:#94a3b8;}
  .bcnt{width:28px;text-align:right;font-size:0.68rem;font-weight:800;color:var(--muted);font-family:'JetBrains Mono',monospace;flex-shrink:0;}

  /* ─── PIPELINE ──────────────────────────────────────────── */
  .pline{display:flex;flex-direction:column;}
  .pstep{display:flex;border-bottom:2px solid #f1f5f9;}
  .pstep:last-child{border-bottom:none;}
  .pbar{width:6px;flex-shrink:0;}
  .pstep.pa .pbar{background:var(--blue);}
  .pstep.pr .pbar{background:var(--yellow);}
  .pstep.pm .pbar{background:var(--red);}
  .pstep.ps .pbar{background:var(--g4);}
  .pin{padding:0.85rem 1rem;flex:1;display:flex;align-items:center;gap:0.75rem;}
  .pn{font-size:0.6rem;font-weight:800;font-family:'JetBrains Mono',monospace;color:#9ca3af;width:18px;flex-shrink:0;}
  .ptxt{flex:1;}
  .ptitle{font-size:0.78rem;font-weight:800;color:var(--black);margin-bottom:2px;}
  .pdesc{font-size:0.67rem;color:var(--muted);}
  .ptag{
    font-size:0.6rem;font-weight:800;padding:2px 7px;border:2px solid;
    font-family:'JetBrains Mono',monospace;white-space:nowrap;flex-shrink:0;
  }
  .pstep.pa .ptag{color:var(--blue);border-color:var(--blue);background:#eff6ff;}
  .pstep.pr .ptag{color:#92400e;border-color:#fcd34d;background:#fffbeb;}
  .pstep.pm .ptag{color:var(--red);border-color:var(--red);background:#fef2f2;}
  .pstep.ps .ptag{color:#0e7490;border-color:#22d3ee;background:#ecfeff;}

  /* ─── KEYS ──────────────────────────────────────────────── */
  .krow{display:flex;align-items:center;gap:0.6rem;padding:0.75rem 1.25rem;border-bottom:2px solid #f1f5f9;font-size:0.72rem;}
  .krow:last-child{border-bottom:none;}
  .kdot{width:9px;height:9px;border-radius:50%;flex-shrink:0;}
  .ksubj{font-weight:800;color:var(--black);width:76px;flex-shrink:0;}
  .kval{font-family:'JetBrains Mono',monospace;font-size:0.64rem;background:var(--off);border:2px solid #d1d5db;padding:2px 7px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .kval.danger{border-color:var(--red);color:var(--red);background:#fef2f2;}

  /* ─── TABLES ─────────────────────────────────────────────── */
  .tbl{width:100%;border-collapse:collapse;}
  .tbl th{
    font-size:0.6rem;font-weight:800;text-transform:uppercase;letter-spacing:1.2px;
    color:var(--muted);padding:0.55rem 1rem;text-align:left;
    border-bottom:3px solid var(--black);background:var(--off);white-space:nowrap;
  }
  .tbl td{padding:0.55rem 1rem;border-bottom:1px solid #f1f5f9;vertical-align:middle;font-size:0.77rem;}
  .tbl tr:last-child td{border-bottom:none;}
  .tbl tbody tr:hover td{background:#f0f4ff;}

  /* ─── CHIPS & BADGES ─────────────────────────────────────── */
  .tag{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:0.65rem;font-weight:700;padding:2px 7px;border:2px solid;white-space:nowrap;}
  .tag-r{color:var(--red);border-color:#fca5a5;background:#fef2f2;}
  .tag-b{color:var(--blue);border-color:#93c5fd;background:#eff6ff;}
  .tag-t{color:#0e7490;border-color:#67e8f9;background:#ecfeff;}
  .tag-p{color:#7c3aed;border-color:#c4b5fd;background:#faf5ff;}
  .tag-g{color:var(--muted);border-color:#d1d5db;background:var(--off);}

  .badge{display:inline-block;font-size:0.62rem;font-weight:800;padding:3px 9px;text-transform:uppercase;letter-spacing:0.4px;}
  .ok{background:#16a34a;color:#fff;}
  .err{background:var(--red);color:#fff;}
  .warn{background:var(--yellow);color:var(--black);}
  .dis{background:#94a3b8;color:#fff;}

  /* ─── EMPTY ─────────────────────────────────────────────── */
  .empty{padding:2rem 1.5rem;text-align:center;color:var(--muted);}
  .empty-ico{font-size:1.8rem;margin-bottom:0.6rem;opacity:0.35;}
  .empty p{font-size:0.78rem;margin-bottom:1.25rem;}
  .cblock{
    font-family:'JetBrains Mono',monospace;font-size:0.69rem;color:var(--red);
    background:#fef2f2;padding:0.875rem 1rem;text-align:left;line-height:2;
    border:3px solid var(--red);display:block;width:100%;
  }
  .cblock .dim{color:#9ca3af;}
  .cblock .kw{color:var(--blue);}

  /* ─── FOOTER ─────────────────────────────────────────────── */
  footer{background:var(--black);border-top:4px solid var(--black);padding:1.5rem 1.75rem;color:rgba(255,255,255,0.4);font-size:0.7rem;}
  .fi{max-width:1100px;margin:0 auto;display:flex;align-items:center;flex-wrap:wrap;gap:1.25rem;}
  .flogo{display:grid;grid-template-columns:1fr 1fr;width:24px;height:24px;border:1.5px solid rgba(255,255,255,0.2);}
  .flogo span{display:flex;align-items:center;justify-content:center;font-size:7px;font-weight:900;color:#fff;}
  .flogo .lm{background:var(--g1);}
  .flogo .lf{background:var(--g3);}
  .flogo .lo{background:var(--g2);}
  .flogo .la{background:var(--g4);}
  .fname{font-size:0.82rem;font-weight:900;color:rgba(255,255,255,0.7);margin-right:auto;}
  .fpills{display:flex;gap:0.5rem;flex-wrap:wrap;}
  .fp{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);padding:3px 8px;display:flex;align-items:center;gap:4px;font-size:0.64rem;}
  .fp strong{color:rgba(255,255,255,0.7);font-weight:700;}
  .fp code{font-family:'JetBrains Mono',monospace;color:var(--g4);font-size:0.6rem;}
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <img src="/logo.png" alt="MoFA" style="width:34px;height:34px;object-fit:cover;border-radius:6px;flex-shrink:0;">
  <span class="brand">MoFA</span>
  <div class="vsep"></div>
  <span class="sub">Cognitive Gateway</span>

  <div class="nav">
    <a class="ghbtn" href="https://github.com/mofa-org/mofa" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="currentColor" width="13" height="13"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
      mofa-org/mofa
    </a>
    <a href="https://github.com/mugiwaraluffy56/mofa/tree/demo/gateway-live-demo" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:4px;">
      <svg viewBox="0 0 24 24" fill="currentColor" width="10" height="10"><path d="M6 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6zm0 8a5 5 0 0 1 4.9 4H21v2H10.9A5.002 5.002 0 0 1 1 16a5 5 0 0 1 5-5zm6-8h2v2.126A5.002 5.002 0 0 1 18 15a5 5 0 0 1-4.9-4H3V9h10.1A5.002 5.002 0 0 1 12 5V3z"/></svg>
      demo/gateway-live-demo
    </a>
    <div class="dropdown" id="dd-issues">
      <button class="dd-trigger" onclick="toggleDd('dd-issues')">
        Issues
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="10" height="10"><path d="M6 9l6 6 6-6"/></svg>
      </button>
      <div class="dd-menu">
        <div class="dd-group-label">Core Gateway (#699 - #708)</div>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/699" target="_blank" rel="noopener">
          <span class="dd-num">#699</span>
          <span class="dd-title">GatewayRoute / RouteRegistry / RoutingContext</span>
          <span class="dd-tag">kernel</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/700" target="_blank" rel="noopener">
          <span class="dd-num">#700</span>
          <span class="dd-title">RequestEnvelope / GatewayResponse types</span>
          <span class="dd-tag">kernel</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/701" target="_blank" rel="noopener">
          <span class="dd-num">#701</span>
          <span class="dd-title">AuthClaims / AuthProvider / ApiKeyStore</span>
          <span class="dd-tag">kernel</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/702" target="_blank" rel="noopener">
          <span class="dd-num">#702</span>
          <span class="dd-title">Token-bucket rate limiter</span>
          <span class="dd-tag">foundation</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/703" target="_blank" rel="noopener">
          <span class="dd-num">#703</span>
          <span class="dd-title">Weighted round-robin + capability routing</span>
          <span class="dd-tag">foundation</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/704" target="_blank" rel="noopener">
          <span class="dd-num">#704</span>
          <span class="dd-title">TOML config + atomic hot-reload</span>
          <span class="dd-tag">foundation</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/705" target="_blank" rel="noopener">
          <span class="dd-num">#705</span>
          <span class="dd-title">Composable middleware pipeline</span>
          <span class="dd-tag">foundation</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/706" target="_blank" rel="noopener">
          <span class="dd-num">#706</span>
          <span class="dd-title">Admin REST API</span>
          <span class="dd-tag">example</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/707" target="_blank" rel="noopener">
          <span class="dd-num">#707</span>
          <span class="dd-title">Per-route deadline propagation + 504 enforcement</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/708" target="_blank" rel="noopener">
          <span class="dd-num">#708</span>
          <span class="dd-title">Integration test harness + fault injection</span>
          <span class="dd-tag">infra</span>
        </a>
        <div class="dd-group-label">Extended Gateway (#922 - #928)</div>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/922" target="_blank" rel="noopener">
          <span class="dd-num">#922</span>
          <span class="dd-title">MQTT transport + IoT capability layer</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/923" target="_blank" rel="noopener">
          <span class="dd-num">#923</span>
          <span class="dd-title">MCP bridge: external servers as gateway agents</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/924" target="_blank" rel="noopener">
          <span class="dd-num">#924</span>
          <span class="dd-title">Agent-to-Agent protocol bridge</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/925" target="_blank" rel="noopener">
          <span class="dd-num">#925</span>
          <span class="dd-title">JWT + OAuth2 AuthProvider</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/926" target="_blank" rel="noopener">
          <span class="dd-num">#926</span>
          <span class="dd-title">Request + response transformation middleware</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/927" target="_blank" rel="noopener">
          <span class="dd-num">#927</span>
          <span class="dd-title">Plugin registry + Ed25519 signature verification</span>
          <span class="dd-tag">platform</span>
        </a>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/issues/928" target="_blank" rel="noopener">
          <span class="dd-num">#928</span>
          <span class="dd-title">Wasm plugin sandbox for third-party adapters</span>
          <span class="dd-tag">platform</span>
        </a>
      </div>
    </div>

    <div class="dropdown" id="dd-prs">
      <button class="dd-trigger" onclick="toggleDd('dd-prs')">
        PRs
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="10" height="10"><path d="M6 9l6 6 6-6"/></svg>
      </button>
      <div class="dd-menu">
        <div class="dd-group-label">Open / Merged</div>
        <a class="dd-item" href="https://github.com/mofa-org/mofa/pulls/mugiwaraluffy56" target="_blank" rel="noopener">
          <span class="dd-num" style="color:var(--blue);">⇡</span>
          <span class="dd-title">All PRs by mugiwaraluffy56</span>
          <span class="dd-tag" style="color:var(--blue);border-color:var(--blue);">view all</span>
        </a>
        <a class="dd-item" href="https://github.com/mugiwaraluffy56/mofa/tree/demo/gateway-live-demo" target="_blank" rel="noopener">
          <span class="dd-num" style="color:#7c3aed;">⎇</span>
          <span class="dd-title">demo/gateway-live-demo</span>
          <span class="dd-tag" style="color:#7c3aed;border-color:#c4b5fd;">branch</span>
        </a>
      </div>
    </div>
  </div>

  <div class="hdr-end">
    <span class="up-pill" id="uptime-pill">up 0s</span>
    <span class="live-btn" id="live-btn">Live</span>
  </div>
</header>

<!-- STATS STRIP -->
<div class="stats-wrap">
<div class="stats">
  <div class="sp sr">
    <div class="sp-top">
      <div class="sp-label">Total Requests</div>
      <div class="sp-badge">ALL TIME</div>
    </div>
    <div class="sp-num" id="stat-total">0</div>
    <div class="sp-hint">requests received</div>
  </div>
  <div class="sp sb">
    <div class="sp-top">
      <div class="sp-label">Routed OK</div>
      <div class="sp-badge">HTTP 200</div>
    </div>
    <div class="sp-num" id="stat-routed">0</div>
    <div class="sp-hint">dispatched to agents</div>
  </div>
  <div class="sp sy">
    <div class="sp-top">
      <div class="sp-label">Rate Limited</div>
      <div class="sp-badge">HTTP 429</div>
    </div>
    <div class="sp-num" id="stat-ratelimited">0</div>
    <div class="sp-hint">token bucket exhausted</div>
  </div>
  <div class="sp sk">
    <div class="sp-top">
      <div class="sp-label">Auth Rejected</div>
      <div class="sp-badge">HTTP 401</div>
    </div>
    <div class="sp-num" id="stat-auth">0</div>
    <div class="sp-hint">invalid or missing key</div>
  </div>
</div>
</div><!-- /stats-wrap -->

<!-- PAGE -->
<div class="page">

  <div class="sh"><span>Live Traffic</span></div>
  <div class="g3">

    <!-- Routing chart -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon" style="color:var(--red);"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="5" r="3"/><circle cx="5" cy="19" r="3"/><circle cx="19" cy="19" r="3"/><path d="M12 8v3m0 0-5 5m5-5 5 5"/></svg></div>
        <h3>Agent Routing Distribution</h3>
        <span class="ch-meta" id="dist-badge">0 req</span>
      </div>
      <div class="cb" id="routing-chart">
        <div class="empty">
          <p>No requests yet. Send traffic to see the routing split live.</p>
          <code class="cblock">
            <span class="dim"># send a request</span><br>
            curl -s -X POST http://127.0.0.1:8080/v1/invoke/chat \<br>
            &nbsp; -H <span class="kw">'x-api-key: alice-key-abc123'</span> \<br>
            &nbsp; -H 'content-type: application/json' \<br>
            &nbsp; -d '{"message":"hello"}' | jq .
          </code>
        </div>
      </div>
    </div>

    <!-- Active routes -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon" style="color:var(--blue);"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M3 12h18M3 6h18M3 18h18"/></svg></div>
        <h3>Active Routes</h3>
        <span class="ch-meta" id="routes-badge"></span>
      </div>
      <div class="cb flush">
        <table class="tbl">
          <thead><tr><th>ID</th><th>Path</th><th>State</th></tr></thead>
          <tbody id="routes-table">
            <tr><td colspan="3" style="text-align:center;color:var(--muted);padding:1.5rem;font-size:0.75rem;">loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- API keys -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="8" cy="15" r="4"/><path d="m15 9-1.5 1.5M21 3l-6 6-1.5-1.5"/></svg></div>
        <h3>API Keys</h3>
      </div>
      <div class="cb flush">
        <div class="krow">
          <div class="kdot" style="background:#16a34a;"></div>
          <div class="ksubj">user:alice</div>
          <div class="kval">alice-key-abc123</div>
        </div>
        <div class="krow">
          <div class="kdot" style="background:#16a34a;"></div>
          <div class="ksubj">user:bob</div>
          <div class="kval">bob-key-xyz789</div>
        </div>
        <div class="krow" style="border-top:3px solid var(--black);background:#fef2f2;">
          <div class="kdot" style="background:var(--red);"></div>
          <div class="ksubj">admin</div>
          <div class="kval danger">admin-secret-2025</div>
        </div>
      </div>
    </div>

  </div>

  <div class="sh"><span>Architecture</span></div>
  <div class="g2">

    <!-- Pipeline -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
        <h3>Request Pipeline</h3>
        <span class="ch-meta">auth / rate / route / strategy</span>
      </div>
      <div class="cb flush">
        <div class="pline">
          <div class="pstep pa">
            <div class="pbar"></div>
            <div class="pin">
              <div class="pn">01</div>
              <div class="ptxt">
                <div class="ptitle">Auth: ApiKeyStore</div>
                <div class="pdesc">Validates <code style="font-family:monospace;font-size:0.65rem;">x-api-key</code> header · returns 401 on missing or invalid</div>
              </div>
              <div class="ptag">kernel #701</div>
            </div>
          </div>
          <div class="pstep pr">
            <div class="pbar"></div>
            <div class="pin">
              <div class="pn">02</div>
              <div class="ptxt">
                <div class="ptitle">Rate Limit: TokenBucketRateLimiter</div>
                <div class="pdesc">10 burst · 2 req/s per subject · returns 429 + retry_after_ms</div>
              </div>
              <div class="ptag">kernel #702</div>
            </div>
          </div>
          <div class="pstep pm">
            <div class="pbar"></div>
            <div class="pin">
              <div class="pn">03</div>
              <div class="ptxt">
                <div class="ptitle">Route Match: RouteRegistry</div>
                <div class="pdesc">Highest-priority enabled route for path + HTTP method · 404 if none</div>
              </div>
              <div class="ptag">kernel #699</div>
            </div>
          </div>
          <div class="pstep ps">
            <div class="pbar"></div>
            <div class="pin">
              <div class="pn">04</div>
              <div class="ptxt">
                <div class="ptitle">Strategy: WRR / CapabilityMatch</div>
                <div class="pdesc">WeightedRoundRobin (chat 70/30) · CapabilityMatch (vision, code)</div>
              </div>
              <div class="ptag">kernel #703</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Recent log -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg></div>
        <h3>Recent Requests</h3>
        <span class="ch-meta" id="log-badge">0 entries</span>
      </div>
      <div class="cb flush">
        <table class="tbl" style="width:100%;">
          <thead><tr><th>Time</th><th>Path</th><th>Agent</th><th>Status</th><th>ms</th></tr></thead>
        </table>
        <div style="max-height:260px;overflow-y:auto;overflow-x:hidden;">
          <table class="tbl" style="width:100%;">
            <tbody id="recent-log">
              <tr><td colspan="5">
                <div class="empty">
                  <p>Waiting for requests.</p>
                </div>
              </td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>
</div>

<!-- INFRASTRUCTURE -->
<div class="page" style="padding-top:0;">
  <div class="sh"><span>Infrastructure</span></div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.25rem;margin-bottom:1.5rem;">

    <!-- Cache card -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon" style="color:var(--blue);"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
        <h3>L1 Cache</h3>
        <span class="ch-meta" id="cache-badge">TTL 60s</span>
      </div>
      <div class="cb">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-bottom:1rem;">
          <div style="text-align:center;padding:0.75rem;background:var(--off);border:1.5px solid #e5e7eb;">
            <div style="font-size:0.55rem;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:0.25rem;">Hit Rate</div>
            <div id="cache-hitrate" style="font-size:1.5rem;font-weight:900;color:var(--blue);font-variant-numeric:tabular-nums;">0%</div>
          </div>
          <div style="text-align:center;padding:0.75rem;background:var(--off);border:1.5px solid #e5e7eb;">
            <div style="font-size:0.55rem;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:0.25rem;">Entries</div>
            <div id="cache-size" style="font-size:1.5rem;font-weight:900;color:var(--black);font-variant-numeric:tabular-nums;">0</div>
          </div>
        </div>
        <div style="display:flex;gap:0.5rem;font-size:0.7rem;color:var(--muted);">
          <span>Hits: <strong id="cache-hits" style="color:var(--blue);">0</strong></span>
          <span style="margin-left:auto;">Misses: <strong id="cache-misses" style="color:var(--muted);">0</strong></span>
        </div>
      </div>
    </div>

    <!-- MQTT card -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon" style="color:#16a34a;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2a10 10 0 0 1 10 10"/><path d="M12 2a6 6 0 0 1 6 6"/><path d="M12 2a2 2 0 0 1 2 2"/><circle cx="12" cy="19" r="3"/></svg></div>
        <h3>IoT / MQTT</h3>
        <span class="ch-meta" id="mqtt-badge">in-process broker</span>
      </div>
      <div class="cb flush">
        <table class="tbl" style="width:100%;">
          <thead><tr><th>Device</th><th>Topic</th><th>Msgs</th><th>Status</th></tr></thead>
          <tbody id="mqtt-devices">
            <tr><td colspan="4"><div class="empty"><p>No devices.</p></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Plugins card -->
    <div class="card">
      <div class="ch">
        <div class="ch-icon" style="color:#7c3aed;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6 6 18M8 6v4m8-4v4M5 10h14a1 1 0 0 1 1 1v2a6 6 0 0 1-6 6H9a6 6 0 0 1-6-6v-2a1 1 0 0 1 1-1z"/></svg></div>
        <h3>Plugin Registry</h3>
        <span class="ch-meta" id="plugin-badge">Ed25519 signed</span>
      </div>
      <div class="cb flush">
        <table class="tbl" style="width:100%;">
          <thead><tr><th>Plugin</th><th>Version</th><th>Caps</th><th>Sig</th></tr></thead>
          <tbody id="plugin-list">
            <tr><td colspan="4"><div class="empty"><p>No plugins.</p></div></td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<!-- ABOUT -->
<div class="page" style="padding-top:0;">
  <div class="sh"><span>About</span></div>
  <div class="card">
    <div style="display:grid;grid-template-columns:1fr 280px;border-bottom:none;">

      <!-- left: project info -->
      <div style="padding:1.75rem 2rem;border-right:2px solid var(--black);">
        <div style="font-size:0.58rem;font-weight:800;text-transform:uppercase;letter-spacing:1.4px;color:var(--muted);margin-bottom:0.6rem;">Project</div>
        <div style="font-size:1.05rem;font-weight:900;color:var(--black);margin-bottom:0.875rem;letter-spacing:-0.3px;">MoFA Cognitive Gateway</div>
        <p style="font-size:0.8rem;line-height:1.75;color:var(--black);margin-bottom:1rem;">
          A Rust-native AI agent gateway connecting the digital world (LLM, MCP, A2A) with the physical world (IoT, edge). Implements a composable request pipeline backed by kernel trait contracts: auth, rate limiting, route matching, and capability-aware strategy dispatch with zero-cost foundation implementations.
        </p>
        <p style="font-size:0.75rem;line-height:1.65;color:var(--muted);margin-bottom:1.25rem;">
          Built for GSoC 2025 under the MoFA project (Idea 1: Cognitive Gateway). Covers issues #699 to #706: kernel traits for routing, auth, and rate limiting; WeightedRoundRobin and CapabilityMatch routing strategies in the foundation layer; and this live demo wiring it all together end-to-end.
        </p>
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid var(--black);color:var(--black);font-family:'JetBrains Mono',monospace;">GSoC 2025</span>
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid var(--red);color:var(--red);font-family:'JetBrains Mono',monospace;">Rust</span>
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid var(--blue);color:var(--blue);font-family:'JetBrains Mono',monospace;">axum 0.7</span>
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid #d1d5db;color:var(--muted);font-family:'JetBrains Mono',monospace;">tokio</span>
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid #d1d5db;color:var(--muted);font-family:'JetBrains Mono',monospace;">mofa-kernel</span>
          <span style="font-size:0.62rem;font-weight:700;padding:3px 9px;border:2px solid #d1d5db;color:var(--muted);font-family:'JetBrains Mono',monospace;">mofa-foundation</span>
        </div>
      </div>

      <!-- right: author -->
      <div style="padding:1.75rem 1.5rem;display:flex;flex-direction:column;gap:1rem;">
        <div style="font-size:0.58rem;font-weight:800;text-transform:uppercase;letter-spacing:1.4px;color:var(--muted);">Author</div>
        <a href="https://github.com/mugiwaraluffy56" target="_blank" rel="noopener"
           style="display:flex;align-items:center;gap:0.75rem;text-decoration:none;
                  border:2px solid var(--black);padding:0.875rem 1rem;background:var(--white);
                  transition:transform .12s,box-shadow .12s;"
           onmouseover="this.style.transform='translate(-2px,-2px)';this.style.boxShadow='4px 4px 0 var(--black)'"
           onmouseout="this.style.transform='';this.style.boxShadow=''">
          <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22" style="flex-shrink:0;color:var(--black);"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
          <div>
            <div style="font-size:0.88rem;font-weight:800;color:var(--black);line-height:1.2;">Puneeth Aditya</div>
            <div style="font-size:0.7rem;font-family:'JetBrains Mono',monospace;color:var(--muted);margin-top:2px;">@mugiwaraluffy56</div>
          </div>
        </a>
        <div style="font-size:0.72rem;line-height:1.6;color:var(--muted);">
          GSoC 2025 contributor to the MoFA project. Working on Idea 1: Cognitive Gateway architecture covering the full routing, auth, and rate-limiting stack.
        </div>
      </div>

    </div>
  </div>
</div>

<!-- FOOTER -->
<footer>
  <div class="fi">
    <img src="/logo.png" alt="MoFA" style="width:22px;height:22px;object-fit:cover;border:1.5px solid rgba(255,255,255,0.2);border-radius:4px;">
    <span class="fname">MoFA Cognitive Gateway</span>
    <div class="fpills">
      <span class="fp"><strong>Refresh</strong> 500ms</span>
      <span class="fp"><strong>Rate</strong> 10 burst / 2 req/s</span>
      <a href="https://github.com/mugiwaraluffy56/mofa/tree/demo/gateway-live-demo" target="_blank" rel="noopener" class="fp" style="text-decoration:none;color:inherit;"><strong>Branch</strong> <code>demo/gateway-live-demo</code></a>
      <span class="fp"><strong>Issues</strong> #699 – #706</span>
    </div>
  </div>
</footer>

<script>
const BAR={
  'gpt-4':'cr','claude-3':'cp','vision-agent':'cy',
  'text-agent':'cb2','code-agent':'ct'
};
const TAG={
  'gpt-4':'tag-r','claude-3':'tag-p','vision-agent':'tag-t',
  'text-agent':'tag-b','code-agent':'tag-t'
};
function bc(n){return BAR[n]||'cg';}
function tc(n){return TAG[n]||'tag-g';}
function hms(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}
function ts(ms){return new Date(ms).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});}

async function refresh(){
  try{
    const m=await fetch('/live/metrics').then(r=>r.json());
    document.getElementById('stat-total').textContent=m.total;
    document.getElementById('stat-routed').textContent=m.routed;
    document.getElementById('stat-ratelimited').textContent=m.rate_limited;
    document.getElementById('stat-auth').textContent=m.auth_rejected;
    document.getElementById('uptime-pill').textContent='up '+hms(m.uptime_secs);

    // distribution
    const chart=document.getElementById('routing-chart');
    const agents=m.agents||{};
    const total=Object.values(agents).reduce((a,b)=>a+b,0);
    document.getElementById('dist-badge').textContent=total+' req';
    if(total>0){
      chart.innerHTML='<div style="padding:1rem 1.25rem;">'+
        Object.entries(agents).sort((a,b)=>b[1]-a[1]).map(([n,c])=>{
          const p=(c/total*100).toFixed(1);
          return `<div class="arow">
            <div class="aname">${n}</div>
            <div class="btrack"><div class="bfill ${bc(n)}" style="width:${p}%">${p}%</div></div>
            <div class="bcnt">${c}</div>
          </div>`;
        }).join('')+'</div>';
    }

    // routes
    try{
      const routes=await fetch('/admin/routes',{headers:{'x-admin-key':'admin-secret-2025'}}).then(r=>r.json());
      document.getElementById('routes-badge').textContent=(routes.length||0)+' routes';
      const tb=document.getElementById('routes-table');
      if(Array.isArray(routes)&&routes.length>0){
        tb.innerHTML=routes.map(r=>`
          <tr>
            <td><span class="tag tag-r">${r.id}</span></td>
            <td><span class="tag tag-b">${r.path_pattern}</span></td>
            <td>${r.enabled?'<span class="badge ok">enabled</span>':'<span class="badge dis">disabled</span>'}</td>
          </tr>`).join('');
      }
    }catch(_){}

    // log
    const recent=(m.recent||[]).slice().reverse();
    document.getElementById('log-badge').textContent=recent.length+' entries';
    const lb=document.getElementById('recent-log');
    if(recent.length>0){
      lb.innerHTML=recent.map(r=>`
        <tr style="display:table;width:100%;table-layout:fixed;">
          <td style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:var(--muted);width:90px;">${ts(r.ts_ms)}</td>
          <td><span class="tag tag-r">${r.path}</span></td>
          <td style="width:130px;"><span class="tag ${tc(r.agent)}">${r.agent}</span></td>
          <td style="width:80px;">${r.status<300?`<span class="badge ok">${r.status}</span>`:r.status===429?`<span class="badge warn">${r.status}</span>`:`<span class="badge err">${r.status}</span>`}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:var(--muted);width:60px;">${r.latency_ms}</td>
        </tr>`).join('');
    }

    // cache
    const cache=m.cache||{};
    document.getElementById('cache-hitrate').textContent=(cache.hit_rate_pct||0)+'%';
    document.getElementById('cache-size').textContent=cache.size||0;
    document.getElementById('cache-hits').textContent=cache.hits||0;
    document.getElementById('cache-misses').textContent=cache.misses||0;
    document.getElementById('cache-badge').textContent='size '+(cache.size||0)+' · TTL 60s';

    // mqtt — fetch device list from admin endpoint
    try{
      const tmp2=await fetch('/admin/mqtt',{headers:{'x-admin-key':'admin-secret-2025'}});
      if(tmp2.ok){
        const md=await tmp2.json();
        const devs=md.devices||[];
        const mqtt=m.mqtt||{};
        document.getElementById('mqtt-badge').textContent=devs.length+' devices · pub '+( mqtt.published||0);
        document.getElementById('mqtt-devices').innerHTML=devs.length>0?devs.map(d=>`
          <tr>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;">${d.id}</td>
            <td style="font-size:0.62rem;color:var(--muted);">${d.topic.replace('mofa/requests/','')}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;">${d.messages_handled}</td>
            <td>${d.online?'<span class="badge ok">online</span>':'<span class="badge err">offline</span>'}</td>
          </tr>`).join(''):'<tr><td colspan="4"><div class="empty"><p>No devices.</p></div></td></tr>';
      }
    }catch(_){}

    // plugins — fetch from admin endpoint
    try{
      const tmp3=await fetch('/admin/plugins',{headers:{'x-admin-key':'admin-secret-2025'}});
      if(tmp3.ok){
        const pl=await tmp3.json();
        const pinst=m.plugins||{};
        document.getElementById('plugin-badge').textContent=pl.length+' registered · '+( pinst.installed||0)+' installed';
        document.getElementById('plugin-list').innerHTML=pl.length>0?pl.map(p=>`
          <tr>
            <td style="font-size:0.7rem;font-weight:600;">${p.name.replace(' Plugin','').replace(' Adapter','').replace(' Provider','')}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;color:var(--muted);">${p.version}</td>
            <td style="font-size:0.62rem;color:var(--muted);">${p.capabilities.slice(0,2).join(', ')}</td>
            <td>${p.verified?'<span class="badge ok">verified</span>':'<span class="badge warn">unsigned</span>'}</td>
          </tr>`).join(''):'<tr><td colspan="4"><div class="empty"><p>No plugins.</p></div></td></tr>';
      }
    }catch(_){}

  }catch(e){
    const b=document.getElementById('live-btn');
    b.textContent='Offline';
    b.style.borderColor='var(--red)';
    b.style.color='var(--red)';
  }
}
function toggleDd(id) {
  const el = document.getElementById(id);
  const isOpen = el.classList.contains('open');
  document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
  if (!isOpen) el.classList.add('open');
}
document.addEventListener('click', e => {
  if (!e.target.closest('.dropdown')) {
    document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
  }
});

setInterval(refresh,500);
refresh();
</script>
</body>
</html>"##;