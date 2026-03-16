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
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

        Self {
            routes: RwLock::new(InMemoryRouteRegistry::new()),
            keys,
            auth,
            rate_limiter: TokenBucketRateLimiter::new(&rate_cfg),
            strategies: RwLock::new(RouterRegistry::new()),
            metrics: GatewayMetrics::default(),
            started_at: Instant::now(),
            admin_key: admin_key.into(),
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

// ─────────────────────────────────────────────────────────────────────────────
// GET /live/metrics
// ─────────────────────────────────────────────────────────────────────────────

async fn live_metrics(State(state): State<SharedState>) -> Json<Value> {
    let snap = state.metrics.snapshot();
    let routes_active = state.routes.read().unwrap().list_active().len();
    let uptime = state.started_at.elapsed().as_secs();
    Json(json!({
        "total": snap.total,
        "rate_limited": snap.rate_limited,
        "auth_rejected": snap.auth_rejected,
        "routed": snap.routed,
        "routes_active": routes_active,
        "uptime_secs": uptime,
        "agents": snap.agents,
        "recent": snap.recent,
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

    // ── 4. Routing strategy ───────────────────────────────────────────────────
    let agent_id = {
        let strats = state.strategies.read().unwrap();
        strats
            .get(&route_id)
            .and_then(|s| s.select_agent(&envelope))
            .unwrap_or_else(|| "default-agent".to_string())
    };

    // ── 5. Mock agent dispatch (echo + metadata) ─────────────────────────────
    let resp = AgentResponse::new(
        200,
        json!({
            "agent_id": agent_id,
            "route_id": route_id,
            "subject": claims.subject,
            "echo": payload,
            "message": format!("handled by {}", agent_id),
        }),
        &agent_id,
        &envelope,
    );

    state.metrics.record_agent_hit(&agent_id);
    state.metrics.push_recent(RecentReq {
        ts_ms: now_ms(),
        path: path.clone(),
        agent: agent_id.clone(),
        status: 200,
        latency_ms: resp.latency_ms,
        subject: claims.subject.clone(),
    });

    (StatusCode::OK, Json(json!({
        "status": resp.status_code,
        "agent_id": resp.agent_id,
        "route_id": route_id,
        "correlation_id": resp.correlation_id,
        "latency_ms": resp.latency_ms,
        "subject": claims.subject,
        "body": resp.body,
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
        .route("/live/metrics", get(live_metrics))
        .route("/v1/invoke/{path}", post(invoke))
        .route("/admin/health", get(admin_health))
        .route(
            "/admin/routes",
            get(admin_list_routes).post(admin_register_route),
        )
        .route(
            "/admin/routes/{id}",
            patch(admin_toggle_route).delete(admin_deregister_route),
        )
        .route("/admin/keys", get(admin_list_keys).post(admin_issue_key))
        .route("/admin/keys/{key}", delete(admin_revoke_key))
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
    info!("    POST /v1/chat   → WeightedRoundRobin (gpt-4 70%, claude-3 30%)");
    info!("    POST /v1/vision → CapabilityMatch    (vision/text/code agents)");
    info!("    POST /v1/code   → CapabilityMatch    (code agent preferred)");
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

static DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MoFA Cognitive Gateway</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --green: #3fb950;
    --blue: #58a6ff;
    --purple: #bc8cff;
    --orange: #ffa657;
    --red: #f85149;
    --yellow: #d29922;
    --accent: #1f6feb;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }

  header {
    background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 1.25rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  header .logo {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--accent), var(--purple));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.2rem; font-weight: bold;
  }
  header h1 { font-size: 1.3rem; font-weight: 600; letter-spacing: -0.3px; }
  header .badge {
    margin-left: auto;
    background: rgba(63,185,80,0.15);
    border: 1px solid rgba(63,185,80,0.3);
    color: var(--green);
    font-size: 0.75rem;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    display: flex; align-items: center; gap: 0.4rem;
  }
  header .badge::before {
    content: '';
    width: 7px; height: 7px;
    background: var(--green);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  .main { padding: 1.5rem 2rem; max-width: 1400px; margin: 0 auto; }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem;
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }
  .stat-card.blue::before  { background: var(--blue); }
  .stat-card.green::before { background: var(--green); }
  .stat-card.red::before   { background: var(--red); }
  .stat-card.purple::before{ background: var(--purple); }
  .stat-card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 0.5rem; }
  .stat-card .value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
  .stat-card.blue .value  { color: var(--blue); }
  .stat-card.green .value { color: var(--green); }
  .stat-card.red .value   { color: var(--red); }
  .stat-card.purple .value{ color: var(--purple); }
  .stat-card .sub { font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; }

  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
  @media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }
  .panel-header {
    padding: 0.9rem 1.25rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.6px;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .panel-body { padding: 1.25rem; }

  .agent-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.9rem;
  }
  .agent-row:last-child { margin-bottom: 0; }
  .agent-name {
    width: 110px;
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .bar-wrap { flex: 1; background: var(--surface2); border-radius: 4px; height: 20px; overflow: hidden; }
  .bar {
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
    min-width: 0;
    display: flex;
    align-items: center;
    padding-left: 6px;
    font-size: 0.7rem;
    font-weight: 600;
    color: rgba(255,255,255,0.9);
    white-space: nowrap;
  }
  .bar.gpt4    { background: linear-gradient(90deg, #1f6feb, #58a6ff); }
  .bar.claude  { background: linear-gradient(90deg, #6e40c9, #bc8cff); }
  .bar.vision  { background: linear-gradient(90deg, #b08800, #ffa657); }
  .bar.text    { background: linear-gradient(90deg, #1a7f37, #3fb950); }
  .bar.code    { background: linear-gradient(90deg, #b62324, #f85149); }
  .bar.default { background: linear-gradient(90deg, #444c56, #8b949e); }
  .bar-count { width: 40px; text-align: right; font-size: 0.75rem; color: var(--muted); }

  .log-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .log-table th { color: var(--muted); font-weight: 500; text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .log-table td { padding: 0.45rem 0.6rem; border-bottom: 1px solid rgba(48,54,61,0.4); vertical-align: middle; }
  .log-table tr:last-child td { border-bottom: none; }
  .log-table tr:hover td { background: rgba(33,38,45,0.5); }

  .badge-ok  { background: rgba(63,185,80,0.15); color: var(--green); border-radius: 4px; padding: 2px 6px; font-size: 0.7rem; font-weight: 600; }
  .badge-err { background: rgba(248,81,73,0.15); color: var(--red);   border-radius: 4px; padding: 2px 6px; font-size: 0.7rem; font-weight: 600; }
  .path-tag  { font-family: monospace; color: var(--blue); font-size: 0.78rem; }
  .agent-tag { font-family: monospace; color: var(--orange); font-size: 0.75rem; }

  .footer {
    border-top: 1px solid var(--border);
    padding: 1rem 2rem;
    font-size: 0.75rem;
    color: var(--muted);
    display: flex;
    gap: 2rem;
    margin-top: 1.5rem;
  }
  .footer code {
    background: var(--surface2);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-family: monospace;
    color: var(--blue);
  }
</style>
</head>
<body>

<header>
  <div class="logo">M</div>
  <div>
    <h1>MoFA Cognitive Gateway</h1>
    <div style="font-size:0.75rem; color: var(--muted); margin-top:2px;">
      Token-bucket rate limiting · Weighted round-robin · Capability-aware routing
    </div>
  </div>
  <div class="badge" id="live-badge">LIVE</div>
</header>

<div class="main">

  <div class="stats-grid">
    <div class="stat-card blue">
      <div class="label">Total Requests</div>
      <div class="value" id="stat-total">0</div>
      <div class="sub" id="stat-uptime">uptime 0s</div>
    </div>
    <div class="stat-card green">
      <div class="label">Routed OK</div>
      <div class="value" id="stat-routed">0</div>
      <div class="sub">dispatched to agents</div>
    </div>
    <div class="stat-card red">
      <div class="label">Rate Limited</div>
      <div class="value" id="stat-ratelimited">0</div>
      <div class="sub">429 responses</div>
    </div>
    <div class="stat-card purple">
      <div class="label">Auth Rejected</div>
      <div class="value" id="stat-auth">0</div>
      <div class="sub">401 responses</div>
    </div>
  </div>

  <div class="grid2">

    <div class="panel">
      <div class="panel-header">▸ Routing Distribution</div>
      <div class="panel-body" id="routing-chart">
        <div style="color:var(--muted); font-size:0.82rem;">No requests yet — send some traffic!</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">▸ Active Routes</div>
      <div class="panel-body">
        <table class="log-table">
          <thead>
            <tr><th>ID</th><th>Path</th><th>Strategy</th></tr>
          </thead>
          <tbody id="routes-table">
            <tr><td colspan="3" style="color:var(--muted)">loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <div class="panel">
    <div class="panel-header">▸ Recent Requests</div>
    <div class="panel-body" style="padding:0;">
      <table class="log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Path</th>
            <th>Agent</th>
            <th>Subject</th>
            <th>Status</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody id="recent-log">
          <tr><td colspan="6" style="color:var(--muted); padding:1rem;">
            No requests yet. Try:<br>
            <code style="font-size:0.75rem; color:var(--blue);">
              curl -s -X POST http://127.0.0.1:8080/v1/invoke/chat \<br>
              &nbsp;&nbsp;-H 'x-api-key: alice-key-abc123' \<br>
              &nbsp;&nbsp;-H 'content-type: application/json' \<br>
              &nbsp;&nbsp;-d '{"message":"hello"}' | jq .
            </code>
          </td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  <span>Refresh: <strong>500ms</strong></span>
  <span>Rate limit: <strong>10 burst / 2 per-sec</strong></span>
  <span>Admin key: <code>admin-secret-2025</code></span>
  <span>Alice key: <code>alice-key-abc123</code></span>
  <span>Bob key: <code>bob-key-xyz789</code></span>
</div>

<script>
const AGENT_CLASSES = {
  'gpt-4': 'gpt4',
  'claude-3': 'claude',
  'vision-agent': 'vision',
  'text-agent': 'text',
  'code-agent': 'code',
};

function agentClass(name) {
  return AGENT_CLASSES[name] || 'default';
}

function fmt(ts_ms) {
  const d = new Date(ts_ms);
  return d.toLocaleTimeString('en-US', { hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

async function refresh() {
  try {
    const m = await fetch('/live/metrics').then(r => r.json());

    document.getElementById('stat-total').textContent = m.total;
    document.getElementById('stat-routed').textContent = m.routed;
    document.getElementById('stat-ratelimited').textContent = m.rate_limited;
    document.getElementById('stat-auth').textContent = m.auth_rejected;
    document.getElementById('stat-uptime').textContent = `uptime ${m.uptime_secs}s`;

    // Routing chart
    const chart = document.getElementById('routing-chart');
    const agents = m.agents || {};
    const total = Object.values(agents).reduce((a,b) => a+b, 0);
    if (total > 0) {
      chart.innerHTML = Object.entries(agents)
        .sort((a,b) => b[1]-a[1])
        .map(([name, count]) => {
          const pct = total > 0 ? (count / total * 100).toFixed(1) : 0;
          const cls = agentClass(name);
          return `
            <div class="agent-row">
              <div class="agent-name">${name}</div>
              <div class="bar-wrap">
                <div class="bar ${cls}" style="width:${pct}%">${pct}%</div>
              </div>
              <div class="bar-count">${count}</div>
            </div>`;
        }).join('');
    }

    // Routes table — re-fetch to stay current
    try {
      const routes = await fetch('/admin/routes', {
        headers: { 'x-admin-key': 'admin-secret-2025' }
      }).then(r => r.json());

      const tbody = document.getElementById('routes-table');
      if (Array.isArray(routes) && routes.length > 0) {
        tbody.innerHTML = routes.map(r => `
          <tr>
            <td><span class="path-tag">${r.id}</span></td>
            <td><span class="path-tag">${r.path_pattern}</span></td>
            <td style="color:var(--muted);font-size:0.75rem;">
              ${r.enabled ? '<span class="badge-ok">enabled</span>' : '<span class="badge-err">disabled</span>'}
            </td>
          </tr>`).join('');
      }
    } catch(e) {}

    // Recent log
    const recent = (m.recent || []).slice().reverse();
    const tbody = document.getElementById('recent-log');
    if (recent.length > 0) {
      tbody.innerHTML = recent.map(r => `
        <tr>
          <td style="color:var(--muted)">${fmt(r.ts_ms)}</td>
          <td><span class="path-tag">${r.path}</span></td>
          <td><span class="agent-tag">${r.agent}</span></td>
          <td style="color:var(--muted);font-size:0.75rem">${r.subject}</td>
          <td>${r.status < 300 ? `<span class="badge-ok">${r.status}</span>` : `<span class="badge-err">${r.status}</span>`}</td>
          <td style="color:var(--muted)">${r.latency_ms}ms</td>
        </tr>`).join('');
    }

  } catch(e) {
    document.getElementById('live-badge').textContent = 'OFFLINE';
    document.getElementById('live-badge').style.color = 'var(--red)';
  }
}

setInterval(refresh, 500);
refresh();
</script>
</body>
</html>"#;
