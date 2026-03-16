#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MoFA Cognitive Gateway — full-scale test suite
# Usage: ./scripts/gateway-test.sh [--base=http://host:port]
#
# By default, spins up the server itself, runs all 97 tests, then tears it down.
# Pass --no-server to skip the server lifecycle and test an already-running instance.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; DIM='\033[2m'; NC='\033[0m'

# ── config ────────────────────────────────────────────────────────────────────
BASE="http://127.0.0.1:8080"
ADMIN_KEY="admin-secret-2025"
ALICE="alice-key-abc123"
BOB="bob-key-xyz789"
MANAGE_SERVER=true
SERVER_PID=""

for arg in "$@"; do
  case "$arg" in
    --base=*)      BASE="${arg#--base=}" ;;
    --no-server)   MANAGE_SERVER=false ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${BASE##*:}"

# ── helpers ───────────────────────────────────────────────────────────────────
PASS=0; FAIL=0

pass() { echo -e "  ${GREEN}PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)); }

section() {
  echo ""
  echo -e "${BOLD}${BLUE}━━━  $1${NC}"
  echo -e "${BLUE}$(printf '%.0s─' {1..70})${NC}"
}

req() {
  local method="$1" url="$2"; shift 2
  local tmp
  tmp=$(mktemp)
  STATUS=$(curl -s -o "$tmp" -w "%{http_code}" -X "$method" "$url" \
    -H "content-type: application/json" "$@")
  BODY=$(cat "$tmp")
  rm -f "$tmp"
}

check_status() {
  local label="$1" expected="$2"
  if [[ "$STATUS" == "$expected" ]]; then
    pass "$label [HTTP $STATUS]"
  else
    fail "$label — expected HTTP $expected, got $STATUS"
  fi
}

jq_val() {
  echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print($2)" 2>/dev/null
}

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── server lifecycle ──────────────────────────────────────────────────────────
if [[ "$MANAGE_SERVER" == true ]]; then
  echo ""
  echo -e "${BOLD}${CYAN}  MoFA Cognitive Gateway — Test Suite${NC}"
  echo -e "  ${DIM}building...${NC}"

  # kill any existing process on the port
  if lsof -ti:"$PORT" &>/dev/null; then
    lsof -ti:"$PORT" | xargs kill -9 2>/dev/null || true
    sleep 1
  fi

  cd "$REPO_ROOT/examples"
  cargo build -p gateway_live_demo -q 2>&1

  GATEWAY_PORT="$PORT" cargo run -p gateway_live_demo -q &>/tmp/gw-test.log &
  SERVER_PID=$!

  echo -e "  ${DIM}waiting for server (pid $SERVER_PID)...${NC}"
  for i in $(seq 1 20); do
    if curl -s "$BASE/admin/health" -H "x-admin-key: $ADMIN_KEY" | grep -q healthy; then
      echo -e "  ${GREEN}server ready${NC}"
      break
    fi
    sleep 1
    if [[ $i -eq 20 ]]; then
      echo -e "  ${RED}server failed to start — check /tmp/gw-test.log${NC}"
      exit 1
    fi
  done
else
  echo ""
  echo -e "${BOLD}${CYAN}  MoFA Cognitive Gateway — Test Suite${NC}"
  echo -e "  ${DIM}$BASE  (external server)${NC}"
  if ! curl -s "$BASE/admin/health" -H "x-admin-key: $ADMIN_KEY" | grep -q healthy; then
    echo -e "  ${RED}server not reachable at $BASE${NC}"
    exit 1
  fi
fi

# ── 1. Server Health ──────────────────────────────────────────────────────────
section "1. Server Health"

req GET "$BASE/admin/health" -H "x-admin-key: $ADMIN_KEY"
check_status "Admin health endpoint" "200"
uptime=$(jq_val "$BODY" "d['uptime_secs']")
[[ -n "$uptime" && "$uptime" =~ ^[0-9]+$ ]] \
  && pass "uptime_secs is a number ($uptime)" || fail "uptime_secs invalid: $uptime"

req GET "$BASE/live/metrics"
check_status "Live metrics endpoint" "200"

req GET "$BASE/"
check_status "Dashboard HTML" "200"

req GET "$BASE/logo.png"
check_status "Logo PNG" "200"

# ── 2. Authentication ─────────────────────────────────────────────────────────
section "2. Authentication"

req POST "$BASE/v1/invoke/chat" -d '{"message":"hello"}'
check_status "No key → 401" "401"
[[ "$BODY" == *"missing"* ]] \
  && pass "401 hints at missing key" || fail "401 body missing hint: $BODY"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: totally-wrong-key" -d '{"message":"hello"}'
check_status "Bad key → 401" "401"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $ALICE" -d '{"message":"hello"}'
check_status "Alice valid key → 200" "200"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $BOB" -d '{"message":"hello"}'
check_status "Bob valid key → 200" "200"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $ADMIN_KEY" -d '{"message":"hello"}'
check_status "Admin key on user endpoint → 401" "401"

# ── 3. Route Matching ─────────────────────────────────────────────────────────
section "3. Route Matching"

req POST "$BASE/v1/invoke/chat"   -H "x-api-key: $ALICE" -d '{"message":"hi"}'
check_status "/v1/invoke/chat → 200" "200"

req POST "$BASE/v1/invoke/vision" -H "x-api-key: $ALICE" -d '{"task":"analyze"}'
check_status "/v1/invoke/vision → 200" "200"

req POST "$BASE/v1/invoke/code"   -H "x-api-key: $ALICE" -d '{"task":"write fn"}'
check_status "/v1/invoke/code → 200" "200"

req POST "$BASE/v1/invoke/nope"   -H "x-api-key: $ALICE" -d '{"message":"hi"}'
check_status "/v1/invoke/nope → 404 (no route)" "404"

req POST "$BASE/v1/invoke/CHAT"   -H "x-api-key: $ALICE" -d '{"message":"hi"}'
check_status "/v1/invoke/CHAT (wrong case) → 404" "404"

req GET "$BASE/v1/invoke/chat"    -H "x-api-key: $ALICE"
check_status "GET on POST route → 405" "405"

# ── 4. Rate Limiting ──────────────────────────────────────────────────────────
section "4. Rate Limiting  (alice — 10 burst / 2 req/s)"

echo -e "  ${DIM}Sending 15 rapid requests as alice...${NC}"
allowed=0; limited=0; last_429_body=""
for i in $(seq 1 15); do
  tmp=$(mktemp)
  st=$(curl -s -o "$tmp" -w "%{http_code}" -X POST "$BASE/v1/invoke/chat" \
    -H "x-api-key: $ALICE" -H "content-type: application/json" -d '{"message":"ping"}')
  if [[ "$st" == "200" ]]; then ((allowed++))
  elif [[ "$st" == "429" ]]; then ((limited++)); last_429_body=$(cat "$tmp"); fi
  rm -f "$tmp"
done
echo -e "  ${DIM}$allowed allowed, $limited rate-limited${NC}"

[[ $allowed -ge 1 ]] && pass "$allowed requests allowed before limit"  || fail "No requests allowed at all"
[[ $limited -ge 1 ]] && pass "$limited requests hit rate limit (429)"  || fail "Rate limit never triggered"
[[ -n "$last_429_body" && "$last_429_body" == *"retry_after_ms"* ]] \
  && pass "429 body contains retry_after_ms" || fail "retry_after_ms missing"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $BOB" -d '{"message":"hello"}'
check_status "Bob unaffected by alice limit → 200" "200"

# ── 5. WeightedRoundRobin ─────────────────────────────────────────────────────
section "5. WeightedRoundRobin Distribution  (chat: gpt-4 70% / claude-3 30%)"

echo -e "  ${DIM}Waiting 6s for alice bucket to refill...${NC}"
sleep 6

gpt4=0; claude3=0
for i in $(seq 1 10); do
  tmp=$(mktemp)
  curl -s -o "$tmp" -X POST "$BASE/v1/invoke/chat" \
    -H "x-api-key: $ALICE" -H "content-type: application/json" \
    -d "{\"message\":\"wrr-$i-$$\"}"
  agent=$(python3 -c "import sys,json; print(json.load(open('$tmp')).get('agent_id',''))" 2>/dev/null)
  [[ "$agent" == "gpt-4"    ]] && ((gpt4++))
  [[ "$agent" == "claude-3" ]] && ((claude3++))
  rm -f "$tmp"
done
echo -e "  ${DIM}gpt-4=$gpt4  claude-3=$claude3  (10 requests)${NC}"

[[ $gpt4    -ge 1 ]] && pass "gpt-4 received requests ($gpt4)"       || fail "gpt-4 got 0 requests"
[[ $claude3 -ge 1 ]] && pass "claude-3 received requests ($claude3)"  || fail "claude-3 got 0 requests"
[[ $gpt4 -gt $claude3 ]] \
  && pass "gpt-4 ($gpt4) > claude-3 ($claude3) — 70/30 bias correct" \
  || fail "gpt-4 ($gpt4) not more than claude-3 ($claude3)"

# ── 6. CapabilityMatch ────────────────────────────────────────────────────────
section "6. CapabilityMatch Routing  (vision / code)"

req POST "$BASE/v1/invoke/vision" -H "x-api-key: $BOB" -d '{"task":"describe image"}'
check_status "Vision route → 200" "200"
agent=$(jq_val "$BODY" "d.get('agent_id','')")
[[ -n "$agent" ]] && pass "Vision resolved to agent: $agent" || fail "Vision: no agent in response"

req POST "$BASE/v1/invoke/code" -H "x-api-key: $BOB" -d '{"task":"write code"}'
check_status "Code route → 200" "200"
agent=$(jq_val "$BODY" "d.get('agent_id','')")
[[ -n "$agent" ]] && pass "Code resolved to agent: $agent" || fail "Code: no agent in response"

# ── 7. Admin Routes CRUD ──────────────────────────────────────────────────────
section "7. Admin Routes CRUD"

req GET "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY"
check_status "List routes → 200" "200"
count=$(jq_val "$BODY" "len(d)")
[[ "$count" == "5" ]] && pass "5 pre-seeded routes (incl MQTT)" || fail "Expected 5, got $count"

req POST "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"test-route","path_pattern":"/v1/test","agent_id":"test-agent","method":"POST","enabled":true}'
check_status "Register route → 201" "201"

req POST "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"test-route","path_pattern":"/v1/test","agent_id":"test-agent","method":"POST","enabled":true}'
check_status "Duplicate route → 409" "409"

req POST "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"bad","path_pattern":"v1/no-slash","agent_id":"x","method":"POST","enabled":true}'
check_status "Path without leading / → 422" "422"

req POST "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"","path_pattern":"/v1/x","agent_id":"x","method":"POST","enabled":true}'
check_status "Empty id → 422" "422"

req PATCH "$BASE/admin/routes/test-route" -H "x-admin-key: $ADMIN_KEY" -d '{"enabled":false}'
check_status "Disable route → 200" "200"
[[ "$BODY" == *'"enabled":false'* || "$BODY" == *'"enabled": false'* ]] \
  && pass "Response shows enabled=false" || fail "Body: $BODY"

req POST "$BASE/v1/invoke/test" -H "x-api-key: $BOB" -d '{"x":1}'
check_status "Disabled route not matched → 404" "404"

req PATCH "$BASE/admin/routes/test-route" -H "x-admin-key: $ADMIN_KEY" -d '{"enabled":true}'
check_status "Re-enable route → 200" "200"

req PATCH "$BASE/admin/routes/ghost" -H "x-admin-key: $ADMIN_KEY" -d '{"enabled":true}'
check_status "Toggle unknown route → 404" "404"

req DELETE "$BASE/admin/routes/test-route" -H "x-admin-key: $ADMIN_KEY"
check_status "Deregister route → 200" "200"

req DELETE "$BASE/admin/routes/test-route" -H "x-admin-key: $ADMIN_KEY"
check_status "Deregister again → 404" "404"

req GET "$BASE/admin/routes" -H "x-admin-key: $ADMIN_KEY"
count=$(jq_val "$BODY" "len(d)")
[[ "$count" == "5" ]] && pass "Back to 5 routes after cleanup" || fail "Expected 5, got $count"

# ── 8. Admin Key Management ───────────────────────────────────────────────────
section "8. Admin Key Management"

req GET "$BASE/admin/keys" -H "x-admin-key: $ADMIN_KEY"
check_status "List keys → 200" "200"
count=$(jq_val "$BODY" "len(d)")
[[ "$count" -ge 2 ]] && pass "At least 2 pre-seeded keys ($count total)" || fail "Expected >=2, got $count"

req POST "$BASE/admin/keys" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"subject":"user:carol","scopes":["agents:invoke"]}'
check_status "Issue new key → 201" "201"
NEW_KEY=$(jq_val "$BODY" "d['key']")
[[ -n "$NEW_KEY" ]] && pass "Key returned: $NEW_KEY" || fail "No key in: $BODY"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $NEW_KEY" -d '{"message":"carol"}'
check_status "New key is valid → 200" "200"

req DELETE "$BASE/admin/keys/$NEW_KEY" -H "x-admin-key: $ADMIN_KEY"
check_status "Revoke key → 200" "200"

req POST "$BASE/v1/invoke/chat" -H "x-api-key: $NEW_KEY" -d '{"message":"carol"}'
check_status "Revoked key rejected → 401" "401"

req DELETE "$BASE/admin/keys/does-not-exist" -H "x-admin-key: $ADMIN_KEY"
check_status "Revoke unknown key → 404" "404"

# ── 9. Admin Auth Guard ───────────────────────────────────────────────────────
section "9. Admin Auth Guard"

req GET "$BASE/admin/routes"
check_status "No admin key → 401" "401"

req GET "$BASE/admin/routes" -H "x-admin-key: wrong"
check_status "Wrong admin key → 401" "401"

req GET "$BASE/admin/health" -H "x-admin-key: $ALICE"
check_status "User key on admin endpoint → 401" "401"

req POST "$BASE/admin/routes" -H "x-admin-key: $ALICE" \
  -d '{"id":"x","path_pattern":"/x","agent_id":"x","method":"POST","enabled":true}'
check_status "Unauthorized route register → 401" "401"

# ── 10. Metrics Consistency ───────────────────────────────────────────────────
section "10. Metrics Consistency"

req GET "$BASE/live/metrics"
check_status "Metrics → 200" "200"
M="$BODY"

total=$(jq_val "$M"    "d['total']")
routed=$(jq_val "$M"   "d['routed']")
rl=$(jq_val "$M"       "d['rate_limited']")
auth_rej=$(jq_val "$M" "d['auth_rejected']")
routes_n=$(jq_val "$M" "d['routes_active']")
agents_n=$(jq_val "$M" "len(d['agents'])")
recent_n=$(jq_val "$M" "len(d['recent'])")

echo -e "  ${DIM}total=$total  routed=$routed  rate_limited=$rl  auth_rejected=$auth_rej  routes_active=$routes_n${NC}"

[[ "$total"    -gt 0 ]] && pass "total > 0  ($total)"            || fail "total = 0"
[[ "$routed"   -gt 0 ]] && pass "routed > 0  ($routed)"          || fail "routed = 0"
[[ "$rl"       -gt 0 ]] && pass "rate_limited > 0  ($rl)"        || fail "rate_limited = 0"
[[ "$auth_rej" -gt 0 ]] && pass "auth_rejected > 0  ($auth_rej)" || fail "auth_rejected = 0"
[[ "$routes_n" -eq 5 ]] && pass "routes_active = 5"              || fail "routes_active = $routes_n, expected 5"
[[ "$agents_n" -ge 2 ]] && pass "agent map has $agents_n agents" || fail "agent map has $agents_n agents"
[[ "$recent_n" -ge 1 ]] && pass "recent log has $recent_n entries" || fail "recent log empty"

cache_hits=$(jq_val "$M" "d['cache']['hits']")
mqtt_dev=$(jq_val "$M" "d['mqtt']['devices']")
plugin_reg=$(jq_val "$M" "d['plugins']['registered']")
echo -e "  ${DIM}cache hits=$cache_hits  mqtt_devices=$mqtt_dev  plugins=$plugin_reg${NC}"
[[ "$cache_hits" -ge 0 ]] && pass "cache stats present (hits=$cache_hits)" || fail "cache stats missing"
[[ "$mqtt_dev"   -ge 2 ]] && pass "mqtt broker has $mqtt_dev devices"      || fail "mqtt broker has no devices"
[[ "$plugin_reg" -ge 3 ]] && pass "plugin registry has $plugin_reg plugins" || fail "plugin registry empty"

# ── 11. L1 Cache ─────────────────────────────────────────────────────────────
section "11. L1 Cache"

echo -e "  ${DIM}Waiting 5s for alice bucket to refill...${NC}"
sleep 5

req POST "$BASE/v1/invoke/code" -H "x-api-key: $ALICE" -d '{"task":"cache-probe-unique-xyz"}'
check_status "Cache probe first call → 200" "200"
first_cache=$(jq_val "$BODY" "d.get('cache','?')")
[[ "$first_cache" == "miss" ]] && pass "First call is cache miss" || fail "Expected miss, got $first_cache"

req POST "$BASE/v1/invoke/code" -H "x-api-key: $ALICE" -d '{"task":"cache-probe-unique-xyz"}'
check_status "Cache probe second call → 200" "200"
second_cache=$(jq_val "$BODY" "d.get('cache','?')")
[[ "$second_cache" == "hit" ]] && pass "Second identical call is cache hit" || fail "Expected hit, got $second_cache"

req POST "$BASE/v1/invoke/code" -H "x-api-key: $ALICE" -d '{"task":"different-body-no-cache"}'
diff_cache=$(jq_val "$BODY" "d.get('cache','?')")
[[ "$diff_cache" == "miss" ]] && pass "Different body → new cache miss" || fail "Expected miss, got $diff_cache"

req GET "$BASE/admin/cache" -H "x-admin-key: $ADMIN_KEY"
check_status "Cache stats endpoint → 200" "200"
hits=$(jq_val "$BODY" "d['hits']")
[[ "$hits" -ge 1 ]] && pass "Cache hit counter > 0 ($hits)" || fail "Cache hit counter is 0"

req DELETE "$BASE/admin/cache" -H "x-admin-key: $ADMIN_KEY"
check_status "Clear cache → 200" "200"
pass_val=$(jq_val "$BODY" "str(d.get('cleared',''))")
[[ "$pass_val" == "True" ]] && pass "Cache cleared" || fail "Cache clear failed"

# ── 12. MQTT IoT Adapter ──────────────────────────────────────────────────────
section "12. MQTT IoT Adapter"

req POST "$BASE/v1/invoke/sensor" -H "x-api-key: $BOB" -d '{"command":"read_temperature"}'
check_status "IoT sensor route → 200" "200"
device_id=$(jq_val "$BODY" "d['body'].get('device_id','')")
[[ -n "$device_id" ]] && pass "Sensor responded: device=$device_id" || fail "No device_id in response"
reading=$(jq_val "$BODY" "str(d['body']['reading']['value'])")
[[ -n "$reading" ]] && pass "Sensor reading present: $reading celsius" || fail "No reading in response"

req POST "$BASE/v1/invoke/actuator" -H "x-api-key: $BOB" -d '{"command":"setBrightness","value":80}'
check_status "IoT actuator route → 200" "200"
act_device=$(jq_val "$BODY" "d['body'].get('device_id','')")
[[ -n "$act_device" ]] && pass "Actuator responded: device=$act_device" || fail "No device_id in actuator response"

req GET "$BASE/admin/mqtt" -H "x-admin-key: $ADMIN_KEY"
check_status "MQTT devices list → 200" "200"
n_devices=$(jq_val "$BODY" "len(d['devices'])")
[[ "$n_devices" -ge 2 ]] && pass "MQTT broker has $n_devices devices" || fail "Expected 2+ devices, got $n_devices"

req PATCH "$BASE/admin/mqtt/temp-sensor-01" -H "x-admin-key: $ADMIN_KEY" -d '{"online":false}'
check_status "Set device offline → 200" "200"

req PATCH "$BASE/admin/mqtt/temp-sensor-01" -H "x-admin-key: $ADMIN_KEY" -d '{"online":true}'
check_status "Set device online → 200" "200"

# ── 13. Plugin Registry ───────────────────────────────────────────────────────
section "13. Plugin Registry"

req GET "$BASE/admin/plugins" -H "x-admin-key: $ADMIN_KEY"
check_status "List plugins → 200" "200"
n_plugins=$(jq_val "$BODY" "len(d)")
[[ "$n_plugins" -ge 3 ]] && pass "Registry has $n_plugins pre-seeded plugins" || fail "Expected 3+, got $n_plugins"

verified=$(jq_val "$BODY" "sum(1 for p in d if p['verified'])")
[[ "$verified" -eq "$n_plugins" ]] \
  && pass "All $n_plugins plugins are verified" || fail "$verified/$n_plugins verified"

req POST "$BASE/admin/plugins" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"test-plugin","name":"Test Plugin","version":"0.1.0","description":"test","author":"ci","capabilities":["test"],"entry_point":"test.so","checksum":"aabbccdd"}'
check_status "Publish plugin → 201" "201"

req POST "$BASE/admin/plugins" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"test-plugin","name":"Test Plugin","version":"0.1.0","description":"test","author":"ci","capabilities":["test"],"entry_point":"test.so","checksum":"aabbccdd"}'
check_status "Duplicate publish → 409" "409"

req POST "$BASE/admin/plugins/test-plugin/sign" -H "x-admin-key: $ADMIN_KEY"
check_status "Sign plugin → 200" "200"
sig=$(jq_val "$BODY" "d.get('signature','')")
[[ -n "$sig" ]] && pass "Signature returned (${sig:0:12}...)" || fail "No signature returned"
verified_flag=$(jq_val "$BODY" "str(d.get('verified',''))")
[[ "$verified_flag" == "True" ]] && pass "Plugin marked verified after signing" || fail "verified flag not set"

req POST "$BASE/admin/plugins/test-plugin/install" -H "x-admin-key: $ADMIN_KEY"
check_status "Install plugin → 200" "200"
installed=$(jq_val "$BODY" "d.get('installed','')")
[[ "$installed" == "test-plugin" ]] && pass "Plugin installed successfully" || fail "Install returned: $installed"

req POST "$BASE/admin/plugins" -H "x-admin-key: $ADMIN_KEY" \
  -d '{"id":"unverified-plugin","name":"Unverified","version":"0.1.0","description":"no sig","author":"ci","capabilities":[],"entry_point":"x.so","checksum":"00"}'
req POST "$BASE/admin/plugins/unverified-plugin/install" -H "x-admin-key: $ADMIN_KEY"
check_status "Install unverified plugin → 400" "400"

req GET "$BASE/admin/plugins/search?capability=mqtt" -H "x-admin-key: $ADMIN_KEY"
check_status "Search plugins by capability → 200" "200"
n_mqtt=$(jq_val "$BODY" "len(d)")
[[ "$n_mqtt" -ge 1 ]] && pass "Capability search returned $n_mqtt mqtt plugins" || fail "No plugins found for capability=mqtt"

req DELETE "$BASE/admin/plugins/test-plugin" -H "x-admin-key: $ADMIN_KEY"
check_status "Remove plugin → 200" "200"

req DELETE "$BASE/admin/plugins/unverified-plugin" -H "x-admin-key: $ADMIN_KEY"

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}$(printf '%.0s━' {1..70})${NC}"
if [[ $FAIL -eq 0 ]]; then
  echo -e "${BOLD}  ${GREEN}All $PASS tests passed${NC}"
else
  echo -e "${BOLD}  ${GREEN}$PASS passed${NC}  ${RED}$FAIL failed${NC}  $(( PASS + FAIL )) total"
fi
echo -e "${BOLD}$(printf '%.0s━' {1..70})${NC}"
echo ""

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
