#!/usr/bin/env bash
# MoFA Gateway Admin API — live curl demo
#
# Prerequisites:
#   1. cargo run -p gateway_admin_demo --bin gateway_server   (in another terminal)
#   2. bash scripts/gateway_demo.sh
#
# Requires: curl, jq

set -euo pipefail

BASE="http://127.0.0.1:9090"
KEY="demo-secret-key"

# ── colours ──────────────────────────────────────────────────────────────────
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

step() { echo -e "\n${BOLD}${CYAN}▶  $*${RESET}"; }
ok()   { echo -e "${GREEN}✔  $*${RESET}"; }
info() { echo -e "   ${YELLOW}$*${RESET}"; }

# ── helpers ───────────────────────────────────────────────────────────────────
get()    { curl -s -X GET    "$BASE$1" -H "x-admin-key: $KEY" | jq .; }
post()   { curl -s -X POST   "$BASE$1" -H "x-admin-key: $KEY" -H 'content-type: application/json' -d "$2" | jq .; }
patch()  { curl -s -X PATCH  "$BASE$1" -H "x-admin-key: $KEY" -H 'content-type: application/json' -d "$2" | jq .; }
delete() { curl -s -X DELETE "$BASE$1" -H "x-admin-key: $KEY" | jq .; }
status() { curl -s -o /dev/null -w '%{http_code}' -X GET "$BASE$1" -H "x-admin-key: wrong-key"; }

# ── wait for server ───────────────────────────────────────────────────────────
echo -e "${BOLD}MoFA Gateway Admin API — live demo${RESET}"
echo -e "Waiting for server at $BASE ..."
for i in $(seq 1 20); do
  if curl -s -o /dev/null -w '' "$BASE/admin/health" -H "x-admin-key: $KEY" 2>/dev/null; then
    ok "Server is up"; break
  fi
  sleep 0.5
  if [ "$i" -eq 20 ]; then
    echo -e "${RED}Server not reachable. Run:  cargo run -p gateway_admin_demo --bin gateway_server${RESET}"
    exit 1
  fi
done

# ── 1: health ─────────────────────────────────────────────────────────────────
step "GET /admin/health"
get /admin/health
ok "Gateway is up and healthy"

# ── 2: register chat route ────────────────────────────────────────────────────
step "POST /admin/routes  →  register 'chat' agent"
post /admin/routes '{
  "id": "chat",
  "path_pattern": "/v1/chat",
  "agent_id": "agent-chat",
  "method": "POST",
  "strategy": "weighted_round_robin"
}'
ok "Route registered"

# ── 3: register summariser route ──────────────────────────────────────────────
step "POST /admin/routes  →  register 'summarise' agent"
post /admin/routes '{
  "id": "summarise",
  "path_pattern": "/v1/summarise",
  "agent_id": "agent-summariser",
  "method": "POST",
  "strategy": "capability_match"
}'
ok "Route registered"

# ── 4: list routes ────────────────────────────────────────────────────────────
step "GET /admin/routes  →  inspect live route table"
get /admin/routes
ok "2 routes in the table"

# ── 5: disable summariser ─────────────────────────────────────────────────────
step "PATCH /admin/routes/summarise  →  disable without deregistering"
patch /admin/routes/summarise '{"enabled": false}'
ok "Route disabled"

# ── 6: confirm ────────────────────────────────────────────────────────────────
step "GET /admin/routes  →  verify enabled flags"
get /admin/routes
info "summarise.enabled should be false, chat.enabled should be true"

# ── 7: delete the disabled route ──────────────────────────────────────────────
step "DELETE /admin/routes/summarise  →  deregister"
delete /admin/routes/summarise
ok "Route deregistered"

# ── 8: final state ───────────────────────────────────────────────────────────
step "GET /admin/routes  →  only 'chat' should remain"
get /admin/routes
ok "Exactly 1 route remaining"

# ── 9: auth guard ─────────────────────────────────────────────────────────────
step "Auth guard — bad key must return 401"
CODE=$(status /admin/routes)
if [ "$CODE" = "401" ]; then
  ok "Got 401 UNAUTHORIZED — auth guard is working"
else
  echo -e "${RED}Expected 401 but got $CODE${RESET}"; exit 1
fi

echo -e "\n${BOLD}${GREEN}Demo complete — all checks passed 🎉${RESET}"
