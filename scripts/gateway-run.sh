#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# MoFA Cognitive Gateway — run script
# Usage: ./scripts/gateway-run.sh [--release]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=8080
PROFILE="dev"
CARGO_FLAGS=""

for arg in "$@"; do
  case "$arg" in
    --release) PROFILE="release"; CARGO_FLAGS="--release" ;;
    --port=*)  PORT="${arg#--port=}" ;;
  esac
done

echo ""
echo -e "${BOLD}${CYAN}  MoFA Cognitive Gateway${NC}"
echo -e "  profile : $PROFILE"
echo -e "  port    : $PORT"
echo ""

# Kill anything already holding the port
if lsof -ti:"$PORT" &>/dev/null; then
  echo -e "  ${RED}port $PORT in use — killing existing process${NC}"
  lsof -ti:"$PORT" | xargs kill -9 2>/dev/null || true
  sleep 1
fi

cd "$REPO_ROOT/examples"

echo -e "  ${BOLD}building gateway_live_demo...${NC}"
cargo build -p gateway_live_demo $CARGO_FLAGS 2>&1

echo ""
echo -e "  ${GREEN}starting server on http://127.0.0.1:$PORT${NC}"
echo -e "  ${BOLD}Ctrl-C to stop${NC}"
echo ""

GATEWAY_PORT="$PORT" cargo run -p gateway_live_demo $CARGO_FLAGS
