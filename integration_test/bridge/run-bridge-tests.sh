#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

# Required env vars
: "${TAILNET1_TS_CLIENT_ID:?TAILNET1_TS_CLIENT_ID is required}"
: "${TAILNET1_TS_CLIENT_SECRET:?TAILNET1_TS_CLIENT_SECRET is required}"
: "${TAILNET2_TS_CLIENT_ID:?TAILNET2_TS_CLIENT_ID is required}"
: "${TAILNET2_TS_CLIENT_SECRET:?TAILNET2_TS_CLIENT_SECRET is required}"

BRIDGE_BIN="/tmp/tailvoy-bridge-$$"
BACKEND_PID=""
BRIDGE_PID=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    rm -f "$BRIDGE_BIN"
}
trap cleanup EXIT

# --- Render config with env var expansion ---
render_config() {
    local src="$SCRIPT_DIR/bridge-config.yaml"
    local dst="/tmp/bridge-config-$$.yaml"
    sed \
        -e "s|\${TAILNET1_TS_CLIENT_ID}|$TAILNET1_TS_CLIENT_ID|g" \
        -e "s|\${TAILNET1_TS_CLIENT_SECRET}|$TAILNET1_TS_CLIENT_SECRET|g" \
        -e "s|\${TAILNET2_TS_CLIENT_ID}|$TAILNET2_TS_CLIENT_ID|g" \
        -e "s|\${TAILNET2_TS_CLIENT_SECRET}|$TAILNET2_TS_CLIENT_SECRET|g" \
        "$src" > "$dst"
    echo "$dst"
}

# --- Obtain bearer token via OAuth client credentials ---
get_token() {
    local client_id="$1" client_secret="$2"
    curl -sf \
        -d "client_id=$client_id" \
        -d "client_secret=$client_secret" \
        -d "grant_type=client_credentials" \
        https://api.tailscale.com/api/v2/oauth/token \
        | jq -r '.access_token'
}

# --- Build ---
section "Building tailvoy"
cd "$ROOT_DIR"
go build -o "$BRIDGE_BIN" ./cmd/tailvoy/
echo "Built: $BRIDGE_BIN"

# --- Start a simple HTTP backend (the CI runner is the discoverable node on tailnet1) ---
section "Starting HTTP backend on port 8080"
python3 -m http.server 8080 &>/dev/null &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# --- Render config and start bridge ---
section "Starting bridge"
CONFIG_FILE=$(render_config)
"$BRIDGE_BIN" -config "$CONFIG_FILE" -log-level debug &>"$SCRIPT_DIR/bridge.log" &
BRIDGE_PID=$!
echo "Bridge PID: $BRIDGE_PID (logs: $SCRIPT_DIR/bridge.log)"

# --- Wait for bridge to initialize ---
section "Waiting for bridge to initialize (60s)"
READY=false
for i in $(seq 1 60); do
    if grep -q "bridge initialized\|poll complete" "$SCRIPT_DIR/bridge.log" 2>/dev/null; then
        READY=true
        echo "Bridge ready (attempt $i)"
        break
    fi
    if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
        echo "FATAL: bridge process exited early"
        tail -30 "$SCRIPT_DIR/bridge.log" || true
        exit 1
    fi
    [ $((i % 10)) -eq 0 ] && echo "  waiting... (${i}s)"
    sleep 1
done

if [ "$READY" = "false" ]; then
    echo "WARNING: bridge did not log expected init message; continuing anyway"
    tail -20 "$SCRIPT_DIR/bridge.log" || true
fi

# Give the bridge extra time to complete its first poll and create VIP services
echo "Waiting 30s for first poll cycle..."
sleep 30

# --- Get API tokens ---
section "Fetching API tokens"
TAILNET1_TOKEN=$(get_token "$TAILNET1_TS_CLIENT_ID" "$TAILNET1_TS_CLIENT_SECRET")
TAILNET2_TOKEN=$(get_token "$TAILNET2_TS_CLIENT_ID" "$TAILNET2_TS_CLIENT_SECRET")

if [ -z "$TAILNET1_TOKEN" ] || [ "$TAILNET1_TOKEN" = "null" ]; then
    echo "FATAL: could not obtain tailnet1 token"
    exit 1
fi
if [ -z "$TAILNET2_TOKEN" ] || [ "$TAILNET2_TOKEN" = "null" ]; then
    echo "FATAL: could not obtain tailnet2 token"
    exit 1
fi
echo "Tokens obtained"

# --- Get tailnet names from the API ---
TAILNET1_NAME=$(curl -sf -H "Authorization: Bearer $TAILNET1_TOKEN" \
    "https://api.tailscale.com/api/v2/tailnet/-/dns/preferences" \
    | jq -r '.magicDNS' || true)

# --- Verify: bridge joined tailnet2 ---
section "Verifying bridge joined tailnet2"
BRIDGE_NODES=$(curl -sf -H "Authorization: Bearer $TAILNET2_TOKEN" \
    "https://api.tailscale.com/api/v2/tailnet/-/devices" \
    | jq -r '[.devices[] | select(.tags != null) | select(.tags[] | test("tag:bridge"))] | length' 2>/dev/null || echo "0")

if [ "$BRIDGE_NODES" -gt 0 ] 2>/dev/null; then
    test_pass "bridge node present on tailnet2 (tag:bridge)"
else
    test_fail "bridge node on tailnet2" "no devices with tag:bridge found (got: $BRIDGE_NODES)"
fi

# --- Verify: VIP services created on tailnet2 ---
section "Verifying VIP services on tailnet2"
VIP_RAW=$(curl -sf -H "Authorization: Bearer $TAILNET2_TOKEN" \
    "https://api.tailscale.com/api/v2/tailnet/-/vip-services" || echo "{}")
# API returns {"vipServices": [...]} or bare array; normalize to array
VIP_LIST=$(echo "$VIP_RAW" | jq 'if type == "array" then . elif .vipServices then .vipServices else [] end' 2>/dev/null || echo "[]")
echo "VIP services on tailnet2: $(echo "$VIP_LIST" | jq 'length')"
echo "Raw VIP response: $(echo "$VIP_RAW" | jq -c '.' 2>/dev/null || echo "$VIP_RAW")"

BRIDGE_SVCS=$(echo "$VIP_LIST" | jq '[.[] | select(.comment == "Managed by tailvoy bridge")]' 2>/dev/null || echo "[]")
BRIDGE_SVC_COUNT=$(echo "$BRIDGE_SVCS" | jq 'length')

if [ "$BRIDGE_SVC_COUNT" -gt 0 ] 2>/dev/null; then
    test_pass "VIP services created on tailnet2 ($BRIDGE_SVC_COUNT services)"
else
    echo "All VIP services: $(echo "$VIP_LIST" | jq -c '[.[].comment]')"
    test_fail "VIP service creation on tailnet2" "no services with comment 'Managed by tailvoy bridge' found"
fi

# --- Verify: VIP services have ports ---
section "Verifying VIP service ports"
VIP_WITH_PORTS=$(echo "$BRIDGE_SVCS" | jq '[.[] | select(.ports != null and (.ports | length) > 0)] | length' 2>/dev/null || echo "0")

if [ "$VIP_WITH_PORTS" -gt 0 ] 2>/dev/null; then
    test_pass "VIP services have ports configured"
else
    test_fail "VIP service ports" "no bridge VIP services have ports"
fi

# --- Verify: VIP services have tag:bridge-svc ---
section "Verifying VIP service tags"
VIP_WITH_TAG=$(echo "$BRIDGE_SVCS" | jq '[.[] | select(.tags != null) | select(.tags[] | test("tag:bridge-svc"))] | length' 2>/dev/null || echo "0")

if [ "$VIP_WITH_TAG" -gt 0 ] 2>/dev/null; then
    test_pass "VIP services tagged tag:bridge-svc"
else
    test_fail "VIP service tags" "no bridge VIP services have tag:bridge-svc"
fi

# --- Verify: split-DNS configured on tailnet2 ---
section "Verifying split-DNS on tailnet2"
SPLIT_DNS=$(curl -sf -H "Authorization: Bearer $TAILNET2_TOKEN" \
    "https://api.tailscale.com/api/v2/tailnet/-/dns/split-dns" || echo "{}")
echo "split-DNS config: $(echo "$SPLIT_DNS" | jq -c .)"

# The bridge creates a split-DNS entry for tailnet1's MagicDNS suffix
SPLIT_KEYS=$(echo "$SPLIT_DNS" | jq -r 'keys[]' 2>/dev/null || true)
if [ -n "$SPLIT_KEYS" ]; then
    test_pass "split-DNS configured on tailnet2 (zones: $(echo "$SPLIT_KEYS" | tr '\n' ' '))"
else
    test_fail "split-DNS" "no split-DNS zones configured on tailnet2"
fi

# --- Verify: bridge joined tailnet1 ---
section "Verifying bridge joined tailnet1"
BRIDGE_NODES_TN1=$(curl -sf -H "Authorization: Bearer $TAILNET1_TOKEN" \
    "https://api.tailscale.com/api/v2/tailnet/-/devices" \
    | jq -r '[.devices[] | select(.tags != null) | select(.tags[] | test("tag:bridge"))] | length' 2>/dev/null || echo "0")

if [ "$BRIDGE_NODES_TN1" -gt 0 ] 2>/dev/null; then
    test_pass "bridge node present on tailnet1 (tag:bridge)"
else
    test_fail "bridge node on tailnet1" "no devices with tag:bridge found"
fi

# --- Bridge process health check ---
section "Bridge process health"
if kill -0 "$BRIDGE_PID" 2>/dev/null; then
    test_pass "bridge process still running"
else
    test_fail "bridge process" "bridge exited unexpectedly"
    tail -20 "$SCRIPT_DIR/bridge.log" || true
fi

# =====================================================
print_results
