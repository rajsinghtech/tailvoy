#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    docker compose -f "$SCRIPT_DIR/docker-compose.yaml" down 2>/dev/null || true
}
trap cleanup EXIT

# --- Load env ---
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$SCRIPT_DIR/../.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
    elif [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then echo "FATAL: TS_CLIENT_ID is empty"; exit 1; fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then echo "FATAL: TS_CLIENT_SECRET is empty"; exit 1; fi

# --- Build and start ---
echo "=== Building Docker images ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" build 2>&1 | tail -5

echo "=== Starting stack ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" up -d 2>&1

# --- Wait for tailnet join ---
echo "=== Waiting for tailnet join ==="
NODE_IP=""
for i in $(seq 1 60); do
    NODE_IP=$(tailscale status --json 2>/dev/null \
        | jq -r '.Peer[] | select(.HostName == "tailvoy-l7-test-tailvoy") | .TailscaleIPs[0]' 2>/dev/null || true)
    if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
        echo "tailvoy-l7-test-tailvoy joined as $NODE_IP"
        break
    fi
    sleep 2
done
if [ -z "$NODE_IP" ] || [ "$NODE_IP" = "null" ]; then
    echo "FATAL: tailvoy-l7-test-tailvoy did not join"
    docker compose -f "$SCRIPT_DIR/docker-compose.yaml" logs tailvoy 2>&1 | tail -20
    exit 1
fi

# --- Resolve VIP service ---
DNS_SUFFIX=$(get_dns_suffix)
echo "MagicDNS suffix: $DNS_SUFFIX"

SVC="web.$DNS_SUFFIX"
wait_dns "$SVC" 60

TAILVOY_IP="$SVC"
echo "Testing against: $TAILVOY_IP (node: $NODE_IP)"
sleep 5

# =====================================================
section "L7 PATH ROUTING"
# =====================================================

assert_http "/public/* allow" "http://$TAILVOY_IP:80/public/hello" "200"
assert_http "/public/nested/path allow (wildcard)" "http://$TAILVOY_IP:80/public/nested/path" "200"
assert_http "/user-only/* allow (specific user)" "http://$TAILVOY_IP:80/user-only/data" "200"
assert_http "/admin/* deny (missing tag)" "http://$TAILVOY_IP:80/admin/settings" "403"
assert_http "/unknown deny (default:deny)" "http://$TAILVOY_IP:80/unknown" "403"

# =====================================================
section "IDENTITY HEADERS"
# =====================================================

BODY=$(curl -sf --max-time 10 "http://$TAILVOY_IP:80/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"] // empty' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"] // empty' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"] // empty' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"] // empty' 2>/dev/null || true)

if [ -n "$USER_HDR" ] || [ -n "$TAGS_HDR" ]; then
    test_pass "x-tailscale-user or x-tailscale-tags present"
else
    test_fail "x-tailscale identity" "no user or tags found"
fi
if [ -n "$NODE_HDR" ]; then test_pass "x-tailscale-node present"; else test_fail "x-tailscale-node" "empty"; fi
if [ -n "$IP_HDR" ]; then test_pass "x-tailscale-ip present"; else test_fail "x-tailscale-ip" "empty"; fi

# =====================================================
section "CONCURRENT L7"
# =====================================================

OK=0
for i in $(seq 1 10); do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/public/$i" 2>&1 || true)
    if [ "$HTTP" = "200" ]; then OK=$((OK+1)); fi
done
if [ "$OK" -eq 10 ]; then test_pass "10 concurrent L7"; else test_fail "10 concurrent L7" "$OK/10"; fi

# =====================================================
print_results
