#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PASS=0
FAIL=0
TESTS=()

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    docker compose -f "$SCRIPT_DIR/docker-compose.yaml" down 2>/dev/null || true
}
trap cleanup EXIT

test_pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
    TESTS+=("PASS: $1")
}

test_fail() {
    echo "  FAIL: $1: $2"
    FAIL=$((FAIL + 1))
    TESTS+=("FAIL: $1: $2")
}

# --- Check prerequisites ---
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then echo "FATAL: TS_CLIENT_ID is empty"; exit 1; fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then echo "FATAL: TS_CLIENT_SECRET is empty"; exit 1; fi

# --- Build and start Docker stack ---
echo "=== Building Docker images ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" build 2>&1 | tail -5

echo "=== Starting stack ==="
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" up -d 2>&1

# --- Wait for tailnet join ---
echo "=== Waiting for tailnet join ==="
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

# --- Wait for VIP service ---
echo "=== Waiting for VIP service ==="
TAILVOY_IP=""
SVC_NAME="svc:tailvoy-l7-test"
TS_TOKEN=$(curl -sf -X POST \
    -d "client_id=$TS_CLIENT_ID" \
    -d "client_secret=$TS_CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    "https://api.tailscale.com/api/v2/oauth/token" | jq -r '.access_token')
if [ -z "$TS_TOKEN" ] || [ "$TS_TOKEN" = "null" ]; then
    echo "FATAL: Failed to get Tailscale API token"
    exit 1
fi
for i in $(seq 1 30); do
    TAILVOY_IP=$(curl -sf -H "Authorization: Bearer $TS_TOKEN" \
        "https://api.tailscale.com/api/v2/tailnet/-/vip-services/${SVC_NAME}" \
        | jq -r '[.addrs[] | select(contains(":") | not)] | .[0]' 2>/dev/null || true)
    if [ -n "$TAILVOY_IP" ] && [ "$TAILVOY_IP" != "null" ]; then
        echo "VIP service $SVC_NAME at $TAILVOY_IP"
        break
    fi
    echo "  waiting for VIP service $SVC_NAME (attempt $i)..."
    sleep 2
done
if [ -z "$TAILVOY_IP" ] || [ "$TAILVOY_IP" = "null" ]; then
    echo "FATAL: VIP service $SVC_NAME not found"
    curl -sf -H "Authorization: Bearer $TS_TOKEN" \
        "https://api.tailscale.com/api/v2/tailnet/-/vip-services/${SVC_NAME}" 2>&1 || true
    docker compose -f "$SCRIPT_DIR/docker-compose.yaml" logs tailvoy 2>&1 | tail -20
    exit 1
fi
sleep 5

# --- L7 Tests ---
echo ""
echo "=== L7 Tests ==="

# /public/* → ALLOW (any_tailscale)
echo "Test: /public/* allow (any_tailscale)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/public/hello" 2>&1 || true)
if [ "$HTTP" = "200" ]; then test_pass "/public/* allow"; else test_fail "/public/* allow" "got $HTTP"; fi

# /user-only/* → ALLOW (rajsinghtech@github)
echo "Test: /user-only/* allow (specific user)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/user-only/data" 2>&1 || true)
if [ "$HTTP" = "200" ]; then test_pass "/user-only/* allow"; else test_fail "/user-only/* allow" "got $HTTP"; fi

# /admin/* → DENY (requires nonexistent tag)
echo "Test: /admin/* deny (missing tag)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/admin/settings" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "/admin/* deny"; else test_fail "/admin/* deny" "expected 403, got $HTTP"; fi

# /unknown → DENY (default:deny)
echo "Test: /unknown deny (default:deny)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/unknown" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "default deny"; else test_fail "default deny" "expected 403, got $HTTP"; fi

# Wildcard nesting
echo "Test: /public/nested/path allow (wildcard)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/public/nested/path" 2>&1 || true)
if [ "$HTTP" = "200" ]; then test_pass "nested wildcard"; else test_fail "nested wildcard" "got $HTTP"; fi

# Identity headers on allowed request
echo "Test: identity headers injected"
BODY=$(curl -sf --max-time 10 "http://$TAILVOY_IP:80/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)
if [ "$USER_HDR" = "rajsinghtech@github" ]; then test_pass "x-tailscale-user header"; else test_fail "x-tailscale-user header" "got '$USER_HDR'"; fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "x-tailscale-node header"; else test_fail "x-tailscale-node header" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "x-tailscale-ip header"; else test_fail "x-tailscale-ip header" "empty"; fi

# Concurrent L7 requests
echo "Test: concurrent L7 requests"
OK=0
for i in $(seq 1 10); do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/public/$i" 2>&1 || true)
    if [ "$HTTP" = "200" ]; then OK=$((OK+1)); fi
done
if [ "$OK" -eq 10 ]; then test_pass "10 concurrent L7"; else test_fail "10 concurrent L7" "$OK/10"; fi

# --- Results ---
echo ""
echo "=== Results ==="
echo "Passed: $PASS / $((PASS + FAIL))"
for t in "${TESTS[@]}"; do echo "  $t"; done
if [ "$FAIL" -gt 0 ]; then exit 1; fi
