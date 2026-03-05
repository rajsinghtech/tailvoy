#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose-full.yaml"

PASS=0
FAIL=0
TESTS=()

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
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

assert_http() {
    local desc="$1" url="$2" expected="$3"
    local actual
    actual=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>&1 || true)
    if [ "$actual" = "$expected" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "expected $expected, got $actual"
    fi
}

assert_body_field() {
    local desc="$1" url="$2" field="$3" expected="$4"
    local body actual
    body=$(curl -sf --max-time 10 "$url" 2>&1 || true)
    actual=$(echo "$body" | jq -r ".$field" 2>/dev/null || true)
    if [ "$actual" = "$expected" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "expected $field=$expected, got $actual"
    fi
}

# --- Detect ncat/nc ---
NC_CMD=""
if command -v ncat &>/dev/null; then
    NC_CMD="ncat"
elif command -v nc &>/dev/null; then
    NC_CMD="nc"
else
    echo "WARNING: ncat/nc not found, TCP/UDP tests will be skipped"
fi

# --- Load env ---
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

# --- Build and start ---
echo "=== Building Docker images ==="
docker compose -f "$COMPOSE_FILE" build 2>&1 | tail -5

echo "=== Starting stack ==="
docker compose -f "$COMPOSE_FILE" up -d 2>&1

# --- Wait for tailnet join (node) ---
echo "=== Waiting for tailnet join ==="
NODE_IP=""
for i in $(seq 1 60); do
    NODE_IP=$(tailscale status --json 2>/dev/null \
        | jq -r '.Peer[] | select(.HostName == "tailvoy-docker-test-tailvoy") | .TailscaleIPs[0]' 2>/dev/null || true)
    if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
        echo "tailvoy-docker-test-tailvoy joined as $NODE_IP"
        break
    fi
    sleep 2
done
if [ -z "$NODE_IP" ] || [ "$NODE_IP" = "null" ]; then
    echo "FATAL: tailvoy did not join"
    docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | tail -30
    exit 1
fi

# --- Wait for VIP service ---
echo "=== Waiting for VIP service ==="
IP=""
SVC_NAME="svc-tailvoy-docker-test"
for i in $(seq 1 30); do
    # Try resolving the VIP service via tailscale ip (MagicDNS)
    IP=$(tailscale ip "$SVC_NAME" 2>/dev/null | head -1 || true)
    if [ -n "$IP" ] && [ "$IP" != "null" ]; then
        echo "VIP service $SVC_NAME at $IP"
        break
    fi
    sleep 2
done
if [ -z "$IP" ] || [ "$IP" = "null" ]; then
    echo "FATAL: VIP service $SVC_NAME not found"
    tailscale status 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | tail -30
    exit 1
fi
sleep 5

# Check Envoy is healthy
echo "=== Checking Envoy health ==="
docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | grep -q "all dependencies initialized" && echo "Envoy initialized" || echo "WARNING: Envoy may not have initialized"

# =====================================================
# HTTP L7 TESTS (port 80, through Envoy ext_authz)
# =====================================================
echo ""
echo "========================================"
echo "  HTTP L7 TESTS"
echo "========================================"

# Allow: /public/* prefix
assert_http "L7: /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "L7: /public/nested/path allow" "http://$IP:80/public/nested/path" "200"

# Allow: /health exact match
assert_http "L7: /health allow (exact)" "http://$IP:80/health" "200"

# Allow: /api/* prefix
assert_http "L7: /api/data allow" "http://$IP:80/api/data" "200"
assert_http "L7: /api/v1/users allow" "http://$IP:80/api/v1/users" "200"

# Allow: /admin/* prefix
assert_http "L7: /admin/settings allow" "http://$IP:80/admin/settings" "200"

# Deny: / root (not in cap routes)
assert_http "L7: / deny (not in routes)" "http://$IP:80/" "403"

# Deny: /secret/data (not in cap routes)
assert_http "L7: /secret/data deny" "http://$IP:80/secret/data" "403"

# Deny: /unknown (not in cap routes)
assert_http "L7: /unknown deny" "http://$IP:80/unknown" "403"

# Deny: /health/ (exact match boundary, trailing slash)
assert_http "L7: /health/ deny (exact boundary)" "http://$IP:80/health/" "403"

# Deny: /apiary (not /api/*)
assert_http "L7: /apiary deny (not /api/*)" "http://$IP:80/apiary" "403"

# =====================================================
# IDENTITY HEADER TESTS (port 80)
# =====================================================
echo ""
echo "========================================"
echo "  IDENTITY HEADER TESTS"
echo "========================================"

BODY=$(curl -sf --max-time 10 "http://$IP:80/public/headers" 2>&1 || true)

# Tagged nodes have tags, not UserLogin — check for either
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"] // empty' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"] // empty' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"] // empty' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"] // empty' 2>/dev/null || true)

if [ -n "$USER_HDR" ] || [ -n "$TAGS_HDR" ]; then
    test_pass "Header: x-tailscale-user or x-tailscale-tags present"
else
    test_fail "Header: x-tailscale-user or x-tailscale-tags" "both empty"
fi

if [ -n "$NODE_HDR" ]; then
    test_pass "Header: x-tailscale-node present"
else
    test_fail "Header: x-tailscale-node" "empty"
fi

if [ -n "$IP_HDR" ]; then
    test_pass "Header: x-tailscale-ip present"
else
    test_fail "Header: x-tailscale-ip" "empty"
fi

# =====================================================
# TCP L4 TESTS (port 5432, listener=tcp)
# =====================================================
echo ""
echo "========================================"
echo "  TCP L4 TESTS"
echo "========================================"

if [ -n "$NC_CMD" ]; then
    TCP_RESP=$(echo "hello" | $NC_CMD -w 5 "$IP" 5432 2>/dev/null || true)
    if echo "$TCP_RESP" | grep -q "echo: hello"; then
        test_pass "TCP: echo allow (cap grants L4 access)"
    else
        test_fail "TCP: echo allow (cap grants L4 access)" "got '$TCP_RESP'"
    fi

    TCP_RESP2=$(echo "world" | $NC_CMD -w 5 "$IP" 5432 2>/dev/null || true)
    if echo "$TCP_RESP2" | grep -q "echo: world"; then
        test_pass "TCP: second connection allow"
    else
        test_fail "TCP: second connection allow" "got '$TCP_RESP2'"
    fi
else
    echo "  SKIP: TCP tests (no ncat/nc)"
fi

# =====================================================
# UDP TESTS (port 9053, listener=udp)
# =====================================================
echo ""
echo "========================================"
echo "  UDP TESTS"
echo "========================================"

if [ -n "$NC_CMD" ]; then
    UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 9053 2>/dev/null || true)
    if echo "$UDP_RESP" | grep -q "echo: hello"; then
        test_pass "UDP: echo allow (cap grants L4 access)"
    else
        # Fallback: try socat or bash /dev/udp
        if command -v socat &>/dev/null; then
            UDP_RESP2=$(echo -n "hello" | socat -T5 - UDP:"$IP":9053 2>/dev/null || true)
        else
            UDP_RESP2=$(bash -c "exec 3<>/dev/udp/$IP/9053; echo -n 'hello' >&3; read -t 5 resp <&3; echo \"\$resp\"" 2>/dev/null || true)
        fi
        if echo "$UDP_RESP2" | grep -q "echo: hello"; then
            test_pass "UDP: echo allow (cap grants L4 access)"
        else
            test_fail "UDP: echo allow (cap grants L4 access)" "ncat='$UDP_RESP', fallback='${UDP_RESP2:-}'"
        fi
    fi
else
    echo "  SKIP: UDP tests (no ncat/nc)"
fi

# =====================================================
# L4 DENY TEST (port 9999, listener=no-access)
# =====================================================
echo ""
echo "========================================"
echo "  L4 DENY TEST"
echo "========================================"

if [ -n "$NC_CMD" ]; then
    DENY_RESP=$(echo "test" | $NC_CMD -w 5 "$IP" 9999 2>/dev/null || true)
    if [ -z "$DENY_RESP" ]; then
        test_pass "L4: port 9999 deny (no-access listener not in caps)"
    else
        test_fail "L4: port 9999 deny" "got response '$DENY_RESP'"
    fi
else
    # Fall back to curl for the deny test since it's forwarding to an HTTP backend
    if curl -sf -o /dev/null --max-time 5 "http://$IP:9999/" 2>/dev/null; then
        test_fail "L4: port 9999 deny" "connection should have been denied"
    else
        test_pass "L4: port 9999 deny (no-access listener not in caps)"
    fi
fi

# =====================================================
# RESULTS
# =====================================================
echo ""
echo "========================================"
echo "  RESULTS"
echo "========================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo "Total:  $((PASS + FAIL))"
echo ""
for t in "${TESTS[@]}"; do echo "  $t"; done
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
fi
