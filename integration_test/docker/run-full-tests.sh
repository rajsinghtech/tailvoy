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
    shift 3
    local actual
    actual=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "$@" "$url" 2>&1 || true)
    if [ "$actual" = "$expected" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "expected $expected, got $actual"
    fi
}

assert_body_field() {
    local desc="$1" url="$2" field="$3" expected="$4"
    shift 4
    local body actual
    body=$(curl -sf --max-time 10 "$@" "$url" 2>&1 || true)
    actual=$(echo "$body" | jq -r ".$field" 2>/dev/null || true)
    if [ "$actual" = "$expected" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "expected $field=$expected, got $actual (body: $body)"
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

# Use node IP for tests — tailvoy listens on both VIP service and node IP.
IP="$NODE_IP"
sleep 5

# Check Envoy is healthy
echo "=== Checking Envoy health ==="
docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | grep -q "all dependencies initialized" && echo "Envoy initialized" || echo "WARNING: Envoy may not have initialized"

# =====================================================
# UDP VIP WARNING CHECK
# =====================================================
echo ""
echo "========================================"
echo "  UDP VIP WARNING CHECK"
echo "========================================"

TAILVOY_LOGS=$(docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 || true)
if echo "$TAILVOY_LOGS" | grep -q "UDP listener"; then
    test_pass "UDP VIP warning emitted in logs"
else
    echo "  DEBUG: tailvoy log output (last 20 lines):"
    echo "$TAILVOY_LOGS" | tail -20 | sed 's/^/    /'
    test_fail "UDP VIP warning emitted in logs" "warning not found in tailvoy logs"
fi

# =====================================================
# HTTP L7 TESTS — path routing (port 80)
# =====================================================
echo ""
echo "========================================"
echo "  HTTP L7 TESTS — PATH ROUTING"
echo "========================================"

# Allow: /public/* prefix
assert_http "L7: /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "L7: /public/nested/path allow" "http://$IP:80/public/nested/path" "200"

# Allow: /health exact match
assert_http "L7: /health allow (exact)" "http://$IP:80/health" "200"

# Allow: /api/* prefix
assert_http "L7: /api/data allow" "http://$IP:80/api/data" "200"
assert_http "L7: /api/v1/users allow" "http://$IP:80/api/v1/users" "200"

# Deny: /admin/* (not in cap routes)
assert_http "L7: /admin/settings deny (not in caps)" "http://$IP:80/admin/settings" "403"

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
# HTTP L7 TESTS — hostname routing
# =====================================================
echo ""
echo "========================================"
echo "  HTTP L7 TESTS — HOSTNAME ROUTING"
echo "========================================"

# app.tailvoy.test: grant gives /* for this hostname
assert_http "L7: app.tailvoy.test /anything allow" "http://$IP:80/anything" "200" -H "Host: app.tailvoy.test"
assert_http "L7: app.tailvoy.test / allow" "http://$IP:80/" "200" -H "Host: app.tailvoy.test"
assert_http "L7: app.tailvoy.test /admin allow" "http://$IP:80/admin" "200" -H "Host: app.tailvoy.test"

# api.tailvoy.test: grant gives /v1/* only
assert_http "L7: api.tailvoy.test /v1/users allow" "http://$IP:80/v1/users" "200" -H "Host: api.tailvoy.test"
assert_http "L7: api.tailvoy.test /v1/data allow" "http://$IP:80/v1/data" "200" -H "Host: api.tailvoy.test"
assert_http "L7: api.tailvoy.test /v2/users deny" "http://$IP:80/v2/users" "403" -H "Host: api.tailvoy.test"
# No route defined for / on this hostname, Envoy returns 404 (no matching route)
assert_http "L7: api.tailvoy.test / no route" "http://$IP:80/" "404" -H "Host: api.tailvoy.test"

# unknown.tailvoy.test: no hostname-specific grant, falls back to default route
# The default route has no hostname restriction, so /public/* should work
assert_http "L7: unknown host /public/hello allow (default route)" "http://$IP:80/public/hello" "200" -H "Host: unknown.tailvoy.test"
assert_http "L7: unknown host /admin deny (default route)" "http://$IP:80/admin" "403" -H "Host: unknown.tailvoy.test"

# =====================================================
# HTTP L7 TESTS — multi-path routing (different backends)
# =====================================================
echo ""
echo "========================================"
echo "  HTTP L7 TESTS — MULTI-PATH ROUTING"
echo "========================================"

# api.tailvoy.test routes /v1/* to backend:8080, /v2/* to backend-alt:8081
# The backend echo servers return the path they received
assert_body_field "L7: api.tailvoy.test /v1/test routed correctly" "http://$IP:80/v1/test" "path" "/v1/test" -H "Host: api.tailvoy.test"

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
# TLS PASSTHROUGH TESTS (port 8443, listener=tls)
# =====================================================
echo ""
echo "========================================"
echo "  TLS PASSTHROUGH TESTS"
echo "========================================"

# Allow: SNI secure.tailvoy.test (cap grants tls + hostname)
TLS_RESP=$(curl -sk --max-time 10 --resolve "secure.tailvoy.test:8443:$IP" "https://secure.tailvoy.test:8443/" 2>&1 || true)
if echo "$TLS_RESP" | jq -e '.tls == true' &>/dev/null; then
    test_pass "TLS: passthrough to tls-echo (secure.tailvoy.test)"
else
    test_fail "TLS: passthrough to tls-echo" "got '$TLS_RESP'"
fi

# Deny: SNI unknown.tailvoy.test (hostname not in caps)
TLS_DENY=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --resolve "unknown.tailvoy.test:8443:$IP" "https://unknown.tailvoy.test:8443/" 2>&1 || true)
if [ "$TLS_DENY" = "000" ] || [ -z "$TLS_DENY" ]; then
    test_pass "TLS: deny unknown hostname (conn reset)"
else
    test_fail "TLS: deny unknown hostname" "expected conn reset, got $TLS_DENY"
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
    # Allow: udp listener is in caps
    UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 9053 2>/dev/null || true)
    if echo "$UDP_RESP" | grep -q "echo: hello"; then
        test_pass "UDP: echo allow (cap grants udp access)"
    else
        test_fail "UDP: echo allow (cap grants udp access)" "got '$UDP_RESP'"
    fi
else
    echo "  SKIP: UDP tests (no ncat/nc)"
fi

# =====================================================
# gRPC TESTS (port 50051, listener=grpc)
# =====================================================
echo ""
echo "========================================"
echo "  gRPC TESTS"
echo "========================================"

if command -v grpc-health-probe &>/dev/null; then
    # Allow: health check (cap grants /grpc.health.v1.Health/*)
    if grpc-health-probe -addr "$IP:50051" -connect-timeout 5s -rpc-timeout 5s 2>/dev/null; then
        test_pass "gRPC: health check allow"
    else
        test_fail "gRPC: health check allow" "health probe failed"
    fi

    # Allow: named service health
    if grpc-health-probe -addr "$IP:50051" -service echo -connect-timeout 5s -rpc-timeout 5s 2>/dev/null; then
        test_pass "gRPC: named service health allow"
    else
        test_fail "gRPC: named service health allow" "health probe failed"
    fi
else
    echo "  SKIP: gRPC health tests (grpc-health-probe not found)"
fi

if command -v grpcurl &>/dev/null; then
    # Deny: reflection (not in cap routes)
    GRPC_REFL=$(grpcurl -plaintext "$IP:50051" list 2>&1 || true)
    if echo "$GRPC_REFL" | grep -qi "denied\|permission\|forbidden\|code = 7\|PermissionDenied"; then
        test_pass "gRPC: reflection deny (not in cap routes)"
    elif echo "$GRPC_REFL" | grep -qi "grpc.health"; then
        test_fail "gRPC: reflection deny" "reflection succeeded, expected deny"
    else
        # Connection reset or other error also counts as deny
        test_pass "gRPC: reflection deny (connection error)"
    fi
else
    echo "  SKIP: gRPC reflection tests (grpcurl not found)"
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
