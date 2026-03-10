#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose-full.yaml"

# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

cleanup() {
    echo ""
    echo "=== Collecting logs ==="
    docker compose -f "$COMPOSE_FILE" logs > "$SCRIPT_DIR/docker-compose.log" 2>&1 || true
    echo "=== Cleanup ==="
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
}
trap cleanup EXIT

# --- Detect ncat/nc (needed for UDP + L4 deny) ---
NC_CMD=""
if command -v ncat &>/dev/null; then NC_CMD="ncat"
elif command -v nc &>/dev/null; then NC_CMD="nc"
else echo "WARNING: ncat/nc not found, some tests will be skipped"
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

# --- Wait for tailnet join ---
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

sleep 5
docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | grep -q "all dependencies initialized" && echo "Envoy initialized" || echo "WARNING: Envoy may not have initialized"

# --- Resolve VIP service FQDNs ---
DNS_SUFFIX=$(get_dns_suffix)
echo "MagicDNS suffix: $DNS_SUFFIX"

SVC_HTTP="docker-http.$DNS_SUFFIX"
SVC_GRPC="docker-grpc.$DNS_SUFFIX"
SVC_TLS="docker-tls.$DNS_SUFFIX"
SVC_TCP="docker-tcp.$DNS_SUFFIX"
SVC_RESTRICTED="docker-restricted.$DNS_SUFFIX"
IP="$SVC_HTTP"

wait_dns "$SVC_HTTP" 60
dump_peers
wait_http "http://$SVC_HTTP:80/health" 45 || {
    echo "Tailvoy container logs:"
    docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | tail -30
    exit 1
}

# =====================================================
section "HTTP L7 — PATH ROUTING"
# =====================================================

assert_http "L7: /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "L7: /public/nested/path allow" "http://$IP:80/public/nested/path" "200"
assert_http "L7: /health allow (exact)" "http://$IP:80/health" "200"
assert_http "L7: /api/data allow" "http://$IP:80/api/data" "200"
assert_http "L7: /api/v1/users allow" "http://$IP:80/api/v1/users" "200"
assert_http "L7: /admin/settings deny" "http://$IP:80/admin/settings" "403"
assert_http "L7: / deny" "http://$IP:80/" "403"
assert_http "L7: /secret/data deny" "http://$IP:80/secret/data" "403"
assert_http "L7: /unknown deny" "http://$IP:80/unknown" "403"
assert_http "L7: /health/ deny (exact boundary)" "http://$IP:80/health/" "403"
assert_http "L7: /apiary deny (not /api/*)" "http://$IP:80/apiary" "403"

# =====================================================
section "HTTP L7 — HOSTNAME ROUTING"
# =====================================================

# app.tailvoy.test: grant gives /* for this hostname
assert_http "L7: app.tailvoy.test /anything allow" "http://$IP:80/anything" "200" -H "Host: app.tailvoy.test"
assert_http "L7: app.tailvoy.test / allow" "http://$IP:80/" "200" -H "Host: app.tailvoy.test"
assert_http "L7: app.tailvoy.test /admin allow" "http://$IP:80/admin" "200" -H "Host: app.tailvoy.test"

# api.tailvoy.test: grant gives /v1/* only
assert_http "L7: api.tailvoy.test /v1/users allow" "http://$IP:80/v1/users" "200" -H "Host: api.tailvoy.test"
assert_http "L7: api.tailvoy.test /v1/data allow" "http://$IP:80/v1/data" "200" -H "Host: api.tailvoy.test"
assert_http "L7: api.tailvoy.test /v2/users deny" "http://$IP:80/v2/users" "403" -H "Host: api.tailvoy.test"
assert_http "L7: api.tailvoy.test / no route" "http://$IP:80/" "404" -H "Host: api.tailvoy.test"

# unknown host falls back to default route
assert_http "L7: unknown host /public/hello allow" "http://$IP:80/public/hello" "200" -H "Host: unknown.tailvoy.test"
assert_http "L7: unknown host /admin deny" "http://$IP:80/admin" "403" -H "Host: unknown.tailvoy.test"

# =====================================================
section "HTTP L7 — MULTI-PATH ROUTING"
# =====================================================

assert_body_field "L7: api.tailvoy.test /v1/test routed correctly" "http://$IP:80/v1/test" "path" "/v1/test" -H "Host: api.tailvoy.test"

# =====================================================
section "IDENTITY HEADERS"
# =====================================================

BODY=$(curl -sf --max-time 10 "http://$IP:80/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"] // empty' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"] // empty' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"] // empty' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"] // empty' 2>/dev/null || true)

if [ -n "$USER_HDR" ] || [ -n "$TAGS_HDR" ]; then
    test_pass "Header: x-tailscale-user or x-tailscale-tags present"
else
    test_fail "Header: x-tailscale-user or x-tailscale-tags" "both empty"
fi
if [ -n "$NODE_HDR" ]; then test_pass "Header: x-tailscale-node present"; else test_fail "Header: x-tailscale-node" "empty"; fi
if [ -n "$IP_HDR" ]; then test_pass "Header: x-tailscale-ip present"; else test_fail "Header: x-tailscale-ip" "empty"; fi

# =====================================================
section "TLS PASSTHROUGH"
# =====================================================

TLS_RESP=$(curl -sk --max-time 10 --connect-to "secure.tailvoy.test:8443:$SVC_TLS:8443" "https://secure.tailvoy.test:8443/" 2>&1 || true)
if echo "$TLS_RESP" | jq -e '.tls == true' &>/dev/null; then
    test_pass "TLS: passthrough to tls-echo (secure.tailvoy.test)"
else
    test_fail "TLS: passthrough to tls-echo" "got '$TLS_RESP'"
fi

TLS_DENY=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-to "unknown.tailvoy.test:8443:$SVC_TLS:8443" "https://unknown.tailvoy.test:8443/" 2>&1 || true)
if [ "$TLS_DENY" = "000" ] || [ -z "$TLS_DENY" ]; then
    test_pass "TLS: deny unknown hostname (conn reset)"
else
    test_fail "TLS: deny unknown hostname" "expected conn reset, got $TLS_DENY"
fi

# =====================================================
section "TCP L4"
# =====================================================

assert_tcp_echo "TCP: echo allow" "$SVC_TCP" 5432 "hello" 5
assert_tcp_echo "TCP: second connection allow" "$SVC_TCP" 5432 "world" 3

# =====================================================
section "UDP"
# =====================================================

if [ -n "$NC_CMD" ]; then
    # UDP has no VIP support (ListenService is TCP-only), use node IP
    UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -4 -u -w 5 "$NODE_IP" 9053 2>/dev/null || true)
    if echo "$UDP_RESP" | grep -q "echo: hello"; then
        test_pass "UDP: echo allow"
    else
        test_fail "UDP: echo allow" "got '$UDP_RESP'"
    fi
else
    echo "  SKIP: UDP tests (no ncat/nc)"
fi

# =====================================================
section "gRPC"
# =====================================================

if command -v grpc-health-probe &>/dev/null; then
    if grpc-health-probe -addr "$SVC_GRPC:50051" -connect-timeout 5s -rpc-timeout 5s 2>/dev/null; then
        test_pass "gRPC: health check allow"
    else
        test_fail "gRPC: health check allow" "health probe failed"
    fi
    if grpc-health-probe -addr "$SVC_GRPC:50051" -service echo -connect-timeout 5s -rpc-timeout 5s 2>/dev/null; then
        test_pass "gRPC: named service health allow"
    else
        test_fail "gRPC: named service health allow" "health probe failed"
    fi
else
    echo "  SKIP: gRPC health tests (grpc-health-probe not found)"
fi

if command -v grpcurl &>/dev/null; then
    GRPC_REFL=$(grpcurl -plaintext "$SVC_GRPC:50051" list 2>&1 || true)
    if echo "$GRPC_REFL" | grep -qi "denied\|permission\|forbidden\|code = 7\|PermissionDenied"; then
        test_pass "gRPC: reflection deny"
    elif echo "$GRPC_REFL" | grep -qi "grpc.health"; then
        test_fail "gRPC: reflection deny" "reflection succeeded"
    else
        test_pass "gRPC: reflection deny (connection error)"
    fi
else
    echo "  SKIP: gRPC reflection tests (grpcurl not found)"
fi

# =====================================================
section "L4 DENY"
# =====================================================

if [ -n "$NC_CMD" ]; then
    DENY_RESP=$(echo "test" | $NC_CMD -4 -w 5 "$SVC_RESTRICTED" 9999 2>/dev/null || true)
    if [ -z "$DENY_RESP" ]; then
        test_pass "L4: port 9999 deny (no-access)"
    else
        test_fail "L4: port 9999 deny" "got response '$DENY_RESP'"
    fi
else
    if curl -sf -o /dev/null --max-time 5 "http://$SVC_RESTRICTED:9999/" 2>/dev/null; then
        test_fail "L4: port 9999 deny" "connection should have been denied"
    else
        test_pass "L4: port 9999 deny (no-access)"
    fi
fi

# =====================================================
section "MULTI-SERVICE ALIAS"
# =====================================================

SVC_HTTP_ALIAS="docker-http-alias.$DNS_SUFFIX"
wait_dns "$SVC_HTTP_ALIAS" 60

assert_http "Alias: /public/hello allow" "http://$SVC_HTTP_ALIAS:80/public/hello" "200"
assert_http "Alias: /admin deny" "http://$SVC_HTTP_ALIAS:80/admin" "403"

# =====================================================
print_results
