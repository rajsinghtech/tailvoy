#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../.."
CLUSTER_NAME="tailvoy-kind-test"
EG_VERSION="v1.7.0"
TAILVOY_HOSTNAME="tailvoy-kind-test-tailvoy"

PASS=0
FAIL=0
TESTS=()

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
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
    local body actual
    body=$(curl -sf --max-time 10 "$url" 2>&1 || true)
    actual=$(echo "$body" | jq -r ".$field" 2>/dev/null || true)
    if [ "$actual" = "$expected" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "expected $field=$expected, got $actual"
    fi
}

dump_logs() {
    echo ""
    echo "=== Tailvoy (EG Data Plane) Pod Logs ==="
    kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg --tail=100 2>/dev/null || true
    echo ""
    echo "=== EG Controller Logs ==="
    kubectl logs -n envoy-gateway-system -l control-plane=envoy-gateway --tail=50 2>/dev/null || true
}

# --- Check prerequisites ---
echo "=== Checking prerequisites ==="
for cmd in kind kubectl helm docker jq curl tailscale; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: $cmd not found"
        exit 1
    fi
done
# Check for ncat or nc (needed for TCP/UDP tests)
if command -v ncat &>/dev/null; then
    NC_CMD="ncat"
elif command -v nc &>/dev/null; then
    NC_CMD="nc"
else
    echo "FATAL: ncat or nc not found"
    exit 1
fi
# Check for grpcurl (needed for gRPC deny tests)
HAS_GRPCURL=false
if command -v grpcurl &>/dev/null; then
    HAS_GRPCURL=true
fi
# Check for grpc-health-probe (needed for gRPC health tests)
HAS_HEALTHPROBE=false
if command -v grpc-health-probe &>/dev/null; then
    HAS_HEALTHPROBE=true
fi
echo "All prerequisites found (using $NC_CMD for TCP/UDP, grpcurl=$HAS_GRPCURL, grpc-health-probe=$HAS_HEALTHPROBE)"

# --- Load OAuth credentials ---
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
    elif [ -f "$SCRIPT_DIR/../.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then
    echo "FATAL: TS_CLIENT_ID is empty"
    exit 1
fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then
    echo "FATAL: TS_CLIENT_SECRET is empty"
    exit 1
fi

# --- Create kind cluster ---
echo "=== Creating kind cluster ==="
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml" --wait 60s

# --- Build images ---
echo "=== Building tailvoy image ==="
docker build -t tailvoy:test -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT" 2>&1 | tail -5

echo "=== Building backend images ==="
docker build -t tailvoy-backend:test "$REPO_ROOT/integration_test/backend" 2>&1 | tail -5
docker build -t tailvoy-tcp-echo:test "$REPO_ROOT/integration_test/backend/tcp-echo" 2>&1 | tail -5
docker build -t tailvoy-udp-echo:test "$REPO_ROOT/integration_test/backend/udp-echo" 2>&1 | tail -5
docker build -t tailvoy-tls-backend:test "$REPO_ROOT/integration_test/backend/tls-echo" 2>&1 | tail -5
docker build -t tailvoy-grpc-echo:test "$REPO_ROOT/integration_test/backend/grpc-echo" 2>&1 | tail -5

# --- Load images into kind ---
echo "=== Loading images into kind ==="
kind load docker-image tailvoy:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-backend:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-tcp-echo:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-udp-echo:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-tls-backend:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-grpc-echo:test --name "$CLUSTER_NAME"

# --- Install Envoy Gateway ---
echo "=== Installing Envoy Gateway $EG_VERSION ==="
helm install eg oci://docker.io/envoyproxy/gateway-helm \
    --version "$EG_VERSION" \
    -n envoy-gateway-system --create-namespace \
    --wait --timeout 120s 2>&1 | tail -5

echo "Waiting for EG controller to be ready..."
kubectl wait --namespace envoy-gateway-system \
    deployment/envoy-gateway \
    --for=condition=available --timeout=120s

# --- Create OAuth secret ---
echo "=== Creating OAuth secret ==="
kubectl create secret generic tailvoy-oauth \
    -n envoy-gateway-system \
    --from-literal=TS_CLIENT_ID="$TS_CLIENT_ID" \
    --from-literal=TS_CLIENT_SECRET="$TS_CLIENT_SECRET"

# --- Apply tailvoy config + authz service + ReferenceGrant ---
echo "=== Deploying tailvoy config ==="
kubectl apply -f "$SCRIPT_DIR/manifests/tailvoy-config.yaml"

# --- Apply EnvoyProxy CRD ---
echo "=== Deploying EnvoyProxy CRD ==="
kubectl apply -f "$SCRIPT_DIR/manifests/envoy-proxy.yaml"

# --- Apply GatewayClass + Gateway + ClientTrafficPolicy ---
echo "=== Deploying Gateway ==="
kubectl apply -f "$SCRIPT_DIR/manifests/gateway.yaml"

echo "Waiting for Gateway to be accepted..."
for i in $(seq 1 60); do
    STATUS=$(kubectl get gateway eg -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)
    if [ "$STATUS" = "True" ]; then
        echo "Gateway is accepted"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FATAL: Gateway not accepted after 120s"
        kubectl get gateway eg -o yaml 2>/dev/null || true
        exit 1
    fi
    sleep 2
done

# --- Deploy backend services ---
echo "=== Deploying backend services ==="
kubectl apply -f "$SCRIPT_DIR/manifests/backend.yaml"
kubectl wait deployment/backend --for=condition=available --timeout=60s
kubectl wait deployment/tcp-echo --for=condition=available --timeout=60s
kubectl wait deployment/udp-echo --for=condition=available --timeout=60s
kubectl wait deployment/tls-backend --for=condition=available --timeout=60s
kubectl wait deployment/grpc-echo --for=condition=available --timeout=60s

# --- Apply routes ---
echo "=== Deploying routes ==="
kubectl apply -f "$SCRIPT_DIR/manifests/routes.yaml"

# --- Apply SecurityPolicy ---
echo "=== Deploying SecurityPolicy ==="
kubectl apply -f "$SCRIPT_DIR/manifests/security-policy.yaml"

# --- Wait for data plane pod ---
echo "Waiting for data plane pod to be ready..."
for i in $(seq 1 60); do
    READY=$(kubectl get pods -n envoy-gateway-system \
        -l "gateway.envoyproxy.io/owning-gateway-name=eg" \
        -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
    if [ "$READY" = "True" ]; then
        echo "Data plane pod is ready"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FATAL: Data plane pod not ready after 120s"
        kubectl get pods -n envoy-gateway-system -o wide 2>/dev/null || true
        dump_logs
        exit 1
    fi
    sleep 2
done

# --- Wait for tailnet join ---
echo "=== Waiting for tailnet join ==="
IP=""
for i in $(seq 1 90); do
    IP=$(tailscale status --json 2>/dev/null \
        | jq -r ".Peer[] | select(.HostName == \"$TAILVOY_HOSTNAME\" and .Online == true) | .TailscaleIPs[0]" 2>/dev/null || true)
    if [ -n "$IP" ] && [ "$IP" != "null" ]; then
        echo "$TAILVOY_HOSTNAME joined as $IP"
        break
    fi
    sleep 2
done
if [ -z "$IP" ] || [ "$IP" = "null" ]; then
    echo "FATAL: tailvoy did not join tailnet"
    dump_logs
    exit 1
fi
sleep 5

# Smoke test — retry to allow time for discovery mode to find Envoy listeners
echo "=== Smoke test ==="
SMOKE_OK=false
for i in $(seq 1 30); do
    SMOKE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:8080/health" 2>&1 || true)
    if [ "$SMOKE" = "200" ]; then
        SMOKE_OK=true
        break
    fi
    echo "  smoke attempt $i: got $SMOKE, retrying..."
    sleep 2
done
if [ "$SMOKE_OK" != "true" ]; then
    echo "FATAL: Smoke test failed after 30 attempts (GET /health returned $SMOKE)"
    dump_logs
    exit 1
fi
echo "Smoke test passed"

# =====================================================
# HTTPRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  HTTPRoute TESTS"
echo "========================================"

# Cap rule: {"listeners": ["http"], "routes": ["/public/*", "/health", "/api/*", "/admin/*"]}
# SecurityPolicy contextExtensions: listener=http

# Allow: prefix match /public/*
assert_http "HTTP: GET /public/hello allow" "http://$IP:8080/public/hello" "200"
assert_http "HTTP: GET /public/nested/path allow" "http://$IP:8080/public/nested/path" "200"

# Allow: exact match /health
assert_http "HTTP: GET /health allow" "http://$IP:8080/health" "200"

# Allow: prefix match /api/*
assert_http "HTTP: GET /api/data allow" "http://$IP:8080/api/data" "200"
assert_http "HTTP: GET /api/v1/users allow" "http://$IP:8080/api/v1/users" "200"

# Allow: prefix match /admin/*
assert_http "HTTP: GET /admin/settings allow" "http://$IP:8080/admin/settings" "200"

# Deny: root path not in cap routes
assert_http "HTTP: GET / deny" "http://$IP:8080/" "403"

# Deny: paths not matching any cap route
assert_http "HTTP: GET /secret/data deny" "http://$IP:8080/secret/data" "403"
assert_http "HTTP: GET /internal/config deny" "http://$IP:8080/internal/config" "403"
assert_http "HTTP: GET /login deny" "http://$IP:8080/login" "403"
assert_http "HTTP: GET /dashboard deny" "http://$IP:8080/dashboard" "403"

# Deny: exact match boundary — /health with trailing slash is not /health
assert_http "HTTP: GET /health/ deny (exact match)" "http://$IP:8080/health/" "403"

# Deny: similar prefix but no match — /apiary is not /api/*
assert_http "HTTP: GET /apiary deny (not /api/*)" "http://$IP:8080/apiary" "403"

# Identity headers
BODY=$(curl -sf --max-time 10 "http://$IP:8080/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"]' 2>/dev/null || true)

# Tagged nodes (tag:kind) have no user login — check for tags or user
if [ -n "$USER_HDR" ] && [ "$USER_HDR" != "null" ]; then
    test_pass "HTTP: x-tailscale identity (user)"
elif [ -n "$TAGS_HDR" ] && [ "$TAGS_HDR" != "null" ] && [ "$TAGS_HDR" != "" ]; then
    test_pass "HTTP: x-tailscale identity (tagged node)"
else
    test_fail "HTTP: x-tailscale identity" "no user or tags found"
fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-node present"; else test_fail "HTTP: x-tailscale-node present" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-ip present"; else test_fail "HTTP: x-tailscale-ip present" "empty"; fi

# =====================================================
# TCPRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  TCPRoute TESTS"
echo "========================================"

# Cap rule: {"listeners": ["tcp", "udp", "tls"]} — no routes = L4 access only.
# HasAccess(listener="tcp", sni="", id) matches because "tcp" is in listeners.
# Retry the first TCP connection — identity resolution on the first connection
# can race with ncat's short write-then-close lifecycle.
TCP_OK=false
for i in 1 2 3; do
    TCP_RESP=$(echo "hello" | $NC_CMD -w 5 "$IP" 8090 2>/dev/null || true)
    if echo "$TCP_RESP" | grep -q "echo: hello"; then
        TCP_OK=true
        break
    fi
    sleep 1
done
if [ "$TCP_OK" = "true" ]; then
    test_pass "TCP: echo allow (cap grants L4 access)"
else
    test_fail "TCP: echo allow (cap grants L4 access)" "got '$TCP_RESP'"
fi

TCP_RESP2=$(echo "world" | $NC_CMD -w 5 "$IP" 8090 2>/dev/null || true)
if echo "$TCP_RESP2" | grep -q "echo: world"; then
    test_pass "TCP: second connection allow"
else
    test_fail "TCP: second connection allow" "got '$TCP_RESP2'"
fi

# =====================================================
# UDPRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  UDPRoute TESTS"
echo "========================================"

# Cap rule: {"listeners": ["tcp", "udp", "tls"]} — "udp" in listeners = L4 access.
# Keep stdin open with sleep so ncat waits for the response before exiting.
UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 8053 2>/dev/null || true)
if echo "$UDP_RESP" | grep -q "echo: hello"; then
    test_pass "UDP: echo allow (cap grants L4 access)"
else
    # Try alternate approach with socat if available
    if command -v socat &>/dev/null; then
        UDP_RESP2=$(echo -n "hello" | socat -T5 - UDP:"$IP":8053 2>/dev/null || true)
    else
        UDP_RESP2=$(bash -c "exec 3<>/dev/udp/$IP/8053; echo -n 'hello' >&3; read -t 5 resp <&3; echo \"\$resp\"" 2>/dev/null || true)
    fi
    if echo "$UDP_RESP2" | grep -q "echo: hello"; then
        test_pass "UDP: echo allow (cap grants L4 access)"
    else
        test_fail "UDP: echo allow (cap grants L4 access)" "ncat='$UDP_RESP', fallback='$UDP_RESP2'"
    fi
fi

# =====================================================
# TLSRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  TLSRoute TESTS"
echo "========================================"

# Cap rule: {"listeners": ["tcp", "udp", "tls"]} — "tls" in listeners = L4 passthrough access.
TLS_HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --insecure \
    --resolve "secure.tailvoy.test:8443:$IP" \
    --max-time 10 \
    "https://secure.tailvoy.test:8443/" 2>&1 || true)
if [ "$TLS_HTTP" = "200" ]; then
    test_pass "TLS: passthrough allow (cap grants L4 access)"
else
    test_fail "TLS: passthrough allow (cap grants L4 access)" "got $TLS_HTTP"
fi

# Verify backend cert (not Envoy-terminated) — check CN
TLS_SUBJECT=$(echo | openssl s_client -connect "$IP:8443" -servername secure.tailvoy.test 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null || true)
if echo "$TLS_SUBJECT" | grep -qi "secure.tailvoy.test"; then
    test_pass "TLS: backend cert CN matches"
else
    test_fail "TLS: backend cert CN matches" "got '$TLS_SUBJECT'"
fi

TLS_BODY=$(curl -sf --insecure \
    --resolve "secure.tailvoy.test:8443:$IP" \
    --max-time 10 \
    "https://secure.tailvoy.test:8443/" 2>&1 || true)
TLS_FLAG=$(echo "$TLS_BODY" | jq -r '.tls' 2>/dev/null || true)
if [ "$TLS_FLAG" = "true" ]; then
    test_pass "TLS: backend reports tls=true"
else
    test_fail "TLS: backend reports tls=true" "got '$TLS_FLAG'"
fi

# =====================================================
# GRPCRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  GRPCRoute TESTS"
echo "========================================"

# Cap rule: {"listeners": ["grpc"], "routes": ["/grpc.health.v1.Health/*"]}
# SecurityPolicy contextExtensions: listener=grpc

# grpc-health-probe doesn't use reflection, so it works with restricted cap routes.
if [ "$HAS_HEALTHPROBE" = "true" ]; then
    # Allow: /grpc.health.v1.Health/Check matches prefix /grpc.health.v1.Health/*
    GRPC_OUT=$(grpc-health-probe -addr "$IP:8081" -connect-timeout 10s -rpc-timeout 10s 2>&1; echo "EXIT:$?")
    GRPC_EXIT=$(echo "$GRPC_OUT" | grep -o 'EXIT:[0-9]*' | cut -d: -f2)
    if [ "$GRPC_EXIT" = "0" ]; then
        test_pass "gRPC: health check allow"
    else
        test_fail "gRPC: health check allow" "got '$GRPC_OUT'"
    fi

    # Allow: named service health check (same path prefix /grpc.health.v1.Health/*)
    GRPC_OUT2=$(grpc-health-probe -addr "$IP:8081" -service echo -connect-timeout 10s -rpc-timeout 10s 2>&1; echo "EXIT:$?")
    GRPC_EXIT2=$(echo "$GRPC_OUT2" | grep -o 'EXIT:[0-9]*' | cut -d: -f2)
    if [ "$GRPC_EXIT2" = "0" ]; then
        test_pass "gRPC: named service health allow"
    else
        test_fail "gRPC: named service health allow" "got '$GRPC_OUT2'"
    fi
else
    echo "  SKIP: grpc-health-probe not found, skipping gRPC health tests"
fi

# grpcurl uses reflection which is denied by cap routes — perfect for deny test.
if [ "$HAS_GRPCURL" = "true" ]; then
    # Deny: reflection uses /grpc.reflection.v1alpha.ServerReflection/* — not in cap routes
    GRPC_DENY=$(grpcurl -plaintext -max-time 10 "$IP:8081" list 2>&1 || true)
    if echo "$GRPC_DENY" | grep -qi "PermissionDenied\|code = 7\|PERMISSION_DENIED"; then
        test_pass "gRPC: reflection deny (not in cap routes)"
    else
        test_fail "gRPC: reflection deny (not in cap routes)" "got '$GRPC_DENY'"
    fi
else
    echo "  SKIP: grpcurl not found, skipping gRPC deny test"
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
    dump_logs
    echo ""
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
fi
