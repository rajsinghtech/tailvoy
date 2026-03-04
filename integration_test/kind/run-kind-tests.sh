#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../.."
CLUSTER_NAME="tailvoy-kind-test"
EG_VERSION="v1.7.0"
TAILVOY_HOSTNAME="tailvoy-kind-test"

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
# Check for grpcurl (needed for gRPC tests)
HAS_GRPCURL=false
if command -v grpcurl &>/dev/null; then
    HAS_GRPCURL=true
fi
echo "All prerequisites found (using $NC_CMD for TCP/UDP, grpcurl=$HAS_GRPCURL)"

# --- Load TS_AUTHKEY ---
if [ -z "${TS_AUTHKEY:-}" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
    elif [ -f "$SCRIPT_DIR/../.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
    else
        echo "FATAL: TS_AUTHKEY not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_AUTHKEY:-}" ]; then
    echo "FATAL: TS_AUTHKEY is empty"
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

# --- Create TS_AUTHKEY secret ---
echo "=== Creating TS_AUTHKEY secret ==="
kubectl create secret generic tailvoy-authkey \
    -n envoy-gateway-system \
    --from-literal=TS_AUTHKEY="$TS_AUTHKEY"

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

# Smoke test
echo "=== Smoke test ==="
SMOKE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 15 "http://$IP:80/" 2>&1 || true)
if [ "$SMOKE" != "200" ]; then
    echo "FATAL: Smoke test failed (GET / returned $SMOKE)"
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

assert_http "HTTP: GET / allow" "http://$IP:80/" "200"
assert_http "HTTP: GET /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "HTTP: GET /health allow" "http://$IP:80/health" "200"
assert_http "HTTP: GET /admin/settings allow" "http://$IP:80/admin/settings" "200"
assert_http "HTTP: GET /any/path allow" "http://$IP:80/any/path" "200"

# Identity headers
BODY=$(curl -sf --max-time 10 "http://$IP:80/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)

if [ -n "$USER_HDR" ] && [ "$USER_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-user present"; else test_fail "HTTP: x-tailscale-user present" "got '$USER_HDR'"; fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-node present"; else test_fail "HTTP: x-tailscale-node present" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-ip present"; else test_fail "HTTP: x-tailscale-ip present" "empty"; fi

# =====================================================
# TCPRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  TCPRoute TESTS"
echo "========================================"

TCP_RESP=$(echo "hello" | $NC_CMD -w 5 "$IP" 5432 2>/dev/null || true)
if echo "$TCP_RESP" | grep -q "echo: hello"; then
    test_pass "TCP: echo hello"
else
    test_fail "TCP: echo hello" "got '$TCP_RESP'"
fi

TCP_RESP2=$(echo "world" | $NC_CMD -w 5 "$IP" 5432 2>/dev/null || true)
if echo "$TCP_RESP2" | grep -q "echo: world"; then
    test_pass "TCP: echo world (second connection)"
else
    test_fail "TCP: echo world (second connection)" "got '$TCP_RESP2'"
fi

# =====================================================
# UDPRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  UDPRoute TESTS"
echo "========================================"

# UDP test: send a packet and read response with timeout.
# Keep stdin open with sleep so ncat waits for the response before exiting.
UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 9053 2>/dev/null || true)
if echo "$UDP_RESP" | grep -q "echo: hello"; then
    test_pass "UDP: echo hello"
else
    # Try alternate approach with socat if available
    if command -v socat &>/dev/null; then
        UDP_RESP2=$(echo -n "hello" | socat -T5 - UDP:"$IP":9053 2>/dev/null || true)
    else
        UDP_RESP2=$(bash -c "exec 3<>/dev/udp/$IP/9053; echo -n 'hello' >&3; read -t 5 resp <&3; echo \"\$resp\"" 2>/dev/null || true)
    fi
    if echo "$UDP_RESP2" | grep -q "echo: hello"; then
        test_pass "UDP: echo hello"
    else
        test_fail "UDP: echo hello" "ncat='$UDP_RESP', fallback='$UDP_RESP2'"
    fi
fi

# =====================================================
# TLSRoute TESTS
# =====================================================
echo ""
echo "========================================"
echo "  TLSRoute TESTS"
echo "========================================"

TLS_HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --insecure \
    --resolve "secure.tailvoy.test:443:$IP" \
    --max-time 10 \
    "https://secure.tailvoy.test:443/" 2>&1 || true)
if [ "$TLS_HTTP" = "200" ]; then
    test_pass "TLS: GET / via passthrough"
else
    test_fail "TLS: GET / via passthrough" "got $TLS_HTTP"
fi

# Verify backend cert (not Envoy-terminated) — check CN
TLS_SUBJECT=$(echo | openssl s_client -connect "$IP:443" -servername secure.tailvoy.test 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null || true)
if echo "$TLS_SUBJECT" | grep -qi "secure.tailvoy.test"; then
    test_pass "TLS: backend cert CN matches"
else
    test_fail "TLS: backend cert CN matches" "got '$TLS_SUBJECT'"
fi

TLS_BODY=$(curl -sf --insecure \
    --resolve "secure.tailvoy.test:443:$IP" \
    --max-time 10 \
    "https://secure.tailvoy.test:443/" 2>&1 || true)
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

if [ "$HAS_GRPCURL" = "true" ]; then
    # Health check — should succeed (L7 rule allows /grpc.health.v1.Health/*)
    GRPC_OUT=$(grpcurl -plaintext -max-time 10 "$IP:50051" grpc.health.v1.Health/Check 2>&1 || true)
    if echo "$GRPC_OUT" | grep -q "SERVING"; then
        test_pass "gRPC: health check SERVING"
    else
        test_fail "gRPC: health check SERVING" "got '$GRPC_OUT'"
    fi

    # Named service health check
    GRPC_OUT2=$(grpcurl -plaintext -max-time 10 -d '{"service":"echo"}' "$IP:50051" grpc.health.v1.Health/Check 2>&1 || true)
    if echo "$GRPC_OUT2" | grep -q "SERVING"; then
        test_pass "gRPC: named service health check"
    else
        test_fail "gRPC: named service health check" "got '$GRPC_OUT2'"
    fi

    # Reflection — list services
    GRPC_LIST=$(grpcurl -plaintext -max-time 10 "$IP:50051" list 2>&1 || true)
    if echo "$GRPC_LIST" | grep -q "grpc.health.v1.Health"; then
        test_pass "gRPC: reflection lists health service"
    else
        test_fail "gRPC: reflection lists health service" "got '$GRPC_LIST'"
    fi
else
    echo "  SKIP: grpcurl not found, skipping gRPC tests"
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
