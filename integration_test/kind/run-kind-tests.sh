#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../.."
CLUSTER_NAME="tailvoy-kind-test"
EG_VERSION="v1.3.3"
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
    echo "=== Tailvoy Pod Logs ==="
    kubectl logs -l app=tailvoy --tail=80 2>/dev/null || true
    echo ""
    echo "=== EG Data Plane Logs ==="
    kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg --tail=30 2>/dev/null || true
}

# --- Check prerequisites ---
echo "=== Checking prerequisites ==="
for cmd in kind kubectl helm docker jq curl tailscale; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: $cmd not found"
        exit 1
    fi
done
echo "All prerequisites found"

# --- Load TS_AUTHKEY ---
if [ -z "${TS_AUTHKEY:-}" ]; then
    if [ -f "$SCRIPT_DIR/../.env" ]; then
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

echo "=== Building backend image ==="
docker build -t tailvoy-backend:test "$REPO_ROOT/integration_test/backend" 2>&1 | tail -5

# --- Load images into kind ---
echo "=== Loading images into kind ==="
kind load docker-image tailvoy:test --name "$CLUSTER_NAME"
kind load docker-image tailvoy-backend:test --name "$CLUSTER_NAME"

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

# --- Apply backend ---
echo "=== Deploying backend ==="
kubectl apply -f "$SCRIPT_DIR/manifests/backend.yaml"
kubectl wait deployment/backend --for=condition=available --timeout=60s

# --- Apply gateway resources ---
echo "=== Deploying Gateway ==="
kubectl apply -f "$SCRIPT_DIR/manifests/gateway.yaml"

echo "Waiting for Gateway to be programmed..."
for i in $(seq 1 60); do
    STATUS=$(kubectl get gateway eg -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null || true)
    if [ "$STATUS" = "True" ]; then
        echo "Gateway is programmed"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "FATAL: Gateway not programmed after 120s"
        kubectl get gateway eg -o yaml 2>/dev/null || true
        exit 1
    fi
    sleep 2
done

# --- Discover EG data plane service ---
echo "=== Discovering EG data plane service ==="
EG_SVC_NAME=""
EG_SVC_NS=""
for i in $(seq 1 30); do
    EG_SVC_NAME=$(kubectl get svc -A \
        -l "gateway.envoyproxy.io/owning-gateway-name=eg,gateway.envoyproxy.io/owning-gateway-namespace=default" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    EG_SVC_NS=$(kubectl get svc -A \
        -l "gateway.envoyproxy.io/owning-gateway-name=eg,gateway.envoyproxy.io/owning-gateway-namespace=default" \
        -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
    if [ -n "$EG_SVC_NAME" ] && [ -n "$EG_SVC_NS" ]; then
        break
    fi
    sleep 2
done
if [ -z "$EG_SVC_NAME" ] || [ -z "$EG_SVC_NS" ]; then
    echo "FATAL: Could not discover EG data plane service"
    kubectl get svc -A 2>/dev/null || true
    exit 1
fi
EG_SVC_DNS="${EG_SVC_NAME}.${EG_SVC_NS}.svc.cluster.local"
echo "EG data plane: $EG_SVC_DNS"

# --- Apply routes ---
echo "=== Deploying HTTPRoute ==="
kubectl apply -f "$SCRIPT_DIR/manifests/routes.yaml"

# --- Create TS_AUTHKEY secret and deploy tailvoy ---
echo "=== Deploying tailvoy ==="
kubectl create secret generic tailvoy-authkey --from-literal=TS_AUTHKEY="$TS_AUTHKEY"
sed "s/PLACEHOLDER_EG_SVC/${EG_SVC_DNS}/g" "$SCRIPT_DIR/manifests/tailvoy.yaml" | kubectl apply -f -

# --- Apply security policy ---
echo "=== Deploying SecurityPolicy ==="
kubectl apply -f "$SCRIPT_DIR/manifests/security-policy.yaml"

# --- Wait for tailvoy pod ---
echo "Waiting for tailvoy pod to be ready..."
kubectl wait deployment/tailvoy --for=condition=available --timeout=120s || {
    echo "FATAL: tailvoy deployment not available"
    dump_logs
    exit 1
}

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

# Smoke test — make sure the basic path works before running full suite
echo "=== Smoke test ==="
SMOKE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 15 "http://$IP:80/" 2>&1 || true)
if [ "$SMOKE" != "200" ]; then
    echo "FATAL: Smoke test failed (GET / returned $SMOKE)"
    dump_logs
    exit 1
fi
echo "Smoke test passed"

# =====================================================
# PATH-BASED TESTS
# =====================================================
echo ""
echo "========================================"
echo "  PATH-BASED TESTS"
echo "========================================"

assert_http "Path: / allow" "http://$IP:80/" "200"
assert_http "Path: /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "Path: /public/nested/deep allow" "http://$IP:80/public/nested/deep" "200"
assert_http "Path: /health allow" "http://$IP:80/health" "200"
assert_http "Path: /admin/settings deny" "http://$IP:80/admin/settings" "403"
assert_http "Path: /admin/users deny" "http://$IP:80/admin/users" "403"
assert_http "Path: /admin/ deny" "http://$IP:80/admin/" "403"
assert_http "Path: /unknown deny (default)" "http://$IP:80/unknown" "403"
assert_http "Path: /foo/bar deny (default)" "http://$IP:80/foo/bar" "403"

# =====================================================
# HOST-BASED TESTS
# =====================================================
echo ""
echo "========================================"
echo "  HOST-BASED TESTS"
echo "========================================"

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -H "Host: admin.tailvoy.test" --max-time 10 "http://$IP:80/host-test/page" 2>&1 || true)
if [ "$HTTP" = "200" ]; then test_pass "Host: /host-test with matching host"; else test_fail "Host: /host-test with matching host" "got $HTTP"; fi

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -H "Host: other.tailvoy.test" --max-time 10 "http://$IP:80/host-test/page" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "Host: /host-test with wrong host deny"; else test_fail "Host: /host-test with wrong host deny" "got $HTTP"; fi

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:80/host-test/page" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "Host: /host-test with no custom host deny"; else test_fail "Host: /host-test with no custom host deny" "got $HTTP"; fi

# =====================================================
# METHOD-BASED TESTS
# =====================================================
echo ""
echo "========================================"
echo "  METHOD-BASED TESTS"
echo "========================================"

assert_http "Method: GET /readonly/data allow" "http://$IP:80/readonly/data" "200"

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X HEAD --max-time 10 "http://$IP:80/readonly/data" 2>&1 || true)
if [ "$HTTP" = "200" ] || [ "$HTTP" = "204" ]; then test_pass "Method: HEAD /readonly/data allow"; else test_fail "Method: HEAD /readonly/data allow" "got $HTTP"; fi

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X POST --max-time 10 "http://$IP:80/readonly/data" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "Method: POST /readonly/data deny"; else test_fail "Method: POST /readonly/data deny" "got $HTTP"; fi

HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X DELETE --max-time 10 "http://$IP:80/readonly/data" 2>&1 || true)
if [ "$HTTP" = "403" ]; then test_pass "Method: DELETE /readonly/data deny"; else test_fail "Method: DELETE /readonly/data deny" "got $HTTP"; fi

# =====================================================
# IDENTITY HEADER TESTS
# =====================================================
echo ""
echo "========================================"
echo "  IDENTITY HEADER TESTS"
echo "========================================"

BODY=$(curl -sf --max-time 10 "http://$IP:80/public/headers" 2>&1 || true)

USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"]' 2>/dev/null || true)

if [ "$USER_HDR" = "rajsinghtech@github" ]; then test_pass "Header: x-tailscale-user"; else test_fail "Header: x-tailscale-user" "got '$USER_HDR'"; fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "Header: x-tailscale-node"; else test_fail "Header: x-tailscale-node" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "Header: x-tailscale-ip"; else test_fail "Header: x-tailscale-ip" "empty"; fi
if [ "$TAGS_HDR" != "null" ]; then test_pass "Header: x-tailscale-tags present"; else test_fail "Header: x-tailscale-tags" "missing"; fi

# =====================================================
# EDGE CASE TESTS
# =====================================================
echo ""
echo "========================================"
echo "  EDGE CASE TESTS"
echo "========================================"

# Multiple HTTP methods on /public/* (all should allow)
for method in GET POST PUT DELETE HEAD; do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X "$method" --max-time 10 "http://$IP:80/public/method-test" 2>&1 || true)
    if [ "$HTTP" = "200" ] || [ "$HTTP" = "204" ]; then
        test_pass "Edge: $method /public/method-test allow"
    else
        test_fail "Edge: $method /public/method-test allow" "got $HTTP"
    fi
done

# Concurrent allow+deny mix
echo "Test: concurrent mixed requests"
ALLOW_OK=0
DENY_OK=0
for i in $(seq 1 10); do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:80/public/$i" 2>&1 || true)
    if [ "$HTTP" = "200" ]; then ALLOW_OK=$((ALLOW_OK+1)); fi
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:80/admin/$i" 2>&1 || true)
    if [ "$HTTP" = "403" ]; then DENY_OK=$((DENY_OK+1)); fi
done
if [ "$ALLOW_OK" -eq 10 ] && [ "$DENY_OK" -eq 10 ]; then
    test_pass "Edge: 10 allow + 10 deny concurrent"
else
    test_fail "Edge: concurrent mixed" "allow=$ALLOW_OK/10, deny=$DENY_OK/10"
fi

# Verify echo body on allowed request
assert_body_field "Edge: echo path" "http://$IP:80/public/echo-test" "path" "/public/echo-test"

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
