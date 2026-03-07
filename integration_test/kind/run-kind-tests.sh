#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/../.."
CLUSTER_NAME="tailvoy-kind-test"
EG_VERSION="v1.7.0"
TAILVOY_HOSTNAME="tailvoy-kind-test-tailvoy"

# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ "${CI:-}" = "true" ]; then
        echo "CI detected, skipping kind cluster cleanup (workflow handles it)"
        return
    fi
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

dump_logs() {
    echo ""
    echo "=== Tailvoy (EG Data Plane) Pod Logs ==="
    kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg --tail=100 2>/dev/null || true
    echo ""
    echo "=== EG Controller Logs ==="
    kubectl logs -n envoy-gateway-system -l control-plane=envoy-gateway --tail=50 2>/dev/null || true
}

# --- Prerequisites ---
echo "=== Checking prerequisites ==="
for cmd in kind kubectl helm docker jq curl tailscale; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: $cmd not found"; exit 1
    fi
done

NC_CMD=""
if command -v ncat &>/dev/null; then NC_CMD="ncat"
elif command -v nc &>/dev/null; then NC_CMD="nc"
else echo "FATAL: ncat or nc not found"; exit 1
fi

HAS_GRPCURL=false; command -v grpcurl &>/dev/null && HAS_GRPCURL=true
HAS_HEALTHPROBE=false; command -v grpc-health-probe &>/dev/null && HAS_HEALTHPROBE=true
echo "Prerequisites OK (nc=$NC_CMD, grpcurl=$HAS_GRPCURL, grpc-health-probe=$HAS_HEALTHPROBE)"

# --- Load OAuth credentials ---
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
    elif [ -f "$SCRIPT_DIR/../.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"; exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then echo "FATAL: TS_CLIENT_ID is empty"; exit 1; fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then echo "FATAL: TS_CLIENT_SECRET is empty"; exit 1; fi

# --- Create kind cluster ---
echo "=== Creating kind cluster ==="
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml" --wait 60s

# --- Build and load images ---
echo "=== Building images ==="
docker build -t tailvoy:test -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT" 2>&1 | tail -5
docker build -t tailvoy-backend:test "$REPO_ROOT/integration_test/backend" 2>&1 | tail -5
docker build -t tailvoy-tcp-echo:test "$REPO_ROOT/integration_test/backend/tcp-echo" 2>&1 | tail -5
docker build -t tailvoy-udp-echo:test "$REPO_ROOT/integration_test/backend/udp-echo" 2>&1 | tail -5
docker build -t tailvoy-tls-backend:test "$REPO_ROOT/integration_test/backend/tls-echo" 2>&1 | tail -5
docker build -t tailvoy-grpc-echo:test "$REPO_ROOT/integration_test/backend/grpc-echo" 2>&1 | tail -5

echo "=== Loading images into kind ==="
for img in tailvoy:test tailvoy-backend:test tailvoy-tcp-echo:test tailvoy-udp-echo:test tailvoy-tls-backend:test tailvoy-grpc-echo:test; do
    kind load docker-image "$img" --name "$CLUSTER_NAME"
done

# --- Install Envoy Gateway ---
echo "=== Installing Envoy Gateway $EG_VERSION ==="
helm install eg oci://docker.io/envoyproxy/gateway-helm \
    --version "$EG_VERSION" \
    -n envoy-gateway-system --create-namespace \
    --wait --timeout 120s 2>&1 | tail -5

kubectl wait --namespace envoy-gateway-system \
    deployment/envoy-gateway \
    --for=condition=available --timeout=120s

# --- Deploy manifests ---
echo "=== Creating OAuth secret ==="
kubectl create secret generic tailvoy-oauth \
    -n envoy-gateway-system \
    --from-literal=TS_CLIENT_ID="$TS_CLIENT_ID" \
    --from-literal=TS_CLIENT_SECRET="$TS_CLIENT_SECRET"

echo "=== Deploying manifests ==="
kubectl apply -f "$SCRIPT_DIR/manifests/tailvoy-config.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/envoy-proxy.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/gateway.yaml"

echo "Waiting for Gateway to be accepted..."
for i in $(seq 1 60); do
    STATUS=$(kubectl get gateway eg -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)
    if [ "$STATUS" = "True" ]; then echo "Gateway accepted"; break; fi
    if [ "$i" -eq 60 ]; then
        echo "FATAL: Gateway not accepted after 120s"
        kubectl get gateway eg -o yaml 2>/dev/null || true
        exit 1
    fi
    sleep 2
done

kubectl apply -f "$SCRIPT_DIR/manifests/backend.yaml"
kubectl wait deployment/backend --for=condition=available --timeout=60s
kubectl wait deployment/tcp-echo --for=condition=available --timeout=60s
kubectl wait deployment/udp-echo --for=condition=available --timeout=60s
kubectl wait deployment/tls-backend --for=condition=available --timeout=60s
kubectl wait deployment/grpc-echo --for=condition=available --timeout=60s

kubectl apply -f "$SCRIPT_DIR/manifests/routes.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/security-policy.yaml"

# --- Wait for data plane ---
echo "Waiting for data plane pod..."
for i in $(seq 1 60); do
    READY=$(kubectl get pods -n envoy-gateway-system \
        -l "gateway.envoyproxy.io/owning-gateway-name=eg" \
        -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
    if [ "$READY" = "True" ]; then echo "Data plane ready"; break; fi
    if [ "$i" -eq 60 ]; then
        echo "FATAL: Data plane pod not ready after 120s"
        kubectl get pods -n envoy-gateway-system -o wide 2>/dev/null || true
        dump_logs; exit 1
    fi
    sleep 2
done

# --- Wait for tailnet join ---
echo "=== Waiting for tailnet join ==="
NODE_IP=""
for i in $(seq 1 90); do
    NODE_IP=$(tailscale status --json 2>/dev/null \
        | jq -r ".Peer[] | select(.HostName == \"$TAILVOY_HOSTNAME\" and .Online == true) | .TailscaleIPs[0]" 2>/dev/null || true)
    if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
        echo "$TAILVOY_HOSTNAME joined as $NODE_IP"
        break
    fi
    sleep 2
done
if [ -z "$NODE_IP" ] || [ "$NODE_IP" = "null" ]; then
    echo "FATAL: tailvoy did not join tailnet"
    dump_logs; exit 1
fi

# --- Resolve VIP services ---
DNS_SUFFIX=$(get_dns_suffix)
echo "MagicDNS suffix: $DNS_SUFFIX"

SVC_HTTP="kind-http.$DNS_SUFFIX"
SVC_TCP="kind-tcp.$DNS_SUFFIX"
SVC_GRPC="kind-grpc.$DNS_SUFFIX"
SVC_TLS="kind-tls.$DNS_SUFFIX"
IP="$SVC_HTTP"

wait_dns "$SVC_HTTP" 60
dump_peers "tailvoy-kind"
wait_http "http://$SVC_HTTP:8080/health" 60 || { dump_logs; exit 1; }

# Discovery mode needs time to poll Envoy admin and reconcile listeners
sleep 5

# Smoke test — verify discovery mode found the Envoy listeners
echo "=== Smoke test ==="
SMOKE_OK=false
for i in $(seq 1 30); do
    SMOKE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:8080/health" 2>&1 || true)
    if [ "$SMOKE" = "200" ]; then SMOKE_OK=true; break; fi
    echo "  smoke attempt $i: got $SMOKE"
    sleep 2
done
if [ "$SMOKE_OK" != "true" ]; then
    echo "FATAL: Smoke test failed (GET /health returned $SMOKE)"
    dump_logs; exit 1
fi
echo "Smoke test passed"

# =====================================================
section "HTTPRoute"
# =====================================================

assert_http "HTTP: /public/hello allow" "http://$IP:8080/public/hello" "200"
assert_http "HTTP: /public/nested/path allow" "http://$IP:8080/public/nested/path" "200"
assert_http "HTTP: /health allow" "http://$IP:8080/health" "200"
assert_http "HTTP: /api/data deny (hostname-restricted)" "http://$IP:8080/api/data" "403"
assert_http "HTTP: /api/v1/users deny (hostname-restricted)" "http://$IP:8080/api/v1/users" "403"
assert_http "HTTP: /admin/settings deny" "http://$IP:8080/admin/settings" "403"
assert_http "HTTP: / deny" "http://$IP:8080/" "403"
assert_http "HTTP: /secret/data deny" "http://$IP:8080/secret/data" "403"
assert_http "HTTP: /internal/config deny" "http://$IP:8080/internal/config" "403"
assert_http "HTTP: /login deny" "http://$IP:8080/login" "403"
assert_http "HTTP: /dashboard deny" "http://$IP:8080/dashboard" "403"
assert_http "HTTP: /health/ deny (exact)" "http://$IP:8080/health/" "403"
assert_http "HTTP: /apiary deny (not /api/*)" "http://$IP:8080/apiary" "403"

# Identity headers
BODY=$(curl -sf --max-time 10 "http://$IP:8080/public/headers" 2>&1 || true)
USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"]' 2>/dev/null || true)

if [ -n "$USER_HDR" ] && [ "$USER_HDR" != "null" ]; then
    test_pass "HTTP: x-tailscale identity (user)"
elif [ -n "$TAGS_HDR" ] && [ "$TAGS_HDR" != "null" ] && [ "$TAGS_HDR" != "" ]; then
    test_pass "HTTP: x-tailscale identity (tagged node)"
else
    test_fail "HTTP: x-tailscale identity" "no user or tags found"
fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-node"; else test_fail "HTTP: x-tailscale-node" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "HTTP: x-tailscale-ip"; else test_fail "HTTP: x-tailscale-ip" "empty"; fi

# =====================================================
section "HOSTNAME DIMENSION"
# =====================================================

assert_http "Hostname: /api/data Host:public.tailvoy.test allow" "http://$IP:8080/api/data" "200" -H "Host: public.tailvoy.test"
assert_http "Hostname: /health Host:public.tailvoy.test allow" "http://$IP:8080/health" "200" -H "Host: public.tailvoy.test"
assert_http "Hostname: /api/data Host:admin.tailvoy.test deny" "http://$IP:8080/api/data" "403" -H "Host: admin.tailvoy.test"
assert_http "Hostname: /admin/x Host:public.tailvoy.test deny" "http://$IP:8080/admin/x" "403" -H "Host: public.tailvoy.test"
assert_http "Hostname: /public/hello Host:admin.tailvoy.test allow" "http://$IP:8080/public/hello" "200" -H "Host: admin.tailvoy.test"

# =====================================================
section "TCPRoute"
# =====================================================

assert_tcp_echo "TCP: echo allow" "$SVC_TCP" 8090 "hello" 5
assert_tcp_echo "TCP: second connection allow" "$SVC_TCP" 8090 "world" 3

# =====================================================
section "UDPRoute"
# =====================================================

# Discovery mode skips UDP — no listener created. Verify no response.
UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -4 -u -w 5 "$IP" 8053 2>/dev/null || true)
if echo "$UDP_RESP" | grep -q "echo: hello"; then
    test_fail "UDP: no listener in discovery mode" "got unexpected response '$UDP_RESP'"
else
    test_pass "UDP: no listener in discovery mode"
fi

# =====================================================
section "TLSRoute"
# =====================================================

TLS_HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --insecure \
    --connect-to "secure.tailvoy.test:8443:$SVC_TLS:8443" \
    --max-time 10 \
    "https://secure.tailvoy.test:8443/" 2>&1 || true)
if [ "$TLS_HTTP" = "200" ]; then
    test_pass "TLS: passthrough allow"
else
    test_fail "TLS: passthrough allow" "got $TLS_HTTP"
fi

TLS_VIP_IP=$(dig +short "$SVC_TLS" 2>/dev/null | head -1 || true)
TLS_SUBJECT=$(echo | openssl s_client -connect "${TLS_VIP_IP:-$SVC_TLS}:8443" -servername secure.tailvoy.test 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null || true)
if echo "$TLS_SUBJECT" | grep -qi "secure.tailvoy.test"; then
    test_pass "TLS: backend cert CN matches"
else
    test_fail "TLS: backend cert CN matches" "got '$TLS_SUBJECT'"
fi

TLS_BODY=$(curl -sf --insecure \
    --connect-to "secure.tailvoy.test:8443:$SVC_TLS:8443" \
    --max-time 10 \
    "https://secure.tailvoy.test:8443/" 2>&1 || true)
TLS_FLAG=$(echo "$TLS_BODY" | jq -r '.tls' 2>/dev/null || true)
if [ "$TLS_FLAG" = "true" ]; then
    test_pass "TLS: backend reports tls=true"
else
    test_fail "TLS: backend reports tls=true" "got '$TLS_FLAG'"
fi

# =====================================================
section "GRPCRoute"
# =====================================================

if [ "$HAS_HEALTHPROBE" = "true" ]; then
    GRPC_OUT=$(grpc-health-probe -addr "$SVC_GRPC:8081" -connect-timeout 10s -rpc-timeout 10s 2>&1; echo "EXIT:$?")
    GRPC_EXIT=$(echo "$GRPC_OUT" | grep -o 'EXIT:[0-9]*' | cut -d: -f2)
    if [ "$GRPC_EXIT" = "0" ]; then test_pass "gRPC: health check allow"
    else test_fail "gRPC: health check allow" "got '$GRPC_OUT'"; fi

    GRPC_OUT2=$(grpc-health-probe -addr "$SVC_GRPC:8081" -service echo -connect-timeout 10s -rpc-timeout 10s 2>&1; echo "EXIT:$?")
    GRPC_EXIT2=$(echo "$GRPC_OUT2" | grep -o 'EXIT:[0-9]*' | cut -d: -f2)
    if [ "$GRPC_EXIT2" = "0" ]; then test_pass "gRPC: named service health allow"
    else test_fail "gRPC: named service health allow" "got '$GRPC_OUT2'"; fi
else
    echo "  SKIP: grpc-health-probe not found"
fi

if [ "$HAS_GRPCURL" = "true" ]; then
    GRPC_DENY=$(grpcurl -plaintext -max-time 10 "$SVC_GRPC:8081" list 2>&1 || true)
    if echo "$GRPC_DENY" | grep -qi "PermissionDenied\|code = 7\|PERMISSION_DENIED"; then
        test_pass "gRPC: reflection deny"
    else
        test_fail "gRPC: reflection deny" "got '$GRPC_DENY'"
    fi
else
    echo "  SKIP: grpcurl not found"
fi

# =====================================================
if ! print_results; then
    dump_logs
    exit 1
fi
