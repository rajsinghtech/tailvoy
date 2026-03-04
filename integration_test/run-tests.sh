#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
TESTS=()

BACKEND_PID=""
TAILVOY_PID=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "$TAILVOY_PID" ]; then
        kill "$TAILVOY_PID" 2>/dev/null || true
        wait "$TAILVOY_PID" 2>/dev/null || true
        echo "stopped tailvoy (pid $TAILVOY_PID)"
    fi
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
        echo "stopped backend (pid $BACKEND_PID)"
    fi
    # clean up built binaries
    rm -f "$SCRIPT_DIR/tailvoy" "$SCRIPT_DIR/backend_server"
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

# --- Build ---
echo "=== Building tailvoy ==="
(cd "$PROJECT_ROOT" && go build -o "$SCRIPT_DIR/tailvoy" ./cmd/tailvoy/)

echo "=== Building backend ==="
(cd "$SCRIPT_DIR/backend" && go build -o "$SCRIPT_DIR/backend_server" .)

# --- Start backend ---
echo "=== Starting backend ==="
"$SCRIPT_DIR/backend_server" &
BACKEND_PID=$!
sleep 1

if curl -sf http://127.0.0.1:8080/ > /dev/null 2>&1; then
    test_pass "backend is running"
else
    test_fail "backend is running" "curl to 127.0.0.1:8080 failed"
    exit 1
fi

# --- Start tailvoy ---
echo "=== Starting tailvoy ==="
export TS_AUTHKEY="${TS_AUTHKEY:-tskey-auth-k12q9xDxRo11CNTRL-mtTgZ7vLFP6muwWJE4dBP6da47xvdHVz}"
"$SCRIPT_DIR/tailvoy" --policy "$SCRIPT_DIR/test-policy.yaml" --log-level debug &
TAILVOY_PID=$!

# --- Wait for tailvoy to join the tailnet ---
echo "=== Waiting for tailvoy to join tailnet ==="
TAILVOY_IP=""
for i in $(seq 1 60); do
    TAILVOY_IP=$(tailscale status --json 2>/dev/null \
        | jq -r '.Peer[] | select(.HostName == "tailvoy-integration-test") | .TailscaleIPs[0]' 2>/dev/null || true)
    if [ -n "$TAILVOY_IP" ] && [ "$TAILVOY_IP" != "null" ]; then
        echo "tailvoy joined as $TAILVOY_IP"
        break
    fi
    sleep 2
done

if [ -z "$TAILVOY_IP" ] || [ "$TAILVOY_IP" = "null" ]; then
    echo "FATAL: tailvoy did not join the tailnet after 120s"
    exit 1
fi

# Give listeners a moment to bind
sleep 3

# --- L4 Tests ---
echo ""
echo "=== Running L4 Tests ==="

# Test: L4 allow on port 80 (any_tailscale)
echo "Test: L4 allow on port 80 (any_tailscale)"
HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 5 "http://$TAILVOY_IP:80/" 2>/dev/null || true)
if [ "$HTTP_STATUS" = "200" ]; then
    test_pass "L4 allow on port 80"
else
    test_fail "L4 allow on port 80" "expected HTTP 200, got '$HTTP_STATUS'"
fi

# Test: L4 deny on port 9999 (restricted tag)
echo "Test: L4 deny on port 9999 (restricted tag)"
if curl -sf -o /dev/null --max-time 3 "http://$TAILVOY_IP:9999/" 2>/dev/null; then
    test_fail "L4 deny on port 9999" "connection should have been denied"
else
    test_pass "L4 deny on port 9999"
fi

# Test: verify backend echo through allowed port
echo "Test: backend echo through tailvoy"
ECHO_PATH=$(curl -sf --max-time 5 "http://$TAILVOY_IP:80/public/hello" 2>/dev/null | jq -r '.path' 2>/dev/null || true)
if [ "$ECHO_PATH" = "/public/hello" ]; then
    test_pass "backend echo returns correct path"
else
    test_fail "backend echo returns correct path" "expected '/public/hello', got '$ECHO_PATH'"
fi

# --- Results ---
echo ""
echo "=== Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""
for t in "${TESTS[@]}"; do
    echo "  $t"
done

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
