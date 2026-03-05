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
    rm -f "$SCRIPT_DIR/tailvoy" "$SCRIPT_DIR/backend_server"
    rm -rf "$HOME/Library/Application Support/tsnet-tailvoy" 2>/dev/null || true
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
echo "=== Building ==="
(cd "$PROJECT_ROOT" && go build -o "$SCRIPT_DIR/tailvoy" ./cmd/tailvoy/)
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

# --- Start tailvoy (L4-only mode) ---
echo "=== Starting tailvoy ==="
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    elif [ -f "$PROJECT_ROOT/.env" ]; then
        export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then echo "FATAL: TS_CLIENT_ID is empty"; exit 1; fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then echo "FATAL: TS_CLIENT_SECRET is empty"; exit 1; fi
"$SCRIPT_DIR/tailvoy" --config "$SCRIPT_DIR/l4-test-policy.yaml" --log-level debug 2>&1 &
TAILVOY_PID=$!

# --- Wait for tailnet join ---
echo "=== Waiting for tailnet join ==="
for i in $(seq 1 60); do
    NODE_IP=$(tailscale status --json 2>/dev/null \
        | jq -r '.Peer[] | select(.HostName == "tailvoy-l4-test-tailvoy") | .TailscaleIPs[0]' 2>/dev/null || true)
    if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
        echo "tailvoy joined as $NODE_IP"
        break
    fi
    sleep 2
done
if [ -z "$NODE_IP" ] || [ "$NODE_IP" = "null" ]; then
    echo "FATAL: tailvoy did not join the tailnet"
    exit 1
fi

# --- Wait for VIP service ---
echo "=== Waiting for VIP service ==="
TAILVOY_IP=""
SVC_NAME="svc-tailvoy-l4-test"
for i in $(seq 1 30); do
    TAILVOY_IP=$(tailscale ip "$SVC_NAME" 2>/dev/null | head -1 || true)
    if [ -n "$TAILVOY_IP" ]; then
        echo "VIP service $SVC_NAME at $TAILVOY_IP"
        break
    fi
    sleep 2
done
if [ -z "$TAILVOY_IP" ]; then
    echo "FATAL: VIP service $SVC_NAME not found"
    tailscale status 2>/dev/null || true
    exit 1
fi
sleep 3

# --- L4 Tests ---
echo ""
echo "=== L4 Tests ==="

# L4 allow on port 80
echo "Test: L4 allow on port 80 (any_tailscale)"
HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$TAILVOY_IP:80/" 2>&1 || true)
if [ "$HTTP" = "200" ]; then test_pass "L4 allow port 80"; else test_fail "L4 allow port 80" "got $HTTP"; fi

# L4 deny on port 9999
echo "Test: L4 deny on port 9999 (restricted tag)"
if curl -sf -o /dev/null --max-time 5 "http://$TAILVOY_IP:9999/" 2>/dev/null; then
    test_fail "L4 deny port 9999" "should have been denied"
else
    test_pass "L4 deny port 9999"
fi

# Echo verification
echo "Test: backend echo through tailvoy"
ECHO_PATH=$(curl -sf --max-time 10 "http://$TAILVOY_IP:80/test/path" 2>&1 | jq -r '.path' 2>/dev/null || true)
if [ "$ECHO_PATH" = "/test/path" ]; then test_pass "echo path"; else test_fail "echo path" "got '$ECHO_PATH'"; fi

# Concurrent connections
echo "Test: concurrent connections"
OK=0
for i in $(seq 1 10); do
    if curl -sf -o /dev/null --max-time 5 "http://$TAILVOY_IP:80/$i" 2>/dev/null; then OK=$((OK+1)); fi
done
if [ "$OK" -eq 10 ]; then test_pass "10 concurrent"; else test_fail "10 concurrent" "$OK/10"; fi

# --- Results ---
echo ""
echo "=== Results ==="
echo "Passed: $PASS / $((PASS + FAIL))"
for t in "${TESTS[@]}"; do echo "  $t"; done
if [ "$FAIL" -gt 0 ]; then exit 1; fi
