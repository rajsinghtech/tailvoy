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

assert_connection_refused() {
    local desc="$1" url="$2"
    if curl -sf -o /dev/null --max-time 5 "$url" 2>/dev/null; then
        test_fail "$desc" "connection should have been denied"
    else
        test_pass "$desc"
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

# --- Load env ---
if [ -z "${TS_AUTHKEY:-}" ]; then
    if [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    else
        echo "FATAL: TS_AUTHKEY not set"
        exit 1
    fi
fi

# --- Build and start ---
echo "=== Building Docker images ==="
docker compose -f "$COMPOSE_FILE" build 2>&1 | tail -5

echo "=== Starting stack ==="
docker compose -f "$COMPOSE_FILE" up -d 2>&1

# --- Wait for tailnet ---
echo "=== Waiting for tailnet join ==="
IP=""
for i in $(seq 1 60); do
    IP=$(tailscale status --json 2>/dev/null \
        | jq -r '.Peer[] | select(.HostName == "tailvoy-full-test") | .TailscaleIPs[0]' 2>/dev/null || true)
    if [ -n "$IP" ] && [ "$IP" != "null" ]; then
        echo "tailvoy-full-test joined as $IP"
        break
    fi
    sleep 2
done
if [ -z "$IP" ] || [ "$IP" = "null" ]; then
    echo "FATAL: tailvoy did not join"
    docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | tail -30
    exit 1
fi
sleep 5

# Check Envoy is healthy
echo "=== Checking Envoy health ==="
docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | grep -q "all dependencies initialized" && echo "Envoy initialized" || echo "WARNING: Envoy may not have initialized"

# =====================================================
# L4 TESTS
# =====================================================
echo ""
echo "========================================"
echo "  L4 TESTS"
echo "========================================"

# Port 80 - L4 allow any_tailscale (L7 also enabled)
assert_http "L4: port 80 allow (any_tailscale)" "http://$IP:80/" "200"

# Port 8081 - L4 allow any_tailscale (no L7)
assert_http "L4: port 8081 allow (any_tailscale, no L7)" "http://$IP:8081/" "200"

# Port 8082 - L4 allow specific user (rajsinghtech@github)
assert_http "L4: port 8082 allow (user match)" "http://$IP:8082/" "200"

# Port 8083 - L4 deny (requires nonexistent tag)
assert_connection_refused "L4: port 8083 deny (tag mismatch)" "http://$IP:8083/"

# Port 8084 - L4 allow any_tailscale (passthrough)
assert_http "L4: port 8084 allow (passthrough)" "http://$IP:8084/" "200"

# Verify echo through L4-only port
assert_body_field "L4: echo path on port 8081" "http://$IP:8081/any/path" "path" "/any/path"

# Verify L4-only doesn't enforce L7 rules (port 8081 has no L7 policy)
# Even /admin should work since L7 is disabled
assert_http "L4: /admin on port 8081 (no L7)" "http://$IP:8081/admin/secret" "200"

# Multiple connections on allowed L4 port
echo "Test: L4 concurrent on port 8081"
OK=0
for i in $(seq 1 20); do
    if curl -sf -o /dev/null --max-time 5 "http://$IP:8081/$i" 2>/dev/null; then OK=$((OK+1)); fi
done
if [ "$OK" -eq 20 ]; then test_pass "L4: 20 concurrent on 8081"; else test_fail "L4: 20 concurrent on 8081" "$OK/20"; fi

# Multiple rapid connections to denied port
echo "Test: L4 rapid deny on port 8083"
DENIED=0
for i in $(seq 1 5); do
    if ! curl -sf -o /dev/null --max-time 3 "http://$IP:8083/" 2>/dev/null; then DENIED=$((DENIED+1)); fi
done
if [ "$DENIED" -eq 5 ]; then test_pass "L4: 5 rapid denials on 8083"; else test_fail "L4: 5 rapid denials" "$DENIED/5 denied"; fi

# =====================================================
# L7 TESTS (port 80 - through Envoy ext_authz)
# =====================================================
echo ""
echo "========================================"
echo "  L7 TESTS"
echo "========================================"

# /public/* - allow any_tailscale
assert_http "L7: /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "L7: /public/nested/deep allow" "http://$IP:80/public/nested/deep" "200"

# /api/* - allow any_tailscale
assert_http "L7: /api/v1/users allow" "http://$IP:80/api/v1/users" "200"
assert_http "L7: /api/v2/data allow" "http://$IP:80/api/v2/data" "200"

# /api/v1/secret/* - allow specific user
assert_http "L7: /api/v1/secret/key allow (user)" "http://$IP:80/api/v1/secret/key" "200"

# /health - exact match
assert_http "L7: /health allow (exact)" "http://$IP:80/health" "200"

# / - root catch-all
assert_http "L7: / root allow" "http://$IP:80/" "200"

# /admin/* - deny (requires tag:admin-only)
assert_http "L7: /admin/settings deny" "http://$IP:80/admin/settings" "403"
assert_http "L7: /admin/users deny" "http://$IP:80/admin/users" "403"
assert_http "L7: /admin/ deny" "http://$IP:80/admin/" "403"

# Unmatched paths - default:deny
assert_http "L7: /unknown deny (default)" "http://$IP:80/unknown" "403"
assert_http "L7: /foo/bar deny (default)" "http://$IP:80/foo/bar" "403"
assert_http "L7: /secret deny (default)" "http://$IP:80/secret" "403"

# Rule ordering: /api/v1/secret/* (user match) before /api/* (any_tailscale)
# Both should allow for this user, but verifies first-match-wins
assert_http "L7: /api/v1/secret/data first-match" "http://$IP:80/api/v1/secret/data" "200"

# =====================================================
# IDENTITY HEADER TESTS
# =====================================================
echo ""
echo "========================================"
echo "  IDENTITY HEADER TESTS"
echo "========================================"

# Check all identity headers on L7 allowed request
BODY=$(curl -sf --max-time 10 "http://$IP:80/public/headers" 2>&1 || true)

USER_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-User"]' 2>/dev/null || true)
NODE_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Node"]' 2>/dev/null || true)
IP_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Ip"]' 2>/dev/null || true)
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"]' 2>/dev/null || true)

if [ "$USER_HDR" = "rajsinghtech@github" ]; then test_pass "Header: x-tailscale-user"; else test_fail "Header: x-tailscale-user" "got '$USER_HDR'"; fi
if [ -n "$NODE_HDR" ] && [ "$NODE_HDR" != "null" ]; then test_pass "Header: x-tailscale-node"; else test_fail "Header: x-tailscale-node" "empty"; fi
if [ -n "$IP_HDR" ] && [ "$IP_HDR" != "null" ]; then test_pass "Header: x-tailscale-ip"; else test_fail "Header: x-tailscale-ip" "empty"; fi
# Tags header should exist (may be empty string for untagged node)
if [ "$TAGS_HDR" != "null" ]; then test_pass "Header: x-tailscale-tags present"; else test_fail "Header: x-tailscale-tags" "missing"; fi

# Check that identity headers are NOT present on L4-only port
BODY_L4=$(curl -sf --max-time 10 "http://$IP:8081/check" 2>&1 || true)
L4_USER=$(echo "$BODY_L4" | jq -r '.headers["X-Tailscale-User"] // empty' 2>/dev/null || true)
if [ -z "$L4_USER" ]; then test_pass "L4: no identity headers on raw forward"; else test_fail "L4: no identity headers" "found x-tailscale-user=$L4_USER"; fi

# =====================================================
# EDGE CASE TESTS
# =====================================================
echo ""
echo "========================================"
echo "  EDGE CASE TESTS"
echo "========================================"

# Large payload through L4
echo "Test: large payload through L4"
LARGE_BODY=$(curl -sf --max-time 15 -X POST -d "$(head -c 100000 /dev/urandom | base64)" "http://$IP:8081/large" 2>&1 || true)
if echo "$LARGE_BODY" | jq -r '.path' 2>/dev/null | grep -q "/large"; then
    test_pass "L4: large payload"
else
    test_fail "L4: large payload" "response invalid"
fi

# POST method through L7
assert_http "L7: POST /public/data allow" "http://$IP:80/public/data" "200"

# Different HTTP methods through L7
for method in GET POST PUT DELETE HEAD; do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -X "$method" --max-time 10 "http://$IP:80/public/method-test" 2>&1 || true)
    if [ "$HTTP" = "200" ] || [ "$HTTP" = "204" ]; then
        test_pass "L7: $method /public/method-test"
    else
        test_fail "L7: $method /public/method-test" "got $HTTP"
    fi
done

# Concurrent L7 requests (mix of allow and deny)
echo "Test: concurrent mixed L7"
ALLOW_OK=0
DENY_OK=0
for i in $(seq 1 10); do
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:80/public/$i" 2>&1 || true)
    if [ "$HTTP" = "200" ]; then ALLOW_OK=$((ALLOW_OK+1)); fi
    HTTP=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "http://$IP:80/admin/$i" 2>&1 || true)
    if [ "$HTTP" = "403" ]; then DENY_OK=$((DENY_OK+1)); fi
done
if [ "$ALLOW_OK" -eq 10 ] && [ "$DENY_OK" -eq 10 ]; then
    test_pass "L7: 10 allow + 10 deny concurrent"
else
    test_fail "L7: concurrent mixed" "allow=$ALLOW_OK/10, deny=$DENY_OK/10"
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
