#!/bin/bash
# Shared test helpers for integration tests.

PASS=0
FAIL=0
TESTS=()

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

section() {
    echo ""
    echo "========================================"
    echo "  $1"
    echo "========================================"
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

# TCP echo via bash /dev/tcp — avoids ncat pipe EOF race over VIP path.
tcp_echo() {
    local host="$1" port="$2" msg="$3"
    timeout 5 bash -c '
        exec 3<>/dev/tcp/'"$host"'/'"$port"'
        echo "'"$msg"'" >&3
        read -t 5 line <&3
        echo "$line"
        exec 3<&-
    ' 2>/dev/null || true
}

# Retry a TCP echo test. Usage: assert_tcp_echo desc host port msg [retries]
assert_tcp_echo() {
    local desc="$1" host="$2" port="$3" msg="$4" retries="${5:-5}"
    local ok=false resp
    for i in $(seq 1 "$retries"); do
        resp=$(tcp_echo "$host" "$port" "$msg")
        if echo "$resp" | grep -q "echo: $msg"; then
            ok=true
            break
        fi
        sleep 2
    done
    if [ "$ok" = "true" ]; then
        test_pass "$desc"
    else
        test_fail "$desc" "got '$resp'"
    fi
}

# Wait for a DNS name to resolve. Usage: wait_dns name [timeout_secs]
wait_dns() {
    local name="$1" timeout="${2:-60}"
    local ip=""
    for i in $(seq 1 "$timeout"); do
        ip=$(dig +short "$name" 2>/dev/null | head -1 || true)
        if [ -n "$ip" ]; then
            echo "$name resolved to $ip"
            return 0
        fi
        [ $((i % 5)) -eq 0 ] && echo "  waiting for DNS: $name (attempt $i)..."
        sleep 1
    done
    echo "FATAL: $name did not resolve after ${timeout}s"
    return 1
}

# Wait for an HTTP endpoint. Usage: wait_http url [timeout_secs]
wait_http() {
    local url="$1" timeout="${2:-45}"
    for i in $(seq 1 "$timeout"); do
        if curl -sf -o /dev/null --max-time 5 "$url" 2>/dev/null; then
            echo "Reachable on attempt $i: $url"
            return 0
        fi
        [ $((i % 5)) -eq 0 ] && echo "  waiting for HTTP: $url (attempt $i)..."
        sleep 1
    done
    echo "FATAL: $url unreachable after ${timeout}s"
    return 1
}

# Print test results and exit with appropriate code.
print_results() {
    section "RESULTS"
    echo "Passed: $PASS"
    echo "Failed: $FAIL"
    echo "Total:  $((PASS + FAIL))"
    echo ""
    for t in "${TESTS[@]}"; do echo "  $t"; done
    echo ""
    if [ "$FAIL" -gt 0 ]; then
        echo "SOME TESTS FAILED"
        return 1
    else
        echo "ALL TESTS PASSED"
    fi
}

# Resolve MagicDNS suffix from tailscale status.
get_dns_suffix() {
    local suffix
    suffix=$(tailscale status --json 2>/dev/null | jq -r '.MagicDNSSuffix' 2>/dev/null || true)
    if [ -z "$suffix" ] || [ "$suffix" = "null" ]; then
        echo "FATAL: could not get MagicDNS suffix" >&2
        return 1
    fi
    echo "$suffix"
}

# Print VIP diagnostics for CI debugging.
dump_peers() {
    local filter="${1:-}"
    echo "=== Peer diagnostics ==="
    if [ -n "$filter" ]; then
        tailscale status --json 2>/dev/null | jq -c "[.Peer[] | select(.HostName | test(\"$filter\")) | {HostName, TailscaleIPs, AllowedIPs: (.AllowedIPs // []), Online}]" 2>/dev/null || true
    else
        tailscale status --json 2>/dev/null | jq -c '[.Peer[] | {HostName, TailscaleIPs, AllowedIPs: (.AllowedIPs // []), Online}]' 2>/dev/null || true
    fi
}
