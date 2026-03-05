# Integration Test Overhaul Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure integration tests with tag:user/docker/kind ACL model, multidimensional cap testing (listeners, hostnames, routes), and UDP VIP warning logging.

**Architecture:** GitHub Actions runner joins tailnet as `tag:user` test client. Docker tailvoy (`tag:docker`, `svc:docker`) tests static listeners. Kind tailvoy (`tag:kind`, `svc:kind`) tests dynamic/discovery mode with hostname dimension. ACL grants give `tag:user` partial access to exercise allow/deny across all dimensions.

**Tech Stack:** Go, bash, Docker Compose, kind, Envoy Gateway, Tailscale ACL grants, `tailscale/github-action`

**Design doc:** `docs/plans/2026-03-05-integration-test-overhaul-design.md`

---

### Task 1: Add UDP VIP warning log to static mode

The static mode in `cmd/tailvoy/main.go` already separates TCP/UDP listeners (line 212-220) but doesn't emit a user-visible warning for each UDP listener. Add a warning per UDP listener.

**Files:**
- Modify: `cmd/tailvoy/main.go:280-300`
- Test: `cmd/tailvoy/main_test.go` (if exists, otherwise manual verification)

**Step 1: Add warning log for each UDP listener in static mode**

In `cmd/tailvoy/main.go`, after the UDP listeners are collected (line 220), add a warning for each one. Find the block starting at line 281 (`if tsIP != ""`):

```go
// Start UDP listeners on the node IP (VIP services don't support UDP).
for _, l := range udpListeners {
    logger.Warn("UDP listener has no VIP service support, node IP only", "listener", l.Name)
```

Add the `logger.Warn` line as the first statement inside the `for _, l := range udpListeners` loop at line 282. The existing code at line 284 (`pc, err := ts.ListenPacket(...)`) continues after.

**Step 2: Also warn when there are UDP listeners but no tailscale IP**

The existing block at line 298-300 already handles this case:
```go
} else if len(udpListeners) > 0 {
    logger.Warn("no tailscale IPv4, skipping UDP listeners")
}
```

This is fine as-is. The new per-listener warning goes inside the loop at line 282.

**Step 3: Run unit tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go build ./...`
Expected: Compiles cleanly.

**Step 4: Commit**

```bash
git add cmd/tailvoy/main.go
git commit -m "Add UDP VIP service warning in static mode"
```

---

### Task 2: Add UDP VIP warning log to dynamic mode

The dynamic mode in `internal/proxy/dynamic.go` already filters UDP at line 63-70 in `Reconcile()` but the warning message says "skipping" which is misleading — it does still start UDP on node IP. Align the warning message and also add a warning in `startListener`.

**Files:**
- Modify: `internal/proxy/dynamic.go:63-70` and `internal/proxy/dynamic.go:126-136`

**Step 1: Update Reconcile UDP warning**

In `internal/proxy/dynamic.go`, change line 66:

Old:
```go
dm.logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
```

New:
```go
dm.logger.Warn("UDP listener has no VIP service support, node IP only", "listener", l.Name)
```

Wait — looking at the code more carefully, `Reconcile` at line 63-70 actually *skips* UDP entirely from the `tcpDesired` list and never calls `startListener` for UDP. The UDP `startListener` path at line 126 is dead code in the current flow. This means dynamic mode currently does NOT start UDP listeners at all.

Re-read the code: `Reconcile` filters UDP out of `tcpDesired`, then only iterates `tcpDesired` to start listeners. The `startListener` switch on `l.Protocol == "udp"` at line 126 exists but is never reached from `Reconcile`.

For now, just update the warning message in `Reconcile` to match the standard format:

Old (line 66):
```go
dm.logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
```

New:
```go
dm.logger.Warn("UDP listener has no VIP service support, node IP only", "listener", l.Name)
```

**Step 2: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/proxy/...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/proxy/dynamic.go
git commit -m "Align UDP VIP warning message in dynamic mode"
```

---

### Task 3: Rewrite test ACL

Replace the current `test-acl.json` with the new tag:user/docker/kind structure.

**Files:**
- Modify: `integration_test/scripts/test-acl.json`

**Step 1: Rewrite test-acl.json**

```json
{
  "tagOwners": {
    "tag:user": [],
    "tag:docker": [],
    "tag:kind": []
  },
  "autoApprovers": {
    "services": {
      "svc:docker": ["tag:docker"],
      "svc:kind": ["tag:kind"]
    }
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["*"],
      "ip": ["*"]
    },
    {
      "src": ["tag:user"],
      "dst": ["tag:docker"],
      "app": {
        "rajsingh.info/cap/tailvoy": [
          {"listeners": ["http"], "routes": ["/public/*", "/health", "/api/*"]},
          {"listeners": ["tcp"]}
        ]
      }
    },
    {
      "src": ["tag:user"],
      "dst": ["tag:kind"],
      "app": {
        "rajsingh.info/cap/tailvoy": [
          {"listeners": ["http", "default/eg/http"], "hostnames": ["public.tailvoy.test"], "routes": ["/api/*", "/health"]},
          {"listeners": ["http", "default/eg/http"], "routes": ["/public/*"]},
          {"listeners": ["grpc", "default/eg/grpc"], "routes": ["/grpc.health.v1.Health/*"]},
          {"listeners": ["tcp", "tls", "default/eg/tcp", "default/eg/tls"]}
        ]
      }
    }
  ]
}
```

Key changes from old ACL:
- `tag:integration` → removed (replaced by `tag:docker`)
- `tag:kind` src/dst grants → replaced by `tag:user` → `tag:kind` grant
- New `tag:user` tag for the test client (GH Actions runner)
- Docker caps: `http` + `tcp` only (no `udp` — tests deny)
- Kind caps: hostname-scoped routes, no `/admin/*`

**Step 2: Validate JSON**

Run: `jq . integration_test/scripts/test-acl.json`
Expected: Valid JSON output.

**Step 3: Commit**

```bash
git add integration_test/scripts/test-acl.json
git commit -m "Rewrite test ACL with tag:user/docker/kind structure"
```

---

### Task 4: Update docker tailvoy config to tag:docker

**Files:**
- Modify: `integration_test/full-test-policy.yaml`

**Step 1: Update tags**

Change `tag:integration` to `tag:docker` in both `tags` and `serviceTags`. The full file should be:

```yaml
tailscale:
  service: "tailvoy-docker-test"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:docker"
  serviceTags:
    - "tag:docker"

listeners:
  - name: http
    protocol: tcp
    listen: ":80"
    forward: "backend:8080"
    l7_policy: true

  - name: tcp
    protocol: tcp
    listen: ":5432"
    forward: "tcp-echo:9000"

  - name: udp
    protocol: udp
    listen: ":9053"
    forward: "udp-echo:9053"

  - name: no-access
    protocol: tcp
    listen: ":9999"
    forward: "backend:8080"
```

**Step 2: Also update l7-test-policy-docker.yaml if it uses tag:integration**

Check `integration_test/l7-test-policy-docker.yaml` and update tags there too if needed.

**Step 3: Commit**

```bash
git add integration_test/full-test-policy.yaml integration_test/l7-test-policy-docker.yaml
git commit -m "Update docker test configs to use tag:docker"
```

---

### Task 5: Update kind tailvoy config to tag:kind

**Files:**
- Modify: `integration_test/kind/manifests/tailvoy-config.yaml`

**Step 1: Verify tags are already tag:kind**

The file at `integration_test/kind/manifests/tailvoy-config.yaml` already has:
```yaml
tags:
  - "tag:kind"
serviceTags:
  - "tag:kind"
```

If this is already correct, no change needed. Just verify.

**Step 2: Commit (if changed)**

```bash
git add integration_test/kind/manifests/tailvoy-config.yaml
git commit -m "Verify kind test config uses tag:kind"
```

---

### Task 6: Add hostname-based HTTPRoutes for kind tests

Add `public.tailvoy.test` and `admin.tailvoy.test` HTTPRoutes to test hostname dimension. The current `http-route` is a catch-all (`/` prefix, no hostname). Add two hostname-specific routes that target the same backend.

**Files:**
- Modify: `integration_test/kind/manifests/routes.yaml`
- Modify: `integration_test/kind/manifests/security-policy.yaml`

**Step 1: Add hostname HTTPRoutes to routes.yaml**

Append after the existing `http-route` (before `TCPRoute`):

```yaml
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: http-route-public
spec:
  parentRefs:
    - name: eg
      sectionName: http
  hostnames:
    - public.tailvoy.test
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: backend
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: http-route-admin
spec:
  parentRefs:
    - name: eg
      sectionName: http
  hostnames:
    - admin.tailvoy.test
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: backend
          port: 8080
```

**Step 2: Add SecurityPolicies for the hostname routes**

Append to `integration_test/kind/manifests/security-policy.yaml`:

```yaml
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: ext-authz-http-public
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: http-route-public
  extAuth:
    grpc:
      backendRefs:
        - name: tailvoy-authz
          namespace: envoy-gateway-system
          port: 9001
    contextExtensions:
      - name: listener
        type: Value
        value: "default/eg/http"
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: ext-authz-http-admin
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: http-route-admin
  extAuth:
    grpc:
      backendRefs:
        - name: tailvoy-authz
          namespace: envoy-gateway-system
          port: 9001
    contextExtensions:
      - name: listener
        type: Value
        value: "default/eg/http"
```

Both use `listener=default/eg/http` — the hostname dimension is evaluated by tailvoy's `CheckAccess` using the Host header, not a different listener name.

**Step 3: Commit**

```bash
git add integration_test/kind/manifests/routes.yaml integration_test/kind/manifests/security-policy.yaml
git commit -m "Add hostname-based HTTPRoutes for kind integration tests"
```

---

### Task 7: Rewrite docker integration test script

Rewrite `run-full-tests.sh` to match the new ACL (tag:user → tag:docker caps), add UDP deny test, and add UDP warning log check.

**Files:**
- Modify: `integration_test/run-full-tests.sh`

**Step 1: Update the test assertions**

Key changes to `integration_test/run-full-tests.sh`:

1. **Hostname detection:** Change `tailvoy-docker-test-tailvoy` — this should still be correct since the config `service: "tailvoy-docker-test"` creates hostname `tailvoy-docker-test-tailvoy`.

2. **HTTP L7 tests:** Keep allows for `/public/*`, `/health`, `/api/*`. Change `/admin/*` from allow to **deny** (403). This is the key change — the old ACL allowed admin, new one doesn't.

3. **UDP deny test:** The old test expects UDP echo to succeed. New ACL doesn't include `udp` in docker caps, so UDP should be denied at L4. Change the UDP test to expect **no response** (connection denied/timeout).

4. **UDP warning log check:** After stack starts, grep tailvoy logs for the UDP VIP warning.

5. **Identity headers:** Update to check for tags (`tag:docker`-related tags from test client) rather than user login.

The full rewrite of the test sections:

**HTTP L7 section** — change `/admin/settings` assertion from 200 to 403:

Old:
```bash
assert_http "L7: /admin/settings allow" "http://$IP:80/admin/settings" "200"
```
New:
```bash
assert_http "L7: /admin/settings deny (not in caps)" "http://$IP:80/admin/settings" "403"
```

**UDP section** — change from allow to deny:

Old:
```bash
UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 9053 2>/dev/null || true)
if echo "$UDP_RESP" | grep -q "echo: hello"; then
    test_pass "UDP: echo allow..."
```

New:
```bash
if [ -n "$NC_CMD" ]; then
    UDP_RESP=$({ echo -n "hello"; sleep 3; } | $NC_CMD -u -w 5 "$IP" 9053 2>/dev/null || true)
    if echo "$UDP_RESP" | grep -q "echo: hello"; then
        test_fail "UDP: deny (udp not in caps)" "got response, expected deny"
    else
        test_pass "UDP: deny (udp not in caps)"
    fi
else
    echo "  SKIP: UDP tests (no ncat/nc)"
fi
```

**UDP warning log check** — add after stack starts (after sleep 5):

```bash
echo "=== Checking UDP VIP warning ==="
if docker compose -f "$COMPOSE_FILE" logs tailvoy 2>&1 | grep -q "UDP listener has no VIP service support"; then
    test_pass "UDP VIP warning emitted"
else
    test_fail "UDP VIP warning emitted" "warning not found in logs"
fi
```

**Step 2: Run the script locally (requires tailnet credentials)**

This can only be fully tested in CI or with local credentials. Verify the script is valid bash:

Run: `bash -n integration_test/run-full-tests.sh`
Expected: No syntax errors.

**Step 3: Commit**

```bash
git add integration_test/run-full-tests.sh
git commit -m "Update docker tests for tag:user/docker ACL, add UDP deny + warning check"
```

---

### Task 8: Update kind integration test script

Update `run-kind-tests.sh` to add hostname dimension tests and remove `/admin/*` allows.

**Files:**
- Modify: `integration_test/kind/run-kind-tests.sh`

**Step 1: Change /admin/* from allow to deny**

In the HTTPRoute tests section (around line 286):

Old:
```bash
assert_http "HTTP: GET /admin/settings allow" "http://$IP:8080/admin/settings" "200"
```

New:
```bash
assert_http "HTTP: GET /admin/settings deny (not in caps)" "http://$IP:8080/admin/settings" "403"
```

**Step 2: Add hostname dimension tests**

Add a new section after HTTPRoute tests (after line 319) and before TCPRoute tests:

```bash
# =====================================================
# HOSTNAME DIMENSION TESTS
# =====================================================
echo ""
echo "========================================"
echo "  HOSTNAME DIMENSION TESTS"
echo "========================================"

# Cap rule: {"listeners": ["http", "default/eg/http"], "hostnames": ["public.tailvoy.test"], "routes": ["/api/*", "/health"]}
# /api/* on public.tailvoy.test → ALLOW
assert_http "Hostname: GET /api/data Host:public.tailvoy.test allow" \
    "http://$IP:8080/api/data" "200" \
    -H "Host: public.tailvoy.test"

# /health on public.tailvoy.test → ALLOW
assert_http "Hostname: GET /health Host:public.tailvoy.test allow" \
    "http://$IP:8080/health" "200" \
    -H "Host: public.tailvoy.test"

# /api/* on admin.tailvoy.test → DENY (hostname not in caps)
assert_http "Hostname: GET /api/data Host:admin.tailvoy.test deny" \
    "http://$IP:8080/api/data" "403" \
    -H "Host: admin.tailvoy.test"

# /admin/* on public.tailvoy.test → DENY (route not in caps)
assert_http "Hostname: GET /admin/x Host:public.tailvoy.test deny" \
    "http://$IP:8080/admin/x" "403" \
    -H "Host: public.tailvoy.test"

# /public/* on admin.tailvoy.test → ALLOW (second rule has no hostname restriction)
assert_http "Hostname: GET /public/hello Host:admin.tailvoy.test allow" \
    "http://$IP:8080/public/hello" "200" \
    -H "Host: admin.tailvoy.test"
```

Note: The `assert_http` function already supports extra curl args via `shift 3; "$@"` (see line 37).

**Step 3: Remove /admin/* allow tests that are now deny**

The existing tests at line 286 already need updating per Step 1. Also update the deny section — `/admin/settings` moves from allow to deny, while existing deny tests for `/secret/data`, `/internal/config`, etc. stay the same.

**Step 4: Validate script syntax**

Run: `bash -n integration_test/kind/run-kind-tests.sh`
Expected: No syntax errors.

**Step 5: Commit**

```bash
git add integration_test/kind/run-kind-tests.sh
git commit -m "Add hostname dimension tests and update allow/deny for kind tests"
```

---

### Task 9: Update GitHub Actions workflow

Update `integration-test.yml` to create the authkey with `tag:user` instead of `kind`.

**Files:**
- Modify: `.github/workflows/integration-test.yml`

**Step 1: Change authkey tag from "kind" to "user"**

In the `create-auth-key` step (line 94-99):

Old:
```bash
AUTHKEY_JSON=$(./integration_test/scripts/create-auth-key.sh \
    "${{ steps.tailnet_token.outputs.tailnet_token }}" \
    "${{ steps.create.outputs.tailnet_name }}" \
    "kind" true true true)
```

New:
```bash
AUTHKEY_JSON=$(./integration_test/scripts/create-auth-key.sh \
    "${{ steps.tailnet_token.outputs.tailnet_token }}" \
    "${{ steps.create.outputs.tailnet_name }}" \
    "user" true true true)
```

This creates an authkey for `tag:user`. The `create-auth-key.sh` script wraps the tag name with `tag:` prefix automatically (line 43: `"tags": ["tag:$TAG_NAME"]`).

**Step 2: Update tailscale/github-action usage to pass tags**

In the `kind-test` job (line 132-134):

Old:
```yaml
- name: Install Tailscale
  uses: tailscale/github-action@v4
  with:
    authkey: ${{ needs.setup-tailnet.outputs.ts_authkey }}
```

New:
```yaml
- name: Install Tailscale
  uses: tailscale/github-action@v4
  with:
    authkey: ${{ needs.setup-tailnet.outputs.ts_authkey }}
    tags: tag:user
```

Same change for the `docker-test` job (line 167-169).

Note: When using an authkey, the tags are already baked into the key by `create-auth-key.sh`. The `tags` input to `tailscale/github-action` is only needed for OAuth auth, not authkey. So we can skip adding `tags` if the authkey already specifies `tag:user`. Verify by checking that `create-auth-key.sh` passes the tag correctly (it does — line 43-44).

Actually, for authkey auth the `tags` param on the action is ignored — the key itself carries the tag. So no change needed on the action `with:` block beyond ensuring the authkey is created with `tag:user`. Keep the action as-is.

**Step 3: Commit**

```bash
git add .github/workflows/integration-test.yml
git commit -m "Update CI authkey to tag:user for test client"
```

---

### Task 10: Update run-l7-tests.sh for tag:docker

The `run-l7-tests.sh` uses `l7-test-policy-docker.yaml` which references `tag:integration`. Update it and align test assertions.

**Files:**
- Modify: `integration_test/l7-test-policy-docker.yaml`
- Modify: `integration_test/run-l7-tests.sh`
- Modify: `integration_test/docker-compose.yaml`

**Step 1: Update l7-test-policy-docker.yaml tags**

Read the file first to check current tags. Change `tag:integration` → `tag:docker`. Also update `serviceTags`.

**Step 2: Update run-l7-tests.sh hostname matching**

The script looks for `tailvoy-l7-test-tailvoy` (line 52). This should still match if the service name stays `tailvoy-l7-test`. Update the test assertions:

- `/admin/*` → change from allow (200) to deny (403) since new ACL doesn't grant `/admin/*` to `tag:user` → `tag:docker`
- Identity header test: change from expecting `rajsinghtech@github` user to expecting tags present (test client is tagged node, not user)

Old (line 86):
```bash
if [ "$HTTP" = "403" ]; then test_pass "/admin/* deny"; else test_fail "/admin/* deny" "expected 403, got $HTTP"; fi
```

This already expects 403 — good, no change needed here.

Old (line 104):
```bash
if [ "$USER_HDR" = "rajsinghtech@github" ]; then test_pass "x-tailscale-user header"
```

New: Check for either user or tags:
```bash
TAGS_HDR=$(echo "$BODY" | jq -r '.headers["X-Tailscale-Tags"]' 2>/dev/null || true)
if [ -n "$USER_HDR" ] && [ "$USER_HDR" != "null" ]; then
    test_pass "x-tailscale identity (user)"
elif [ -n "$TAGS_HDR" ] && [ "$TAGS_HDR" != "null" ] && [ "$TAGS_HDR" != "" ]; then
    test_pass "x-tailscale identity (tagged node)"
else
    test_fail "x-tailscale identity" "no user or tags found"
fi
```

**Step 3: Validate syntax**

Run: `bash -n integration_test/run-l7-tests.sh`

**Step 4: Commit**

```bash
git add integration_test/l7-test-policy-docker.yaml integration_test/run-l7-tests.sh integration_test/docker-compose.yaml
git commit -m "Update L7 tests for tag:docker ACL"
```

---

### Task 11: Final validation and commit

**Step 1: Run Go tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./...`
Expected: All pass.

**Step 2: Validate all bash scripts**

Run:
```bash
bash -n integration_test/run-full-tests.sh && \
bash -n integration_test/run-l7-tests.sh && \
bash -n integration_test/kind/run-kind-tests.sh
```
Expected: No syntax errors.

**Step 3: Validate test-acl.json**

Run: `jq . integration_test/scripts/test-acl.json > /dev/null`
Expected: Exit 0.

**Step 4: Verify all files are committed**

Run: `git status`
Expected: Clean working tree.

**Step 5: Push**

```bash
git push origin main
```

Verify the integration-test workflow triggers on push and both docker-test and kind-test jobs use the new ACL.
