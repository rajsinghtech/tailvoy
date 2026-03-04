# CI Workflow Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the disabled integration-test.yml with a working workflow that creates ephemeral tailnets per CI run, applies tag-based cap grants, and runs kind integration tests.

**Architecture:** 3-job GitHub Actions workflow (setup-tailnet → kind-test → cleanup-tailnet). Scripts from kubernetes-manifests copied into repo. OIDC token exchange for auth. `tag:kind` with `rajsingh.info/cap/tailvoy` cap grants in test ACL.

**Tech Stack:** GitHub Actions, Tailscale API, kind, Envoy Gateway, bash

---

### Task 1: Copy tailnet lifecycle scripts

**Files:**
- Create: `integration_test/scripts/exchange-oidc-token.sh`
- Create: `integration_test/scripts/create-tailnet.sh`
- Create: `integration_test/scripts/delete-tailnet.sh`
- Create: `integration_test/scripts/create-auth-key.sh`
- Create: `integration_test/scripts/update-acl.sh`

**Step 1: Create the scripts directory and copy scripts**

Copy these 5 scripts from `../kubernetes-manifests/tailscale/scripts/` into `integration_test/scripts/`:
- `exchange-oidc-token.sh`
- `create-tailnet.sh`
- `delete-tailnet.sh`
- `create-auth-key.sh`
- `update-acl.sh`

No modifications needed — the scripts are generic and parameterized.

**Step 2: Make scripts executable**

Run: `chmod +x integration_test/scripts/*.sh`

**Step 3: Verify scripts have correct shebang and set -e**

Run: `head -2 integration_test/scripts/*.sh`
Expected: Each file starts with `#!/bin/bash` and `set -e`

**Step 4: Commit**

```bash
git add integration_test/scripts/
git commit -m "Add tailnet lifecycle scripts for CI workflow"
```

---

### Task 2: Create the test ACL file

**Files:**
- Create: `integration_test/scripts/test-acl.json`

**Step 1: Create the test ACL JSON**

```json
{
  "tagOwners": {
    "tag:kind": []
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["*"],
      "ip": ["*"]
    },
    {
      "src": ["tag:kind"],
      "dst": ["tag:kind"],
      "app": {
        "rajsingh.info/cap/tailvoy": [
          {"routes": ["/public/*", "/health", "/api/*", "/admin/*"]}
        ]
      }
    }
  ]
}
```

- First grant: L3/L4 connectivity (all nodes can reach each other)
- Second grant: cap-based routes that WhoIs will return via CapMap for `tag:kind` peers
- Routes `/public/*`, `/health`, `/api/*`, `/admin/*` are allowed; everything else denied

**Step 2: Validate JSON syntax**

Run: `jq empty integration_test/scripts/test-acl.json`
Expected: No output (valid JSON)

**Step 3: Commit**

```bash
git add integration_test/scripts/test-acl.json
git commit -m "Add cap-based test ACL for CI integration tests"
```

---

### Task 3: Rewrite the integration-test.yml workflow

**Files:**
- Modify: `.github/workflows/integration-test.yml`

**Step 1: Replace the entire workflow file**

The new workflow has 3 jobs: `setup-tailnet`, `kind-test`, `cleanup-tailnet`.

```yaml
name: Integration Tests

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  id-token: write
  contents: read

jobs:
  setup-tailnet:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      tailnet_name: ${{ steps.create.outputs.tailnet_name }}
      ts_authkey: ${{ steps.authkey.outputs.ts_authkey }}

    steps:
      - uses: actions/checkout@v6

      - name: Get OIDC token
        id: oidc
        run: |
          JWT=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api.tailscale.com/${{ secrets.TS_OAUTH_CLIENT_ID }}" \
            | jq -r '.value')
          echo "::add-mask::$JWT"
          echo "jwt=$JWT" >> "$GITHUB_OUTPUT"

      - name: Exchange OIDC token for access token
        id: token
        run: |
          ACCESS_TOKEN=$(./integration_test/scripts/exchange-oidc-token.sh \
            "${{ secrets.TS_OAUTH_CLIENT_ID }}" \
            "${{ steps.oidc.outputs.jwt }}")
          echo "::add-mask::$ACCESS_TOKEN"
          echo "access_token=$ACCESS_TOKEN" >> "$GITHUB_OUTPUT"

      - name: Create ephemeral tailnet
        id: create
        run: |
          TAILNET_NAME="tailvoy-ci-${{ github.run_id }}"
          ./integration_test/scripts/create-tailnet.sh \
            "${{ steps.token.outputs.access_token }}" \
            "$TAILNET_NAME"
          echo "tailnet_name=$TAILNET_NAME" >> "$GITHUB_OUTPUT"

      - name: Apply test ACL
        run: |
          ./integration_test/scripts/update-acl.sh \
            "${{ steps.token.outputs.access_token }}" \
            "${{ steps.create.outputs.tailnet_name }}" \
            ./integration_test/scripts/test-acl.json

      - name: Create auth key
        id: authkey
        run: |
          AUTHKEY_JSON=$(./integration_test/scripts/create-auth-key.sh \
            "${{ steps.token.outputs.access_token }}" \
            "${{ steps.create.outputs.tailnet_name }}" \
            "kind" true true)
          TS_AUTHKEY=$(echo "$AUTHKEY_JSON" | jq -r '.key')
          echo "::add-mask::$TS_AUTHKEY"
          echo "ts_authkey=$TS_AUTHKEY" >> "$GITHUB_OUTPUT"

  kind-test:
    needs: setup-tailnet
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Install kind
        run: |
          curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
          chmod +x ./kind
          sudo mv ./kind /usr/local/bin/kind

      - name: Install Helm
        uses: azure/setup-helm@v4

      - name: Install grpcurl
        run: |
          curl -sSL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_amd64.tar.gz \
            | sudo tar -xz -C /usr/local/bin grpcurl

      - name: Install ncat
        run: sudo apt-get install -y ncat

      - name: Install Tailscale
        uses: tailscale/github-action@v4
        with:
          oauth-client-id: ${{ secrets.TS_OAUTH_CLIENT_ID }}
          audience: api.tailscale.com/${{ secrets.TS_OAUTH_CLIENT_ID }}
          tags: tag:kind

      - name: Run kind integration tests
        env:
          TS_AUTHKEY: ${{ needs.setup-tailnet.outputs.ts_authkey }}
        run: make kind-test

      - name: Collect logs on failure
        if: failure()
        run: |
          kubectl logs -n envoy-gateway-system -l gateway.envoyproxy.io/owning-gateway-name=eg --tail=200 > tailvoy-data-plane.log 2>&1 || true
          kubectl logs -n envoy-gateway-system -l control-plane=envoy-gateway --tail=100 > eg-controller.log 2>&1 || true

      - name: Upload logs
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: kind-test-logs
          path: |
            tailvoy-data-plane.log
            eg-controller.log
          retention-days: 7

  cleanup-tailnet:
    if: always()
    needs: setup-tailnet
    runs-on: ubuntu-latest
    timeout-minutes: 5

    steps:
      - uses: actions/checkout@v6

      - name: Get OIDC token
        id: oidc
        run: |
          JWT=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api.tailscale.com/${{ secrets.TS_OAUTH_CLIENT_ID }}" \
            | jq -r '.value')
          echo "::add-mask::$JWT"
          echo "jwt=$JWT" >> "$GITHUB_OUTPUT"

      - name: Exchange OIDC token for access token
        id: token
        run: |
          ACCESS_TOKEN=$(./integration_test/scripts/exchange-oidc-token.sh \
            "${{ secrets.TS_OAUTH_CLIENT_ID }}" \
            "${{ steps.oidc.outputs.jwt }}")
          echo "::add-mask::$ACCESS_TOKEN"
          echo "access_token=$ACCESS_TOKEN" >> "$GITHUB_OUTPUT"

      - name: Delete ephemeral tailnet
        continue-on-error: true
        run: |
          ./integration_test/scripts/delete-tailnet.sh \
            "${{ steps.token.outputs.access_token }}" \
            "${{ needs.setup-tailnet.outputs.tailnet_name }}"
```

Key details:
- `permissions: id-token: write` enables OIDC token requests
- `setup-tailnet` outputs are passed to both `kind-test` and `cleanup-tailnet` via `needs`
- `cleanup-tailnet` uses `if: always()` to run even on failure/cancellation
- `cleanup-tailnet` uses `continue-on-error: true` on the delete step
- `cleanup-tailnet` re-exchanges OIDC token (original may have expired)
- Auth key is extracted from JSON output with `jq -r '.key'`
- Secrets are masked with `::add-mask::` before being set as outputs
- `tailscale/github-action@v4` in kind-test connects the runner to tailnet with `tag:kind`
- Docker-compose job removed (kind-only per design decision)

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/integration-test.yml'))"`
Expected: No errors

**Step 3: Commit**

```bash
git add .github/workflows/integration-test.yml
git commit -m "Rewrite integration test workflow with ephemeral tailnets"
```

---

### Task 4: Update kind test script for cap-based deny tests

**Files:**
- Modify: `integration_test/kind/run-kind-tests.sh:241-263` (HTTPRoute TESTS section)

**Step 1: Update the HTTPRoute test section**

Replace the current HTTPRoute TESTS block (lines 241-263) with tests that validate both allowed and denied paths:

After the existing allow tests, add deny tests:

```bash
# Cap-based deny tests — paths not in cap grants should return 403
assert_http "HTTP: GET /secret/data deny" "http://$IP:80/secret/data" "403"
assert_http "HTTP: GET /internal/config deny" "http://$IP:80/internal/config" "403"
```

Update the existing allow tests to match cap grant routes. Replace lines 249-253:

```bash
assert_http "HTTP: GET /public/hello allow" "http://$IP:80/public/hello" "200"
assert_http "HTTP: GET /health allow" "http://$IP:80/health" "200"
assert_http "HTTP: GET /api/data allow" "http://$IP:80/api/data" "200"
assert_http "HTTP: GET /admin/settings allow" "http://$IP:80/admin/settings" "200"

# Cap-based deny tests — paths not in cap grants should return 403
assert_http "HTTP: GET /secret/data deny" "http://$IP:80/secret/data" "403"
assert_http "HTTP: GET /internal/config deny" "http://$IP:80/internal/config" "403"
```

Remove `assert_http "HTTP: GET / allow"` and `assert_http "HTTP: GET /any/path allow"` — root `/` and arbitrary paths are not in the cap grants, so they'd be denied now.

Also update the smoke test (line 233) to hit `/health` instead of `/`:

```bash
SMOKE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 15 "http://$IP:80/health" 2>&1 || true)
```

**Step 2: Update identity header test URL**

Change line 256 from `/public/headers` to `/api/headers` or keep `/public/headers` (it's under `/public/*` which is allowed). Either works — `/public/headers` matches `/public/*`. Keep as-is.

**Step 3: Run shellcheck on the script**

Run: `shellcheck integration_test/kind/run-kind-tests.sh || true`
Expected: No new errors from our changes

**Step 4: Commit**

```bash
git add integration_test/kind/run-kind-tests.sh
git commit -m "Add cap-based deny tests to kind integration tests"
```

---

### Task 5: Verify and clean up

**Step 1: Run unit tests to make sure nothing is broken**

Run: `make test`
Expected: All tests pass (these are unit tests, not integration)

**Step 2: Run linter**

Run: `make lint`
Expected: No new lint errors

**Step 3: Review the full workflow file one more time**

Read `.github/workflows/integration-test.yml` and verify:
- `permissions: id-token: write` is at top level
- `setup-tailnet` outputs `tailnet_name` and `ts_authkey`
- `kind-test` reads outputs via `needs.setup-tailnet.outputs.*`
- `cleanup-tailnet` has `if: always()` and `continue-on-error: true`
- All secrets reference `secrets.TS_OAUTH_CLIENT_ID`
- No references to old `secrets.TS_AUTHKEY`

**Step 4: Verify script permissions**

Run: `ls -la integration_test/scripts/*.sh`
Expected: All scripts have execute permission

**Step 5: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "Clean up integration test workflow"
```

---

### Post-Implementation: Manual Steps (not automated)

These require GitHub UI / Tailscale admin access:

1. **Add `TS_OAUTH_CLIENT_ID` secret** to the tailvoy GitHub repo settings
   - Value: same OAuth client ID used by openclaw-workspace
   - Settings → Secrets and variables → Actions → New repository secret

2. **Verify OIDC token exchange works** by manually triggering the workflow
   - Actions → Integration Tests → Run workflow

3. **Add cap grant to personal tailnet** (optional, for local testing)
   - Add to `kubernetes-manifests/tailscale/policy.hujson`:
   ```hujson
   {
     "src": ["tag:kind"],
     "dst": ["tag:kind"],
     "app": {
       "rajsingh.info/cap/tailvoy": [{"routes": ["/public/*", "/health", "/api/*", "/admin/*"]}]
     }
   }
   ```
