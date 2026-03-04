# CI Workflow Refactor: Ephemeral Tailnets with Tag-Based Cap Grants

## Problem

The integration test workflow (`integration-test.yml`) is disabled — it requires a `TS_AUTHKEY` secret manually provisioned against a static tailnet. With the cap-based policy migration, tests need a real tailnet to validate that WhoIs returns `rajsingh.info/cap/tailvoy` capabilities. Since ephemeral test tailnets have no users, all authorization must flow through tags.

## Design

### Architecture

Single workflow with 3 jobs:

```
setup-tailnet ──► kind-test ──► (done)
      │
      └──────► cleanup-tailnet (if: always())
```

- **setup-tailnet**: OIDC auth → create ephemeral tailnet → apply cap-based ACL → create auth key
- **kind-test**: standard kind cluster integration tests using the provisioned auth key
- **cleanup-tailnet**: delete ephemeral tailnet (runs even on test failure)

### Authentication

Uses GitHub OIDC token exchange (no long-lived secrets):

```
GitHub OIDC provider → JWT
    ↓
exchange-oidc-token.sh(TS_OAUTH_CLIENT_ID, JWT) → ACCESS_TOKEN
    ↓
Tailscale API calls with ACCESS_TOKEN
```

**GitHub Secrets**: `TS_OAUTH_CLIENT_ID` — same OAuth client as openclaw-workspace (`TbqNGJkY5611CNTRL-kz4CwX2LK721CNTRL`)

**Workflow permissions**: `id-token: write`

### Ephemeral Tailnet Lifecycle

Each CI run creates a tailnet named `tailvoy-ci-{run_id}`:

1. `create-tailnet.sh` → new tailnet
2. `update-acl.sh` → apply test ACL with `tag:kind` + cap grants
3. `create-auth-key.sh` → auth key for `tag:kind` (ephemeral, preauthorized)
4. Tests run against the tailnet
5. `delete-tailnet.sh` → cleanup (`if: always()`, `continue-on-error: true`)

### Test ACL

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

- First grant: L3/L4 connectivity between all nodes
- Second grant: cap-based routes for tailvoy ext_authz evaluation
- `tag:kind`: matches the existing tag in `kubernetes-manifests/tailscale/policy.hujson`

The same tests pass on the personal tailnet (where `tag:kind` is already defined) if the cap grant is added to `policy.hujson`.

### Scripts

Copy from `kubernetes-manifests/tailscale/scripts/` into `integration_test/scripts/`:

| Script | Purpose |
|--------|---------|
| `exchange-oidc-token.sh` | GitHub OIDC JWT → Tailscale access token |
| `create-tailnet.sh` | Create ephemeral tailnet |
| `delete-tailnet.sh` | Delete tailnet (cleanup) |
| `create-auth-key.sh` | Create auth key with `tag:kind` |
| `update-acl.sh` | Apply ACL from JSON file |

New file: `integration_test/scripts/test-acl.json` — the cap-based test ACL above.

### Kind Test Updates

**policy.yaml in ConfigMap**: becomes infrastructure-only (listeners, no rules):
```yaml
tailscale:
  hostname: "tailvoy-kind-test"
  ephemeral: true
listeners:
  - name: http
    protocol: tcp
    listen: ":80"
    forward: "127.0.0.1:8080"
    proxy_protocol: v2
    l7_policy: true
  # ... other listeners unchanged
```

**run-kind-tests.sh changes**:
- Add deny test cases: paths not in cap grants (e.g., `/secret/data`) should return 403
- Keep existing allow tests for paths covered by grants (`/public/*`, `/health`, `/api/*`, `/admin/*`)
- Keep identity header validation
- Keep TCP/UDP/TLS/gRPC route tests (L4 — caps grant peer-level access)

### Workflow Triggers

```yaml
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
```

Replaces the current `workflow_dispatch`-only + disabled kind job.

### Failure Handling

- `cleanup-tailnet` job uses `if: always()` — runs even if `kind-test` fails or is cancelled
- `cleanup-tailnet` uses `continue-on-error: true` — won't fail the workflow if cleanup fails
- OIDC token re-exchanged in cleanup job (tokens are short-lived)
- `delete-tailnet.sh` is idempotent — safe to call even if tailnet was never created

### Concurrency

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Prevents parallel runs from creating orphaned tailnets.
