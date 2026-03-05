# Integration Test Overhaul: Tailscale Test Client + Multidimensional ACL Testing

## Problem

Integration tests depend on the host machine being on the tailnet and use a flat ACL structure that doesn't exercise the full dimensionality of tailvoy's cap-based authorization (listeners, hostnames, routes). UDP VIP service limitations are silently ignored.

## Architecture

### Tags & Services

| Entity | Tag | Service | Mode |
|--------|-----|---------|------|
| GH Actions runner (test client) | `tag:user` | -- | `tailscale/github-action` |
| Docker tailvoy | `tag:docker` | `svc:docker` | Static listeners |
| Kind tailvoy | `tag:kind` | `svc:kind` | Dynamic/discovery |

### ACL (`test-acl.json`)

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
    {"src": ["*"], "dst": ["*"], "ip": ["*"]},
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

### Test Matrix

**Docker (static listeners):**

| Test | Listener | Dimension | Expected |
|------|----------|-----------|----------|
| GET /public/hello | http | route allow | 200 |
| GET /health | http | route allow | 200 |
| GET /api/data | http | route allow | 200 |
| GET /admin/settings | http | route deny | 403 |
| GET /unknown | http | default deny | 403 |
| GET /health/ | http | exact boundary | 403 |
| TCP echo | tcp | L4 allow | echo |
| UDP echo | udp | L4 deny (not in caps) | timeout |
| Port 9999 | no-access | L4 deny | refused |
| Identity headers | http | injection | present |
| UDP warning log | -- | log check | warning emitted |

**Kind (dynamic/discovery):**

| Test | Listener | Dimension | Expected |
|------|----------|-----------|----------|
| GET /public/hello (any host) | http | route allow | 200 |
| GET /api/data Host: public.tailvoy.test | http | hostname+route allow | 200 |
| GET /api/data Host: admin.tailvoy.test | http | hostname deny | 403 |
| GET /admin/settings | http | route deny | 403 |
| GET /health Host: public.tailvoy.test | http | hostname+route allow | 200 |
| TCP echo | tcp | L4 allow | echo |
| TLS passthrough | tls | L4+SNI allow | 200 |
| gRPC health check | grpc | route allow | SERVING |
| gRPC reflection | grpc | route deny | PERMISSION_DENIED |
| Identity headers | http | injection | tags present |

### UDP Warning

When tailvoy encounters a UDP listener in static config or discovers a UDP route in dynamic mode, log:

```
WARN  UDP listener has no VIP service support, node IP only  listener=<name>
```

Docker tests verify the warning was emitted by grepping container logs.

### Hostname Testing

Hostname dimension tested only in kind tests where Envoy provides Host header (L7) and SNI (TLS passthrough). Docker tests focus on listener + route dimensions.

Kind adds two HTTPRoute hostname variants:
- `public.tailvoy.test` -- granted in ACL
- `admin.tailvoy.test` -- not granted, tests hostname deny

### GitHub Actions Workflow

1. **setup-tailnet** -- ephemeral tailnet, apply test-acl.json, create authkey with `tag:user`
2. **docker-test** (parallel) -- `tailscale/github-action` tags=tag:user
3. **kind-test** (parallel) -- `tailscale/github-action` tags=tag:user
4. **cleanup-tailnet** (always)

## Files Changed

| File | Action |
|------|--------|
| `integration_test/scripts/test-acl.json` | Rewrite |
| `integration_test/full-test-policy.yaml` | Tags to tag:docker |
| `integration_test/run-full-tests.sh` | Add UDP deny, UDP warning check, update assertions |
| `integration_test/kind/manifests/tailvoy-config.yaml` | Tags to tag:kind |
| `integration_test/kind/manifests/routes.yaml` | Add hostname HTTPRoutes |
| `integration_test/kind/run-kind-tests.sh` | Add hostname tests, UDP warning check |
| `.github/workflows/integration-test.yml` | Authkey tag:user |
| Source: static mode (cmd/tailvoy/main.go) | UDP VIP warning |
| Source: dynamic mode (internal/proxy/dynamic.go) | UDP VIP warning |
