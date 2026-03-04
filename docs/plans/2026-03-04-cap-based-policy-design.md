# Cap-Based Policy Design

## Problem

tailvoy's `policy.yaml` duplicates authorization logic that Tailscale ACLs already express natively. L4/L7 rules with users/tags/groups must stay in sync with `policy.hujson`. Peer capabilities (`CapMap` via WhoIs) let the coordination server pre-resolve all identity matching, making tailvoy's authorization config redundant.

## Design

Move all authorization into Tailscale ACL grants using `rajsingh.info/cap/tailvoy` peer capabilities. `policy.yaml` becomes infrastructure-only config. Gateway API (HTTPRoute) handles host/method matching. Tailvoy ext_authz only evaluates path access against capability-derived routes.

### Capability Structure

```go
type TailvoyCapRule struct {
    Routes []string `json:"routes,omitempty"`
}
```

- Having the cap = L4 access (peer can connect)
- `routes: ["/*"]` or omitted = full L7 access
- `routes: ["/raj/*", "/api/*"]` = only those paths
- Multiple grants merge additively
- No cap = denied (hujson deny-all default)
- Path patterns: `/*` (everything), `/prefix/*` (prefix match), `/exact` (exact match)

### Example hujson grants

```hujson
{
    "src": ["autogroup:member"],
    "dst": ["tag:ottawa"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"routes": ["/public/*", "/health"]}]
    }
}
{
    "src": ["rajsinghtech@github"],
    "dst": ["tag:ottawa"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"routes": ["/raj/*"]}]
    }
}
{
    "src": ["group:superuser"],
    "dst": ["tag:ottawa"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"routes": ["/superuser/*", "/admin/*"]}]
    }
}
```

raj (in group:superuser) gets caps from all three grants. Merged routes: `/public/*`, `/health`, `/raj/*`, `/superuser/*`, `/admin/*`.

### policy.yaml (after)

```yaml
tailscale:
  hostname: "tailvoy-ottawa"
  ephemeral: true
listeners:
  - name: http
    protocol: tcp
    listen: ":80"
    forward: "127.0.0.1:8080"
    proxy_protocol: v2
```

No `l4_rules`, `l7_rules`, or `default`.

### Data Flow

```
Request → Envoy → ext_authz (gRPC) → tailvoy:
  1. Extract source IP from x-forwarded-for
  2. WhoIs(ip) → WhoIsResponse with CapMap
  3. UnmarshalCapJSON[TailvoyCapRule](CapMap, "rajsingh.info/cap/tailvoy")
  4. No rules → deny (no cap = no access)
  5. Merge routes from all cap rules
  6. matchPath(allowed routes, request path) → allow/deny
  7. Allow → OkResponse + identity headers / Deny → PERMISSION_DENIED
```

### Deleted

- `config.Rule`, `config.RuleMatch`, `config.AllowSpec`
- `config.L4Rules`, `config.L7Rules`, `config.Default`
- `engine.CheckL4()`, `engine.CheckL7()`, `engine.matchesAllow()`
- `engine.matchHost()`, `engine.matchMethod()`
- `policy.Identity.Groups`

### Changed

| Component | Before | After |
|-----------|--------|-------|
| `TailvoyCapRule` | `Groups []string` | `Routes []string` |
| `policy.Identity` | UserLogin, NodeName, Tags, Groups, IsTagged, TailscaleIP | UserLogin, NodeName, Tags, IsTagged, TailscaleIP, AllowedRoutes |
| `policy.Engine` | CheckL4/CheckL7 with rule evaluation | `CheckAccess(path, id) bool` — match path against id.AllowedRoutes |
| `config.Config` | Tailscale + Listeners + L4Rules + L7Rules + Default | Tailscale + Listeners |
| `identity.toIdentity()` | Extract groups from caps | Extract routes from caps |
| `matchPath()` | Stays as-is | Stays as-is |
