# Multi-Dimensional Cap Structure

## Problem

The current cap structure only has `routes`. There's no way to restrict which listeners a peer can connect to, or gate by hostname (SNI/Host header). A peer with any tailvoy cap gets L4 access to ALL listeners.

## Cap Rule Schema

```go
type TailvoyCapRule struct {
    Listeners []string `json:"listeners,omitempty"`
    Routes    []string `json:"routes,omitempty"`
    Hostnames []string `json:"hostnames,omitempty"`
}
```

Omitted or empty field = unrestricted on that dimension.

## Evaluation Semantics

- **Within a rule**: AND across dimensions. All specified dimensions must match.
- **Across rules**: OR. Any matching rule grants access.
- **`[{}]`** (empty rule): full access to everything.

## Hostname Sources by Layer

| Layer | Source |
|-------|--------|
| L4 TLS passthrough | SNI from ClientHello peek |
| L7 HTTP | `Host` header |
| L7 gRPC | `:authority` pseudo-header |
| L4 TCP (non-TLS) | Not available — hostnames field can't match |

## Identity Model

Rules are kept as discrete units, not merged into flat lists. Merging would lose AND relationships.

```go
type Identity struct {
    UserLogin   string
    NodeName    string
    Tags        []string
    IsTagged    bool
    TailscaleIP string
    Rules       []TailvoyCapRule  // replaces AllowedRoutes
}
```

## Engine Methods

```go
// L4: listener name + optional SNI
func (e *Engine) HasAccess(listener string, sni string, id *Identity) bool

// L7: listener name + hostname (Host header) + path
func (e *Engine) CheckAccess(listener string, hostname string, path string, id *Identity) bool
```

Both iterate `id.Rules` and return true if any rule matches all specified dimensions.

## Matching Logic

- **listeners**: current listener name must be in `rule.Listeners`. Omitted = all listeners.
- **routes**: path must match any pattern (existing glob logic). Omitted = all paths.
- **hostnames**: SNI/Host must match any pattern. Supports globs (`*.example.com`). Omitted = all hostnames.

## SNI Extraction

For TLS passthrough listeners, tailvoy peeks at the TLS ClientHello to extract SNI without terminating TLS. The first bytes of the connection are buffered, SNI is parsed, then the full stream (including the peeked bytes) is forwarded to the backend.

## Example Grants

```jsonc
// Frontend: HTTP listener, restricted paths
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [
            {"listeners": ["http"], "routes": ["/api/*", "/health"]}
        ]
    }
}

// DBA: postgres listener only
{
    "src": ["tag:dba"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [
            {"listeners": ["postgres"]}
        ]
    }
}

// TLS: hostname-scoped access
{
    "src": ["group:eng"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [
            {"listeners": ["tls"], "hostnames": ["app.example.com"]},
            {"listeners": ["tls"], "hostnames": ["staging.example.com"], "routes": ["/debug/*"]}
        ]
    }
}

// HTTP: multi-tenant virtual host gating
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [
            {"listeners": ["http"], "hostnames": ["api.example.com"], "routes": ["/v1/*"]},
            {"listeners": ["http"], "hostnames": ["admin.example.com"], "routes": ["/*"]}
        ]
    }
}

// Full access
{
    "src": ["group:admins"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{}]
    }
}
```

## Grant Merging Across ACL Entries

Multiple matching ACL grants produce multiple cap rules. These are collected into `Identity.Rules` as-is. Since evaluation is OR across rules, grants are additive:

```jsonc
// Grant 1: alice gets HTTP /api/*
{"listeners": ["http"], "routes": ["/api/*"]}
// Grant 2: group:eng (includes alice) gets postgres
{"listeners": ["postgres"]}
// alice's Identity.Rules = both rules above
// alice can access HTTP /api/* AND postgres
```

## Changes Required

| Component | Change |
|-----------|--------|
| `internal/identity/whois.go` | Parse `listeners`, `hostnames` from cap. Return `[]TailvoyCapRule` instead of merged routes. |
| `internal/policy/types.go` | Replace `AllowedRoutes []string` with `Rules []TailvoyCapRule`. |
| `internal/policy/engine.go` | Rewrite `HasAccess(listener, sni, id)` and `CheckAccess(listener, hostname, path, id)` to iterate rules with AND/OR semantics. Add `matchHostname()`. |
| `internal/proxy/listener.go` | Pass listener name to `HasAccess()`. For TLS passthrough, peek SNI and pass it. |
| `internal/proxy/udp.go` | Pass listener name to `HasAccess()`. |
| `internal/authz/extauthz.go` | Extract Host header. Pass listener name (from context_extensions) + hostname + path to `CheckAccess()`. |
| `internal/envoy/bootstrap.go` | No structural changes — context_extensions already passes listener name. |
| Tests | Rewrite for multi-dimensional rules. |
| README | Update examples for all dimensions. |
| ACL grants | Update kind test and ottawa grants. |
