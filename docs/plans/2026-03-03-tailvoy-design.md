# tailvoy Design Document

## Overview

tailvoy is a Tailscale identity-aware firewall that wraps Envoy proxy. It uses tsnet to join a tailnet directly, performs WhoIs lookups on every connection to identify callers (user, node, tags), and enforces access policies before forwarding traffic to Envoy for proxying.

tailvoy is an L4 firewall with L7 awareness — it never touches TLS, certificates, or HTTP parsing itself. Envoy handles all actual proxying. tailvoy gates access based on Tailscale identity at two levels:

- **L4 (connection time):** block/allow by source identity + port/protocol
- **L7 (HTTP request time):** block/allow by source identity + HTTP path, via Envoy's ext_authz filter

## Architecture

```
                     tailvoy                          Envoy
                  ┌────────────┐                   ┌───────────────────────┐
                  │            │  raw TCP forward   │  TLS termination     │
 Tailnet ────────>│ tsnet L4   │──────────────────>│  certificates        │
 Client           │ WhoIs      │  PROXY protocol   │  routing             │
 (100.x.x.x)     │ + policy   │  (preserves src)  │  load balancing      │
                  │            │                    │  ext_authz -> tailvoy│
                  │ :9001 <────┼────────────────────┤  for path decisions  │
                  │ (authz)    │                    │                      │
                  └────────────┘                    └───────────────────────┘
```

### Components

1. **tailvoy binary** (Go, uses tsnet) — tsnet listener, L4 gate, ext_authz server, Envoy process manager
2. **Envoy binary** — managed as a subprocess by tailvoy, handles all proxying
3. **policy.yaml** — user-authored access control rules (L4 + L7)
4. **envoy.yaml** — generated or augmented by tailvoy to inject ext_authz filter config

### Roles

| Role | Description |
|------|-------------|
| tsnet listener | Joins the tailnet, accepts connections on configured ports |
| L4 gate | WhoIs check on every TCP/UDP connection before forwarding to Envoy |
| ext_authz server | HTTP service on localhost:9001 that Envoy calls for L7 path decisions |
| Envoy manager | Starts Envoy as subprocess, injects ext_authz config, passes through all other args |

## Data Flows

### L4 Flow (TCP/UDP — port-based identity gating)

```
1. Client (100.64.1.5) connects to tsnet listener :5432
2. tailvoy: WhoIs("100.64.1.5") -> {tags:["tag:db-access"], user:"dba@co.com"}
3. Policy check: listener=postgres, identity matches -> ALLOW
4. tailvoy dials Envoy :5432 (or direct backend if configured)
5. Raw byte proxying (io.Copy both directions)
6. If DENY: close immediately, log rejection
```

### L7 Flow (HTTP path-based identity gating)

```
1. Client (100.64.1.5) connects to tsnet listener :443
2. tailvoy: L4 policy check (port 443 allowed for this identity?) -> ALLOW at L4
3. tailvoy sends PROXY protocol v2 header with source 100.64.1.5 to Envoy :443
4. tailvoy forwards raw TLS bytes to Envoy (never decrypts)
5. Envoy terminates TLS (certs from gateway config or envoy.yaml)
6. Envoy parses HTTP, hits ext_authz filter
7. ext_authz calls tailvoy :9001 with source IP (from PROXY protocol) + path + method
8. tailvoy: WhoIs("100.64.1.5") -> identity (cached from step 2)
9. Policy check: path="/admin/*" + identity -> ALLOW or DENY
10. Envoy forwards to backend with identity headers (or returns 403)
```

### Connection Tracking

tailvoy maintains a lightweight cache of `tailscaleIP -> WhoIsResponse` populated at L4 gate time (step 2). The ext_authz handler reuses this cache to avoid double WhoIs calls. Cache entries expire when the connection closes.

## Policy Format

```yaml
# policy.yaml
tailscale:
  hostname: "tailvoy-gw"
  authkey: "${TS_AUTHKEY}"       # env var expansion
  ephemeral: true

listeners:
  - name: https
    protocol: tcp                # tailvoy treats as raw TCP
    listen: ":443"
    forward: "envoy:443"         # raw forward to Envoy
    proxy_protocol: v2           # preserve source IP
    l7_policy: true              # enable ext_authz for HTTP path decisions

  - name: http
    protocol: tcp
    listen: ":80"
    forward: "envoy:80"
    proxy_protocol: v2
    l7_policy: true

  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "db-server:5432"    # direct to backend, no Envoy
    l7_policy: false

  - name: dns
    protocol: udp
    listen: ":5353"
    forward: "dns-server:53"
    l7_policy: false

# L4 rules — evaluated at connection time
l4_rules:
  - match:
      listener: https
    allow:
      any_tailscale: true

  - match:
      listener: postgres
    allow:
      tags: ["tag:db-access"]
      users: ["dba@company.com"]

  - match:
      listener: dns
    allow:
      any_tailscale: true

# L7 rules — evaluated by ext_authz on HTTP requests
l7_rules:
  - match:
      listener: https
      path: "/admin/*"
    allow:
      users: ["alice@company.com"]
      tags: ["tag:admin"]

  - match:
      listener: https
      path: "/api/*"
    allow:
      tags: ["tag:prod", "tag:staging"]

  - match:
      listener: https
      path: "/*"
    allow:
      any_tailscale: true

default: deny
```

### Policy Evaluation

- Rules evaluated top-to-bottom, first match wins
- `users` matches `WhoIs.UserProfile.LoginName`
- `tags` matches `WhoIs.Node.Tags`
- `groups` matches Tailscale ACL groups (resolved via peer capabilities)
- `any_tailscale: true` matches any authenticated Tailscale identity
- `default: deny` — unmatched connections/requests are rejected
- Policy file supports hot-reload on file change (fsnotify)

## envoy-gateway Drop-in Replacement

### Contract

tailvoy's Docker image must satisfy the envoy-gateway contract:

| Requirement | Value |
|-------------|-------|
| Binary | `envoy` in PATH |
| Args | `--config-yaml`, `--service-cluster`, `--service-node`, `--log-level`, `--cpuset-threads`, `--drain-strategy`, `--drain-time-s` |
| Admin port | 19000 |
| Stats port | 19001 (Prometheus at `/stats/prometheus`) |
| Readiness | `GET /ready` on port 19003 returns 200 |
| UID | 65532 (non-root, distroless) |
| Volumes | `/certs` (TLS), `/sds` (SDS config) |
| XDS | delta gRPC v3 |

### Strategy

The tailvoy Docker image:

1. Starts FROM `envoyproxy/envoy:distroless-v1.37.0`
2. ADDs the `tailvoy` binary
3. Replaces the entrypoint: tailvoy starts first, launches `envoy` as subprocess
4. tailvoy intercepts `--config-yaml` to inject ext_authz filter pointing to localhost:9001
5. All other args pass through to the real Envoy binary
6. Health checks, XDS, admin — all handled by real Envoy, transparent to gateway

Users swap the image in their EnvoyProxy CRD:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyDeployment:
        container:
          image: "ghcr.io/rajsinghtech/tailvoy:v0.1.0"
```

Gateway doesn't know tailvoy exists — it sees Envoy responding normally.

### Config Injection

When tailvoy intercepts `--config-yaml`:

1. Parse the bootstrap YAML from gateway
2. For each HTTP listener, inject an ext_authz HTTP filter pointing to `127.0.0.1:9001`
3. Add PROXY protocol listener filter to accept source IPs from tailvoy's L4 forwarding
4. Pass modified YAML to real Envoy via `--config-yaml`

For standalone mode (no gateway), tailvoy generates the full envoy.yaml from policy.yaml.

## Project Structure

```
tailvoy/
├── cmd/
│   └── tailvoy/
│       └── main.go              # entry point: parse flags, start tsnet, launch envoy
├── internal/
│   ├── config/
│   │   └── config.go            # parse policy.yaml, env var expansion
│   ├── identity/
│   │   └── whois.go             # WhoIs wrapper, connection cache (IP -> identity)
│   ├── proxy/
│   │   ├── l4.go                # TCP/UDP raw proxy with PROXY protocol v2
│   │   └── listener.go          # tsnet listener management per policy listener
│   ├── authz/
│   │   └── extauthz.go          # ext_authz HTTP server on :9001
│   ├── policy/
│   │   └── engine.go            # rule matching engine (L4 + L7), hot-reload
│   └── envoy/
│       ├── manager.go           # start/stop Envoy subprocess, signal forwarding
│       └── bootstrap.go         # parse/inject ext_authz into envoy bootstrap yaml
├── policy.yaml                  # example policy
├── Dockerfile                   # tailvoy + envoy in one image
├── go.mod
└── go.sum
```

## Key Dependencies

| Dependency | Purpose |
|------------|---------|
| `tailscale.com/tsnet` | Join tailnet, listen for connections |
| `tailscale.com/client/local` | WhoIs API for identity lookups |
| `tailscale.com/tailcfg` | Node, UserProfile, tag types |
| `github.com/pires/go-proxyproto` | PROXY protocol v2 encoding |
| `gopkg.in/yaml.v3` | Policy YAML parsing |
| `github.com/fsnotify/fsnotify` | Policy hot-reload |

## Milestones

### v0.1 — Core Firewall
- tsnet listener with WhoIs-based L4 gating
- TCP proxy with PROXY protocol v2
- Policy YAML parsing (l4_rules)
- Envoy subprocess management (standalone mode)
- ext_authz HTTP server for L7 path decisions
- Docker image (tailvoy + Envoy)

### v0.2 — Gateway Integration
- Bootstrap YAML interception and ext_authz injection
- Drop-in replacement for envoy-gateway EnvoyProxy image
- Policy hot-reload via fsnotify

### v0.3 — Advanced Features
- UDP proxy support
- Group-based rules
- Structured logging with identity context
- Prometheus metrics (connections allowed/denied by identity)
- Connection draining on policy change
