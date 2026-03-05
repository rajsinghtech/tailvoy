# Config v2 Design

Redesign the tailvoy static config format for standalone mode. Goal: make tailvoy
the obvious choice for Docker users who want a Tailscale-aware gateway. No backwards
compatibility.

## Principles

- **Config controls where traffic goes.** ACL grants control who has access.
- **Standalone is the default.** No `-standalone` flag needed. Discovery/Envoy Gateway
  is the opt-in advanced path.
- **OAuth only.** Credentials come from `TS_CLIENT_ID` and `TS_CLIENT_SECRET` env vars.
  No auth keys, no credentials in the config file.
- **Protocol field encodes behavior.** A single `protocol` value determines TLS handling,
  L7 routing capability, and transport. No more `l7_policy` boolean.

## Config Structure

Three top-level sections:

```yaml
tailscale:
  # Tailscale identity and service registration

listeners:
  # Named listeners with protocol, port, routing, and backends
```

### tailscale

```yaml
tailscale:
  service: my-gw            # VIP name: svc:my-gw, node hostname: my-gw-tailvoy
  tags:
    - tag:my-gw              # ACL tags for the tsnet node
  serviceTags:
    - tag:my-gw              # ACL tags for the VIP service
```

- `service` (required): derives node hostname (`<service>-tailvoy`) and VIP name (`svc:<service>`).
- `tags` (required): tags applied to the ephemeral tsnet node.
- `serviceTags` (required): tags applied to the VIP service.
- `clientId`/`clientSecret` are removed. Read from `TS_CLIENT_ID` and `TS_CLIENT_SECRET`
  environment variables.

### listeners

Map keyed by listener name (used in ACL grants). Each listener has a `port`, `protocol`,
and either a direct `backend` or a `routes` list.

```yaml
listeners:
  <name>:
    port: <number>
    protocol: <http|https|grpc|tls|tcp|udp>
    tls:                      # optional, for https/grpc only
      cert: <path>
      key: <path>
    backend: <host:port>      # simple listeners (tcp/udp/tls without hostname routing)
    routes:                   # L7 or hostname-based routing
      - hostname: <pattern>
        tls:                  # optional per-hostname override
          cert: <path>
          key: <path>
        backend: <host:port>  # single backend for this hostname
        paths:                # path-based routing within hostname
          <pattern>: <host:port>
```

### Protocol behavior

| Protocol | TLS termination | L7 routing (paths + hostnames) | SNI hostname match | Transport |
|----------|----------------|-------------------------------|-------------------|-----------|
| `http`   | none           | yes                           | n/a               | TCP       |
| `https`  | Envoy          | yes                           | n/a               | TCP       |
| `grpc`   | Envoy          | yes                           | n/a               | TCP       |
| `tls`    | passthrough    | no                            | yes (SNI peek)    | TCP       |
| `tcp`    | n/a            | no                            | no                | TCP       |
| `udp`    | n/a            | no                            | no                | UDP       |

### TLS

- `https` and `grpc` listeners terminate TLS at Envoy. User provides cert/key.
- `tls` listeners pass through the raw TLS connection. tailvoy peeks at ClientHello
  for SNI-based hostname matching.
- TLS config is set at listener level (default) and optionally overridden per hostname.
- `http`, `tcp`, `udp` have no TLS config.

### Routing rules

**L7 protocols** (`http`, `https`, `grpc`):
- `routes` is a list of hostname blocks.
- Each hostname block has either `backend` (single destination) or `paths` (map of
  path pattern to backend address).
- A route without `hostname` is the default/catch-all.
- Path matching follows existing glob-style rules (`/api/*`, `/health`, `/*`).

**TLS passthrough** (`tls`):
- `routes` is a list of hostname blocks with SNI matching.
- Each hostname block has a `backend`.
- Wildcard hostnames supported (`*.example.com`).

**Simple protocols** (`tcp`, `udp`):
- `backend` directly on the listener. No routes.

### Backends

Inline `host:port` strings. No separate backends section. This keeps the config flat
and avoids indirection for the common case. If a backend is reused across routes, the
address is repeated -- acceptable tradeoff for simplicity.

## Full example

```yaml
tailscale:
  service: my-gw
  tags:
    - tag:my-gw
  serviceTags:
    - tag:my-gw

listeners:
  web:
    port: 443
    protocol: https
    tls:
      cert: /certs/wildcard.pem
      key: /certs/wildcard-key.pem
    routes:
      - hostname: app.example.com
        paths:
          /api/*: api:8080
          /admin/*: admin:3000
          /*: frontend:3000

      - hostname: blog.example.com
        backend: ghost:2368

      - hostname: special.other.com
        tls:
          cert: /certs/other.pem
          key: /certs/other-key.pem
        backend: other-app:8080

  plain:
    port: 80
    protocol: http
    routes:
      - backend: app:8080

  grpc:
    port: 50051
    protocol: grpc
    tls:
      cert: /certs/grpc.pem
      key: /certs/grpc-key.pem
    routes:
      - hostname: api.example.com
        paths:
          /myapp.UserService/*: user-svc:50051
          /myapp.OrderService/*: order-svc:50052

  vault:
    port: 8443
    protocol: tls
    routes:
      - hostname: vault.example.com
        backend: vault:8200
      - hostname: "*.internal.com"
        backend: internal-proxy:443

  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432

  dns:
    port: 53
    protocol: udp
    backend: coredns:1053
```

## Minimal example

```yaml
tailscale:
  service: my-app
  tags:
    - tag:my-app
  serviceTags:
    - tag:my-app

listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: app:8080
```

## Validation rules

- `tailscale.service` required.
- `tailscale.tags` required, non-empty.
- `tailscale.serviceTags` required, non-empty.
- `TS_CLIENT_ID` and `TS_CLIENT_SECRET` env vars must be set (validated at startup, not in config parsing).
- Each listener must have a unique `port`.
- Each listener must have a valid `protocol`.
- `http`, `https`, `grpc` listeners must have `routes` (not `backend`).
- `tcp`, `udp` listeners must have `backend` (not `routes`).
- `tls` listeners must have `routes` with hostname blocks (SNI matching).
- `tls` config required on `https`/`grpc` listeners (no auto-certs).
- `tls` config not allowed on `http`, `tcp`, `udp` listeners.
- Listener names must be unique (enforced by map keys).
- Path patterns must start with `/`.
- Backend addresses must be `host:port` format.

## What this replaces

| v1 field | v2 equivalent |
|----------|---------------|
| `listeners[].name` | map key |
| `listeners[].protocol: tcp` + `l7_policy: true` | `protocol: http` or `protocol: https` |
| `listeners[].protocol: tcp` + `l7_policy: false` | `protocol: tcp` or `protocol: tls` |
| `listeners[].protocol: udp` | `protocol: udp` |
| `listeners[].listen: ":443"` | `port: 443` |
| `listeners[].forward: "host:port"` | `backend: host:port` or route-level backends |
| `listeners[].proxy_protocol: v2` | automatic in standalone mode (internal detail) |
| `tailscale.clientId` | `TS_CLIENT_ID` env var |
| `tailscale.clientSecret` | `TS_CLIENT_SECRET` env var |
| `-standalone` flag | default behavior |

## Out of scope

- Discovery mode / Envoy Gateway integration (separate design)
- Docker label-based discovery (rejected -- security concerns with socket access)
- Tailscale HTTPS auto-certs (user-provided only)
- Auth key support (OAuth only)
- Separate backends section (inline addresses only)
