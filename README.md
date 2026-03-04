# tailvoy

Tailscale identity-aware firewall for Envoy. tailvoy joins your tailnet, identifies callers via WhoIs, and enforces fine-grained L4/L7 access policies before traffic reaches your backend.

```
Tailnet Client (100.x.x.x)
        │
   tsnet Listener ── L4 policy (port/identity gating)
        │
    L4 Proxy ── PROXY protocol v2 (optional)
        │
      Envoy ── L7 policy via ext_authz (path, host, method)
        │
   Backend Service
```

## How it works

tailvoy embeds [tsnet](https://pkg.go.dev/tailscale.com/tsnet) to join the tailnet directly — no sidecar Tailscale daemon needed. Every inbound connection triggers a WhoIs lookup to resolve the caller's Tailscale identity (user, tags, node). L4 rules gate connections at the listener level. For HTTP traffic, tailvoy runs an [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) server that Envoy consults on every request, enabling path/host/method-level policies.

tailvoy manages Envoy as a subprocess. In standalone mode (`-standalone`), it auto-generates the Envoy bootstrap config from your policy file so you don't need to write Envoy YAML at all.

## Install

### Docker (recommended)

```sh
docker pull ghcr.io/rajsinghtech/tailvoy:latest
```

### Build from source

```sh
make build
```

Requires Go 1.25+.

## Usage

```sh
tailvoy -policy policy.yaml -standalone
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-policy` | `policy.yaml` | Path to policy file |
| `-authz-addr` | `127.0.0.1:9001` | ext_authz listen address |
| `-log-level` | `info` | Log level (`debug`/`info`/`warn`/`error`) |
| `-standalone` | `false` | Auto-generate Envoy bootstrap from policy |

Any arguments after `--` are passed directly to Envoy.

### Docker

```sh
docker run -e TS_AUTHKEY=tskey-auth-... \
  -v $(pwd)/policy.yaml:/policy.yaml \
  ghcr.io/rajsinghtech/tailvoy:latest \
  -policy /policy.yaml -standalone
```

## Policy

Policies are defined in YAML. Environment variables are expanded with `${VAR}` syntax.

```yaml
tailscale:
  hostname: "my-gateway"
  authkey: "${TS_AUTHKEY}"
  ephemeral: true

listeners:
  - name: https
    protocol: tcp
    listen: ":443"
    forward: "127.0.0.1:8080"
    proxy_protocol: v2
    l7_policy: true

  - name: metrics
    protocol: tcp
    listen: ":9090"
    forward: "127.0.0.1:9090"

l4_rules:
  - match:
      listener: https
    allow:
      any_tailscale: true

  - match:
      listener: metrics
    allow:
      tags: ["tag:monitoring"]

l7_rules:
  - match:
      listener: https
      path: "/admin/*"
      methods: ["GET", "POST"]
    allow:
      tags: ["tag:admin"]

  - match:
      listener: https
      path: "/api/*"
      host: "api.example.com"
    allow:
      users: ["alice@example.com"]

  - match:
      listener: https
      path: "/health"
    allow:
      any_tailscale: true

default: deny
```

### Policy reference

**Identity matchers** (used in `allow` blocks):

| Field | Description |
|-------|-------------|
| `any_tailscale: true` | Any authenticated Tailscale user |
| `users` | List of Tailscale login names |
| `tags` | List of Tailscale ACL tags |
| `groups` | List of Tailscale groups |

**L4 rules** match on `listener` name and gate entire connections.

**L7 rules** add `path` (glob patterns with `*`), `host` (supports `*.domain`), and `methods` (HTTP methods). Rules are evaluated first-match-wins.

## Development

```sh
make test              # unit tests with race detector
make lint              # golangci-lint
make cover             # coverage report
make integration-test  # full integration tests (requires TS_AUTHKEY)
make docker-build      # build container image
```

## License

[MIT](LICENSE)
