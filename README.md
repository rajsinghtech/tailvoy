# tailvoy

Tailscale identity-aware firewall for Envoy. tailvoy joins your tailnet, identifies callers via WhoIs, and enforces fine-grained L4/L7 access policies before traffic reaches your backend.

```
Tailnet Client (100.x.x.x)
        │
   tsnet Listener ── L4 policy (identity gating per listener)
        │
   TCP/UDP Proxy ── PROXY protocol v2 (preserves client IP)
        │
      Envoy ── L7 policy via ext_authz (path, host, method)
        │
   Backend Service
```

## How it works

tailvoy embeds [tsnet](https://pkg.go.dev/tailscale.com/tsnet) to join the tailnet directly — no sidecar Tailscale daemon needed. Every inbound connection triggers a WhoIs lookup to resolve the caller's Tailscale identity (user, tags, node). L4 rules gate connections at the listener level. For HTTP/gRPC traffic, tailvoy runs a gRPC [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) server that Envoy consults on every request, enabling path/host/method-level policies. In EG data plane mode, each SecurityPolicy uses `contextExtensions` to pass the listener name to the auth server per-route, so policy evaluation targets the correct listener.

tailvoy supports two deployment modes:

- **Standalone** (`-standalone`): tailvoy auto-generates Envoy bootstrap config and manages Envoy as a subprocess. No Envoy YAML needed.
- **Envoy Gateway data plane**: tailvoy replaces the default Envoy image via the `EnvoyProxy` CRD, acting as the data plane for [Envoy Gateway](https://gateway.envoyproxy.io/). EG manages routing via xDS while tailvoy handles Tailscale ingress and identity-based policy.

## Supported protocols

| Protocol | Listener | Policy |
|----------|----------|--------|
| TCP | `protocol: tcp` | L4 identity check |
| UDP | `protocol: udp` | L4 identity check |
| HTTP | TCP listener with `l7_policy: true` | L4 + L7 ext_authz (path/host/method) |
| gRPC | TCP listener with `l7_policy: true` | L4 + L7 ext_authz (service/method path) |
| TLS passthrough | TCP listener (no `l7_policy`) | L4 identity check only |

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

### Standalone mode

```sh
tailvoy -policy policy.yaml -standalone
```

### Envoy Gateway data plane

Deploy tailvoy as the EG data plane via the `EnvoyProxy` CRD:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: tailvoy-proxy
  namespace: envoy-gateway-system
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyDeployment:
        container:
          image: "ghcr.io/rajsinghtech/tailvoy:latest"
        patch:
          type: StrategicMerge
          value:
            spec:
              template:
                spec:
                  containers:
                    - name: envoy
                      command: ["tailvoy", "--policy", "/etc/tailvoy/policy.yaml",
                                "--authz-addr", "0.0.0.0:9001", "--"]
                      env:
                        - name: TS_AUTHKEY
                          valueFrom:
                            secretKeyRef:
                              name: tailvoy-authkey
                              key: TS_AUTHKEY
                      volumeMounts:
                        - name: tailvoy-policy
                          mountPath: /etc/tailvoy
                          readOnly: true
                  volumes:
                    - name: tailvoy-policy
                      configMap:
                        name: tailvoy-policy
```

EG's generated Envoy args are appended after `--` automatically.

Then apply a SecurityPolicy with gRPC ext_authz and `contextExtensions` to pass the listener name:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: tailvoy-authz
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: my-route
  extAuth:
    grpc:
      backendRefs:
        - name: tailvoy-authz
          namespace: envoy-gateway-system
          port: 9001
    contextExtensions:
      - name: listener
        type: Value
        value: "http"    # must match a listener name in the policy file
```

The `contextExtensions` field tells Envoy to include `{"listener": "http"}` in the gRPC `CheckRequest` sent to the auth server. This is how tailvoy knows which listener's L7 rules to evaluate for each route. Without it, requests fall back to the `"default"` listener.

> **Requires Envoy Gateway v1.7.0+** — `contextExtensions` support was added in [envoyproxy/gateway#7383](https://github.com/envoyproxy/gateway/pull/7383).

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

  - name: dns
    protocol: udp
    listen: ":53"
    forward: "127.0.0.1:1053"

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
      listener: dns
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

### Listener options

| Field | Description |
|-------|-------------|
| `name` | Listener identifier, referenced by rules |
| `protocol` | `tcp` or `udp` |
| `listen` | Address to bind (e.g. `:443`) |
| `forward` | Backend address to proxy to |
| `proxy_protocol` | Set to `v2` to prepend a PROXY protocol v2 header. Preserves the caller's Tailscale IP so Envoy and your backend see the real client address. |
| `l7_policy` | Set to `true` to route through Envoy with ext_authz for HTTP-level rules. When `false`, the listener is L4-only (pure TCP/UDP forwarding after identity check). |

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
make integration-test  # docker compose integration tests (requires TS_AUTHKEY)
make kind-test         # kind cluster integration tests (requires TS_AUTHKEY)
make docker-build      # build container image
```

## License

[MIT](LICENSE)
