# tailvoy

Tailscale identity-aware proxy for Envoy. tailvoy joins your tailnet, identifies callers via WhoIs, and enforces access policy using [Tailscale peer capabilities](https://tailscale.com/kb/1324/acl-grants#app-capabilities) before traffic reaches your backend.

```
Tailnet Client (100.x.x.x)
        │
   tsnet Listener ── L4 check (has tailvoy cap?)
        │
   TCP/UDP Proxy ── PROXY protocol v2 (preserves client IP)
        │
      Envoy ── L7 check via gRPC ext_authz (cap routes match path?)
        │
   Backend Service
```

## How it works

tailvoy embeds [tsnet](https://pkg.go.dev/tailscale.com/tsnet) to join the tailnet directly — no sidecar Tailscale daemon needed. Every inbound connection triggers a WhoIs lookup to resolve the caller's Tailscale identity and peer capabilities.

Authorization is driven entirely by Tailscale ACL grants using the `rajsingh.info/cap/tailvoy` capability:

- **L4 gating**: if the caller has the tailvoy cap, the connection is allowed. No cap = connection reset.
- **L7 gating**: for HTTP/gRPC listeners, the cap's `routes` field controls which paths are accessible. tailvoy runs a gRPC [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) server that Envoy consults on every request.

The policy file (`policy.yaml`) only defines infrastructure — tailscale identity and listener configuration. All authorization lives in your Tailscale ACL.

### ACL grant example

```jsonc
// In your Tailscale ACL (policy.hujson)
{
    "grants": [
        {
            "src": ["alice@example.com"],
            "dst": ["tag:my-gateway"],
            "app": {
                "rajsingh.info/cap/tailvoy": [{"routes": ["/api/*", "/health"]}]
            }
        },
        {
            "src": ["group:admins"],
            "dst": ["tag:my-gateway"],
            "app": {
                "rajsingh.info/cap/tailvoy": [{"routes": ["/*"]}]
            }
        }
    ]
}
```

- `alice@example.com` can access `/api/*` and `/health` on the gateway
- `group:admins` gets full access (`/*`)
- Anyone without the cap is denied at L4
- Multiple matching grants merge routes additively
- A cap with no `routes` field grants full access (`/*`)

### Deployment modes

- **Standalone** (`-standalone`): tailvoy auto-generates Envoy bootstrap config and manages Envoy as a subprocess. No Envoy YAML needed.
- **Envoy Gateway data plane**: tailvoy replaces the default Envoy image via the `EnvoyProxy` CRD, acting as the data plane for [Envoy Gateway](https://gateway.envoyproxy.io/). EG manages routing via xDS while tailvoy handles Tailscale ingress and cap-based policy.

## Supported protocols

| Protocol | Listener | Policy |
|----------|----------|--------|
| TCP | `protocol: tcp` | L4 cap check |
| UDP | `protocol: udp` | L4 cap check |
| HTTP | TCP listener with `l7_policy: true` | L4 cap check + L7 route matching via ext_authz |
| gRPC | TCP listener with `l7_policy: true` | L4 cap check + L7 route matching via ext_authz |
| TLS passthrough | TCP listener (no `l7_policy`) | L4 cap check only |

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

For L7 listeners, apply a SecurityPolicy with gRPC ext_authz:

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
```

> **Requires Envoy Gateway v1.7.0+** for gRPC ext_authz support.

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

## Policy file

The policy file defines infrastructure only. Environment variables are expanded with `${VAR}` syntax.

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
```

### Listener options

| Field | Description |
|-------|-------------|
| `name` | Listener identifier |
| `protocol` | `tcp` or `udp` |
| `listen` | Address to bind (e.g. `:443`) |
| `forward` | Backend address to proxy to |
| `proxy_protocol` | Set to `v2` to prepend a PROXY protocol v2 header. Preserves the caller's Tailscale IP so Envoy and your backend see the real client address. |
| `l7_policy` | Set to `true` to route through Envoy with ext_authz for path-level policy. When `false`, the listener is L4-only (pure TCP/UDP forwarding after cap check). |

### Route patterns

Routes in the tailvoy cap use glob-style matching:

| Pattern | Matches |
|---------|---------|
| `/*` | All paths |
| `/api/*` | `/api/`, `/api/users`, `/api/v1/foo` |
| `/health` | Exactly `/health` |
| `/admin/*` | `/admin/`, `/admin/settings`, `/admin/users/1` |

## Identity headers

On allowed L7 requests, tailvoy injects identity headers into the request before it reaches your backend:

| Header | Value |
|--------|-------|
| `X-Tailscale-User` | Tailscale login (e.g. `alice@example.com`) |
| `X-Tailscale-Node` | Node FQDN (e.g. `alices-laptop.tailnet.ts.net`) |
| `X-Tailscale-Ip` | Tailscale IP (e.g. `100.64.0.1`) |
| `X-Tailscale-Tags` | Comma-separated ACL tags |

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
