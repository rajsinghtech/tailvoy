# tailvoy

Tailscale identity-aware proxy for Envoy. tailvoy joins your tailnet, identifies callers via WhoIs, and enforces access policy using [Tailscale peer capabilities](https://tailscale.com/kb/1324/acl-grants#app-capabilities) before traffic reaches your backend.

```
Tailnet Client (100.x.x.x)
        |
   tsnet Listener -- L4 check (listener + hostname match?)
        |
   TCP/UDP Proxy -- PROXY protocol v2 (preserves client IP)
        |
      Envoy -- L7 check via gRPC ext_authz (listener + hostname + path match?)
        |
   Backend Service
```

## Quickstart

```sh
docker pull ghcr.io/rajsinghtech/tailvoy:latest
```

Create `config.yaml`:

```yaml
tailscale:
  serviceMappings:
    web: [http]
  tags: ["tag:my-gw"]
  serviceTags: ["tag:my-gw"]

listeners:
  http:
    port: 80
    protocol: http
    routes:
      - backend: 127.0.0.1:8080
```

Run:

```sh
docker run \
  -e TS_CLIENT_ID=... \
  -e TS_CLIENT_SECRET=... \
  -v $(pwd)/config.yaml:/config.yaml \
  ghcr.io/rajsinghtech/tailvoy:latest \
  -config /config.yaml
```

tailvoy connects to the tailnet, creates VIP services per service mapping, generates Envoy config, and starts proxying. Authorization is controlled entirely by your Tailscale ACL -- the config file defines infrastructure and service identity.

## How it works

tailvoy embeds [tsnet](https://pkg.go.dev/tailscale.com/tsnet) to join the tailnet as an ephemeral OAuth node. It uses [Tailscale Services](https://tailscale.com/docs/features/tailscale-services) (`tsnet.ListenService`) with per-service VIPs so each service mapping gets its own stable address and multiple replicas can serve it. Every connection triggers a WhoIs lookup to resolve the caller's identity and peer capabilities.

Authorization uses the `rajsingh.info/cap/tailvoy` capability with three dimensions:

| Dimension | Controls | Source |
|-----------|----------|--------|
| `listeners` | Which listeners a peer can reach | Listener name from config or Envoy |
| `routes` | Which paths are accessible (L7 only) | Request path |
| `hostnames` | Which hostnames are allowed | TLS SNI / HTTP Host header |

**Within a rule**: AND -- all specified dimensions must match.
**Across rules**: OR -- any matching rule grants access.
**Omitted dimension**: unrestricted.

## Deployment modes

### Standalone (default)

tailvoy auto-generates Envoy bootstrap config from your listener definitions and manages Envoy as a subprocess. No Envoy YAML needed. Best when you want explicit control over listeners.

```sh
tailvoy -config config.yaml
```

### Envoy Gateway data plane

tailvoy replaces the default Envoy image via the `EnvoyProxy` CRD, acting as the data plane for [Envoy Gateway](https://gateway.envoyproxy.io/). EG manages routing via xDS while tailvoy handles Tailscale ingress and policy. Uses discovery mode to auto-create listeners as Gateway resources change.

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
                      command: ["tailvoy", "--config", "/etc/tailvoy/config.yaml",
                                "--authz-addr", "0.0.0.0:9001", "--"]
                      env:
                        - name: TS_CLIENT_ID
                          valueFrom:
                            secretKeyRef:
                              name: tailvoy-oauth
                              key: TS_CLIENT_ID
                        - name: TS_CLIENT_SECRET
                          valueFrom:
                            secretKeyRef:
                              name: tailvoy-oauth
                              key: TS_CLIENT_SECRET
                      volumeMounts:
                        - name: tailvoy-policy
                          mountPath: /etc/tailvoy
                          readOnly: true
                  volumes:
                    - name: tailvoy-policy
                      configMap:
                        name: tailvoy-policy
```

EG's generated Envoy args are appended after `--` automatically. Requires Envoy Gateway v1.7.0+.

For L7 listeners, apply a SecurityPolicy with gRPC ext_authz pointing at tailvoy's authz server:

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

## Configuration

### Tailscale

```yaml
tailscale:
  serviceMappings:            # map of service name -> listener names
    web: [http, https]        # svc:web serves ports 80 + 443
    postgres: [db]            # svc:postgres serves port 5432
  tags: ["tag:my-gw"]        # ACL tags for the tsnet node
  serviceTags: ["tag:my-gw"] # ACL tags for VIP services
  hostname: tailvoy-proxy    # optional: tsnet node hostname (default: tailvoy-proxy)
```

Credentials are read from `TS_CLIENT_ID` and `TS_CLIENT_SECRET` environment variables. Your ACL must include:

```jsonc
{
    "tagOwners": { "tag:my-gw": ["autogroup:admin"] },
    "autoApprovers": {
        "services": {
            "svc:web": ["tag:my-gw"],
            "svc:postgres": ["tag:my-gw"]
        }
    }
}
```

### Listeners

Listeners are a named map. The key is the listener name used in ACL cap rules.

| Protocol | Behavior | Config |
|----------|----------|--------|
| `http` | L7 via Envoy with ext_authz | `routes` required |
| `https` | L7 via Envoy, TLS terminated | `routes` + `tls` required |
| `grpc` | L7 via Envoy with ext_authz | `routes` required, optional `tls` |
| `tls` | Passthrough, SNI-based routing | `routes` with `hostname` + `backend` |
| `tcp` | Plain TCP forwarding | `backend` required |
| `udp` | UDP forwarding (no VIP support) | `backend` required |

L7 protocols (`http`, `https`, `grpc`) route through Envoy for path-level policy. L4 protocols (`tls`, `tcp`, `udp`) are handled directly by tailvoy.

```yaml
listeners:
  # L7: HTTP with hostname-based virtual hosting and path routing
  http:
    port: 80
    protocol: http
    routes:
      - hostname: app.example.com
        backend: frontend:3000
      - hostname: api.example.com
        paths:
          /v1/*: api-v1:8080
          /v2/*: api-v2:8080
      - backend: fallback:8080          # catch-all

  # L7: gRPC with TLS termination
  grpc:
    port: 50051
    protocol: grpc
    tls:
      cert: /certs/cert.pem
      key: /certs/key.pem
    routes:
      - backend: grpc-backend:50051

  # L4: TLS passthrough with SNI routing
  tls:
    port: 443
    protocol: tls
    routes:
      - hostname: app.example.com
        backend: app:8443
      - hostname: admin.example.com
        backend: admin:8443

  # L4: plain TCP
  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432

  # L4: UDP (node IP only, VIP services don't support UDP)
  dns:
    port: 53
    protocol: udp
    backend: dns:1053
```

### Discovery mode

Instead of static listeners, tailvoy can poll Envoy's admin API to auto-discover listeners. Mutually exclusive with `listeners`.

```yaml
tailscale:
  serviceMappings:
    http: ["default/eg/http"]
    tcp: ["default/eg/tcp"]
  tags: ["tag:my-gw"]
  serviceTags: ["tag:my-gw"]

discovery:
  envoyAdmin: "http://127.0.0.1:19000"
  envoyAddress: "127.0.0.1"
  pollInterval: "5s"
  proxyProtocol: v2
  listenerFilter: "default/eg/.*"      # optional: regex to include only matching names
  healthPolicy: "any"                   # optional: "any" (default) or "all"
  unhealthyThreshold: 3                 # optional: consecutive unhealthy polls before unadvertise (default: 3)
```

#### Health-based VIP advertisement

In discovery mode, tailvoy monitors Envoy cluster health via the `/clusters` admin endpoint. When backends go down, VIP services are automatically unadvertised to prevent traffic from being routed into a black hole.

| Setting | Default | Description |
|---------|---------|-------------|
| `healthPolicy` | `any` | `any`: unadvertise if ANY cluster has 0 healthy hosts. `all`: unadvertise only if ALL clusters have 0 healthy hosts. |
| `unhealthyThreshold` | `3` | Number of consecutive unhealthy polls before unadvertising a service. Recovery (readvertise) is immediate. |

Health checks run at the same interval as discovery polling (`pollInterval`). tsnet listeners stay alive during unadvertisement — only the VIP service advertisement is toggled via `EditPrefs`.

In discovery mode, `serviceMappings` maps Envoy Gateway listener names (format: `<namespace>/<gateway>/<listener>`) to VIP service names. Discovered listeners not in any mapping are skipped with a warning.

Discovered listener names follow Envoy Gateway convention: `<namespace>/<gateway>/<listener>`. Use these names in ACL grants and SecurityPolicy `contextExtensions`:

```yaml
contextExtensions:
  - name: listener
    type: Value
    value: "default/eg/http"
```

## Authorization

All authorization lives in your Tailscale ACL using `rajsingh.info/cap/tailvoy` grants. The config file never defines who can access what.

### Cap rule schema

```jsonc
"rajsingh.info/cap/tailvoy": [
    {
        "listeners": ["http", "grpc"],       // optional: which listeners
        "routes": ["/api/*", "/health"],      // optional: which paths (L7 only)
        "hostnames": ["app.example.com"]      // optional: which hostnames
    }
]
```

An empty rule `[{}]` grants unrestricted access.

### Route patterns

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `/*` | All paths | -- |
| `/api/*` | `/api/users`, `/api/v1/foo` | `/apiv2` |
| `/health` | Exactly `/health` | `/health/`, `/healthz` |
| `/grpc.health.v1.Health/*` | `/grpc.health.v1.Health/Check` | `/grpc.other.Service/Method` |

### Hostname patterns

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `app.example.com` | Exactly `app.example.com` | `other.example.com` |
| `*.example.com` | `app.example.com`, `sub.app.example.com` | `example.com` |

### Example: multi-team gateway

A single tailvoy instance with scoped access per team:

```yaml
tailscale:
  serviceMappings:
    http: [http]
    grpc: [grpc]
    postgres: [postgres]
    tls: [tls]
  tags: ["tag:my-gw"]
  serviceTags: ["tag:my-gw"]

listeners:
  http:
    port: 80
    protocol: http
    routes:
      - backend: web:8080
  grpc:
    port: 50051
    protocol: grpc
    routes:
      - backend: grpc:50051
  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432
  tls:
    port: 443
    protocol: tls
    routes:
      - hostname: app.example.com
        backend: app:8443
```

```jsonc
{
    "grants": [
        {
            // Frontend: HTTP + gRPC health only
            "src": ["tag:frontend"], "dst": ["svc:http", "svc:grpc"],
            "app": { "rajsingh.info/cap/tailvoy": [{
                "routes": ["/api/*", "/grpc.health.v1.Health/*"]
            }]}
        },
        {
            // DBA: postgres only
            "src": ["tag:dba"], "dst": ["svc:postgres"]
        },
        {
            // Engineers: TLS to app.example.com only
            "src": ["group:engineers"], "dst": ["svc:tls"],
            "app": { "rajsingh.info/cap/tailvoy": [{
                "hostnames": ["app.example.com"]
            }]}
        },
        {
            // Ops: all services
            "src": ["group:ops"], "dst": ["svc:http", "svc:grpc", "svc:postgres", "svc:tls"],
            "app": { "rajsingh.info/cap/tailvoy": [{}] }
        }
    ]
}
```

| Caller | HTTP `/api/users` | gRPC `Health/Check` | postgres | TLS `app.example.com` |
|--------|:---:|:---:|:---:|:---:|
| tag:frontend | 200 | OK | conn reset | conn reset |
| tag:dba | conn reset | conn reset | allowed | conn reset |
| group:engineers | conn reset | conn reset | conn reset | allowed |
| group:ops | 200 | OK | allowed | allowed |

Multiple matching grants merge via OR -- if alice is in both `tag:frontend` and `group:engineers`, she gets HTTP + gRPC + TLS access.

## Reference

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `config.yaml` | Path to config file |
| `-authz-addr` | `127.0.0.1:9001` | ext_authz listen address |
| `-log-level` | `info` | Log level (`debug`/`info`/`warn`/`error`) |

Arguments after `--` are passed directly to Envoy.

### Identity headers

On allowed L7 requests, tailvoy injects headers before the request reaches the backend:

| Header | Value |
|--------|-------|
| `X-Tailscale-User` | Tailscale login (e.g. `alice@example.com`) |
| `X-Tailscale-Node` | Node FQDN (e.g. `alices-laptop.tailnet.ts.net`) |
| `X-Tailscale-IP` | Tailscale IP (e.g. `100.64.0.1`) |
| `X-Tailscale-Tags` | Comma-separated ACL tags |

### Deny response

Denied L7 requests return HTTP 403:

```json
{"error":"forbidden","message":"access denied by tailvoy policy"}
```

Denied L4 connections are closed immediately.

## Development

```sh
make test              # unit tests with race detector
make lint              # golangci-lint
make integration-test  # docker compose tests (requires TS_CLIENT_ID, TS_CLIENT_SECRET)
make kind-test         # kind cluster tests with Envoy Gateway
make docker-build      # build container image
```

Build from source: `make build` (requires Go 1.25+).

## License

[MIT](LICENSE)
