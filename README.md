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

## How it works

tailvoy embeds [tsnet](https://pkg.go.dev/tailscale.com/tsnet) to join the tailnet as an ephemeral OAuth node -- no sidecar Tailscale daemon needed. It uses [Tailscale Services](https://tailscale.com/docs/features/tailscale-services) (via `tsnet.ListenService`) so multiple replicas can serve the same stable service address. Every inbound connection triggers a WhoIs lookup to resolve the caller's Tailscale identity and peer capabilities.

Authorization is driven entirely by Tailscale ACL grants using the `rajsingh.info/cap/tailvoy` capability. Each cap rule has three optional dimensions:

| Dimension | Controls | Source |
|-----------|----------|--------|
| `listeners` | Which named listeners a peer can connect to | Listener name from policy.yaml (static) or Envoy dynamic listener name (discovery) |
| `routes` | Which HTTP/gRPC paths are accessible (L7 only) | Request path |
| `hostnames` | Which hostnames are allowed (SNI or Host header) | TLS ClientHello SNI / HTTP Host header |

**Within a rule**: AND -- all specified dimensions must match.
**Across rules**: OR -- any matching rule grants access.
**Omitted dimension**: unrestricted on that dimension.

The policy file (`policy.yaml`) only defines infrastructure -- Tailscale identity and listener configuration. All authorization lives in your Tailscale ACL.

## Authentication

tailvoy authenticates to Tailscale using OAuth client credentials. Create an OAuth client in the Tailscale admin console and provide the ID and secret via environment variables:

```yaml
tailscale:
  service: "my-gw"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:my-gw"        # ACL tags for the tailvoy node itself
  serviceTags:
    - "tag:my-gw"        # ACL tags for the VIP service
```

- **`service`**: The service name. The tsnet node hostname is derived as `<service>-tailvoy` and the VIP service name as `svc:<service>`.
- **`tags`**: Applied to the ephemeral tsnet node. Must match your ACL `tagOwners`.
- **`serviceTags`**: Applied to the VIP service that exposes listeners on the tailnet. Must match `autoApprovers.services` in your ACL.

tailvoy creates the VIP service on startup via the Tailscale API and advertises TCP ports for each listener. The service persists across restarts so multiple replicas can serve the same address.

> **Note:** UDP listeners are not yet supported by VIP services. tailvoy will log a warning and skip UDP listeners in VIP mode. The UDP proxy code is retained for future support.

### Required ACL configuration

```jsonc
{
    "tagOwners": {
        "tag:my-gw": ["autogroup:admin"]
    },
    "autoApprovers": {
        "services": {
            "svc:my-gw": ["tag:my-gw"]
        }
    }
}
```

## Listener modes

tailvoy supports two mutually exclusive ways to define listeners:

- **Static listeners** (`listeners[]`): You declare every listener explicitly in policy.yaml. Full control over names, ports, and protocols.
- **Discovery mode** (`discovery`): tailvoy polls Envoy's admin API to auto-discover listeners. No listener config needed -- tailvoy creates and removes tsnet listeners dynamically as Envoy's configuration changes.

Discovery mode is ideal for Envoy Gateway deployments where listeners are managed by Gateway API resources and change over time. Static mode is better when you want explicit control or are running standalone.

## Cap rule schema

```jsonc
"rajsingh.info/cap/tailvoy": [
    {
        "listeners": ["http", "grpc"],  // optional: which listeners
        "routes": ["/api/*", "/health"],  // optional: which paths (L7 only)
        "hostnames": ["app.example.com"]  // optional: which hostnames
    }
]
```

An empty rule `[{}]` grants full access to all listeners, paths, and hostnames.

## Examples

### HTTP with path-based access control

A web app where different users get access to different paths.

**policy.yaml:**
```yaml
tailscale:
  service: "web-gw"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:web-gw"
  serviceTags:
    - "tag:web-gw"

listeners:
  - name: http
    protocol: tcp
    listen: ":80"
    forward: "127.0.0.1:8080"
    proxy_protocol: v2
    l7_policy: true
```

**ACL grants:**
```jsonc
{
    "grants": [
        {
            "src": ["alice@example.com"],
            "dst": ["tag:web-gw"],
            "app": {
                "rajsingh.info/cap/tailvoy": [{
                    "listeners": ["http"],
                    "routes": ["/api/*", "/health"]
                }]
            }
        },
        {
            "src": ["group:admins"],
            "dst": ["tag:web-gw"],
            "app": {
                "rajsingh.info/cap/tailvoy": [{
                    "listeners": ["http"],
                    "routes": ["/*"]
                }]
            }
        }
    ]
}
```

**Result:**
| Caller | `GET /api/users` | `GET /health` | `GET /admin/settings` |
|--------|:---:|:---:|:---:|
| alice@example.com | 200 | 200 | 403 |
| bob@example.com (in group:admins) | 200 | 200 | 200 |
| eve@example.com (no cap) | conn reset | conn reset | conn reset |

### Listener-scoped access

Restrict which listeners a peer can connect to. A DBA gets postgres but not HTTP:

```jsonc
// DBA: only postgres listener
{
    "src": ["tag:dba"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"listeners": ["postgres"]}]
    }
}
// Frontend: only HTTP listener with path restrictions
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["http"],
            "routes": ["/api/*", "/health"]
        }]
    }
}
```

The DBA can connect to the postgres listener but not HTTP. The frontend can hit HTTP `/api/*` but not postgres.

### TCP (e.g. Postgres)

A database port that only tagged nodes can reach. No L7 policy -- just L4 identity gating.

**policy.yaml:**
```yaml
listeners:
  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "127.0.0.1:5432"
    l7_policy: false
```

**ACL grants:**
```jsonc
{
    "src": ["tag:backend"],
    "dst": ["tag:db-gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"listeners": ["postgres"]}]
    }
}
```

### UDP (e.g. DNS)

> **Note:** UDP listeners are not currently supported by VIP services. In static mode, tailvoy will skip UDP listeners with a warning. UDP proxy code is retained for future VIP service support.

**policy.yaml:**
```yaml
listeners:
  - name: dns
    protocol: udp
    listen: ":53"
    forward: "127.0.0.1:1053"
    l7_policy: false
```

**ACL grants:**
```jsonc
{
    "src": ["autogroup:member"],
    "dst": ["tag:dns-gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"listeners": ["dns"]}]
    }
}
```

All tailnet members can send DNS queries. Non-members are dropped at L4.

### gRPC with service-level access control

gRPC paths follow the `/package.Service/Method` convention. Route matching works the same as HTTP.

**policy.yaml:**
```yaml
listeners:
  - name: grpc
    protocol: tcp
    listen: ":50051"
    forward: "127.0.0.1:50051"
    proxy_protocol: v2
    l7_policy: true
```

**ACL grants:**
```jsonc
{
    "src": ["tag:frontend"],
    "dst": ["tag:grpc-gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["grpc"],
            "routes": [
                "/grpc.health.v1.Health/*",
                "/myapp.UserService/*"
            ]
        }]
    }
}
```

**Result:**
| Caller | `Health/Check` | `UserService/GetUser` | `AdminService/DeleteUser` |
|--------|:---:|:---:|:---:|
| tag:frontend | 200 | 200 | 403 |

### TLS passthrough with hostname gating

tailvoy forwards the raw TLS connection without terminating it. It peeks at the TLS ClientHello to extract the SNI server name for hostname-based access control.

**policy.yaml:**
```yaml
listeners:
  - name: tls
    protocol: tcp
    listen: ":443"
    forward: "127.0.0.1:8443"
    l7_policy: false
```

**ACL grants:**
```jsonc
// Engineers can access app.example.com
{
    "src": ["group:engineers"],
    "dst": ["tag:tls-gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["tls"],
            "hostnames": ["app.example.com"]
        }]
    }
}
// Ops can access any hostname
{
    "src": ["group:ops"],
    "dst": ["tag:tls-gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["tls"],
            "hostnames": ["*.example.com"]
        }]
    }
}
```

**Result:**
| Caller | `app.example.com` | `admin.example.com` |
|--------|:---:|:---:|
| group:engineers | allowed | conn reset |
| group:ops | allowed | allowed |

### HTTP with hostname-based virtual hosting

For L7 listeners, hostnames match against the HTTP `Host` header (or `:authority` for gRPC):

```jsonc
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["http"],
            "hostnames": ["api.example.com"],
            "routes": ["/v1/*"]
        }]
    }
}
```

This grants access only to `api.example.com` on the HTTP listener, and only for `/v1/*` paths. All three dimensions must match (AND).

### Discovery mode (Envoy Gateway)

Instead of declaring listeners manually, let tailvoy discover them from Envoy's admin API. Listeners are created and removed automatically as Gateway resources change.

**policy.yaml:**
```yaml
tailscale:
  service: "my-gateway"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:my-gateway"
  serviceTags:
    - "tag:my-gateway"

discovery:
  envoyAdmin: "http://127.0.0.1:19000"
  envoyAddress: "127.0.0.1"
  pollInterval: "5s"
  proxyProtocol: v2
```

tailvoy polls Envoy's `/config_dump` endpoint, parses dynamic listeners, and creates tsnet listeners for each one. L7 detection is automatic -- if a listener's filter chain contains `http_connection_manager`, tailvoy enables L7 policy for it.

Discovered listener names follow Envoy Gateway's naming convention: `<namespace>/<gateway>/<listener>` (e.g., `default/eg/http`). Use these names in your ACL grants:

```jsonc
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["default/eg/http"],
            "routes": ["/api/*", "/health"]
        }]
    }
}
```

For L7 listeners, SecurityPolicy `contextExtensions` must also use the full listener name:

```yaml
contextExtensions:
  - name: listener
    type: Value
    value: "default/eg/http"
```

### Multi-listener gateway (static)

A single tailvoy instance handling HTTP, TCP, UDP, gRPC, and TLS -- each on its own port.

**policy.yaml:**
```yaml
tailscale:
  service: "my-gateway"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:my-gateway"
  serviceTags:
    - "tag:my-gateway"

listeners:
  - name: http
    protocol: tcp
    listen: ":80"
    forward: "127.0.0.1:8080"
    proxy_protocol: v2
    l7_policy: true

  - name: grpc
    protocol: tcp
    listen: ":50051"
    forward: "127.0.0.1:8081"
    proxy_protocol: v2
    l7_policy: true

  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "127.0.0.1:5432"
    l7_policy: false

  - name: dns
    protocol: udp
    listen: ":53"
    forward: "127.0.0.1:1053"
    l7_policy: false

  - name: tls
    protocol: tcp
    listen: ":443"
    forward: "127.0.0.1:8443"
    l7_policy: false
```

Different teams get scoped access:

```jsonc
// Frontend: HTTP + gRPC health only
{
    "src": ["tag:frontend"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["http", "grpc"],
            "routes": ["/api/*", "/grpc.health.v1.Health/*"]
        }]
    }
}
// DBA: postgres only
{
    "src": ["tag:dba"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"listeners": ["postgres"]}]
    }
}
// Ops: full access to everything
{
    "src": ["group:ops"],
    "dst": ["tag:my-gateway"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{}]
    }
}
```

### Grant merging

Multiple matching grants produce multiple cap rules. Rules are evaluated independently (OR):

```jsonc
// Grant 1: alice gets HTTP /api/*
{
    "src": ["alice@example.com"],
    "dst": ["tag:gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{
            "listeners": ["http"],
            "routes": ["/api/*"]
        }]
    }
},
// Grant 2: group:eng (includes alice) gets postgres
{
    "src": ["group:eng"],
    "dst": ["tag:gw"],
    "app": {
        "rajsingh.info/cap/tailvoy": [{"listeners": ["postgres"]}]
    }
}
// alice's effective rules: [
//   {listeners: ["http"], routes: ["/api/*"]},
//   {listeners: ["postgres"]}
// ]
// alice can access HTTP /api/* AND postgres
```

## Deployment modes

- **Standalone** (`-standalone`): tailvoy auto-generates Envoy bootstrap config and manages Envoy as a subprocess. No Envoy YAML needed. Uses static listeners.
- **Envoy Gateway data plane**: tailvoy replaces the default Envoy image via the `EnvoyProxy` CRD, acting as the data plane for [Envoy Gateway](https://gateway.envoyproxy.io/). EG manages routing via xDS while tailvoy handles Tailscale ingress and cap-based policy. Supports both static listeners and discovery mode (recommended).

## Supported protocols

| Protocol | Listener config | Policy check |
|----------|----------------|-------------|
| HTTP | `protocol: tcp`, `l7_policy: true` | L4 (listener + hostname) + L7 (route) |
| gRPC | `protocol: tcp`, `l7_policy: true` | L4 (listener + hostname) + L7 (route) |
| TCP | `protocol: tcp`, `l7_policy: false` | L4 (listener only) |
| TLS passthrough | `protocol: tcp`, `l7_policy: false` | L4 (listener + SNI hostname) |
| UDP | `protocol: udp` | L4 (listener only) |

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
docker run \
  -e TS_CLIENT_ID=tskey-client-... \
  -e TS_CLIENT_SECRET=tskey-client-secret-... \
  -v $(pwd)/policy.yaml:/policy.yaml \
  ghcr.io/rajsinghtech/tailvoy:latest \
  -policy /policy.yaml -standalone
```

## Reference

### Listener options (static mode)

| Field | Description |
|-------|-------------|
| `name` | Listener identifier (used in cap rules' `listeners` field) |
| `protocol` | `tcp` or `udp` |
| `listen` | Address to bind (e.g. `:443`) |
| `forward` | Backend address to proxy to |
| `proxy_protocol` | Set to `v2` to prepend a PROXY protocol v2 header. Preserves the caller's Tailscale IP so Envoy and your backend see the real client address. |
| `l7_policy` | Set to `true` to route through Envoy with ext_authz for path-level policy. When `false`, the listener is L4-only (pure TCP/UDP forwarding after cap check). |

### Discovery options

| Field | Required | Description |
|-------|----------|-------------|
| `envoyAdmin` | yes | Envoy admin API URL (e.g. `http://127.0.0.1:19000`) |
| `envoyAddress` | yes | Address to forward traffic to (the Envoy data plane, e.g. `127.0.0.1`) |
| `pollInterval` | no | How often to poll for changes (default `10s`) |
| `listenerFilter` | no | Regex to include only matching listener names |
| `proxyProtocol` | no | Set to `v2` to inject PROXY protocol v2 on all discovered listeners |

Discovery auto-detects L7 listeners by inspecting Envoy's filter chains for `http_connection_manager`. Listener names, ports, and protocols are all derived from the Envoy config -- no manual mapping needed.

### Cap rule fields

| Field | Applies to | Description |
|-------|-----------|-------------|
| `listeners` | L4 + L7 | Listener names the peer can access. Omit for all listeners. |
| `routes` | L7 only | Path patterns (glob-style). Omit for all paths. Ignored at L4. |
| `hostnames` | L4 (TLS SNI) + L7 (Host header) | Hostname patterns. Omit for all hostnames. |

### Route patterns

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `/*` | All paths | -- |
| `/api/*` | `/api/`, `/api/users`, `/api/v1/foo` | `/apiv2` |
| `/health` | Exactly `/health` | `/health/`, `/health/db` |
| `/admin/*` | `/admin/`, `/admin/settings` | `/administrator` |
| `/grpc.health.v1.Health/*` | `/grpc.health.v1.Health/Check` | `/grpc.other.Service/Method` |

### Hostname patterns

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `app.example.com` | Exactly `app.example.com` | `other.example.com` |
| `*.example.com` | `app.example.com`, `deep.sub.example.com` | `example.com` |

### Identity headers

On allowed L7 requests, tailvoy injects identity headers before the request reaches your backend:

| Header | Value |
|--------|-------|
| `X-Tailscale-User` | Tailscale login (e.g. `alice@example.com`) |
| `X-Tailscale-Node` | Node FQDN (e.g. `alices-laptop.tailnet.ts.net`) |
| `X-Tailscale-Ip` | Tailscale IP (e.g. `100.64.0.1`) |
| `X-Tailscale-Tags` | Comma-separated ACL tags |

### Deny response

Denied L7 requests return HTTP 403 with a JSON body:

```json
{"error":"forbidden","message":"access denied by tailvoy policy"}
```

## Development

```sh
make test              # unit tests with race detector
make lint              # golangci-lint
make cover             # coverage report
make integration-test  # docker compose integration tests (requires TS_CLIENT_ID, TS_CLIENT_SECRET)
make kind-test         # kind cluster integration tests (requires TS_CLIENT_ID, TS_CLIENT_SECRET)
make docker-build      # build container image
```

## License

[MIT](LICENSE)
