# OAuth + ListenService Migration

## Context

Tailvoy currently uses authkeys to join the tailnet and `tsnet.Listen` for raw TCP/UDP listeners. This works but doesn't integrate with Tailscale Services (VIP services), which provide stable virtual IPs, multi-host HA, and service-level ACL grants.

This migration switches tailvoy to:
- OAuth client credentials for authentication (no more authkeys)
- `tsnet.ListenService` for all TCP listeners (backed by VIP services)
- The `tailscale-client-go-v2` Go client for VIP service lifecycle management

Backwards compatibility is not a concern.

## Config

```yaml
tailscale:
  hostname: "tailvoy-ottawa"
  service: "svc:tailvoy-ottawa"    # optional, defaults to "svc:<hostname>"
  tailnet: "example.com"           # required for Go client API calls
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags: ["tag:ottawa"]             # node AdvertiseTags (host identity)
  serviceTags: ["tag:k8s"]         # VIP service tags (ACL target)
```

Removed: `authkey`, `ephemeral` (always ephemeral).

### Field semantics

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | yes | tsnet node hostname |
| `service` | no | VIP service name, defaults to `svc:<hostname>` |
| `tailnet` | yes | Tailnet name for API calls |
| `clientId` | yes | OAuth client ID (`k*`) |
| `clientSecret` | yes | OAuth client secret (`tskey-client-k*`) |
| `tags` | yes | Node tags for `AdvertiseTags`, at least one required |
| `serviceTags` | yes | Tags applied to the VIP service for ACL grants |

## Architecture

### Auth model

Two separate uses of the OAuth credentials:

1. **tsnet.Server** — `AuthKey` is set to the `clientSecret` (`tskey-client-*`). tsnet's internal OAuth resolver exchanges this for a short-lived authkey using `AdvertiseTags`. The node joins as an ephemeral tagged device.

2. **Go client** — `tailscale.Client` with `tailscale.OAuth{ClientID, ClientSecret}` for VIP service CRUD and any future API calls (device management, key rotation, etc.).

### ListenService

`tsnet.ListenService(svcName, ServiceModeTCP{Port})` returns a `*ServiceListener` wrapping a local `net.Listener` on `localhost:<ephemeral>`. Tailscaled handles routing traffic from the VIP service addresses to that local socket.

The proxy pipeline stays the same:
```
VIP IP:port → tailscaled → localhost:ephemeral → tailvoy accept
  → WhoIs resolve → L4/L7 policy check → PROXY v2 inject → forward to backend
```

For ext_authz (L7), the flow is unchanged — Envoy calls tailvoy's gRPC server directly since they're colocated.

### VIP service lifecycle

**Startup:**
1. Build `tailscale.Client` with OAuth
2. Create `tsnet.Server{Hostname, AuthKey: clientSecret, Ephemeral: true, AdvertiseTags: tags}`
3. `ts.Up(ctx)` — node joins tailnet
4. Resolve listener set (static or discovery)
5. Collect TCP ports, warn and skip UDP listeners
6. `tsClient.VIPServices().CreateOrUpdate(svc)` with `serviceTags`, ports, `Comment: "Managed by Tailvoy"`
7. `ts.ListenService(svcName, ServiceModeTCP{Port})` per port
8. Spawn proxy goroutines on each local listener
9. Start ext_authz gRPC server

**Shutdown:**
1. Cancel context → drain connections
2. Close all ServiceListeners
3. `tsClient.VIPServices().Delete(svcName)`
4. `ts.Close()` — ephemeral node auto-deregisters

**Discovery reconciliation:**
1. Discover updated listener set from Envoy admin API
2. Close removed ServiceListeners
3. `CreateOrUpdate` VIP service with updated port set
4. `ListenService` for new ports, start proxy goroutines

### UDP

VIP services don't support UDP. All UDP proxy code stays intact but is dormant. At config validation, UDP listeners produce a warning:

```
WARN: UDP listeners not supported with VIP services, skipping "<name>"
```

No error — the listener is silently skipped. When Tailscale adds UDP VIP support, the code is ready.

## Service manager (`internal/service/`)

New package encapsulating VIP service lifecycle:

```go
type Manager struct {
    client      *tailscale.Client
    serviceName string
    serviceTags []string
    logger      *slog.Logger
}

func New(client *tailscale.Client, svcName string, tags []string, logger *slog.Logger) *Manager

// Ensure creates or updates the VIP service with the given ports.
func (m *Manager) Ensure(ctx context.Context, ports []string) error

// Delete removes the VIP service.
func (m *Manager) Delete(ctx context.Context) error
```

`Ensure` calls `CreateOrUpdate` with:
```go
VIPService{
    Name:    m.serviceName,
    Tags:    m.serviceTags,
    Ports:   ports,
    Comment: "Managed by Tailvoy",
}
```

## Dynamic listener changes

`DynamicListenerManager` changes:
- `startListener` calls `ts.ListenService(svcName, ServiceModeTCP{Port})` instead of `ts.Listen("tcp", addr)`
- Before reconciling listeners, calls `svcMgr.Ensure(ctx, ports)` with the full port set
- `stopListener` closes the `ServiceListener`
- `StopAll` also calls `svcMgr.Delete(ctx)`

The `TSNetServer` interface gains `ListenService`:
```go
type TSNetServer interface {
    Listen(network, addr string) (net.Listener, error)
    ListenPacket(network, addr string) (net.PacketConn, error)
    ListenService(name string, mode tsnet.ServiceMode) (*tsnet.ServiceListener, error)
    TailscaleIPs() ([]netip.Addr, error)
}
```

## Dependency

```
tailscale.com/client/tailscale/v2 @ rajsinghtech/vip-services
```

This branch adds `VIPServicesResource` with `List`, `Get`, `CreateOrUpdate`, `Delete`.

## ACL requirements

For a tailvoy instance to work with VIP services:

```jsonc
"tagOwners": {
    "tag:ottawa": ["group:superuser"],
},
"autoApprovers": {
    "services": {
        "svc:tailvoy-ottawa": ["tag:ottawa"],
    },
},
"grants": [
    // Traffic to the VIP service
    {"src": ["group:superuser"], "dst": ["svc:tailvoy-ottawa"], "ip": ["*"]},
    // Cap grants for L7 policy (unchanged)
    {"src": ["rajsinghtech@github"], "dst": ["svc:tailvoy-ottawa"],
     "app": {"rajsingh.info/cap/tailvoy": [{"listeners": ["http"], "routes": ["/raj/*"]}]}},
]
```

## Files

| File | Change |
|------|--------|
| `go.mod` / `go.sum` | Add `tailscale-client-go-v2` |
| `internal/config/config.go` | New `TailscaleConfig` fields, remove authkey/ephemeral, new validation |
| `internal/config/config_test.go` | Updated validation tests |
| `internal/service/service.go` | New — VIP service lifecycle manager |
| `internal/service/service_test.go` | New — mock HTTP server tests |
| `internal/proxy/dynamic.go` | Use `ListenService`, integrate service manager |
| `internal/proxy/dynamic_test.go` | Update tests for ListenService |
| `internal/proxy/listener.go` | Update `TSNetServer` interface |
| `cmd/tailvoy/main.go` | Wire OAuth client, ListenService, VIP lifecycle |
| `integration_test/` | Update for OAuth model |
| `README.md` | Update config docs, ACL examples |

## Testing

- Unit tests for service manager with mock HTTP server
- Unit tests for config validation (required fields, defaults, mutual exclusion)
- Unit tests for dynamic listener reconciliation with ListenService
- Integration test update: KinD test creates OAuth client + VIP service
