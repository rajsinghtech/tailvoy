# Architecture: authorization flow

This document traces how a Tailscale ACL grant turns into an allow/deny decision inside tailvoy, from the control plane all the way to Envoy's ext_authz response.

## Overview

```
Tailscale control server
  │  compiles ACL grants → FilterRules with CapGrants
  │  resolves groups/users/tags → IP prefixes
  │  pushes netmap to tailvoy's embedded tsnet node
  ▼
tsnet.Server (in-process LocalBackend + packet filter)
  │  Filter.cap4/cap6 stores CapMatch entries
  │  cap values are opaque JSON blobs at this layer
  │
  │  peer connects via Tailscale
  ▼
ListenerManager.handleConn()
  │  calls LocalClient.WhoIs(peerIP) over in-memory pipe
  │    → LocalBackend looks up peer node in netmap
  │    → Filter.CapsWithValues(peerIP, tailvoyIP) → PeerCapMap
  │    → returns WhoIsResponse with Node + UserProfile + CapMap
  │  toIdentity() deserializes CapMap → []CapRule
  │
  ├─ L4 listener → engine.HasAccess(listener, sni, identity)
  │    allow/drop the TCP connection directly
  │
  └─ L7 listener → forward to Envoy via PROXY protocol
       │
       Envoy → ext_authz gRPC → Check()
         → resolver.Resolve(peerIP) (WhoIs, cached)
         → engine.CheckAccess(listener, host, path, identity)
         → 200 OK + identity headers  or  403 Forbidden
```

## Step by step

### 1. Control server compiles grants into filter rules

When you write a grant in your tailnet ACL:

```jsonc
{
    "grants": [{
        "src": ["group:engineers"],
        "dst": ["tag:tailvoy"],
        "app": {
            "rajsingh.info/cap/tailvoy": [{
                "listeners": ["https"],
                "routes": ["/api/*"]
            }]
        }
    }]
}
```

The Tailscale control server resolves `group:engineers` into its members' IP prefixes and `tag:tailvoy` into the tagged nodes' IP prefixes. The result is a `FilterRule` pushed to tailvoy's node:

```
FilterRule {
    SrcIPs: ["100.64.1.0/24"]              // resolved group members
    CapGrant: [{
        Dsts: ["100.64.5.5/32"]            // resolved tag:tailvoy node IPs
        CapMap: {
            "rajsingh.info/cap/tailvoy": [
                {"listeners":["https"], "routes":["/api/*"]}
            ]
        }
    }]
}
```

**Groups are fully resolved here.** By the time filter rules reach the node, there are only IP prefixes — no group names, no user identities.

### 2. Filter rules are loaded in-process

tailvoy embeds a full Tailscale node via `tsnet.Server`. This runs a `LocalBackend` with its own netmap and packet filter inside the tailvoy process — there is no separate `tailscaled` daemon or unix socket.

When filter rules arrive in the netmap, `MatchesFromFilterRules` ([`wgengine/filter/tailcfg.go`](https://github.com/tailscale/tailscale/blob/main/wgengine/filter/tailcfg.go)) splits each rule into two independent structures:

- **Packet matching** (`Srcs` + `Dsts` + port ranges) → stored in `matches4`/`matches6` → used for TCP/UDP accept/drop decisions on actual packets.
- **Cap matching** (`Srcs` + `Caps`) → stored in `cap4`/`cap6` → used only by `CapsWithValues()`, never consulted during packet filtering.

The cap values (like `{"routes": ["/api/*"]}`) remain opaque `RawMessage` blobs. The packet filter carries them but never interprets them.

### 3. Peer connects

A peer (e.g. Alice at `100.64.1.1`) opens a TCP connection to tailvoy's Tailscale address. The tsnet listener accepts it and `ListenerManager.handleConn()` ([`internal/proxy/listener.go`](internal/proxy/listener.go)) fires.

### 4. WhoIs resolves identity and capabilities

tailvoy calls `lc.WhoIs(ctx, "100.64.1.1:12345")` on the `local.Client` returned by `tsnet.Server.LocalClient()`.

Because tsnet is in-process, this doesn't hit a unix socket. The `LocalClient` connects over an **in-memory listener** (`memnet`) to the local API handler running in the same process ([`tsnet.go`](https://github.com/tailscale/tailscale/blob/main/tsnet/tsnet.go)):

```go
lal := memnet.Listen("local-tailscaled.sock:80")
s.localClient = &local.Client{Dial: lal.Dial}
```

The local API handler `serveWhoIs` ([`ipn/localapi/localapi.go`](https://github.com/tailscale/tailscale/blob/main/ipn/localapi/localapi.go)) does two things:

**a) Node lookup** — finds the peer in the netmap by IP, returning `Node` (name, tags) and `UserProfile` (login name).

**b) Capability computation** — calls `PeerCaps(peerIP)`, which calls `Filter.CapsWithValues(src, dst)` ([`wgengine/filter/filter.go`](https://github.com/tailscale/tailscale/blob/main/wgengine/filter/filter.go)) where:
- `src` = the peer's IP (`100.64.1.1`)
- `dst` = tailvoy's own Tailscale IP (`100.64.5.5`)

This scans the `cap4`/`cap6` match tables. For each rule where `SrcsContains(peerIP)` is true and `CapGrant.Dsts` contains tailvoy's IP, the associated cap values are collected into a `PeerCapMap`.

The response:

```go
WhoIsResponse{
    Node:        {Name: "alice-laptop.tail1234.ts.net."},
    UserProfile: {LoginName: "alice@example.com"},
    CapMap: {
        "rajsingh.info/cap/tailvoy": [
            RawMessage(`{"listeners":["https"],"routes":["/api/*"]}`)
        ],
    },
}
```

### 5. tailvoy deserializes the CapMap

Back in tailvoy, `toIdentity()` ([`internal/identity/whois.go`](internal/identity/whois.go)) calls:

```go
capRules, _ := tailcfg.UnmarshalCapJSON[TailvoyCapRule](resp.CapMap, CapTailvoy)
```

This is where the opaque JSON blobs become structured `CapRule` values with typed `Listeners`, `Routes`, and `Hostnames` fields, attached to the `Identity`.

### 6. Enforcement

#### L4 (TCP/TLS passthrough — no Envoy)

For non-L7 listeners, tailvoy checks policy directly at the connection level ([`internal/proxy/listener.go`](internal/proxy/listener.go)):

```go
if !listenerCfg.IsL7 && !lm.engine.HasAccess(listenerCfg.Name, sni, id) {
    // connection dropped
}
```

`HasAccess` ([`internal/policy/engine.go`](internal/policy/engine.go)) iterates the identity's rules, matching on **listener** and **hostname** (SNI) dimensions. There is no path matching at L4 — there's no HTTP request to inspect. If no rule matches, the connection is closed.

#### L7 (HTTP/HTTPS/gRPC — through Envoy)

For L7 listeners, tailvoy skips L4 policy and forwards the connection to Envoy via PROXY protocol (which preserves the original peer IP).

Envoy parses the HTTP request and, before routing to the backend, calls tailvoy's gRPC ext_authz server ([`internal/authz/extauthz.go`](internal/authz/extauthz.go)). Each Envoy route includes `context_extensions` with the tailvoy listener name.

The ext_authz `Check()` handler:

1. Extracts the peer IP from `x-forwarded-for` (set by Envoy from the PROXY protocol header).
2. Calls `resolver.Resolve(srcIP)` — same WhoIs flow as above, with a 5-minute cache.
3. Calls `engine.CheckAccess(listener, host, path, id)` which evaluates all three dimensions:
   - **Listeners** — does any rule's `listeners` contain this listener name? (empty = unrestricted)
   - **Hostnames** — does any rule's `hostnames` match this `Host` header? (supports `*.domain` wildcards)
   - **Routes** — does any rule's `routes` match this request path? (supports `/prefix/*` globs)
   - Within a rule: **AND** across dimensions. Across rules: **OR**.
4. Returns OK with identity headers (`X-Tailscale-User`, `X-Tailscale-Node`, `X-Tailscale-Tags`, `X-Tailscale-IP`) or 403 Forbidden.

## Key design points

**Groups are invisible to tailvoy.** The control server resolves group membership into IP prefixes before filter rules ever reach the node. tailvoy never sees group names — it only sees which capabilities a given peer IP has toward its own IP.

**Cap values are data, not filter logic.** The Tailscale packet filter carries capability values as opaque blobs alongside its normal accept/drop rules but never interprets them. They only become meaningful when tailvoy deserializes them at the application layer.

**The CapMap is computed per-destination.** `CapsWithValues(src, dst)` matches against `CapGrant.Dsts`, so the same peer can have different capabilities toward different nodes in the tailnet. Each node only computes caps relevant to itself.

**Everything runs in-process.** tsnet embeds a full `LocalBackend` with its own netmap, filter, and local API, connected via an in-memory pipe. There is no system tailscaled daemon involved.
