# Multi-Dimensional Cap Structure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the tailvoy cap from `{routes}` to `{listeners, routes, hostnames}` with AND-within/OR-across rule semantics, including TLS SNI peeking.

**Architecture:** Cap rules are kept as discrete units in `Identity.Rules` (not merged). `HasAccess` and `CheckAccess` take listener name + hostname + path and iterate rules, returning true if any rule matches all specified dimensions. TLS passthrough listeners peek at ClientHello for SNI.

**Tech Stack:** Go, crypto/tls (for SNI parsing), existing gRPC ext_authz

---

### Task 1: Rewrite `TailvoyCapRule` and `Identity`

**Files:**
- Modify: `internal/identity/whois.go:22-24` (TailvoyCapRule)
- Modify: `internal/policy/types.go:1-11` (Identity)

**Step 1: Update TailvoyCapRule**

In `internal/identity/whois.go`, replace:
```go
type TailvoyCapRule struct {
	Routes []string `json:"routes,omitempty"`
}
```
with:
```go
type TailvoyCapRule struct {
	Listeners []string `json:"listeners,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}
```

**Step 2: Update Identity**

In `internal/policy/types.go`, replace:
```go
type Identity struct {
	UserLogin     string
	NodeName      string
	Tags          []string
	IsTagged      bool
	TailscaleIP   string
	AllowedRoutes []string
}
```
with:
```go
type Identity struct {
	UserLogin   string
	NodeName    string
	Tags        []string
	IsTagged    bool
	TailscaleIP string
	Rules       []TailvoyCapRule
}
```

This requires importing the `identity` package from `policy`, which would create a circular import. Instead, define the rule type in the `policy` package and reference it from both places.

Actually — to avoid circular imports, move the cap rule type into `policy/types.go`:

```go
package policy

// CapRule defines a single tailvoy capability rule.
// AND within a rule (all specified dimensions must match),
// OR across rules (any matching rule grants access).
type CapRule struct {
	Listeners []string
	Routes    []string
	Hostnames []string
}

type Identity struct {
	UserLogin   string
	NodeName    string
	Tags        []string
	IsTagged    bool
	TailscaleIP string
	Rules       []CapRule
}
```

In `internal/identity/whois.go`, keep `TailvoyCapRule` for JSON unmarshaling but convert to `policy.CapRule` in `toIdentity()`.

**Step 3: Rewrite `toIdentity()` in `internal/identity/whois.go:166-202`**

Replace the route merging logic with:
```go
func toIdentity(resp *apitype.WhoIsResponse, ip netip.Addr) *policy.Identity {
	id := &policy.Identity{
		TailscaleIP: ip.String(),
	}

	if resp.Node != nil {
		id.NodeName = strings.TrimSuffix(resp.Node.Name, ".")
		if len(resp.Node.Tags) > 0 {
			id.Tags = resp.Node.Tags
			id.IsTagged = true
		}
	}

	if resp.UserProfile != nil && !id.IsTagged {
		id.UserLogin = resp.UserProfile.LoginName
	}

	capRules, _ := tailcfg.UnmarshalCapJSON[TailvoyCapRule](resp.CapMap, CapTailvoy)
	for _, cr := range capRules {
		id.Rules = append(id.Rules, policy.CapRule{
			Listeners: cr.Listeners,
			Routes:    cr.Routes,
			Hostnames: cr.Hostnames,
		})
	}

	return id
}
```

**Step 4: Run tests to see what breaks**

Run: `go build ./...`
Expected: Compilation errors in engine.go, engine_test.go, extauthz.go, extauthz_test.go, listener.go, udp.go, listener_test.go — all referencing `AllowedRoutes` or old engine signatures.

**Step 5: Commit**

```
feat: add multi-dimensional cap rule types (listeners, routes, hostnames)
```

---

### Task 2: Rewrite policy engine

**Files:**
- Modify: `internal/policy/engine.go`
- Test: `internal/policy/engine_test.go`

**Step 1: Write failing tests**

Replace the entire `engine_test.go` with tests for the new signatures. Key test cases:

```go
func TestHasAccess_EmptyRule(t *testing.T) {
	// Empty rule = full access to everything
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{}}}
	if !e.HasAccess("http", "", id) {
		t.Error("empty rule should grant access to any listener")
	}
}

func TestHasAccess_ListenerMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Listeners: []string{"http", "grpc"}}}}
	if !e.HasAccess("http", "", id) {
		t.Error("should match http listener")
	}
	if e.HasAccess("postgres", "", id) {
		t.Error("should not match postgres listener")
	}
}

func TestHasAccess_HostnameMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"app.example.com"}}}}
	if !e.HasAccess("tls", "app.example.com", id) {
		t.Error("should match hostname")
	}
	if e.HasAccess("tls", "other.example.com", id) {
		t.Error("should not match wrong hostname")
	}
}

func TestHasAccess_HostnameWildcard(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"*.example.com"}}}}
	if !e.HasAccess("tls", "app.example.com", id) {
		t.Error("wildcard should match subdomain")
	}
	if e.HasAccess("tls", "example.com", id) {
		t.Error("wildcard should not match bare domain")
	}
}

func TestHasAccess_ListenerPlusHostname(t *testing.T) {
	// AND: both must match
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"tls"},
		Hostnames: []string{"app.example.com"},
	}}}
	if !e.HasAccess("tls", "app.example.com", id) {
		t.Error("both dimensions match, should allow")
	}
	if e.HasAccess("http", "app.example.com", id) {
		t.Error("listener doesn't match, should deny")
	}
	if e.HasAccess("tls", "other.example.com", id) {
		t.Error("hostname doesn't match, should deny")
	}
}

func TestHasAccess_NoRules(t *testing.T) {
	e := NewEngine()
	id := &Identity{}
	if e.HasAccess("http", "", id) {
		t.Error("no rules should deny")
	}
}

func TestHasAccess_MultipleRulesOR(t *testing.T) {
	// OR across rules
	e := NewEngine()
	id := &Identity{Rules: []CapRule{
		{Listeners: []string{"http"}},
		{Listeners: []string{"postgres"}},
	}}
	if !e.HasAccess("http", "", id) {
		t.Error("first rule matches http")
	}
	if !e.HasAccess("postgres", "", id) {
		t.Error("second rule matches postgres")
	}
	if e.HasAccess("dns", "", id) {
		t.Error("neither rule matches dns")
	}
}

func TestHasAccess_PlainTCPIgnoresHostname(t *testing.T) {
	// Plain TCP: sni is empty, rules with hostnames should NOT match
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"db.example.com"}}}}
	if e.HasAccess("postgres", "", id) {
		t.Error("hostname rule should not match plain TCP (no SNI)")
	}
}

func TestCheckAccess_ListenerPlusRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"http"},
		Routes:    []string{"/api/*"},
	}}}
	if !e.CheckAccess("http", "", "/api/data", id) {
		t.Error("listener and route match")
	}
	if e.CheckAccess("http", "", "/admin", id) {
		t.Error("route doesn't match")
	}
	if e.CheckAccess("grpc", "", "/api/data", id) {
		t.Error("listener doesn't match")
	}
}

func TestCheckAccess_HostnamePlusRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Hostnames: []string{"api.example.com"},
		Routes:    []string{"/v1/*"},
	}}}
	if !e.CheckAccess("http", "api.example.com", "/v1/users", id) {
		t.Error("all dimensions match")
	}
	if e.CheckAccess("http", "admin.example.com", "/v1/users", id) {
		t.Error("hostname doesn't match")
	}
	if e.CheckAccess("http", "api.example.com", "/v2/users", id) {
		t.Error("route doesn't match")
	}
}

func TestCheckAccess_AllThreeDimensions(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"http"},
		Hostnames: []string{"api.example.com"},
		Routes:    []string{"/v1/*"},
	}}}
	if !e.CheckAccess("http", "api.example.com", "/v1/users", id) {
		t.Error("all three match")
	}
	if e.CheckAccess("grpc", "api.example.com", "/v1/users", id) {
		t.Error("listener mismatch")
	}
	if e.CheckAccess("http", "other.com", "/v1/users", id) {
		t.Error("hostname mismatch")
	}
	if e.CheckAccess("http", "api.example.com", "/v2/users", id) {
		t.Error("route mismatch")
	}
}

func TestCheckAccess_EmptyRuleAllowsAll(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{}}}
	if !e.CheckAccess("http", "anything.com", "/any/path", id) {
		t.Error("empty rule = full access")
	}
}

func TestCheckAccess_MultipleRulesMerge(t *testing.T) {
	// Rule 1: http + /api/*. Rule 2: http + /admin/*
	// Both should work on http listener
	e := NewEngine()
	id := &Identity{Rules: []CapRule{
		{Listeners: []string{"http"}, Routes: []string{"/api/*"}},
		{Listeners: []string{"http"}, Routes: []string{"/admin/*"}},
	}}
	if !e.CheckAccess("http", "", "/api/data", id) {
		t.Error("first rule matches /api/*")
	}
	if !e.CheckAccess("http", "", "/admin/settings", id) {
		t.Error("second rule matches /admin/*")
	}
	if e.CheckAccess("http", "", "/other", id) {
		t.Error("neither rule matches /other")
	}
}
```

Also keep the existing `matchPath` tests and concurrent access tests, updated for new signatures.

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -v -count=1`
Expected: FAIL (compilation errors from old signatures)

**Step 3: Rewrite engine.go**

```go
package policy

import "strings"

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// HasAccess checks L4 access: does any rule match the given listener + SNI?
func (e *Engine) HasAccess(listener string, sni string, id *Identity) bool {
	for _, rule := range id.Rules {
		if ruleMatchesL4(rule, listener, sni) {
			return true
		}
	}
	return false
}

// CheckAccess checks L7 access: does any rule match listener + hostname + path?
func (e *Engine) CheckAccess(listener string, hostname string, path string, id *Identity) bool {
	for _, rule := range id.Rules {
		if ruleMatchesL7(rule, listener, hostname, path) {
			return true
		}
	}
	return false
}

func ruleMatchesL4(rule CapRule, listener string, sni string) bool {
	if !matchDimension(rule.Listeners, listener) {
		return false
	}
	if !matchHostnameDimension(rule.Hostnames, sni) {
		return false
	}
	return true
}

func ruleMatchesL7(rule CapRule, listener string, hostname string, path string) bool {
	if !matchDimension(rule.Listeners, listener) {
		return false
	}
	if !matchHostnameDimension(rule.Hostnames, hostname) {
		return false
	}
	if !matchRouteDimension(rule.Routes, path) {
		return false
	}
	return true
}

// matchDimension returns true if values is empty (unrestricted) or target is in values.
func matchDimension(values []string, target string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// matchHostnameDimension returns true if patterns is empty (unrestricted) or
// hostname matches any pattern. Supports exact match and *.domain wildcards.
func matchHostnameDimension(patterns []string, hostname string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matchHostname(p, hostname) {
			return true
		}
	}
	return false
}

// matchHostname checks if hostname matches pattern.
// Patterns: "exact.com" for exact, "*.example.com" for wildcard subdomain.
func matchHostname(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostname, suffix) && hostname != suffix[1:]
	}
	return false
}

// matchRouteDimension returns true if patterns is empty (unrestricted) or
// path matches any route pattern.
func matchRouteDimension(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

// matchPath checks whether reqPath matches the given pattern.
func matchPath(pattern, reqPath string) bool {
	if pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(reqPath, prefix) || reqPath == strings.TrimSuffix(prefix, "/")
	}
	return pattern == reqPath
}
```

**Step 4: Run tests**

Run: `go test ./internal/policy/ -v -count=1 -race`
Expected: PASS

**Step 5: Commit**

```
feat: rewrite policy engine for multi-dimensional cap rules
```

---

### Task 3: Update `whois.go` and whois tests

**Files:**
- Modify: `internal/identity/whois.go:166-202`
- Test: `internal/identity/whois_test.go`

**Step 1: Write failing test for multi-dimensional cap parsing**

Add to `whois_test.go`:
```go
func TestToIdentity_MultiDimensionalCap(t *testing.T) {
	ruleJSON1, _ := json.Marshal(map[string]interface{}{
		"listeners": []string{"http"},
		"routes":    []string{"/api/*"},
	})
	ruleJSON2, _ := json.Marshal(map[string]interface{}{
		"listeners": []string{"postgres"},
	})

	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
			CapMap: tailcfg.PeerCapMap{
				CapTailvoy: []tailcfg.RawMessage{
					tailcfg.RawMessage(ruleJSON1),
					tailcfg.RawMessage(ruleJSON2),
				},
			},
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.1.1:80")
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(id.Rules))
	}
	if id.Rules[0].Listeners[0] != "http" {
		t.Errorf("rule 0 listener = %v", id.Rules[0].Listeners)
	}
	if id.Rules[0].Routes[0] != "/api/*" {
		t.Errorf("rule 0 routes = %v", id.Rules[0].Routes)
	}
	if id.Rules[1].Listeners[0] != "postgres" {
		t.Errorf("rule 1 listener = %v", id.Rules[1].Listeners)
	}
}

func TestToIdentity_EmptyCap(t *testing.T) {
	ruleJSON, _ := json.Marshal(map[string]interface{}{})

	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			CapMap: tailcfg.PeerCapMap{
				CapTailvoy: []tailcfg.RawMessage{tailcfg.RawMessage(ruleJSON)},
			},
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.1.1:80")
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	// Empty rule = all dimensions unrestricted
	if len(id.Rules[0].Listeners) != 0 || len(id.Rules[0].Routes) != 0 || len(id.Rules[0].Hostnames) != 0 {
		t.Error("empty cap rule should have all nil/empty fields")
	}
}

func TestToIdentity_HostnamesInCap(t *testing.T) {
	ruleJSON, _ := json.Marshal(map[string]interface{}{
		"listeners": []string{"tls"},
		"hostnames": []string{"app.example.com", "*.staging.example.com"},
	})

	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			CapMap: tailcfg.PeerCapMap{
				CapTailvoy: []tailcfg.RawMessage{tailcfg.RawMessage(ruleJSON)},
			},
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.1.1:80")
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	if len(id.Rules[0].Hostnames) != 2 {
		t.Errorf("expected 2 hostnames, got %v", id.Rules[0].Hostnames)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/ -v -count=1 -run TestToIdentity`
Expected: FAIL (AllowedRoutes doesn't exist)

**Step 3: Update `toIdentity()` and fix existing tests**

Update `toIdentity()` as shown in Task 1 Step 3. Fix existing whois tests that reference `id.AllowedRoutes` or `id.UserLogin` to work with `id.Rules`.

The existing tests that check `id.UserLogin`, `id.NodeName`, `id.Tags`, `id.IsTagged`, `id.TailscaleIP` — those fields still exist and work the same. Only tests that reference `AllowedRoutes` need updating.

**Step 4: Run all identity tests**

Run: `go test ./internal/identity/ -v -count=1 -race`
Expected: PASS

**Step 5: Commit**

```
feat: parse multi-dimensional cap rules in whois resolver
```

---

### Task 4: Update proxy layer (listener.go + udp.go)

**Files:**
- Modify: `internal/proxy/listener.go:88` (HasAccess call)
- Modify: `internal/proxy/udp.go:110` (HasAccess call)
- Test: `internal/proxy/listener_test.go`

**Step 1: Update `handleConn` in listener.go**

Change line 88 from:
```go
if !lm.engine.HasAccess(id) {
```
to:
```go
if !lm.engine.HasAccess(listenerCfg.Name, "", id) {
```

The SNI parameter is `""` for now. TLS SNI peeking is added in Task 6.

**Step 2: Update `Serve` in udp.go**

Change line 110 from:
```go
if !engine.HasAccess(id) {
```
to:
```go
if !engine.HasAccess(listenerName, "", id) {
```

**Step 3: Update listener_test.go and l4_test.go**

Update `tailvoyCapMap` helper in `listener_test.go` to work with the new cap structure. The existing tests use `tailvoyCapMap("/*")` which produces `{routes: ["/*"]}` — this still works as-is since the JSON structure hasn't changed, only how it's parsed. No test changes needed for the cap map helper.

However, the mock WhoIs responses produce identities that are now parsed with the new `toIdentity()`. The tests should still pass since the identity resolver creates `Rules` from the cap JSON.

**Step 4: Run proxy tests**

Run: `go test ./internal/proxy/ -v -count=1 -race`
Expected: PASS

**Step 5: Commit**

```
feat: pass listener name to HasAccess in proxy layer
```

---

### Task 5: Update ext_authz server

**Files:**
- Modify: `internal/authz/extauthz.go:35-60` (Check method)
- Test: `internal/authz/extauthz_test.go`

**Step 1: Write failing tests for listener + hostname dimensions**

Add to `extauthz_test.go`:

```go
// multiCapMap builds a PeerCapMap with multiple cap rules.
func multiCapMap(rules ...identity.TailvoyCapRule) tailcfg.PeerCapMap {
	msgs := make([]tailcfg.RawMessage, len(rules))
	for i, r := range rules {
		b, _ := json.Marshal(r)
		msgs[i] = tailcfg.RawMessage(b)
	}
	return tailcfg.PeerCapMap{identity.CapTailvoy: msgs}
}

func TestCheckWithListenerContextExtension(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "node.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap: multiCapMap(identity.TailvoyCapRule{
			Listeners: []string{"http"},
			Routes:    []string{"/api/*"},
		}),
	}
	srv := testServer(t, map[string]*apitype.WhoIsResponse{"100.64.1.1": resp})
	client := startGRPC(t, srv)

	// Request with listener=http context extension, should allow
	req := checkReqWithContext(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/api/data",
		map[string]string{"listener": "http"},
	)
	r, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(r) {
		t.Error("expected allow: listener and route match")
	}

	// Request with listener=grpc, should deny
	req2 := checkReqWithContext(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/api/data",
		map[string]string{"listener": "grpc"},
	)
	r2, err := client.Check(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r2) {
		t.Error("expected deny: listener mismatch")
	}
}

func TestCheckWithHostHeader(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Name: "node.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap: multiCapMap(identity.TailvoyCapRule{
			Hostnames: []string{"api.example.com"},
			Routes:    []string{"/v1/*"},
		}),
	}
	srv := testServer(t, map[string]*apitype.WhoIsResponse{"100.64.1.1": resp})
	client := startGRPC(t, srv)

	req := checkReqWithContext(
		map[string]string{"x-forwarded-for": "100.64.1.1", ":authority": "api.example.com"},
		"/v1/users",
		map[string]string{"listener": "http"},
	)
	r, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(r) {
		t.Error("expected allow: hostname and route match")
	}
}
```

Add the `checkReqWithContext` helper:
```go
func checkReqWithContext(headers map[string]string, path string, contextExt map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: headers,
					Path:    path,
					Host:    headers[":authority"],
				},
			},
			ContextExtensions: contextExt,
		},
	}
}
```

**Step 2: Update `Check()` method**

```go
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpReq.GetHeaders()

	srcIP := extractSourceIP(headers)
	if srcIP == "" {
		s.logger.Warn("ext_authz: no source IP")
		return denyResponse(), nil
	}

	id, err := s.resolver.Resolve(ctx, srcIP)
	if err != nil {
		s.logger.Warn("ext_authz: identity resolution failed", "ip", srcIP, "err", err)
		return denyResponse(), nil
	}

	path := httpReq.GetPath()
	host := httpReq.GetHost()
	if host == "" {
		host = headers[":authority"]
	}
	// Strip port from host if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Get listener name from context extensions (set by Envoy per-route config)
	listener := req.GetAttributes().GetContextExtensions()["listener"]
	if listener == "" {
		listener = "default"
	}

	if !s.engine.CheckAccess(listener, host, path, id) {
		s.logger.Info("ext_authz: denied",
			"ip", srcIP, "path", path, "host", host, "listener", listener,
			"user", id.UserLogin, "node", id.NodeName)
		return denyResponse(), nil
	}

	s.logger.Debug("ext_authz: allowed",
		"ip", srcIP, "path", path, "host", host, "listener", listener,
		"user", id.UserLogin, "node", id.NodeName)
	return allowResponse(id), nil
}
```

**Step 3: Update existing tests**

Existing tests use `checkReq()` which doesn't set context extensions. These should still work because the ext_authz falls back to `listener: "default"` and the test fixtures use cap rules without listeners (which match all listeners).

Update `checkReq` to also set an empty context extensions or update fixtures.

**Step 4: Run tests**

Run: `go test ./internal/authz/ -v -count=1 -race`
Expected: PASS

**Step 5: Commit**

```
feat: ext_authz checks listener + hostname + path dimensions
```

---

### Task 6: Add TLS SNI peeking for L4 passthrough

**Files:**
- Create: `internal/proxy/sni.go`
- Test: `internal/proxy/sni_test.go`
- Modify: `internal/proxy/listener.go:73-107`

**Step 1: Write failing tests for SNI extraction**

Create `internal/proxy/sni_test.go`:
```go
package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func TestPeekSNI(t *testing.T) {
	// Build a minimal ClientHello with SNI.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true,
		})
		// Initiate handshake (will fail, that's fine — we just need the ClientHello)
		tlsConn.Handshake()
	}()

	sni, reader, err := PeekSNI(serverConn)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "app.example.com" {
		t.Errorf("SNI = %q, want app.example.com", sni)
	}

	// reader should replay the peeked bytes + rest of stream
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	if n == 0 {
		t.Error("expected peeked data to be readable from returned reader")
	}
}

func TestPeekSNI_NoSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send non-TLS data
	go func() {
		clientConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	sni, reader, err := PeekSNI(serverConn)
	if err != nil {
		// Non-TLS data might return error or empty SNI
		_ = err
	}
	if sni != "" {
		t.Errorf("expected empty SNI for non-TLS data, got %q", sni)
	}
	// reader should still work (data not consumed)
	_ = reader
}
```

**Step 2: Implement SNI peeking**

Create `internal/proxy/sni.go`:
```go
package proxy

import (
	"io"
	"net"

	"crypto/tls"
)

// PeekSNI reads enough of the TLS ClientHello from conn to extract the
// SNI server name, without consuming the bytes. It returns the SNI (empty
// if not found or not TLS) and an io.Reader that replays the peeked bytes
// followed by the rest of the connection.
func PeekSNI(conn net.Conn) (string, io.Reader, error) {
	// Read up to 16KB (max TLS record). ClientHello is typically < 1KB.
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	if err != nil {
		return "", io.MultiReader(bytes.NewReader(buf[:n]), conn), err
	}
	buf = buf[:n]

	sni := extractSNI(buf)
	reader := io.MultiReader(bytes.NewReader(buf), conn)
	return sni, reader, nil
}

// extractSNI parses a TLS ClientHello to extract the SNI extension value.
func extractSNI(data []byte) string {
	// Minimal TLS record parsing:
	// byte 0: content type (0x16 = handshake)
	// bytes 1-2: TLS version
	// bytes 3-4: length
	// byte 5: handshake type (0x01 = ClientHello)
	if len(data) < 6 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}

	// Use crypto/tls to parse via the Conn interface would be complex.
	// Instead, use a simple SNI parser.
	// The SNI is in the extensions of the ClientHello.
	// For a robust implementation, use golang.org/x/crypto or manual parsing.

	// Quick approach: use tls.Server with a custom GetConfigForClient callback.
	// This is the cleanest way to extract SNI without manual parsing.
	var sni string
	clientConn, serverConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tlsServer := tls.Server(serverConn, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				sni = hello.ServerName
				return nil, io.EOF // abort after getting SNI
			},
		})
		tlsServer.Handshake()
		serverConn.Close()
	}()

	clientConn.Write(data)
	clientConn.Close()
	<-done

	return sni
}
```

Actually, the `extractSNI` using net.Pipe is wasteful. Use manual TLS ClientHello parsing instead — it's straightforward:

```go
package proxy

import (
	"bytes"
	"io"
	"net"
)

func PeekSNI(conn net.Conn) (string, io.Reader, error) {
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	if n == 0 {
		return "", io.MultiReader(bytes.NewReader(buf[:n]), conn), err
	}
	buf = buf[:n]
	sni := parseSNI(buf)
	return sni, io.MultiReader(bytes.NewReader(buf), conn), nil
}

// parseSNI extracts SNI from a TLS ClientHello record.
func parseSNI(data []byte) string {
	// TLS record: type(1) + version(2) + length(2) + handshake
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return "" // partial record, best effort
	}
	hs := data[5 : 5+recordLen]

	// Handshake: type(1) + length(3) + body
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	ch := hs[4 : 4+hsLen]

	// ClientHello: version(2) + random(32) + session_id(var) + cipher_suites(var) + compression(var) + extensions
	if len(ch) < 34 {
		return ""
	}
	pos := 34

	// Session ID
	if pos >= len(ch) {
		return ""
	}
	sidLen := int(ch[pos])
	pos += 1 + sidLen

	// Cipher suites
	if pos+2 > len(ch) {
		return ""
	}
	csLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2 + csLen

	// Compression methods
	if pos >= len(ch) {
		return ""
	}
	cmLen := int(ch[pos])
	pos += 1 + cmLen

	// Extensions length
	if pos+2 > len(ch) {
		return ""
	}
	extLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2

	extEnd := pos + extLen
	if extEnd > len(ch) {
		extEnd = len(ch)
	}

	for pos+4 <= extEnd {
		extType := int(ch[pos])<<8 | int(ch[pos+1])
		eLen := int(ch[pos+2])<<8 | int(ch[pos+3])
		pos += 4
		if pos+eLen > extEnd {
			break
		}

		if extType == 0 { // SNI extension
			sniData := ch[pos : pos+eLen]
			if len(sniData) < 2 {
				break
			}
			sniListLen := int(sniData[0])<<8 | int(sniData[1])
			sniList := sniData[2:]
			if len(sniList) < sniListLen {
				break
			}
			off := 0
			for off+3 <= sniListLen {
				nameType := sniList[off]
				nameLen := int(sniList[off+1])<<8 | int(sniList[off+2])
				off += 3
				if off+nameLen > sniListLen {
					break
				}
				if nameType == 0 { // host_name
					return string(sniList[off : off+nameLen])
				}
				off += nameLen
			}
		}
		pos += eLen
	}

	return ""
}
```

**Step 3: Wire SNI peeking into `handleConn`**

In `internal/proxy/listener.go`, update `handleConn` to peek SNI for non-L7 TCP listeners before the HasAccess check:

```go
func (lm *ListenerManager) handleConn(ctx context.Context, conn net.Conn, listenerCfg *config.Listener) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	id, err := lm.resolver.Resolve(ctx, remoteAddr)
	if err != nil {
		lm.logger.Warn("identity resolution failed",
			"listener", listenerCfg.Name, "remote", remoteAddr, "err", err)
		return
	}

	// For non-L7 TCP listeners, peek TLS ClientHello for SNI.
	var sni string
	var forwardReader io.Reader
	if !listenerCfg.L7Policy && listenerCfg.Protocol == "tcp" {
		sni, forwardReader, _ = PeekSNI(conn)
	}

	if !lm.engine.HasAccess(listenerCfg.Name, sni, id) {
		lm.logger.Info("connection denied by L4 policy",
			"listener", listenerCfg.Name, "remote", remoteAddr,
			"sni", sni, "identity", id.UserLogin, "node", id.NodeName)
		return
	}

	useProxyProto := listenerCfg.ProxyProtocol == "v2"

	// If we peeked SNI, we need to forward the peeked data + rest of conn.
	// Wrap conn with the replay reader.
	if forwardReader != nil {
		conn = &readerConn{Conn: conn, reader: forwardReader}
	}

	if err := lm.l4proxy.Forward(ctx, conn, listenerCfg.Forward, conn.RemoteAddr(), useProxyProto); err != nil {
		lm.logger.Debug("forward ended",
			"listener", listenerCfg.Name, "remote", remoteAddr, "err", err)
	}
}
```

Add `readerConn` wrapper:
```go
// readerConn wraps a net.Conn, reading from reader (which replays peeked data)
// instead of the underlying connection.
type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
```

**Step 4: Run tests**

Run: `go test ./internal/proxy/ -v -count=1 -race`
Expected: PASS

**Step 5: Commit**

```
feat: add TLS SNI peeking for L4 hostname-based access control
```

---

### Task 7: Update ext_authz tests comprehensively

**Files:**
- Modify: `internal/authz/extauthz_test.go`

**Step 1: Update all test fixtures and helpers**

Update `capMap` helper to support the full rule structure. Add `multiCapMap` helper. Update existing test response fixtures to use `Rules` instead of `AllowedRoutes`. Update `checkReq` to include context extensions.

**Step 2: Run full test suite**

Run: `go test ./... -v -count=1 -race`
Expected: PASS

**Step 3: Commit**

```
test: update ext_authz tests for multi-dimensional cap rules
```

---

### Task 8: Run full test suite and fix any remaining issues

**Step 1: Build**

Run: `go build ./...`
Expected: No errors

**Step 2: Run all tests**

Run: `go test ./... -v -count=1 -race`
Expected: All PASS

**Step 3: Run lint**

Run: `make lint`
Expected: No issues

**Step 4: Commit any fixes**

---

### Task 9: Update README

**Files:**
- Modify: `README.md`

Update all examples to show the full multi-dimensional cap structure. Add sections for:
- Listener-scoped access
- Hostname-based gating (TLS + HTTP)
- Combined dimensions
- Updated cap rule reference table

**Commit:**
```
docs: update README for multi-dimensional cap structure
```

---

### Task 10: Update ACL grants and integration test config

**Files (external repos):**
- `../kubernetes-manifests/tailscale/policy.hujson` — update grants with listener names
- `integration_test/kind/manifests/tailvoy-config.yaml` — update listener names
- `integration_test/kind/run-kind-tests.sh` — update test assertions

**Commit:**
```
chore: update ACL grants and integration test config for multi-dimensional caps
```
