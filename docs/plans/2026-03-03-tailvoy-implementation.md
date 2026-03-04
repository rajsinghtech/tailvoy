# tailvoy v0.1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Tailscale identity-aware L4 firewall that wraps Envoy, using tsnet WhoIs for connection gating and ext_authz for L7 HTTP path decisions.

**Architecture:** tailvoy is a Go binary using tsnet that accepts tailnet connections, identifies callers via WhoIs, enforces YAML-defined access policies at L4 (connection time) and L7 (HTTP path via ext_authz), then forwards allowed traffic to Envoy as raw bytes with PROXY protocol v2 to preserve source IPs.

**Tech Stack:** Go, tsnet, Envoy (subprocess), PROXY protocol v2, ext_authz HTTP, YAML config

**Design doc:** `docs/plans/2026-03-03-tailvoy-design.md`

**Ref repos (read-only):**
- `../tailscale/tsnet/tsnet.go` — tsnet.Server API
- `../tailscale/client/local/local.go` — WhoIs API
- `../tailscale/tailcfg/tailcfg.go` — Node, UserProfile types
- `../examples/ext_authz/` — ext_authz example config
- `../gateway/internal/infrastructure/kubernetes/proxy/resource.go` — gateway Envoy contract

---

## Task 1: Project Scaffold + Go Module

**Files:**
- Create: `go.mod`
- Create: `cmd/tailvoy/main.go`
- Create: `internal/config/config.go`
- Create: `internal/identity/whois.go`
- Create: `internal/proxy/l4.go`
- Create: `internal/proxy/listener.go`
- Create: `internal/authz/extauthz.go`
- Create: `internal/policy/engine.go`
- Create: `internal/envoy/manager.go`
- Create: `internal/envoy/bootstrap.go`

**Step 1: Initialize Go module**

```bash
cd /Users/rajsingh/Documents/GitHub/tailvoy
go mod init github.com/rajsinghtech/tailvoy
```

**Step 2: Create directory structure**

```bash
mkdir -p cmd/tailvoy internal/{config,identity,proxy,authz,policy,envoy}
```

**Step 3: Create stub main.go**

```go
// cmd/tailvoy/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tailvoy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return fmt.Errorf("not implemented")
}
```

**Step 4: Verify it compiles**

```bash
go build ./cmd/tailvoy/
```

Expected: binary builds successfully (exits with error when run, that's fine)

**Step 5: Commit**

```bash
git add -A
git commit -m "Scaffold project structure and go module"
```

---

## Task 2: Config Parsing

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `testdata/policy.yaml` (test fixture)

**Ref:** Design doc policy format section

**Step 1: Write the test fixture**

Create `testdata/policy.yaml`:

```yaml
tailscale:
  hostname: "tailvoy-test"
  authkey: "${TS_AUTHKEY}"
  ephemeral: true

listeners:
  - name: https
    protocol: tcp
    listen: ":443"
    forward: "envoy:443"
    proxy_protocol: v2
    l7_policy: true

  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "db-server:5432"
    l7_policy: false

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

l7_rules:
  - match:
      listener: https
      path: "/admin/*"
    allow:
      users: ["alice@company.com"]
      tags: ["tag:admin"]

  - match:
      listener: https
      path: "/*"
    allow:
      any_tailscale: true

default: deny
```

**Step 2: Write config types and failing tests**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Tailscale TailscaleConfig `yaml:"tailscale"`
	Listeners []Listener      `yaml:"listeners"`
	L4Rules   []Rule          `yaml:"l4_rules"`
	L7Rules   []Rule          `yaml:"l7_rules"`
	Default   string          `yaml:"default"`
}

type TailscaleConfig struct {
	Hostname  string `yaml:"hostname"`
	AuthKey   string `yaml:"authkey"`
	Ephemeral bool   `yaml:"ephemeral"`
}

type Listener struct {
	Name          string `yaml:"name"`
	Protocol      string `yaml:"protocol"`
	Listen        string `yaml:"listen"`
	Forward       string `yaml:"forward"`
	ProxyProtocol string `yaml:"proxy_protocol"`
	L7Policy      bool   `yaml:"l7_policy"`
}

type Rule struct {
	Match RuleMatch `yaml:"match"`
	Allow AllowSpec `yaml:"allow"`
}

type RuleMatch struct {
	Listener string `yaml:"listener"`
	Path     string `yaml:"path"`
}

type AllowSpec struct {
	AnyTailscale bool     `yaml:"any_tailscale"`
	Users        []string `yaml:"users"`
	Tags         []string `yaml:"tags"`
	Groups       []string `yaml:"groups"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	expanded := expandEnvVars(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func expandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return ""
	})
}

func (c *Config) validate() error {
	if c.Tailscale.Hostname == "" {
		return fmt.Errorf("tailscale.hostname is required")
	}

	listenerNames := make(map[string]bool)
	for _, l := range c.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listener name is required")
		}
		if listenerNames[l.Name] {
			return fmt.Errorf("duplicate listener name: %s", l.Name)
		}
		listenerNames[l.Name] = true

		if l.Listen == "" {
			return fmt.Errorf("listener %s: listen address is required", l.Name)
		}
		if l.Forward == "" {
			return fmt.Errorf("listener %s: forward address is required", l.Name)
		}
		if l.Protocol == "" {
			return fmt.Errorf("listener %s: protocol is required", l.Name)
		}
	}

	for i, r := range c.L4Rules {
		if r.Match.Listener == "" {
			return fmt.Errorf("l4_rules[%d]: match.listener is required", i)
		}
		if !listenerNames[r.Match.Listener] {
			return fmt.Errorf("l4_rules[%d]: unknown listener %q", i, r.Match.Listener)
		}
	}

	for i, r := range c.L7Rules {
		if r.Match.Listener == "" {
			return fmt.Errorf("l7_rules[%d]: match.listener is required", i)
		}
		if !listenerNames[r.Match.Listener] {
			return fmt.Errorf("l7_rules[%d]: unknown listener %q", i, r.Match.Listener)
		}
		if r.Match.Path == "" {
			return fmt.Errorf("l7_rules[%d]: match.path is required for l7 rules", i)
		}
	}

	if c.Default != "deny" && c.Default != "allow" {
		// Default to deny if not specified
		if c.Default == "" {
			c.Default = "deny"
		} else {
			return fmt.Errorf("default must be 'allow' or 'deny', got %q", c.Default)
		}
	}

	return nil
}

// ListenerByName returns a listener by name or nil if not found.
func (c *Config) ListenerByName(name string) *Listener {
	for i := range c.Listeners {
		if c.Listeners[i].Name == name {
			return &c.Listeners[i]
		}
	}
	return nil
}

// L7Listeners returns listeners that have l7_policy enabled.
func (c *Config) L7Listeners() []Listener {
	var result []Listener
	for _, l := range c.Listeners {
		if l.L7Policy {
			result = append(result, l)
		}
	}
	return result
}

// Port extracts the port number from a listen address like ":443".
func (l *Listener) Port() string {
	parts := strings.SplitN(l.Listen, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return l.Listen
}
```

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	cfg, err := Load("../../testdata/policy.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tailscale.Hostname != "tailvoy-test" {
		t.Errorf("hostname = %q, want tailvoy-test", cfg.Tailscale.Hostname)
	}
	if len(cfg.Listeners) != 2 {
		t.Errorf("listeners = %d, want 2", len(cfg.Listeners))
	}
	if len(cfg.L4Rules) != 2 {
		t.Errorf("l4_rules = %d, want 2", len(cfg.L4Rules))
	}
	if len(cfg.L7Rules) != 2 {
		t.Errorf("l7_rules = %d, want 2", len(cfg.L7Rules))
	}
	if cfg.Default != "deny" {
		t.Errorf("default = %q, want deny", cfg.Default)
	}
}

func TestEnvVarExpansion(t *testing.T) {
	os.Setenv("TS_AUTHKEY", "tskey-test-123")
	defer os.Unsetenv("TS_AUTHKEY")

	cfg, err := Load("../../testdata/policy.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tailscale.AuthKey != "tskey-test-123" {
		t.Errorf("authkey = %q, want tskey-test-123", cfg.Tailscale.AuthKey)
	}
}

func TestParseMinimal(t *testing.T) {
	yaml := `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "backend:80"
default: deny
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.Hostname != "test" {
		t.Errorf("hostname = %q", cfg.Tailscale.Hostname)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing hostname",
			yaml: `tailscale: {}`,
			want: "hostname is required",
		},
		{
			name: "duplicate listener",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
  - name: web
    protocol: tcp
    listen: ":81"
    forward: "b:81"
`,
			want: "duplicate listener name",
		},
		{
			name: "unknown listener in l4 rule",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
l4_rules:
  - match:
      listener: nonexistent
    allow:
      any_tailscale: true
`,
			want: "unknown listener",
		},
		{
			name: "l7 rule missing path",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
l7_rules:
  - match:
      listener: web
    allow:
      any_tailscale: true
`,
			want: "match.path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want to contain %q", err, tt.want)
			}
		})
	}
}

func TestListenerByName(t *testing.T) {
	cfg, _ := Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
`))
	if l := cfg.ListenerByName("web"); l == nil {
		t.Fatal("expected listener")
	}
	if l := cfg.ListenerByName("nope"); l != nil {
		t.Fatal("expected nil")
	}
}

func TestListenerPort(t *testing.T) {
	l := Listener{Listen: ":443"}
	if l.Port() != "443" {
		t.Errorf("port = %q, want 443", l.Port())
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsAt(s, substr)
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

**Step 3: Add yaml dependency and run tests**

```bash
go get gopkg.in/yaml.v3
go test ./internal/config/ -v
```

Expected: all tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "Add config parsing with YAML policy format and validation"
```

---

## Task 3: Policy Engine

**Files:**
- Create: `internal/policy/engine.go`
- Create: `internal/policy/engine_test.go`

**Ref:** Design doc policy evaluation section. `../tailscale/tailcfg/tailcfg.go` for Node/UserProfile types.

**Step 1: Write policy engine with tests**

Create `internal/policy/engine.go`:

```go
package policy

import (
	"path"
	"strings"
	"sync"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

// Identity represents a Tailscale caller's identity extracted from WhoIs.
type Identity struct {
	UserLogin   string   // UserProfile.LoginName
	NodeName    string   // Node.ComputedName
	Tags        []string // Node.Tags
	IsTagged    bool     // Node.IsTagged()
	TailscaleIP string   // Source Tailscale IP
}

// Engine evaluates access policy rules against caller identity.
type Engine struct {
	mu     sync.RWMutex
	config *config.Config
}

func NewEngine(cfg *config.Config) *Engine {
	return &Engine{config: cfg}
}

// Reload swaps the config atomically.
func (e *Engine) Reload(cfg *config.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}

// CheckL4 evaluates L4 rules for a connection to the named listener.
// Returns true if the connection is allowed.
func (e *Engine) CheckL4(listenerName string, id *Identity) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.config.L4Rules {
		if rule.Match.Listener != listenerName {
			continue
		}
		if matchesAllow(&rule.Allow, id) {
			return true
		}
	}

	return e.config.Default == "allow"
}

// CheckL7 evaluates L7 rules for an HTTP request to the named listener.
// Returns true if the request is allowed.
func (e *Engine) CheckL7(listenerName, reqPath string, id *Identity) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.config.L7Rules {
		if rule.Match.Listener != listenerName {
			continue
		}
		if !matchPath(rule.Match.Path, reqPath) {
			continue
		}
		if matchesAllow(&rule.Allow, id) {
			return true
		}
		// Path matched but identity didn't — continue checking other rules
	}

	return e.config.Default == "allow"
}

func matchesAllow(allow *config.AllowSpec, id *Identity) bool {
	if allow.AnyTailscale {
		return true
	}

	for _, u := range allow.Users {
		if strings.EqualFold(u, id.UserLogin) {
			return true
		}
	}

	for _, t := range allow.Tags {
		for _, nodeTag := range id.Tags {
			if t == nodeTag {
				return true
			}
		}
	}

	for _, g := range allow.Groups {
		// Groups are matched by convention: "group:devs" in the rule
		// matches against node tags (Tailscale resolves group membership to tags)
		for _, nodeTag := range id.Tags {
			if g == nodeTag {
				return true
			}
		}
	}

	return false
}

// matchPath matches a request path against a pattern.
// Supports trailing /* for prefix matching and exact matches.
func matchPath(pattern, reqPath string) bool {
	if pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
	}
	// Use path.Match for glob patterns
	matched, _ := path.Match(pattern, reqPath)
	return matched
}
```

Create `internal/policy/engine_test.go`:

```go
package policy

import (
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

func testConfig() *config.Config {
	cfg, _ := config.Parse([]byte(`
tailscale:
  hostname: test

listeners:
  - name: https
    protocol: tcp
    listen: ":443"
    forward: "envoy:443"
    l7_policy: true

  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "db:5432"

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
      tags: ["tag:prod"]

  - match:
      listener: https
      path: "/*"
    allow:
      any_tailscale: true

default: deny
`))
	return cfg
}

func TestCheckL4_AllowAnyTailscale(t *testing.T) {
	e := NewEngine(testConfig())
	id := &Identity{UserLogin: "anyone@company.com"}
	if !e.CheckL4("https", id) {
		t.Error("expected allow for any tailscale user on https")
	}
}

func TestCheckL4_AllowByTag(t *testing.T) {
	e := NewEngine(testConfig())
	id := &Identity{UserLogin: "dev@company.com", Tags: []string{"tag:db-access"}}
	if !e.CheckL4("postgres", id) {
		t.Error("expected allow for tag:db-access on postgres")
	}
}

func TestCheckL4_AllowByUser(t *testing.T) {
	e := NewEngine(testConfig())
	id := &Identity{UserLogin: "dba@company.com"}
	if !e.CheckL4("postgres", id) {
		t.Error("expected allow for dba user on postgres")
	}
}

func TestCheckL4_DenyUnmatched(t *testing.T) {
	e := NewEngine(testConfig())
	id := &Identity{UserLogin: "random@company.com"}
	if e.CheckL4("postgres", id) {
		t.Error("expected deny for random user on postgres")
	}
}

func TestCheckL7_AdminPath(t *testing.T) {
	e := NewEngine(testConfig())

	alice := &Identity{UserLogin: "alice@company.com"}
	if !e.CheckL7("https", "/admin/settings", alice) {
		t.Error("expected allow for alice on /admin/*")
	}

	random := &Identity{UserLogin: "random@company.com"}
	// random doesn't match /admin/* rule, falls through to /* rule which allows any_tailscale
	if !e.CheckL7("https", "/admin/settings", random) {
		t.Error("expected allow for random on /admin/* (falls through to /* any_tailscale)")
	}
}

func TestCheckL7_ApiPathByTag(t *testing.T) {
	e := NewEngine(testConfig())

	prod := &Identity{UserLogin: "svc@company.com", Tags: []string{"tag:prod"}}
	if !e.CheckL7("https", "/api/users", prod) {
		t.Error("expected allow for tag:prod on /api/*")
	}
}

func TestCheckL7_CatchAll(t *testing.T) {
	e := NewEngine(testConfig())
	id := &Identity{UserLogin: "anyone@company.com"}
	if !e.CheckL7("https", "/random/page", id) {
		t.Error("expected allow for any tailscale user on /*")
	}
}

func TestCheckL7_DefaultDeny(t *testing.T) {
	cfg, _ := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
    l7_policy: true
l7_rules:
  - match:
      listener: web
      path: "/allowed"
    allow:
      users: ["alice@company.com"]
default: deny
`))
	e := NewEngine(cfg)
	id := &Identity{UserLogin: "bob@company.com"}
	if e.CheckL7("web", "/allowed", id) {
		t.Error("expected deny for bob on /allowed")
	}
	if e.CheckL7("web", "/other", id) {
		t.Error("expected deny for bob on /other")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/*", "/anything", true},
		{"/*", "/", true},
		{"/admin/*", "/admin/settings", true},
		{"/admin/*", "/admin", true},
		{"/admin/*", "/admins", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api", true},
		{"/exact", "/exact", true},
		{"/exact", "/exactlyNot", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			if got := matchPath(tt.pattern, tt.path); got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestReload(t *testing.T) {
	cfg1, _ := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
default: deny
`))
	cfg2, _ := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "b:80"
l4_rules:
  - match:
      listener: web
    allow:
      any_tailscale: true
default: deny
`))

	e := NewEngine(cfg1)
	id := &Identity{UserLogin: "test@company.com"}
	if e.CheckL4("web", id) {
		t.Error("expected deny before reload")
	}

	e.Reload(cfg2)
	if !e.CheckL4("web", id) {
		t.Error("expected allow after reload")
	}
}
```

**Step 2: Run tests**

```bash
go test ./internal/policy/ -v
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add policy engine with L4/L7 rule matching"
```

---

## Task 4: Identity / WhoIs Wrapper

**Files:**
- Create: `internal/identity/whois.go`
- Create: `internal/identity/whois_test.go`

**Ref:** `../tailscale/client/local/local.go` for WhoIs API, `../tailscale/client/tailscale/apitype/apitype.go` for WhoIsResponse

**Step 1: Write identity resolver with interface for testing**

Create `internal/identity/whois.go`:

```go
package identity

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/policy"
	"tailscale.com/client/tailscale/apitype"
)

// WhoIsClient is the interface for Tailscale WhoIs lookups.
// Implemented by tailscale local.Client.
type WhoIsClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Resolver wraps WhoIs lookups with a cache keyed by Tailscale IP.
type Resolver struct {
	client WhoIsClient

	mu    sync.RWMutex
	cache map[netip.Addr]*cacheEntry
}

type cacheEntry struct {
	identity *policy.Identity
	resp     *apitype.WhoIsResponse
	expires  time.Time
}

const cacheTTL = 5 * time.Minute

func NewResolver(client WhoIsClient) *Resolver {
	return &Resolver{
		client: client,
		cache:  make(map[netip.Addr]*cacheEntry),
	}
}

// Resolve looks up the identity of a remote address (IP or IP:port).
func (r *Resolver) Resolve(ctx context.Context, remoteAddr string) (*policy.Identity, error) {
	ip := extractIP(remoteAddr)
	if !ip.IsValid() {
		return nil, &ResolveError{Addr: remoteAddr, Reason: "invalid IP"}
	}

	// Check cache
	if id := r.cached(ip); id != nil {
		return id, nil
	}

	// Call WhoIs
	resp, err := r.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, &ResolveError{Addr: remoteAddr, Reason: err.Error()}
	}

	id := toIdentity(resp, ip)
	r.store(ip, id, resp)
	return id, nil
}

// CachedIdentity returns a cached identity for an IP without making a WhoIs call.
// Returns nil if not cached.
func (r *Resolver) CachedIdentity(remoteAddr string) *policy.Identity {
	ip := extractIP(remoteAddr)
	return r.cached(ip)
}

func (r *Resolver) cached(ip netip.Addr) *policy.Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.cache[ip]; ok && time.Now().Before(e.expires) {
		return e.identity
	}
	return nil
}

func (r *Resolver) store(ip netip.Addr, id *policy.Identity, resp *apitype.WhoIsResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ip] = &cacheEntry{
		identity: id,
		resp:     resp,
		expires:  time.Now().Add(cacheTTL),
	}
}

func toIdentity(resp *apitype.WhoIsResponse, ip netip.Addr) *policy.Identity {
	id := &policy.Identity{
		TailscaleIP: ip.String(),
	}

	if resp.UserProfile != nil {
		id.UserLogin = resp.UserProfile.LoginName
	}
	if resp.Node != nil {
		id.NodeName = resp.Node.ComputedName
		id.Tags = resp.Node.Tags
		id.IsTagged = len(resp.Node.Tags) > 0
	}
	return id
}

func extractIP(addr string) netip.Addr {
	// Try as IP:port first
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr()
	}
	// Try as bare IP
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip
	}
	return netip.Addr{}
}

type ResolveError struct {
	Addr   string
	Reason string
}

func (e *ResolveError) Error() string {
	return "whois " + e.Addr + ": " + e.Reason
}

// StripPort removes the port from an addr string, returning just the IP.
func StripPort(addr string) string {
	ip := extractIP(addr)
	if ip.IsValid() {
		return ip.String()
	}
	// Fallback: strip after last colon
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
```

Create `internal/identity/whois_test.go`:

```go
package identity

import (
	"context"
	"net/netip"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/policy"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// mockClient implements WhoIsClient for testing.
type mockClient struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	ip := extractIP(remoteAddr)
	if resp, ok := m.responses[ip.String()]; ok {
		return resp, nil
	}
	return nil, &ResolveError{Addr: remoteAddr, Reason: "not found"}
}

func TestResolve(t *testing.T) {
	client := &mockClient{
		responses: map[string]*apitype.WhoIsResponse{
			"100.64.1.5": {
				Node: &tailcfg.Node{
					ComputedName: "alice-laptop",
					Tags:         []string{"tag:prod"},
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName: "alice@company.com",
				},
			},
		},
	}

	r := NewResolver(client)
	id, err := r.Resolve(context.Background(), "100.64.1.5:54321")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.UserLogin != "alice@company.com" {
		t.Errorf("UserLogin = %q", id.UserLogin)
	}
	if id.NodeName != "alice-laptop" {
		t.Errorf("NodeName = %q", id.NodeName)
	}
	if len(id.Tags) != 1 || id.Tags[0] != "tag:prod" {
		t.Errorf("Tags = %v", id.Tags)
	}
	if id.TailscaleIP != "100.64.1.5" {
		t.Errorf("TailscaleIP = %q", id.TailscaleIP)
	}
}

func TestResolveCache(t *testing.T) {
	callCount := 0
	client := &mockClient{
		responses: map[string]*apitype.WhoIsResponse{
			"100.64.1.5": {
				Node:        &tailcfg.Node{ComputedName: "test"},
				UserProfile: &tailcfg.UserProfile{LoginName: "test@co.com"},
			},
		},
	}
	// Wrap to count calls
	r := NewResolver(client)

	_, _ = r.Resolve(context.Background(), "100.64.1.5:1234")
	_ = callCount // first call

	// Second call should use cache
	cached := r.CachedIdentity("100.64.1.5:5678")
	if cached == nil {
		t.Fatal("expected cached identity")
	}
	if cached.UserLogin != "test@co.com" {
		t.Errorf("cached UserLogin = %q", cached.UserLogin)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"100.64.1.5:1234", "100.64.1.5"},
		{"100.64.1.5", "100.64.1.5"},
		{"[fd7a::1]:443", "fd7a::1"},
		{"invalid", "invalid"},
	}
	for _, tt := range tests {
		ip := extractIP(tt.input)
		if tt.want == "invalid" {
			if ip.IsValid() {
				t.Errorf("extractIP(%q) = %v, want invalid", tt.input, ip)
			}
		} else {
			want := netip.MustParseAddr(tt.want)
			if ip != want {
				t.Errorf("extractIP(%q) = %v, want %v", tt.input, ip, want)
			}
		}
	}
}

func TestResolveIdentityFields(t *testing.T) {
	// Tagged node (no user profile)
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			ComputedName: "ci-runner",
			Tags:         []string{"tag:ci", "tag:prod"},
		},
	}
	id := toIdentity(resp, netip.MustParseAddr("100.64.2.1"))
	if id.UserLogin != "" {
		t.Errorf("UserLogin = %q, want empty for tagged node", id.UserLogin)
	}
	if !id.IsTagged {
		t.Error("expected IsTagged=true")
	}
	if id.NodeName != "ci-runner" {
		t.Errorf("NodeName = %q", id.NodeName)
	}
}

var _ WhoIsClient = (*mockClient)(nil) // compile-time check
var _ *policy.Identity                 // verify import works
```

**Step 2: Add tailscale dependency and run tests**

```bash
go get tailscale.com/tsnet tailscale.com/client/local tailscale.com/tailcfg tailscale.com/client/tailscale/apitype
go test ./internal/identity/ -v
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add WhoIs identity resolver with caching"
```

---

## Task 5: L4 TCP Proxy with PROXY Protocol

**Files:**
- Create: `internal/proxy/l4.go`
- Create: `internal/proxy/l4_test.go`

**Step 1: Write L4 TCP proxy**

Create `internal/proxy/l4.go`:

```go
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// L4Proxy forwards raw TCP connections with optional PROXY protocol v2.
type L4Proxy struct {
	logger *slog.Logger
}

func NewL4Proxy(logger *slog.Logger) *L4Proxy {
	return &L4Proxy{logger: logger}
}

// Forward proxies a client connection to a backend, optionally prepending
// a PROXY protocol v2 header with the real source address.
func (p *L4Proxy) Forward(ctx context.Context, client net.Conn, backendAddr string, srcAddr net.Addr, useProxyProto bool) error {
	backend, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial backend %s: %w", backendAddr, err)
	}

	if useProxyProto && srcAddr != nil {
		if err := writeProxyHeader(backend, srcAddr, client.LocalAddr()); err != nil {
			backend.Close()
			return fmt.Errorf("write proxy protocol header: %w", err)
		}
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	copyDone := make(chan struct{})

	go func() {
		defer wg.Done()
		io.Copy(backend, client)
		// Signal the other direction to stop
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, backend)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		wg.Wait()
		close(copyDone)
	}()

	select {
	case <-copyDone:
	case <-ctx.Done():
	}

	client.Close()
	backend.Close()
	return nil
}

func writeProxyHeader(dst net.Conn, srcAddr, dstAddr net.Addr) error {
	src, srcOK := srcAddr.(*net.TCPAddr)
	d, dstOK := dstAddr.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return fmt.Errorf("unsupported address types: src=%T dst=%T", srcAddr, dstAddr)
	}

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        src,
		DestinationAddr:   d,
	}

	if src.IP.To4() == nil {
		header.TransportProtocol = proxyproto.TCPv6
	}

	_, err := header.WriteTo(dst)
	return err
}
```

Create `internal/proxy/l4_test.go`:

```go
package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestForwardBasic(t *testing.T) {
	// Start a backend that echoes data
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// Create client connection pair
	clientConn, serverConn := net.Pipe()

	proxy := NewL4Proxy(slog.Default())

	go func() {
		proxy.Forward(context.Background(), serverConn, backend.Addr().String(), nil, false)
	}()

	// Write data through the proxy
	testData := []byte("hello tailvoy")
	clientConn.Write(testData)

	buf := make([]byte, len(testData))
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(clientConn, buf)
	if err != nil {
		t.Fatalf("read: %v (got %d bytes)", err, n)
	}
	if !bytes.Equal(buf, testData) {
		t.Errorf("got %q, want %q", buf, testData)
	}
	clientConn.Close()
}

func TestForwardWithProxyProtocol(t *testing.T) {
	// Start a backend that reads PROXY protocol header then echoes
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	var gotHeader *proxyproto.Header
	headerCh := make(chan struct{})

	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read PROXY protocol header
		reader := proxyproto.NewReader(conn)
		gotHeader = reader.ProxyHeader()
		close(headerCh)

		// Echo remaining data
		io.Copy(conn, reader)
	}()

	clientConn, serverConn := net.Pipe()

	srcAddr := &net.TCPAddr{IP: net.ParseIP("100.64.1.5"), Port: 54321}
	proxy := NewL4Proxy(slog.Default())

	go func() {
		proxy.Forward(context.Background(), serverConn, backend.Addr().String(), srcAddr, true)
	}()

	clientConn.Write([]byte("test"))

	select {
	case <-headerCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for proxy header")
	}

	if gotHeader == nil {
		t.Fatal("no proxy protocol header received")
	}
	if gotHeader.Version != 2 {
		t.Errorf("version = %d, want 2", gotHeader.Version)
	}
	gotSrc := gotHeader.SourceAddr.(*net.TCPAddr)
	if gotSrc.IP.String() != "100.64.1.5" {
		t.Errorf("source IP = %s, want 100.64.1.5", gotSrc.IP)
	}
	if gotSrc.Port != 54321 {
		t.Errorf("source port = %d, want 54321", gotSrc.Port)
	}
	clientConn.Close()
}
```

**Step 2: Add dependency and run tests**

```bash
go get github.com/pires/go-proxyproto
go test ./internal/proxy/ -v -count=1
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add L4 TCP proxy with PROXY protocol v2 support"
```

---

## Task 6: ext_authz HTTP Server

**Files:**
- Create: `internal/authz/extauthz.go`
- Create: `internal/authz/extauthz_test.go`

**Ref:** `../examples/ext_authz/` for ext_authz HTTP protocol. The ext_authz HTTP service receives the original request headers and returns 200 (allow) or 403 (deny).

**Step 1: Write ext_authz server with tests**

Create `internal/authz/extauthz.go`:

```go
package authz

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// Server implements the Envoy ext_authz HTTP service.
// Envoy sends the original request headers; we check identity + path and return 200 or 403.
type Server struct {
	engine   *policy.Engine
	resolver *identity.Resolver
	logger   *slog.Logger
}

func NewServer(engine *policy.Engine, resolver *identity.Resolver, logger *slog.Logger) *Server {
	return &Server{
		engine:   engine,
		resolver: resolver,
		logger:   logger,
	}
}

// ServeHTTP handles ext_authz check requests from Envoy.
//
// Envoy sends the original request's headers as-is. Key headers:
//   - x-forwarded-for: original client IP (from PROXY protocol)
//   - :path or x-envoy-original-path: request path
//   - :method: request method
//   - x-envoy-internal: "true" if internal
//
// We also check x-forwarded-for to get the Tailscale source IP.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract source IP from x-forwarded-for (set by Envoy from PROXY protocol)
	sourceIP := extractSourceIP(r)
	if sourceIP == "" {
		s.logger.Warn("ext_authz: no source IP found in request")
		http.Error(w, "no source IP", http.StatusForbidden)
		return
	}

	// Resolve identity — try cache first, then WhoIs
	id := s.resolver.CachedIdentity(sourceIP)
	if id == nil {
		var err error
		id, err = s.resolver.Resolve(r.Context(), sourceIP)
		if err != nil {
			s.logger.Warn("ext_authz: WhoIs failed", "ip", sourceIP, "err", err)
			http.Error(w, "identity resolution failed", http.StatusForbidden)
			return
		}
	}

	// Extract request path and listener name
	reqPath := extractPath(r)
	listenerName := r.Header.Get("x-tailvoy-listener")
	if listenerName == "" {
		listenerName = "default"
	}

	// Check L7 policy
	allowed := s.engine.CheckL7(listenerName, reqPath, id)

	if allowed {
		s.logger.Debug("ext_authz: allowed",
			"ip", sourceIP, "user", id.UserLogin, "node", id.NodeName,
			"path", reqPath, "listener", listenerName)

		// Return 200 with identity headers for backend consumption
		w.Header().Set("x-tailscale-user", id.UserLogin)
		w.Header().Set("x-tailscale-node", id.NodeName)
		w.Header().Set("x-tailscale-tags", strings.Join(id.Tags, ","))
		w.Header().Set("x-tailscale-ip", id.TailscaleIP)
		w.WriteHeader(http.StatusOK)
	} else {
		s.logger.Info("ext_authz: denied",
			"ip", sourceIP, "user", id.UserLogin, "node", id.NodeName,
			"path", reqPath, "listener", listenerName)
		http.Error(w, "access denied", http.StatusForbidden)
	}
}

func extractSourceIP(r *http.Request) string {
	// x-forwarded-for from Envoy (PROXY protocol source)
	if xff := r.Header.Get("x-forwarded-for"); xff != "" {
		// Take the first IP (leftmost = original client)
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Fallback: x-envoy-external-address
	if addr := r.Header.Get("x-envoy-external-address"); addr != "" {
		return addr
	}
	return ""
}

func extractPath(r *http.Request) string {
	// Envoy sends original path in these headers
	if p := r.Header.Get("x-envoy-original-path"); p != "" {
		return p
	}
	// In HTTP ext_authz mode, Envoy sends the original request URI as the path
	return r.URL.Path
}

// ListenAndServe starts the ext_authz HTTP server.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.logger.Info("ext_authz server starting", "addr", addr)
	return srv.ListenAndServe()
}
```

Create `internal/authz/extauthz_test.go`:

```go
package authz

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type mockWhoIs struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockWhoIs) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	ip := addr
	// Strip port if present
	ip = identity.StripPort(ip)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, &identity.ResolveError{Addr: addr, Reason: "not found"}
}

func testServer(t *testing.T) *Server {
	t.Helper()

	cfg, err := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: default
    protocol: tcp
    listen: ":443"
    forward: "envoy:443"
    l7_policy: true
l7_rules:
  - match:
      listener: default
      path: "/admin/*"
    allow:
      users: ["alice@company.com"]
  - match:
      listener: default
      path: "/*"
    allow:
      any_tailscale: true
default: deny
`))
	if err != nil {
		t.Fatal(err)
	}

	client := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"100.64.1.5": {
				Node:        &tailcfg.Node{ComputedName: "alice-laptop", Tags: []string{"tag:admin"}},
				UserProfile: &tailcfg.UserProfile{LoginName: "alice@company.com"},
			},
			"100.64.1.10": {
				Node:        &tailcfg.Node{ComputedName: "bob-desktop"},
				UserProfile: &tailcfg.UserProfile{LoginName: "bob@company.com"},
			},
		},
	}

	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(client)

	return NewServer(engine, resolver, slog.Default())
}

func TestExtAuthzAllow(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.5")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("x-tailscale-user") != "alice@company.com" {
		t.Errorf("x-tailscale-user = %q", w.Header().Get("x-tailscale-user"))
	}
	if w.Header().Get("x-tailscale-node") != "alice-laptop" {
		t.Errorf("x-tailscale-node = %q", w.Header().Get("x-tailscale-node"))
	}
}

func TestExtAuthzAdminAllowAlice(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/admin/settings", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.5")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestExtAuthzAdminDenyBob(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/admin/settings", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.10")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Bob doesn't match /admin/* rule (user alice only),
	// but falls through to /* which allows any_tailscale
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (catch-all allows any tailscale user)", w.Code)
	}
}

func TestExtAuthzNoSourceIP(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	// No x-forwarded-for header
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestExtAuthzUnknownIP(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.99.99")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (unknown IP)", w.Code)
	}
}

func TestExtractSourceIP(t *testing.T) {
	tests := []struct {
		xff  string
		want string
	}{
		{"100.64.1.5", "100.64.1.5"},
		{"100.64.1.5, 10.0.0.1", "100.64.1.5"},
		{"", ""},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		if tt.xff != "" {
			r.Header.Set("x-forwarded-for", tt.xff)
		}
		if got := extractSourceIP(r); got != tt.want {
			t.Errorf("extractSourceIP(xff=%q) = %q, want %q", tt.xff, got, tt.want)
		}
	}
}
```

**Step 2: Run tests**

```bash
go test ./internal/authz/ -v
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add ext_authz HTTP server for L7 path-based access control"
```

---

## Task 7: Envoy Process Manager

**Files:**
- Create: `internal/envoy/manager.go`
- Create: `internal/envoy/manager_test.go`

**Step 1: Write Envoy subprocess manager**

Create `internal/envoy/manager.go`:

```go
package envoy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// Manager starts and manages an Envoy subprocess.
type Manager struct {
	envoyBin string
	logger   *slog.Logger
	cmd      *exec.Cmd
}

func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		envoyBin: findEnvoyBinary(),
		logger:   logger,
	}
}

// Start launches Envoy with the given arguments.
// The configYAML argument, if non-empty, is passed via --config-yaml.
func (m *Manager) Start(ctx context.Context, args []string) error {
	if m.envoyBin == "" {
		return fmt.Errorf("envoy binary not found in PATH")
	}

	m.cmd = exec.CommandContext(ctx, m.envoyBin, args...)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	// Use process group so we can signal the whole group
	m.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	m.logger.Info("starting envoy", "bin", m.envoyBin, "args", args)
	return m.cmd.Start()
}

// Wait waits for Envoy to exit and returns its error status.
func (m *Manager) Wait() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return fmt.Errorf("envoy not started")
	}
	return m.cmd.Wait()
}

// Signal sends a signal to the Envoy process.
func (m *Manager) Signal(sig os.Signal) error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	return m.cmd.Process.Signal(sig)
}

// Stop gracefully stops Envoy with SIGTERM, then waits.
func (m *Manager) Stop() error {
	if err := m.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	return m.Wait()
}

func findEnvoyBinary() string {
	// Check explicit path first
	if p := os.Getenv("ENVOY_BIN"); p != "" {
		return p
	}
	// Look in PATH
	if p, err := exec.LookPath("envoy"); err == nil {
		return p
	}
	// Common locations
	for _, p := range []string{"/usr/local/bin/envoy", "/usr/bin/envoy"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ParseArgs splits tailvoy args from envoy passthrough args.
// Everything before "--" is for tailvoy, everything after is for envoy.
// If no "--" is found, all args are for tailvoy.
func ParseArgs(args []string) (tailvoyArgs, envoyArgs []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
```

Create `internal/envoy/manager_test.go`:

```go
package envoy

import (
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTV     []string
		wantEnvoy  []string
	}{
		{
			name:      "no separator",
			args:      []string{"--policy", "policy.yaml"},
			wantTV:    []string{"--policy", "policy.yaml"},
			wantEnvoy: nil,
		},
		{
			name:      "with separator",
			args:      []string{"--policy", "policy.yaml", "--", "--log-level", "warn"},
			wantTV:    []string{"--policy", "policy.yaml"},
			wantEnvoy: []string{"--log-level", "warn"},
		},
		{
			name:      "only envoy args",
			args:      []string{"--", "--config-yaml", "..."},
			wantTV:    []string{},
			wantEnvoy: []string{"--config-yaml", "..."},
		},
		{
			name:      "empty",
			args:      []string{},
			wantTV:    []string{},
			wantEnvoy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tv, ev := ParseArgs(tt.args)
			if len(tv) != len(tt.wantTV) {
				t.Errorf("tailvoy args = %v, want %v", tv, tt.wantTV)
			}
			if len(ev) != len(tt.wantEnvoy) {
				t.Errorf("envoy args = %v, want %v", ev, tt.wantEnvoy)
			}
		})
	}
}

func TestFindEnvoyBinary(t *testing.T) {
	// This test is environment-dependent.
	// Just verify it doesn't panic and returns a string.
	_ = findEnvoyBinary()
}
```

**Step 2: Run tests**

```bash
go test ./internal/envoy/ -v
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add Envoy subprocess manager with signal forwarding"
```

---

## Task 8: tsnet Listener Manager

**Files:**
- Create: `internal/proxy/listener.go`
- Create: `internal/proxy/listener_test.go`

**Step 1: Write listener manager**

Create `internal/proxy/listener.go`:

```go
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// ListenerManager creates and manages tsnet listeners based on config.
type ListenerManager struct {
	engine   *policy.Engine
	resolver *identity.Resolver
	l4proxy  *L4Proxy
	logger   *slog.Logger
}

func NewListenerManager(engine *policy.Engine, resolver *identity.Resolver, l4proxy *L4Proxy, logger *slog.Logger) *ListenerManager {
	return &ListenerManager{
		engine:   engine,
		resolver: resolver,
		l4proxy:  l4proxy,
		logger:   logger,
	}
}

// Acceptor is a function that accepts a connection and returns the net.Conn.
// This abstracts over tsnet.Server.Listen vs net.Listen for testing.
type Acceptor interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// Serve accepts connections on the given listener, performs L4 identity gating,
// and forwards allowed connections to the backend.
func (m *ListenerManager) Serve(ctx context.Context, ln Acceptor, listenerCfg *config.Listener) error {
	m.logger.Info("serving listener",
		"name", listenerCfg.Name,
		"listen", listenerCfg.Listen,
		"forward", listenerCfg.Forward)

	var wg sync.WaitGroup
	defer wg.Wait()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("accept on %s: %w", listenerCfg.Name, err)
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			m.handleConn(ctx, conn, listenerCfg)
		}()
	}
}

func (m *ListenerManager) handleConn(ctx context.Context, conn net.Conn, listenerCfg *config.Listener) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	// Resolve identity
	id, err := m.resolver.Resolve(ctx, remoteAddr)
	if err != nil {
		m.logger.Warn("identity resolution failed",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"err", err)
		return
	}

	// L4 policy check
	if !m.engine.CheckL4(listenerCfg.Name, id) {
		m.logger.Info("L4 denied",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"user", id.UserLogin,
			"node", id.NodeName,
			"tags", id.Tags)
		return
	}

	m.logger.Debug("L4 allowed",
		"listener", listenerCfg.Name,
		"remote", remoteAddr,
		"user", id.UserLogin,
		"node", id.NodeName)

	useProxyProto := listenerCfg.ProxyProtocol == "v2"

	if err := m.l4proxy.Forward(ctx, conn, listenerCfg.Forward, conn.RemoteAddr(), useProxyProto); err != nil {
		m.logger.Warn("forward failed",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"err", err)
	}
}
```

Create `internal/proxy/listener_test.go`:

```go
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type mockWhoIs struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockWhoIs) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	ip := identity.StripPort(addr)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, &identity.ResolveError{Addr: addr, Reason: "not found"}
}

func TestListenerManagerAllowAndForward(t *testing.T) {
	// Backend echo server
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	cfg, _ := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "` + backend.Addr().String() + `"
l4_rules:
  - match:
      listener: web
    allow:
      any_tailscale: true
default: deny
`))

	client := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node:        &tailcfg.Node{ComputedName: "test-node"},
				UserProfile: &tailcfg.UserProfile{LoginName: "test@co.com"},
			},
		},
	}

	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(client)
	l4 := NewL4Proxy(slog.Default())
	mgr := NewListenerManager(engine, resolver, l4, slog.Default())

	// Create a test listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenerCfg := cfg.ListenerByName("web")

	go mgr.Serve(ctx, ln, listenerCfg)

	// Connect and send data
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q, want hello", buf)
	}
}
```

**Step 2: Run tests**

```bash
go test ./internal/proxy/ -v -count=1
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add tsnet listener manager with L4 identity gating"
```

---

## Task 9: Envoy Bootstrap Injection

**Files:**
- Create: `internal/envoy/bootstrap.go`
- Create: `internal/envoy/bootstrap_test.go`

**Step 1: Write bootstrap config injection**

Create `internal/envoy/bootstrap.go`:

```go
package envoy

import (
	"fmt"
	"strings"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

// InjectExtAuthz takes an Envoy bootstrap YAML string and injects
// the ext_authz filter and PROXY protocol listener filter into all
// HTTP connection managers.
func InjectExtAuthz(bootstrapYAML string, authzAddr string) (string, error) {
	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(bootstrapYAML), &bootstrap); err != nil {
		return "", fmt.Errorf("parsing bootstrap yaml: %w", err)
	}

	// Walk static_resources.listeners and inject
	if sr, ok := bootstrap["static_resources"].(map[string]interface{}); ok {
		if listeners, ok := sr["listeners"].([]interface{}); ok {
			for _, l := range listeners {
				if err := injectIntoListener(l, authzAddr); err != nil {
					return "", err
				}
			}
		}
	}

	out, err := yaml.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("marshaling modified bootstrap: %w", err)
	}
	return string(out), nil
}

func injectIntoListener(listener interface{}, authzAddr string) error {
	l, ok := listener.(map[string]interface{})
	if !ok {
		return nil
	}

	filterChains, ok := l["filter_chains"].([]interface{})
	if !ok {
		return nil
	}

	for _, fc := range filterChains {
		chain, ok := fc.(map[string]interface{})
		if !ok {
			continue
		}
		filters, ok := chain["filters"].([]interface{})
		if !ok {
			continue
		}
		for _, f := range filters {
			filter, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := filter["name"].(string)
			if name != "envoy.filters.network.http_connection_manager" {
				continue
			}
			injectExtAuthzFilter(filter, authzAddr)
		}
	}

	return nil
}

func injectExtAuthzFilter(hcm map[string]interface{}, authzAddr string) {
	tc, ok := hcm["typed_config"].(map[string]interface{})
	if !ok {
		return
	}

	extAuthzFilter := map[string]interface{}{
		"name": "envoy.filters.http.ext_authz",
		"typed_config": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
			"http_service": map[string]interface{}{
				"server_uri": map[string]interface{}{
					"uri":     fmt.Sprintf("http://%s", authzAddr),
					"cluster": "tailvoy_ext_authz",
					"timeout": "1s",
				},
			},
			"failure_mode_allow": false,
			"transport_api_version": "V3",
		},
	}

	httpFilters, ok := tc["http_filters"].([]interface{})
	if !ok {
		httpFilters = []interface{}{}
	}
	// Insert ext_authz before the router filter (which should be last)
	tc["http_filters"] = append([]interface{}{extAuthzFilter}, httpFilters...)
}

// GenerateStandaloneConfig generates a complete envoy.yaml for standalone mode
// (no gateway/xDS) based on the tailvoy policy config.
func GenerateStandaloneConfig(cfg *config.Config, authzAddr string) (string, error) {
	var listeners []map[string]interface{}
	var clusters []map[string]interface{}

	for _, l := range cfg.Listeners {
		if l.L7Policy {
			// HTTP listener with ext_authz
			listener := map[string]interface{}{
				"name": l.Name,
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":    "0.0.0.0",
						"port_value": l.Port(),
					},
				},
				"listener_filters": []map[string]interface{}{
					{
						"name": "envoy.filters.listener.proxy_protocol",
						"typed_config": map[string]interface{}{
							"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol",
						},
					},
				},
				"filter_chains": []map[string]interface{}{
					{
						"filters": []map[string]interface{}{
							{
								"name": "envoy.filters.network.http_connection_manager",
								"typed_config": map[string]interface{}{
									"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
									"stat_prefix": l.Name,
									"route_config": map[string]interface{}{
										"virtual_hosts": []map[string]interface{}{
											{
												"name":    l.Name,
												"domains": []string{"*"},
												"routes": []map[string]interface{}{
													{
														"match": map[string]interface{}{
															"prefix": "/",
														},
														"route": map[string]interface{}{
															"cluster": l.Name + "_backend",
														},
													},
												},
											},
										},
									},
									"http_filters": []map[string]interface{}{
										{
											"name": "envoy.filters.http.ext_authz",
											"typed_config": map[string]interface{}{
												"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
												"http_service": map[string]interface{}{
													"server_uri": map[string]interface{}{
														"uri":     fmt.Sprintf("http://%s", authzAddr),
														"cluster": "tailvoy_ext_authz",
														"timeout": "1s",
													},
												},
												"failure_mode_allow":    false,
												"transport_api_version": "V3",
											},
										},
										{
											"name": "envoy.filters.http.router",
											"typed_config": map[string]interface{}{
												"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
											},
										},
									},
								},
							},
						},
					},
				},
			}
			listeners = append(listeners, listener)

			// Backend cluster for this listener
			host, port := splitHostPort(l.Forward)
			clusters = append(clusters, map[string]interface{}{
				"name":            l.Name + "_backend",
				"connect_timeout": "5s",
				"type":            "STRICT_DNS",
				"lb_policy":       "ROUND_ROBIN",
				"load_assignment": map[string]interface{}{
					"cluster_name": l.Name + "_backend",
					"endpoints": []map[string]interface{}{
						{
							"lb_endpoints": []map[string]interface{}{
								{
									"endpoint": map[string]interface{}{
										"address": map[string]interface{}{
											"socket_address": map[string]interface{}{
												"address":    host,
												"port_value": port,
											},
										},
									},
								},
							},
						},
					},
				},
			})
		} else {
			// Pure L4 TCP proxy (no ext_authz needed, tailvoy gates at L4)
			host, port := splitHostPort(l.Forward)
			listener := map[string]interface{}{
				"name": l.Name,
				"address": map[string]interface{}{
					"socket_address": map[string]interface{}{
						"address":    "0.0.0.0",
						"port_value": l.Port(),
					},
				},
				"filter_chains": []map[string]interface{}{
					{
						"filters": []map[string]interface{}{
							{
								"name": "envoy.filters.network.tcp_proxy",
								"typed_config": map[string]interface{}{
									"@type":       "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
									"stat_prefix": l.Name,
									"cluster":     l.Name + "_backend",
								},
							},
						},
					},
				},
			}
			listeners = append(listeners, listener)

			clusters = append(clusters, map[string]interface{}{
				"name":            l.Name + "_backend",
				"connect_timeout": "5s",
				"type":            "STRICT_DNS",
				"lb_policy":       "ROUND_ROBIN",
				"load_assignment": map[string]interface{}{
					"cluster_name": l.Name + "_backend",
					"endpoints": []map[string]interface{}{
						{
							"lb_endpoints": []map[string]interface{}{
								{
									"endpoint": map[string]interface{}{
										"address": map[string]interface{}{
											"socket_address": map[string]interface{}{
												"address":    host,
												"port_value": port,
											},
										},
									},
								},
							},
						},
					},
				},
			})
		}
	}

	// ext_authz cluster
	authzHost, authzPort := splitHostPort(authzAddr)
	clusters = append(clusters, map[string]interface{}{
		"name":            "tailvoy_ext_authz",
		"connect_timeout": "1s",
		"type":            "STATIC",
		"lb_policy":       "ROUND_ROBIN",
		"load_assignment": map[string]interface{}{
			"cluster_name": "tailvoy_ext_authz",
			"endpoints": []map[string]interface{}{
				{
					"lb_endpoints": []map[string]interface{}{
						{
							"endpoint": map[string]interface{}{
								"address": map[string]interface{}{
									"socket_address": map[string]interface{}{
										"address":    authzHost,
										"port_value": authzPort,
									},
								},
							},
						},
					},
				},
			},
		},
	})

	bootstrap := map[string]interface{}{
		"admin": map[string]interface{}{
			"address": map[string]interface{}{
				"socket_address": map[string]interface{}{
					"address":    "127.0.0.1",
					"port_value": 9901,
				},
			},
		},
		"static_resources": map[string]interface{}{
			"listeners": listeners,
			"clusters":  clusters,
		},
	}

	out, err := yaml.Marshal(bootstrap)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func splitHostPort(addr string) (string, string) {
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return addr, "80"
}
```

Create `internal/envoy/bootstrap_test.go`:

```go
package envoy

import (
	"strings"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

func TestGenerateStandaloneConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "backend:8080"
    l7_policy: true
  - name: db
    protocol: tcp
    listen: ":5432"
    forward: "postgres:5432"
l4_rules:
  - match:
      listener: web
    allow:
      any_tailscale: true
  - match:
      listener: db
    allow:
      any_tailscale: true
default: deny
`))
	if err != nil {
		t.Fatal(err)
	}

	out, err := GenerateStandaloneConfig(cfg, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}

	// Verify key elements are present
	checks := []string{
		"ext_authz",
		"tailvoy_ext_authz",
		"web_backend",
		"db_backend",
		"proxy_protocol",
		"http_connection_manager",
		"tcp_proxy",
		"127.0.0.1",
		"9001",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("generated config missing %q", check)
		}
	}
}

func TestInjectExtAuthz(t *testing.T) {
	bootstrap := `
static_resources:
  listeners:
  - name: test
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`

	out, err := InjectExtAuthz(bootstrap, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "ext_authz") {
		t.Error("injected config missing ext_authz")
	}
	if !strings.Contains(out, "tailvoy_ext_authz") {
		t.Error("injected config missing tailvoy_ext_authz cluster reference")
	}
}
```

**Step 2: Run tests**

```bash
go test ./internal/envoy/ -v
```

Expected: all tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "Add Envoy bootstrap config generation and ext_authz injection"
```

---

## Task 10: Wire Everything Together in main.go

**Files:**
- Modify: `cmd/tailvoy/main.go`

**Ref:** `../tailscale/tsnet/tsnet.go` for Server API, `../tailscale/client/local/local.go` for LocalClient

**Step 1: Write the main entry point**

Replace `cmd/tailvoy/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rajsinghtech/tailvoy/internal/authz"
	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/envoy"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
	"github.com/rajsinghtech/tailvoy/internal/proxy"
	"tailscale.com/tsnet"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tailvoy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	tailvoyArgs, envoyArgs := envoy.ParseArgs(args)

	fs := flag.NewFlagSet("tailvoy", flag.ExitOnError)
	policyPath := fs.String("policy", "policy.yaml", "path to policy YAML file")
	authzAddr := fs.String("authz-addr", "127.0.0.1:9001", "ext_authz listen address")
	logLevel := fs.String("log-level", "info", "log level (debug, info, warn, error)")
	standalone := fs.Bool("standalone", false, "generate envoy config from policy (no xDS)")
	if err := fs.Parse(tailvoyArgs); err != nil {
		return err
	}

	// Setup logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Load policy config
	cfg, err := config.Load(*policyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	logger.Info("policy loaded", "listeners", len(cfg.Listeners),
		"l4_rules", len(cfg.L4Rules), "l7_rules", len(cfg.L7Rules))

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down")
		cancel()
	}()

	// Start tsnet
	ts := &tsnet.Server{
		Hostname:  cfg.Tailscale.Hostname,
		AuthKey:   cfg.Tailscale.AuthKey,
		Ephemeral: cfg.Tailscale.Ephemeral,
	}
	defer ts.Close()

	status, err := ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	logger.Info("tsnet connected", "hostname", cfg.Tailscale.Hostname, "ips", status.TailscaleIPs)

	// Get LocalClient for WhoIs
	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	// Initialize components
	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(lc)
	l4proxy := proxy.NewL4Proxy(logger)
	listenerMgr := proxy.NewListenerManager(engine, resolver, l4proxy, logger)
	authzServer := authz.NewServer(engine, resolver, logger)

	var wg sync.WaitGroup

	// Start ext_authz server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := authzServer.ListenAndServe(ctx, *authzAddr); err != nil {
			logger.Error("ext_authz server error", "err", err)
		}
	}()

	// Start listeners
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		ln, err := ts.Listen("tcp", l.Listen)
		if err != nil {
			return fmt.Errorf("listen %s %s: %w", l.Name, l.Listen, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := listenerMgr.Serve(ctx, ln, l); err != nil {
				logger.Error("listener error", "name", l.Name, "err", err)
			}
		}()
	}

	// Start Envoy subprocess
	envoyMgr := envoy.NewManager(logger)
	if *standalone {
		// Generate config from policy
		envoyYAML, err := envoy.GenerateStandaloneConfig(cfg, *authzAddr)
		if err != nil {
			return fmt.Errorf("generating envoy config: %w", err)
		}
		envoyArgs = append([]string{"--config-yaml", envoyYAML}, envoyArgs...)
	}

	if len(envoyArgs) > 0 || *standalone {
		if err := envoyMgr.Start(ctx, envoyArgs); err != nil {
			return fmt.Errorf("starting envoy: %w", err)
		}

		// Forward signals to Envoy
		go func() {
			<-ctx.Done()
			envoyMgr.Signal(syscall.SIGTERM)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := envoyMgr.Wait(); err != nil {
				logger.Error("envoy exited", "err", err)
				cancel() // If envoy dies, shut everything down
			}
		}()
	}

	logger.Info("tailvoy running",
		"authz", *authzAddr,
		"listeners", len(cfg.Listeners))

	// Wait for shutdown
	<-ctx.Done()
	wg.Wait()
	return nil
}
```

**Step 2: Verify it compiles**

```bash
go mod tidy
go build ./cmd/tailvoy/
```

Expected: compiles successfully

**Step 3: Run all tests**

```bash
go test ./... -v
```

Expected: all tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "Wire up main entry point connecting all components"
```

---

## Task 11: Dockerfile

**Files:**
- Create: `Dockerfile`

**Step 1: Write the Dockerfile**

```dockerfile
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /tailvoy ./cmd/tailvoy/

FROM envoyproxy/envoy:distroless-v1.37.0

COPY --from=builder /tailvoy /usr/local/bin/tailvoy

# tailvoy wraps envoy — it starts tsnet, the ext_authz server,
# then launches envoy as a subprocess with the provided args
ENTRYPOINT ["/usr/local/bin/tailvoy"]
```

**Step 2: Write example policy.yaml at repo root**

Create `policy.yaml`:

```yaml
# Example tailvoy policy
# Copy and modify for your deployment

tailscale:
  hostname: "tailvoy-gw"
  authkey: "${TS_AUTHKEY}"
  ephemeral: true

listeners:
  - name: https
    protocol: tcp
    listen: ":443"
    forward: "127.0.0.1:10443"
    proxy_protocol: v2
    l7_policy: true

  - name: http
    protocol: tcp
    listen: ":80"
    forward: "127.0.0.1:10080"
    proxy_protocol: v2
    l7_policy: true

l4_rules:
  - match:
      listener: https
    allow:
      any_tailscale: true

  - match:
      listener: http
    allow:
      any_tailscale: true

l7_rules:
  - match:
      listener: https
      path: "/admin/*"
    allow:
      tags: ["tag:admin"]

  - match:
      listener: https
      path: "/*"
    allow:
      any_tailscale: true

  - match:
      listener: http
      path: "/*"
    allow:
      any_tailscale: true

default: deny
```

**Step 3: Write .gitignore**

Create `.gitignore`:

```
tailvoy
*.exe
.env
tsnet-*
```

**Step 4: Verify Docker build (if Docker available)**

```bash
docker build -t tailvoy:dev .
```

Expected: image builds successfully

**Step 5: Commit**

```bash
git add -A
git commit -m "Add Dockerfile and example policy configuration"
```

---

## Task 12: Run All Tests, Final Verification

**Step 1: Run full test suite**

```bash
go test ./... -v -count=1 -race
```

Expected: all tests pass with no race conditions

**Step 2: Verify binary runs (shows usage)**

```bash
go run ./cmd/tailvoy/ --help
```

Expected: shows flag usage (policy, authz-addr, etc.)

**Step 3: Verify project compiles clean**

```bash
go vet ./...
```

Expected: no issues

**Step 4: Final commit if any fixes needed**

```bash
git status
# If clean, no commit needed
```
