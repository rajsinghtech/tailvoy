# Config v2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the flat listener config with a Gateway API-inspired model: map-keyed listeners, protocol-driven behavior, nested hostname/path routing to backends, TLS config at listener and hostname levels. Standalone becomes the default mode.

**Architecture:** The new `config.Config` struct uses a `map[string]ListenerV2` instead of `[]Listener`. Each listener has a `protocol` field that encodes transport + L7 behavior (`http`, `https`, `grpc`, `tls`, `tcp`, `udp`). L7 listeners have `routes` with hostname/path/backend mappings. The bootstrap generator reads the new config and produces Envoy listeners, virtual hosts, route entries, and clusters — one cluster per unique backend address. `clientId`/`clientSecret` are removed from config and read from env vars. The `-standalone` flag is inverted (standalone is default, `-discovery` opts in).

**Tech Stack:** Go 1.25, gopkg.in/yaml.v3, Envoy bootstrap YAML generation

---

### Task 1: New config types

**Files:**
- Create: `internal/config/config_v2.go`
- Test: `internal/config/config_v2_test.go`

**Step 1: Write the failing test**

```go
// internal/config/config_v2_test.go
package config

import (
	"os"
	"testing"
)

func TestParseV2_Minimal(t *testing.T) {
	yaml := `
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
`
	os.Setenv("TS_CLIENT_ID", "test-id")
	os.Setenv("TS_CLIENT_SECRET", "test-secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	cfg, err := ParseV2([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tailscale.Service != "my-app" {
		t.Errorf("service = %q, want my-app", cfg.Tailscale.Service)
	}
	if cfg.Tailscale.ClientID != "test-id" {
		t.Errorf("clientId = %q, want test-id", cfg.Tailscale.ClientID)
	}
	l, ok := cfg.Listeners["web"]
	if !ok {
		t.Fatal("listener 'web' not found")
	}
	if l.Port != 80 {
		t.Errorf("port = %d, want 80", l.Port)
	}
	if l.Protocol != "http" {
		t.Errorf("protocol = %q, want http", l.Protocol)
	}
	if len(l.Routes) != 1 {
		t.Fatalf("routes len = %d, want 1", len(l.Routes))
	}
	if l.Routes[0].Backend != "app:8080" {
		t.Errorf("backend = %q, want app:8080", l.Routes[0].Backend)
	}
}

func TestParseV2_FullExample(t *testing.T) {
	yaml := `
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
          /*: frontend:3000
      - hostname: special.other.com
        tls:
          cert: /certs/other.pem
          key: /certs/other-key.pem
        backend: other-app:8080
      - backend: fallback:8080

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
`
	os.Setenv("TS_CLIENT_ID", "test-id")
	os.Setenv("TS_CLIENT_SECRET", "test-secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	cfg, err := ParseV2([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check listener count
	if len(cfg.Listeners) != 5 {
		t.Errorf("listener count = %d, want 5", len(cfg.Listeners))
	}

	// HTTPS listener with TLS and routes
	web := cfg.Listeners["web"]
	if web.Protocol != "https" {
		t.Errorf("web.protocol = %q, want https", web.Protocol)
	}
	if web.TLS == nil || web.TLS.Cert != "/certs/wildcard.pem" {
		t.Error("web.tls.cert wrong")
	}
	if len(web.Routes) != 3 {
		t.Errorf("web.routes len = %d, want 3", len(web.Routes))
	}
	// First route has paths
	if len(web.Routes[0].Paths) != 2 {
		t.Errorf("web.routes[0].paths len = %d, want 2", len(web.Routes[0].Paths))
	}
	if web.Routes[0].Paths["/api/*"] != "api:8080" {
		t.Errorf("web.routes[0].paths[/api/*] = %q, want api:8080", web.Routes[0].Paths["/api/*"])
	}
	// Second route has per-hostname TLS
	if web.Routes[1].TLS == nil || web.Routes[1].TLS.Cert != "/certs/other.pem" {
		t.Error("web.routes[1].tls.cert wrong")
	}
	// Third route is catch-all (no hostname)
	if web.Routes[2].Hostname != "" {
		t.Errorf("web.routes[2].hostname = %q, want empty", web.Routes[2].Hostname)
	}

	// TLS passthrough
	vault := cfg.Listeners["vault"]
	if vault.Protocol != "tls" {
		t.Errorf("vault.protocol = %q, want tls", vault.Protocol)
	}
	if vault.Routes[1].Hostname != "*.internal.com" {
		t.Errorf("vault.routes[1].hostname = %q", vault.Routes[1].Hostname)
	}

	// TCP simple
	pg := cfg.Listeners["postgres"]
	if pg.Backend != "db:5432" {
		t.Errorf("postgres.backend = %q, want db:5432", pg.Backend)
	}

	// UDP simple
	dns := cfg.Listeners["dns"]
	if dns.Protocol != "udp" {
		t.Errorf("dns.protocol = %q, want udp", dns.Protocol)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run TestParseV2 -v`
Expected: FAIL — `ParseV2` not defined

**Step 3: Write the types and parser**

```go
// internal/config/config_v2.go
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigV2 struct {
	Tailscale TailscaleConfigV2        `yaml:"tailscale"`
	Listeners map[string]ListenerV2    `yaml:"listeners"`
}

type TailscaleConfigV2 struct {
	Service     string   `yaml:"service"`
	Tags        []string `yaml:"tags"`
	ServiceTags []string `yaml:"serviceTags"`
	// Populated from environment at parse time.
	ClientID     string `yaml:"-"`
	ClientSecret string `yaml:"-"`
}

func (t *TailscaleConfigV2) Hostname() string {
	return t.Service + "-tailvoy"
}

func (t *TailscaleConfigV2) ServiceName() string {
	return "svc:" + t.Service
}

type ListenerV2 struct {
	Port     int          `yaml:"port"`
	Protocol string       `yaml:"protocol"`
	TLS      *TLSConfig   `yaml:"tls,omitempty"`
	Backend  string       `yaml:"backend,omitempty"`
	Routes   []RouteV2    `yaml:"routes,omitempty"`
}

type RouteV2 struct {
	Hostname string            `yaml:"hostname,omitempty"`
	TLS      *TLSConfig        `yaml:"tls,omitempty"`
	Backend  string            `yaml:"backend,omitempty"`
	Paths    map[string]string `yaml:"paths,omitempty"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

func ParseV2(data []byte) (*ConfigV2, error) {
	expanded := expandEnvVars(string(data))

	var cfg ConfigV2
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	cfg.Tailscale.ClientID = os.Getenv("TS_CLIENT_ID")
	cfg.Tailscale.ClientSecret = os.Getenv("TS_CLIENT_SECRET")

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadV2(path string) (*ConfigV2, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return ParseV2(data)
}

func (c *ConfigV2) validate() error {
	if c.Tailscale.Service == "" {
		return fmt.Errorf("tailscale.service is required")
	}
	if len(c.Tailscale.Tags) == 0 {
		return fmt.Errorf("tailscale.tags is required")
	}
	if len(c.Tailscale.ServiceTags) == 0 {
		return fmt.Errorf("tailscale.serviceTags is required")
	}
	if c.Tailscale.ClientID == "" {
		return fmt.Errorf("TS_CLIENT_ID environment variable is required")
	}
	if c.Tailscale.ClientSecret == "" {
		return fmt.Errorf("TS_CLIENT_SECRET environment variable is required")
	}
	if len(c.Listeners) == 0 {
		return fmt.Errorf("at least one listener is required")
	}

	ports := make(map[int]string)
	for name, l := range c.Listeners {
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("listener %q: port must be 1-65535, got %d", name, l.Port)
		}
		if other, exists := ports[l.Port]; exists {
			return fmt.Errorf("listener %q: duplicate port %d (also used by %q)", name, l.Port, other)
		}
		ports[l.Port] = name

		switch l.Protocol {
		case "http", "https", "grpc", "tls", "tcp", "udp":
		default:
			return fmt.Errorf("listener %q: protocol must be http/https/grpc/tls/tcp/udp, got %q", name, l.Protocol)
		}

		isL7 := l.Protocol == "http" || l.Protocol == "https" || l.Protocol == "grpc"
		isTLS := l.Protocol == "tls"
		isSimple := l.Protocol == "tcp" || l.Protocol == "udp"

		// TLS config validation
		if l.Protocol == "https" || l.Protocol == "grpc" {
			if l.TLS == nil {
				// Check if all routes have per-hostname TLS
				for i, r := range l.Routes {
					if r.TLS == nil {
						return fmt.Errorf("listener %q: tls config required for %s (missing on listener and route[%d])", name, l.Protocol, i)
					}
				}
			}
		}
		if l.Protocol == "http" || l.Protocol == "tcp" || l.Protocol == "udp" {
			if l.TLS != nil {
				return fmt.Errorf("listener %q: tls config not allowed for %s protocol", name, l.Protocol)
			}
		}

		// Backend vs routes validation
		if isSimple {
			if l.Backend == "" {
				return fmt.Errorf("listener %q: backend is required for %s protocol", name, l.Protocol)
			}
			if len(l.Routes) > 0 {
				return fmt.Errorf("listener %q: routes not allowed for %s protocol, use backend", name, l.Protocol)
			}
			if err := validateBackend(name, l.Backend); err != nil {
				return err
			}
		} else if isL7 || isTLS {
			if l.Backend != "" {
				return fmt.Errorf("listener %q: use routes instead of backend for %s protocol", name, l.Protocol)
			}
			if len(l.Routes) == 0 {
				return fmt.Errorf("listener %q: at least one route is required for %s protocol", name, l.Protocol)
			}
			for i, r := range l.Routes {
				if isTLS && r.Hostname == "" {
					return fmt.Errorf("listener %q: route[%d] hostname is required for tls protocol (SNI matching)", name, i)
				}
				if isTLS && len(r.Paths) > 0 {
					return fmt.Errorf("listener %q: route[%d] paths not allowed for tls protocol", name, i)
				}
				if r.Backend == "" && len(r.Paths) == 0 {
					return fmt.Errorf("listener %q: route[%d] must have backend or paths", name, i)
				}
				if r.Backend != "" && len(r.Paths) > 0 {
					return fmt.Errorf("listener %q: route[%d] cannot have both backend and paths", name, i)
				}
				if r.Backend != "" {
					if err := validateBackend(fmt.Sprintf("%s.routes[%d]", name, i), r.Backend); err != nil {
						return err
					}
				}
				for path, backend := range r.Paths {
					if !strings.HasPrefix(path, "/") {
						return fmt.Errorf("listener %q: route[%d] path %q must start with /", name, i, path)
					}
					if err := validateBackend(fmt.Sprintf("%s.routes[%d].paths[%s]", name, i, path), backend); err != nil {
						return err
					}
				}
				if r.TLS != nil && l.Protocol != "https" && l.Protocol != "grpc" {
					return fmt.Errorf("listener %q: route[%d] tls override only allowed for https/grpc protocol", name, i)
				}
			}
		}
	}
	return nil
}

func validateBackend(context, backend string) error {
	if backend == "" {
		return fmt.Errorf("%s: backend address is required", context)
	}
	if !strings.Contains(backend, ":") {
		return fmt.Errorf("%s: backend %q must be host:port format", context, backend)
	}
	return nil
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run TestParseV2 -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config_v2.go internal/config/config_v2_test.go
git commit -m "Add config v2 types with map-keyed listeners and route model"
```

---

### Task 2: Config v2 validation edge cases

**Files:**
- Modify: `internal/config/config_v2_test.go`

**Step 1: Write failing tests for validation edge cases**

```go
func TestParseV2_Validation(t *testing.T) {
	setEnv := func() {
		os.Setenv("TS_CLIENT_ID", "id")
		os.Setenv("TS_CLIENT_SECRET", "secret")
	}

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing service",
			yaml: `
tailscale:
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: app:8080
`,
			wantErr: "tailscale.service is required",
		},
		{
			name: "missing tags",
			yaml: `
tailscale:
  service: x
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: app:8080
`,
			wantErr: "tailscale.tags is required",
		},
		{
			name: "duplicate port",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  a:
    port: 80
    protocol: tcp
    backend: a:80
  b:
    port: 80
    protocol: tcp
    backend: b:80
`,
			wantErr: "duplicate port 80",
		},
		{
			name: "invalid protocol",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: ftp
    backend: app:8080
`,
			wantErr: "protocol must be",
		},
		{
			name: "tcp with routes",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  db:
    port: 5432
    protocol: tcp
    routes:
      - backend: db:5432
`,
			wantErr: "routes not allowed for tcp",
		},
		{
			name: "http with backend instead of routes",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    backend: app:8080
`,
			wantErr: "use routes instead of backend",
		},
		{
			name: "tls route without hostname",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  tls:
    port: 443
    protocol: tls
    routes:
      - backend: app:443
`,
			wantErr: "hostname is required for tls",
		},
		{
			name: "tls config on http protocol",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    tls:
      cert: /a.pem
      key: /a-key.pem
    routes:
      - backend: app:8080
`,
			wantErr: "tls config not allowed for http",
		},
		{
			name: "route with both backend and paths",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: app:8080
        paths:
          /api/*: api:8080
`,
			wantErr: "cannot have both backend and paths",
		},
		{
			name: "path not starting with slash",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - paths:
          api/*: api:8080
`,
			wantErr: "must start with /",
		},
		{
			name: "backend missing port",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  db:
    port: 5432
    protocol: tcp
    backend: db-host
`,
			wantErr: "must be host:port",
		},
		{
			name: "port out of range",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 99999
    protocol: tcp
    backend: app:80
`,
			wantErr: "port must be 1-65535",
		},
		{
			name: "no listeners",
			yaml: `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
`,
			wantErr: "at least one listener",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnv()
			defer os.Unsetenv("TS_CLIENT_ID")
			defer os.Unsetenv("TS_CLIENT_SECRET")

			_, err := ParseV2([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseV2_MissingEnvVars(t *testing.T) {
	yaml := `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: app:8080
`
	os.Unsetenv("TS_CLIENT_ID")
	os.Unsetenv("TS_CLIENT_SECRET")

	_, err := ParseV2([]byte(yaml))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "TS_CLIENT_ID") {
		t.Errorf("error = %q, want TS_CLIENT_ID mention", err.Error())
	}
}
```

**Step 2: Run tests to verify they pass** (they should pass against the implementation from Task 1)

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run TestParseV2 -v`
Expected: PASS

**Step 3: Fix any validation gaps found, then commit**

```bash
git add internal/config/config_v2_test.go internal/config/config_v2.go
git commit -m "Add config v2 validation with comprehensive edge case tests"
```

---

### Task 3: Flatten config v2 for internal consumers

The rest of the codebase (proxy, envoy bootstrap, ext_authz) still operates on listener names, forward addresses, and L7/protocol flags. Rather than rewriting every consumer at once, add a method on `ConfigV2` that produces a flat representation the existing proxy/bootstrap code can consume.

**Files:**
- Modify: `internal/config/config_v2.go`
- Modify: `internal/config/config_v2_test.go`

**Step 1: Write the failing test**

```go
func TestConfigV2_FlatListeners(t *testing.T) {
	os.Setenv("TS_CLIENT_ID", "id")
	os.Setenv("TS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	yaml := `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 443
    protocol: https
    tls:
      cert: /c.pem
      key: /k.pem
    routes:
      - hostname: app.example.com
        paths:
          /api/*: api:8080
          /*: frontend:3000
      - backend: fallback:8080
  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432
  dns:
    port: 53
    protocol: udp
    backend: coredns:1053
`
	cfg, err := ParseV2([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	flat := cfg.FlatListeners()

	// web listener
	web, ok := flat["web"]
	if !ok {
		t.Fatal("web not in flat listeners")
	}
	if web.Port != 443 {
		t.Errorf("web.Port = %d", web.Port)
	}
	if !web.IsL7 {
		t.Error("web should be L7")
	}
	if !web.TerminateTLS {
		t.Error("web should terminate TLS")
	}
	if web.Transport != "tcp" {
		t.Errorf("web.Transport = %q", web.Transport)
	}

	// postgres
	pg, ok := flat["postgres"]
	if !ok {
		t.Fatal("postgres not in flat")
	}
	if pg.IsL7 || pg.TerminateTLS {
		t.Error("postgres should be simple tcp")
	}
	if pg.DefaultBackend != "db:5432" {
		t.Errorf("postgres.DefaultBackend = %q", pg.DefaultBackend)
	}

	// dns
	dns, ok := flat["dns"]
	if !ok {
		t.Fatal("dns not in flat")
	}
	if dns.Transport != "udp" {
		t.Errorf("dns.Transport = %q", dns.Transport)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run TestConfigV2_FlatListeners -v`
Expected: FAIL — `FlatListeners` not defined

**Step 3: Implement FlatListener and FlatListeners()**

```go
// FlatListener is a derived view of a ListenerV2 for consumption by
// proxy, bootstrap, and policy code. It describes the listener's behavior
// without the full route tree.
type FlatListener struct {
	Name           string
	Port           int
	Protocol       string // original protocol value
	Transport      string // "tcp" or "udp"
	IsL7           bool   // http, https, grpc
	TerminateTLS   bool   // https, grpc
	SNIPassthrough bool   // tls
	DefaultBackend string // for tcp/udp — direct backend
	TLS            *TLSConfig
	Routes         []RouteV2 // preserved for bootstrap generation
}

// FlatListeners returns a map of listener name to FlatListener for
// consumption by proxy and bootstrap code.
func (c *ConfigV2) FlatListeners() map[string]FlatListener {
	out := make(map[string]FlatListener, len(c.Listeners))
	for name, l := range c.Listeners {
		fl := FlatListener{
			Name:     name,
			Port:     l.Port,
			Protocol: l.Protocol,
			TLS:      l.TLS,
			Routes:   l.Routes,
		}
		switch l.Protocol {
		case "http":
			fl.Transport = "tcp"
			fl.IsL7 = true
		case "https":
			fl.Transport = "tcp"
			fl.IsL7 = true
			fl.TerminateTLS = true
		case "grpc":
			fl.Transport = "tcp"
			fl.IsL7 = true
			fl.TerminateTLS = true
		case "tls":
			fl.Transport = "tcp"
			fl.SNIPassthrough = true
		case "tcp":
			fl.Transport = "tcp"
			fl.DefaultBackend = l.Backend
		case "udp":
			fl.Transport = "udp"
			fl.DefaultBackend = l.Backend
		}
		out[name] = fl
	}
	return out
}
```

**Step 4: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run TestConfigV2 -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config_v2.go internal/config/config_v2_test.go
git commit -m "Add FlatListeners() for proxy/bootstrap consumption"
```

---

### Task 4: Rewrite Envoy bootstrap generation for v2 config

The bootstrap generator needs to produce Envoy listeners with proper virtual hosts, routes, and clusters derived from the v2 config's route tree — not the old 1:1 listener→backend mapping.

**Files:**
- Create: `internal/envoy/bootstrap_v2.go`
- Create: `internal/envoy/bootstrap_v2_test.go`

**Step 1: Write the failing test**

```go
// internal/envoy/bootstrap_v2_test.go
package envoy

import (
	"os"
	"strings"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

func TestGenerateStandaloneV2_HTTPWithRoutes(t *testing.T) {
	os.Setenv("TS_CLIENT_ID", "id")
	os.Setenv("TS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	cfgYAML := `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 80
    protocol: http
    routes:
      - hostname: app.example.com
        paths:
          /api/*: api:8080
          /*: frontend:3000
      - backend: fallback:9090
`
	cfg, err := config.ParseV2([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}

	result, err := GenerateStandaloneConfigV2(cfg, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}

	// Should have an override for the L7 listener
	ov, ok := result.Overrides["web"]
	if !ok {
		t.Fatal("no override for web")
	}
	if ov.ProxyProtocol != "v2" {
		t.Errorf("proxy protocol = %q", ov.ProxyProtocol)
	}

	// Parse the bootstrap YAML and check structure
	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	if len(listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(listeners))
	}

	clusters := sr["clusters"].([]interface{})
	// api:8080, frontend:3000, fallback:9090, ext_authz = 4
	if len(clusters) < 3 {
		t.Errorf("cluster count = %d, want at least 3 backends + ext_authz", len(clusters))
	}

	// Check that the YAML contains virtual host domains for app.example.com
	if !strings.Contains(result.BootstrapYAML, "app.example.com") {
		t.Error("bootstrap missing app.example.com virtual host")
	}
}

func TestGenerateStandaloneV2_TCPSimple(t *testing.T) {
	os.Setenv("TS_CLIENT_ID", "id")
	os.Setenv("TS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	cfgYAML := `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432
`
	cfg, err := config.ParseV2([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}

	result, err := GenerateStandaloneConfigV2(cfg, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}

	// TCP listeners don't get overrides (no envoy L7 processing)
	if _, ok := result.Overrides["postgres"]; ok {
		t.Error("tcp listener should not have override")
	}
}

func TestGenerateStandaloneV2_HTTPSWithTLS(t *testing.T) {
	os.Setenv("TS_CLIENT_ID", "id")
	os.Setenv("TS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	cfgYAML := `
tailscale:
  service: x
  tags: [tag:x]
  serviceTags: [tag:x]
listeners:
  web:
    port: 443
    protocol: https
    tls:
      cert: /certs/cert.pem
      key: /certs/key.pem
    routes:
      - backend: app:8080
`
	cfg, err := config.ParseV2([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}

	result, err := GenerateStandaloneConfigV2(cfg, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.BootstrapYAML, "/certs/cert.pem") {
		t.Error("bootstrap missing TLS cert path")
	}
	if !strings.Contains(result.BootstrapYAML, "transport_socket") {
		t.Error("bootstrap missing transport_socket for TLS")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/envoy/ -run TestGenerateStandaloneV2 -v`
Expected: FAIL — `GenerateStandaloneConfigV2` not defined

**Step 3: Implement the v2 bootstrap generator**

This is the most complex task. The generator needs to:
1. For each L7 listener (`http`, `https`, `grpc`): create an Envoy HCM listener with virtual hosts derived from routes, one cluster per unique backend address, TLS downstream config for `https`/`grpc`, ext_authz filter with per-route context extensions.
2. For `tls` listeners: create Envoy TCP proxy listeners with filter chain match on SNI, one chain per hostname route.
3. For `tcp`/`udp`: no Envoy listener (handled directly by tsnet proxy).

Create `internal/envoy/bootstrap_v2.go` with `GenerateStandaloneConfigV2(*config.ConfigV2, string) (*GenerateStandaloneResult, error)`.

Key implementation details:
- Cluster names derived from backend address: sanitize `host:port` → `host_port` to avoid duplicates.
- Virtual hosts: group routes by hostname. Routes without hostname go into a `*` catch-all virtual host.
- Path routes become Envoy route entries with prefix matching. Each route entry gets `typed_per_filter_config` with the listener name.
- TLS: add `transport_socket` with `DownstreamTlsContext` referencing cert/key paths. Per-hostname TLS overrides use separate filter chains with `filter_chain_match.server_names`.

**Step 4: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/envoy/ -run TestGenerateStandaloneV2 -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/envoy/bootstrap_v2.go internal/envoy/bootstrap_v2_test.go
git commit -m "Add v2 bootstrap generator with virtual host routing and TLS"
```

---

### Task 5: Wire v2 config into main.go

Replace config loading, flag parsing, and listener setup in `cmd/tailvoy/main.go`.

**Files:**
- Modify: `cmd/tailvoy/main.go`

**Step 1: Update flag parsing**

- Remove `-standalone` flag (standalone is now default).
- Add `-discovery` flag (opt-in for Envoy Gateway mode).
- Change `config.Load()` to `config.LoadV2()`.
- Replace `cfg.Tailscale.ClientID`/`ClientSecret` references (now populated from env).

**Step 2: Update standalone bootstrap generation**

- Replace `envoy.GenerateStandaloneConfig(cfg, authzAddr)` with `envoy.GenerateStandaloneConfigV2(cfg, authzAddr)`.
- The override loop changes: iterate `cfg.Listeners` map instead of slice. Store override forward addresses separately since v2 listeners have routes, not a single forward.

**Step 3: Update static listener startup**

- Iterate `cfg.FlatListeners()` instead of `cfg.Listeners[]`.
- Use `fl.Transport` instead of `l.Protocol` to separate TCP/UDP.
- Use `fl.Port` directly (already an int) instead of `l.Port()` string parsing.
- Use `fl.IsL7` instead of `l.L7Policy`.
- Use `fl.DefaultBackend` for UDP proxy `backendAddr`.
- For TCP listeners needing L4 proxy, the forward address comes from the standalone override (L7) or the flat listener's `DefaultBackend` (L4 simple).

**Step 4: Update the Serve() call signature**

`listenerMgr.Serve()` currently takes `*config.Listener`. It needs to take the flat listener or an adapted struct. Options:
- Pass a `*config.FlatListener` — cleanest but requires updating `proxy/listener.go`.
- Create a shim `config.Listener` from the flat — avoids touching proxy code initially.

Go with passing `*config.FlatListener` and update `proxy/listener.go` in the next task.

**Step 5: Run existing tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./... -v`
Expected: Tests pass (old config_test.go tests may fail — that's expected since we're replacing the config format).

**Step 6: Commit**

```bash
git add cmd/tailvoy/main.go
git commit -m "Wire v2 config into main entrypoint, standalone as default"
```

---

### Task 6: Update proxy layer for v2 config

**Files:**
- Modify: `internal/proxy/listener.go`
- Modify: `internal/proxy/udp.go`
- Modify: `internal/proxy/dynamic.go`
- Modify: `internal/proxy/listener_test.go`

**Step 1: Update ListenerManager.Serve() and handleConn()**

Change the `listenerCfg *config.Listener` parameter to accept the v2 flat listener:

In `listener.go`:
- `Serve(ctx, ln, cfg)` takes a struct with `Name`, `IsL7`, `Protocol`, `Transport`, `SNIPassthrough`, `Forward` (or `DefaultBackend`), `ProxyProtocol`.
- `handleConn()`: use `cfg.IsL7` instead of `cfg.L7Policy`, `cfg.SNIPassthrough` for SNI peeking, `cfg.Transport == "tcp"` for protocol checks.

In `udp.go`:
- `Serve()` already takes individual fields (`backendAddr`, `listenerName`), so no struct change needed.

In `dynamic.go`:
- This is discovery mode code. It constructs `config.Listener` objects from Envoy admin API. For now, keep this working with a compatibility adapter or defer to the discovery redesign (out of scope).

**Step 2: Update listener_test.go**

Update test helpers that construct `config.Listener` to use the new type.

**Step 3: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/proxy/ -v`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/proxy/listener.go internal/proxy/udp.go internal/proxy/dynamic.go internal/proxy/listener_test.go
git commit -m "Update proxy layer to use v2 flat listener model"
```

---

### Task 7: Update ext_authz for v2

**Files:**
- Modify: `internal/authz/extauthz.go`
- Modify: `internal/authz/extauthz_test.go`

The ext_authz server reads `context_extensions["listener"]` to get the listener name. This doesn't change — the bootstrap generator still injects it. No functional change needed here, but verify the listener name flow works end-to-end with the v2 bootstrap output.

**Step 1: Write a test that exercises the full v2 flow**

Parse a v2 config → generate bootstrap → verify the listener name appears in `context_extensions` in the generated YAML.

**Step 2: Run tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/authz/ -v`
Expected: PASS

**Step 3: Commit if any changes were needed**

```bash
git add internal/authz/
git commit -m "Verify ext_authz compatibility with v2 bootstrap"
```

---

### Task 8: Remove old config v1 types

**Files:**
- Modify: `internal/config/config.go` — remove old types, rename v2 types to be the primary
- Modify: `internal/config/config_v2.go` — merge into config.go
- Delete: `internal/config/config_v2.go` (after merge)
- Modify: `internal/config/config_test.go` — rewrite to test new format
- Modify: `internal/config/config_v2_test.go` — merge into config_test.go

**Step 1: Rename types**

- `ConfigV2` → `Config`
- `TailscaleConfigV2` → `TailscaleConfig`
- `ListenerV2` → `Listener`
- `RouteV2` → `Route`
- `ParseV2` → `Parse`
- `LoadV2` → `Load`

**Step 2: Update all imports across the codebase**

Every file that imports `config.Config` or `config.Listener` may need updating. Key files:
- `cmd/tailvoy/main.go`
- `internal/envoy/bootstrap.go` (old) — remove or keep for discovery mode compat
- `internal/envoy/bootstrap_v2.go` → rename to `bootstrap.go`
- `internal/proxy/listener.go`
- `internal/proxy/dynamic.go`
- `internal/discovery/discovery.go`

**Step 3: Run full test suite**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add -A
git commit -m "Remove v1 config types, promote v2 to primary"
```

---

### Task 9: Update example configs and docs

**Files:**
- Modify: `config.yaml`
- Modify: `testdata/config.yaml`
- Modify: `integration_test/` YAML files (as needed for standalone tests)
- Modify: `README.md`

**Step 1: Update config.yaml to v2 format**

```yaml
tailscale:
  service: tailvoy-gw
  tags:
    - tag:tailvoy
  serviceTags:
    - tag:tailvoy

listeners:
  https:
    port: 443
    protocol: https
    tls:
      cert: /certs/cert.pem
      key: /certs/key.pem
    routes:
      - backend: 127.0.0.1:10443

  http:
    port: 80
    protocol: http
    routes:
      - backend: 127.0.0.1:10080
```

**Step 2: Update testdata/config.yaml**

**Step 3: Update README.md**

Rewrite the config reference sections, examples, and listener options table to reflect the v2 format.

**Step 4: Commit**

```bash
git add config.yaml testdata/ README.md integration_test/
git commit -m "Update example configs and docs for v2 config format"
```

---

### Task 10: Final integration verification

**Step 1: Run the full test suite with race detector**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && make test`
Expected: PASS

**Step 2: Run linter**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && make lint`
Expected: PASS

**Step 3: Build the binary**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && make build`
Expected: PASS

**Step 4: Smoke test the config parsing**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && TS_CLIENT_ID=test TS_CLIENT_SECRET=test go run ./cmd/tailvoy -config config.yaml -log-level debug 2>&1 | head -5`
Expected: Should get past config parsing (will fail at tsnet connection, which is fine)

**Step 5: Final commit if needed**

```bash
git add -A
git commit -m "Config v2: final cleanup and integration verification"
```
