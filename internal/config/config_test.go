package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func setTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TS_CLIENT_ID", "test-client-id")
	t.Setenv("TS_CLIENT_SECRET", "test-client-secret")
}

func TestParse_Minimal(t *testing.T) {
	setTestEnv(t)

	data := []byte(`
tailscale:
  serviceMappings:
    myapp: [web]
  tags:
    - tag:web
  serviceTags:
    - tag:svc

listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: "localhost:8080"
`)

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tailscale.Hostname() != "tailvoy-proxy" {
		t.Errorf("Hostname() = %q, want %q", cfg.Tailscale.Hostname(), "tailvoy-proxy")
	}
	if len(cfg.Tailscale.ServiceMappings) != 1 {
		t.Errorf("serviceMappings count = %d, want 1", len(cfg.Tailscale.ServiceMappings))
	}
	if cfg.Tailscale.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", cfg.Tailscale.ClientID, "test-client-id")
	}
	l, ok := cfg.Listeners["web"]
	if !ok {
		t.Fatal("missing listener 'web'")
	}
	if l.Port != 80 {
		t.Errorf("port = %d, want 80", l.Port)
	}
	if l.Protocol != "http" {
		t.Errorf("protocol = %q, want %q", l.Protocol, "http")
	}
	if len(l.Routes) != 1 {
		t.Errorf("routes count = %d, want 1", len(l.Routes))
	}
}

func TestParse_FullExample(t *testing.T) {
	setTestEnv(t)

	data := []byte(`
tailscale:
  serviceMappings:
    web: [https-web]
    api: [grpc-api]
    tls: [tls-passthrough]
    db: [tcp-direct]
    dns: [udp-dns]
  tags:
    - tag:web
    - tag:api
  serviceTags:
    - tag:svc

listeners:
  https-web:
    port: 443
    protocol: https
    tls:
      cert: /certs/web.crt
      key: /certs/web.key
    routes:
      - hostname: app.example.com
        paths:
          /: "localhost:3000"
          /api: "localhost:4000"
      - hostname: admin.example.com
        backend: "localhost:5000"
        tls:
          cert: /certs/admin.crt
          key: /certs/admin.key

  grpc-api:
    port: 9090
    protocol: grpc
    tls:
      cert: /certs/grpc.crt
      key: /certs/grpc.key
    routes:
      - backend: "localhost:9091"

  tls-passthrough:
    port: 8443
    protocol: tls
    routes:
      - hostname: db.example.com
        backend: "localhost:5432"
      - hostname: cache.example.com
        backend: "localhost:6379"

  tcp-direct:
    port: 3306
    protocol: tcp
    backend: "localhost:3307"

  udp-dns:
    port: 53
    protocol: udp
    backend: "localhost:5353"
`)

	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Listeners) != 5 {
		t.Fatalf("got %d listeners, want 5", len(cfg.Listeners))
	}

	hl := cfg.Listeners["https-web"]
	if hl.TLS == nil || hl.TLS.Cert != "/certs/web.crt" {
		t.Error("https listener TLS not parsed correctly")
	}
	if len(hl.Routes) != 2 {
		t.Fatalf("https routes: got %d, want 2", len(hl.Routes))
	}
	if hl.Routes[0].Paths["/"] != "localhost:3000" {
		t.Error("path / not mapped correctly")
	}
	if hl.Routes[1].TLS == nil || hl.Routes[1].TLS.Cert != "/certs/admin.crt" {
		t.Error("route-level TLS override not parsed")
	}

	tl := cfg.Listeners["tls-passthrough"]
	if len(tl.Routes) != 2 {
		t.Error("tls routes wrong count")
	}
	for _, r := range tl.Routes {
		if r.Hostname == "" {
			t.Error("tls route missing hostname")
		}
	}

	tcp := cfg.Listeners["tcp-direct"]
	if tcp.Backend != "localhost:3307" {
		t.Errorf("tcp backend = %q", tcp.Backend)
	}

	udp := cfg.Listeners["udp-dns"]
	if udp.Backend != "localhost:5353" {
		t.Errorf("udp backend = %q", udp.Backend)
	}
}

func TestParse_Validation(t *testing.T) {
	baseConfig := func() string {
		return `
tailscale:
  tags:
    - tag:web
  serviceTags:
    - tag:svc
`
	}

	tests := []struct {
		name    string
		yaml    string
		envID   string
		envSec  string
		wantErr string
	}{
		{
			name:  "missing serviceMappings",
			yaml:  "tailscale:\n  tags: [tag:web]\n  serviceTags: [tag:svc]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "tailscale.serviceMappings is required",
		},
		{
			name:  "old service field rejected",
			yaml:  "tailscale:\n  service: old\n  serviceMappings:\n    svc: [a]\n  tags: [tag:web]\n  serviceTags: [tag:svc]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "tailscale.service has been replaced by tailscale.serviceMappings",
		},
		{
			name:  "missing tags",
			yaml:  "tailscale:\n  serviceMappings:\n    svc: [a]\n  serviceTags: [tag:svc]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "tailscale.tags is required",
		},
		{
			name:  "missing serviceTags",
			yaml:  "tailscale:\n  serviceMappings:\n    svc: [a]\n  tags: [tag:web]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "tailscale.serviceTags is required",
		},
		{
			name:  "no listeners",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\n",
			envID: "x", envSec: "x",
			wantErr: "at least one listener is required",
		},
		{
			name:  "port zero",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 0\n    protocol: tcp\n    backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:  "port too high",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 70000\n    protocol: tcp\n    backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:  "duplicate port",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a, b]\nlisteners:\n  a:\n    port: 80\n    protocol: tcp\n    backend: \"localhost:80\"\n  b:\n    port: 80\n    protocol: tcp\n    backend: \"localhost:81\"\n",
			envID: "x", envSec: "x",
			wantErr: "duplicate port",
		},
		{
			name:  "invalid protocol",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: ftp\n    backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "protocol must be one of",
		},
		{
			name:  "tcp with routes",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: tcp\n    backend: \"localhost:80\"\n    routes:\n      - backend: \"localhost:81\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have routes",
		},
		{
			name:  "tcp missing backend",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: tcp\n",
			envID: "x", envSec: "x",
			wantErr: "must have backend",
		},
		{
			name:  "udp with routes",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 53\n    protocol: udp\n    backend: \"localhost:53\"\n    routes:\n      - backend: \"localhost:54\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have routes",
		},
		{
			name:  "http with backend",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have backend",
		},
		{
			name:  "http missing routes",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n",
			envID: "x", envSec: "x",
			wantErr: "must have routes",
		},
		{
			name:  "tls route missing hostname",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 443\n    protocol: tls\n    routes:\n      - backend: \"localhost:443\"\n",
			envID: "x", envSec: "x",
			wantErr: "hostname is required",
		},
		{
			name:  "tls route with paths",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 443\n    protocol: tls\n    routes:\n      - hostname: x.com\n        paths:\n          /: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have paths",
		},
		{
			name:  "route with both backend and paths",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n        paths:\n          /: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must have either backend or paths, not both",
		},
		{
			name:  "path not starting with slash",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - paths:\n          noslash: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must start with /",
		},
		{
			name:  "backend without colon",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: tcp\n    backend: localhost\n",
			envID: "x", envSec: "x",
			wantErr: "must be host:port format",
		},
		{
			name:  "https missing tls",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 443\n    protocol: https\n    routes:\n      - backend: \"localhost:443\"\n",
			envID: "x", envSec: "x",
			wantErr: "TLS config is required",
		},
		{
			name:  "grpc missing routes",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 9090\n    protocol: grpc\n",
			envID: "x", envSec: "x",
			wantErr: "grpc listener must have routes",
		},
		{
			name:  "http with tls",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    tls:\n      cert: a\n      key: b\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have TLS config",
		},
		{
			name:  "tcp with tls",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: tcp\n    tls:\n      cert: a\n      key: b\n    backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have TLS config",
		},
		{
			name:  "udp with tls",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 53\n    protocol: udp\n    tls:\n      cert: a\n      key: b\n    backend: \"localhost:53\"\n",
			envID: "x", envSec: "x",
			wantErr: "must not have TLS config",
		},
		{
			name:  "http route with tls override",
			yaml:  baseConfig() + "  serviceMappings:\n    svc: [a]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n        tls:\n          cert: a\n          key: b\n",
			envID: "x", envSec: "x",
			wantErr: "per-route TLS override only allowed",
		},
		{
			name:  "listener not in any mapping",
			yaml:  baseConfig() + "  serviceMappings:\n    web: [\"^web$\"]\nlisteners:\n  web:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n  orphan:\n    port: 81\n    protocol: tcp\n    backend: \"localhost:81\"\n",
			envID: "x", envSec: "x",
			wantErr: "listener \"orphan\" is not in any service mapping",
		},
		{
			name:  "invalid regex in serviceMappings",
			yaml:  baseConfig() + "  serviceMappings:\n    web: [\"[bad\"]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "invalid regex",
		},
		{
			name:  "mapping pattern doesn't match any listener",
			yaml:  baseConfig() + "  serviceMappings:\n    web: [ghost]\nlisteners:\n  a:\n    port: 80\n    protocol: http\n    routes:\n      - backend: \"localhost:80\"\n",
			envID: "x", envSec: "x",
			wantErr: "listener \"a\" is not in any service mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_CLIENT_ID", tt.envID)
			t.Setenv("TS_CLIENT_SECRET", tt.envSec)

			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParse_MissingEnvVars(t *testing.T) {
	os.Unsetenv("TS_CLIENT_ID")
	os.Unsetenv("TS_CLIENT_SECRET")

	data := []byte(`
tailscale:
  serviceMappings:
    myapp: [web]
  tags:
    - tag:web
  serviceTags:
    - tag:svc

listeners:
  web:
    port: 80
    protocol: http
    routes:
      - backend: "localhost:8080"
`)

	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing env vars")
	}
	if !strings.Contains(err.Error(), "TS_CLIENT_ID") {
		t.Errorf("error = %q, want mention of TS_CLIENT_ID", err.Error())
	}
}

func TestFlatListeners(t *testing.T) {
	os.Setenv("TS_CLIENT_ID", "id")
	os.Setenv("TS_CLIENT_SECRET", "secret")
	defer os.Unsetenv("TS_CLIENT_ID")
	defer os.Unsetenv("TS_CLIENT_SECRET")

	y := `
tailscale:
  serviceMappings:
    all: [web, postgres, dns, vault]
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
      - backend: app:8080
  postgres:
    port: 5432
    protocol: tcp
    backend: db:5432
  dns:
    port: 53
    protocol: udp
    backend: coredns:1053
  vault:
    port: 8443
    protocol: tls
    routes:
      - hostname: vault.example.com
        backend: vault:8200
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}

	flat := cfg.FlatListeners()

	web := flat["web"]
	if !web.IsL7 || !web.TerminateTLS || web.Transport != "tcp" {
		t.Errorf("web: IsL7=%v TerminateTLS=%v Transport=%s", web.IsL7, web.TerminateTLS, web.Transport)
	}

	pg := flat["postgres"]
	if pg.IsL7 || pg.TerminateTLS || pg.DefaultBackend != "db:5432" || pg.Transport != "tcp" {
		t.Errorf("postgres: IsL7=%v DefaultBackend=%s Transport=%s", pg.IsL7, pg.DefaultBackend, pg.Transport)
	}

	dns := flat["dns"]
	if dns.Transport != "udp" || dns.DefaultBackend != "coredns:1053" {
		t.Errorf("dns: Transport=%s DefaultBackend=%s", dns.Transport, dns.DefaultBackend)
	}

	v := flat["vault"]
	if !v.SNIPassthrough || v.IsL7 || v.Transport != "tcp" {
		t.Errorf("vault: SNIPassthrough=%v IsL7=%v Transport=%s", v.SNIPassthrough, v.IsL7, v.Transport)
	}
}

func TestServiceMatcher_ExactNames(t *testing.T) {
	sm, err := NewServiceMatcher(map[string][]string{
		"web": {"http", "https"},
		"db":  {"postgres"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		listener string
		want     []string
	}{
		{"http", []string{"svc:web"}},
		{"https", []string{"svc:web"}},
		{"postgres", []string{"svc:db"}},
		{"nonexistent", nil},
	}
	for _, tt := range tests {
		got := sm.Match(tt.listener)
		if !slices.Equal(got, tt.want) {
			t.Errorf("Match(%q) = %v, want %v", tt.listener, got, tt.want)
		}
	}
}

func TestServiceMatcher_RegexPatterns(t *testing.T) {
	sm, err := NewServiceMatcher(map[string][]string{
		"web": {".*http.*"},
		"tcp": {".*tcp.*"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		listener string
		want     []string
	}{
		{"default/eg/http", []string{"svc:web"}},
		{"staging/eg/http", []string{"svc:web"}},
		{"default/eg/tcp", []string{"svc:tcp"}},
		{"default/eg/grpc", nil},
	}
	for _, tt := range tests {
		got := sm.Match(tt.listener)
		if !slices.Equal(got, tt.want) {
			t.Errorf("Match(%q) = %v, want %v", tt.listener, got, tt.want)
		}
	}
}

func TestServiceMatcher_InvalidRegex(t *testing.T) {
	_, err := NewServiceMatcher(map[string][]string{
		"web": {"[invalid"},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error = %q, want mention of invalid regex", err.Error())
	}
}

func TestServiceMatcher_MatchAll_MultiService(t *testing.T) {
	// "default/eg/http-tcp" matches both ".*http.*" and ".*tcp.*".
	// Should return both services.
	sm, err := NewServiceMatcher(map[string][]string{
		"web": {".*http.*"},
		"tcp": {".*tcp.*"},
	})
	if err != nil {
		t.Fatal(err)
	}

	result := sm.MatchAll([]string{"default/eg/http-tcp"})
	got := result["default/eg/http-tcp"]
	// Sorted by service name: tcp before web.
	want := []string{"svc:tcp", "svc:web"}
	if !slices.Equal(got, want) {
		t.Errorf("MatchAll multi-service = %v, want %v", got, want)
	}
}

func TestServiceMatcher_Unanchored(t *testing.T) {
	// Patterns are unanchored, so "http" matches "default/eg/http".
	sm, err := NewServiceMatcher(map[string][]string{
		"web": {"http"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := sm.Match("default/eg/http")
	want := []string{"svc:web"}
	if !slices.Equal(got, want) {
		t.Errorf("Match(%q) = %v, want %v (unanchored)", "default/eg/http", got, want)
	}
}
