package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

type mockWhoIs struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockWhoIs) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	ip := identity.StripPort(addr)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("not found: %s", ip)
}

// testServer builds a Server with the given config and mock responses.
func testServer(t *testing.T, cfg *config.Config, responses map[string]*apitype.WhoIsResponse) *Server {
	t.Helper()
	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(&mockWhoIs{responses: responses})
	return NewServer(engine, resolver, slog.Default())
}

// baseCfg returns a config that allows any tailscale user on "/*" for listener "default".
func baseCfg() *config.Config {
	return &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{{
			Name: "default", Protocol: "tcp", Listen: ":443", Forward: "localhost:8080",
		}},
		L7Rules: []config.Rule{{
			Match: config.RuleMatch{Listener: "default", Path: "/*"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		Default: "deny",
	}
}

// adminCfg returns a config with an admin path restricted to a specific user,
// plus a catch-all that allows any tailscale user.
func adminCfg() *config.Config {
	return &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{{
			Name: "default", Protocol: "tcp", Listen: ":443", Forward: "localhost:8080",
		}},
		L7Rules: []config.Rule{
			{
				Match: config.RuleMatch{Listener: "default", Path: "/admin/*"},
				Allow: config.AllowSpec{Users: []string{"admin@example.com"}},
			},
			{
				Match: config.RuleMatch{Listener: "default", Path: "/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		Default: "deny",
	}
}

var aliceResp = &apitype.WhoIsResponse{
	Node: &tailcfg.Node{Name: "alice-laptop.tail1234.ts.net."},
	UserProfile: &tailcfg.UserProfile{
		LoginName: "alice@example.com",
	},
}

var adminResp = &apitype.WhoIsResponse{
	Node: &tailcfg.Node{Name: "admin-box.tail1234.ts.net."},
	UserProfile: &tailcfg.UserProfile{
		LoginName: "admin@example.com",
	},
}

func TestAllowRequest(t *testing.T) {
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("x-tailscale-user"); got != "alice@example.com" {
		t.Errorf("x-tailscale-user = %q, want alice@example.com", got)
	}
	if got := rec.Header().Get("x-tailscale-node"); got != "alice-laptop.tail1234.ts.net" {
		t.Errorf("x-tailscale-node = %q", got)
	}
	if got := rec.Header().Get("x-tailscale-ip"); got != "100.64.1.1" {
		t.Errorf("x-tailscale-ip = %q", got)
	}
}

func TestAdminPathAllowForAdmin(t *testing.T) {
	srv := testServer(t, adminCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.2.2": adminResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.Header.Set("x-forwarded-for", "100.64.2.2")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin user on /admin/settings, got %d", rec.Code)
	}
	if got := rec.Header().Get("x-tailscale-user"); got != "admin@example.com" {
		t.Errorf("x-tailscale-user = %q", got)
	}
}

func TestAdminPathDenyForNonAdmin(t *testing.T) {
	srv := testServer(t, adminCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	// Non-admin user hits /admin path -- should be denied because
	// the /admin/* rule matches but alice isn't in the allow list,
	// and first-match wins so the catch-all never fires.
	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin on /admin path, got %d", rec.Code)
	}
}

func TestNonAdminOnCatchAll(t *testing.T) {
	srv := testServer(t, adminCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	// Non-admin on a non-admin path should be allowed by the catch-all.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for alice on /api/data, got %d", rec.Code)
	}
}

func TestNoSourceIP(t *testing.T) {
	srv := testServer(t, baseCfg(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with no source IP, got %d", rec.Code)
	}
}

func TestUnknownIP(t *testing.T) {
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.99.99")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown IP, got %d", rec.Code)
	}
}

func TestExtractSourceIP(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		envoy string
		want string
	}{
		{
			name: "single xff",
			xff:  "100.64.1.1",
			want: "100.64.1.1",
		},
		{
			name: "multiple xff picks first",
			xff:  "100.64.1.1, 10.0.0.1, 192.168.1.1",
			want: "100.64.1.1",
		},
		{
			name: "empty xff falls back to envoy header",
			envoy: "100.64.2.2",
			want:  "100.64.2.2",
		},
		{
			name: "no headers returns empty",
			want: "",
		},
		{
			name: "xff with port strips it",
			xff:  "100.64.1.1:8080",
			want: "100.64.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xff != "" {
				req.Header.Set("x-forwarded-for", tt.xff)
			}
			if tt.envoy != "" {
				req.Header.Set("x-envoy-external-address", tt.envoy)
			}
			got := extractSourceIP(req)
			if got != tt.want {
				t.Errorf("extractSourceIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractPath(t *testing.T) {
	tests := []struct {
		name     string
		original string
		urlPath  string
		want     string
	}{
		{
			name:     "uses x-envoy-original-path",
			original: "/real/path",
			urlPath:  "/authz",
			want:     "/real/path",
		},
		{
			name:    "falls back to URL path",
			urlPath: "/fallback",
			want:    "/fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.urlPath, nil)
			if tt.original != "" {
				req.Header.Set("x-envoy-original-path", tt.original)
			}
			got := extractPath(req)
			if got != tt.want {
				t.Errorf("extractPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnvoyOriginalPathHeader(t *testing.T) {
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/ext_authz", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	req.Header.Set("x-envoy-original-path", "/api/resource")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestListenerHeader(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "internal", Protocol: "tcp", Listen: ":8080", Forward: "localhost:9090"},
		},
		L7Rules: []config.Rule{{
			Match: config.RuleMatch{Listener: "internal", Path: "/*"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		Default: "deny",
	}

	srv := testServer(t, cfg, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	// Without the listener header, defaults to "default" which has no rules -> deny.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong listener, got %d", rec.Code)
	}

	// With the correct listener header -> allow.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("x-forwarded-for", "100.64.1.1")
	req2.Header.Set("x-tailvoy-listener", "internal")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct listener, got %d", rec2.Code)
	}
}

func TestTaggedNodeHeaders(t *testing.T) {
	taggedResp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name: "server.tail1234.ts.net.",
			Tags: []string{"tag:web", "tag:prod"},
		},
	}

	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{{
			Name: "default", Protocol: "tcp", Listen: ":443", Forward: "localhost:8080",
		}},
		L7Rules: []config.Rule{{
			Match: config.RuleMatch{Listener: "default", Path: "/*"},
			Allow: config.AllowSpec{Tags: []string{"tag:web"}},
		}},
		Default: "deny",
	}

	srv := testServer(t, cfg, map[string]*apitype.WhoIsResponse{
		"100.64.5.5": taggedResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.5.5")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for tagged node, got %d", rec.Code)
	}
	if got := rec.Header().Get("x-tailscale-tags"); got != "tag:web,tag:prod" {
		t.Errorf("x-tailscale-tags = %q, want tag:web,tag:prod", got)
	}
	// Tagged nodes have no user login.
	if got := rec.Header().Get("x-tailscale-user"); got != "" {
		t.Errorf("x-tailscale-user = %q, want empty for tagged node", got)
	}
}
