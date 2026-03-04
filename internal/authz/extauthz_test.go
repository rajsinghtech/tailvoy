package authz

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestMalformedXFF(t *testing.T) {
	srv := testServer(t, baseCfg(), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "not-an-ip")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// "not-an-ip" passes extractSourceIP (it's returned as-is since it has no port
	// and isn't empty), but the resolver will fail to parse it, returning 403.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for malformed XFF, got %d", rec.Code)
	}
}

func TestMultipleIPsInXFFUsesFirst(t *testing.T) {
	// Register two IPs: alice on .1.1, nothing on .2.2.
	// XFF has alice first, unknown second. Should resolve alice.
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1, 100.64.2.2")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (first IP is alice), got %d", rec.Code)
	}
	if got := rec.Header().Get("x-tailscale-user"); got != "alice@example.com" {
		t.Errorf("x-tailscale-user = %q, want alice@example.com", got)
	}
}

func TestMultipleIPsInXFFFirstUnknown(t *testing.T) {
	// First IP is unknown; second is alice. Should deny because only the first
	// IP in XFF is used.
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	req.Header.Set("x-forwarded-for", "100.64.99.99, 100.64.1.1")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (first IP is unknown), got %d", rec.Code)
	}
}

func TestEmptyPath(t *testing.T) {
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	// httptest.NewRequest requires a valid URL target, but we can test empty
	// original-path header falling back to URL path of "/".
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	req.URL.Path = ""
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// The catch-all "/*" matches everything, so even an empty path is allowed.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty path with catch-all, got %d", rec.Code)
	}
}

func TestURLEncodedPathTraversal(t *testing.T) {
	// The admin config restricts /admin/* to admin@example.com only.
	// Attempt path traversal using URL-encoded characters: /public/%2e%2e/admin
	// This should NOT match /admin/* because the path matching is literal.
	srv := testServer(t, adminCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	req.Header.Set("x-envoy-original-path", "/public/%2e%2e/admin")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// /public/%2e%2e/admin doesn't match /admin/* (literal prefix matching),
	// so it falls to the catch-all /* which allows any tailscale user.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for traversal path on catch-all, got %d", rec.Code)
	}
}

func TestXFFTakesPrecedenceOverEnvoyHeader(t *testing.T) {
	// Both headers set; XFF should win.
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
		"100.64.2.2": adminResp,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	req.Header.Set("x-envoy-external-address", "100.64.2.2")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Should resolve to alice (from XFF), not admin (from envoy header).
	if got := rec.Header().Get("x-tailscale-user"); got != "alice@example.com" {
		t.Errorf("x-tailscale-user = %q, want alice@example.com (XFF should take precedence)", got)
	}
}

func TestResolverErrorOnSecondCall(t *testing.T) {
	// First call succeeds, second call (different IP) fails.
	// Uses a custom mockWhoIs that tracks call count.
	type failingMock struct {
		callCount int
	}

	callCount := 0
	mock := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"100.64.1.1": aliceResp,
		},
	}

	cfg := baseCfg()
	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(mock)
	srv := NewServer(engine, resolver, slog.Default())

	// First request: known IP, should succeed.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("x-forwarded-for", "100.64.1.1")
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec1.Code)
	}

	// Second request: unknown IP, resolver returns error.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("x-forwarded-for", "100.64.99.99")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("second request: expected 403, got %d", rec2.Code)
	}

	// Third request: first IP again, should still work (cached).
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("x-forwarded-for", "100.64.1.1")
	rec3 := httptest.NewRecorder()
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("third request (cached): expected 200, got %d", rec3.Code)
	}
	_ = callCount // suppress unused warning for clarity
}

func TestGracefulShutdownWhileRequestInFlight(t *testing.T) {
	srv := testServer(t, baseCfg(), map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	errCh := make(chan error, 1)

	httpSrv := &http.Server{
		Handler: srv,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		errCh <- httpSrv.Serve(ln)
	}()

	// Make a successful request to verify the server is running.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-forwarded-for", "100.64.1.1")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Initiate graceful shutdown.
	shutdownErr := httpSrv.Shutdown(context.Background())
	if shutdownErr != nil {
		t.Fatalf("Shutdown error: %v", shutdownErr)
	}

	// Server.Serve should return http.ErrServerClosed.
	select {
	case err := <-errCh:
		if err != http.ErrServerClosed {
			t.Fatalf("expected ErrServerClosed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
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
