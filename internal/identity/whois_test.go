package identity

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// mockClient implements WhoIsClient for tests.
type mockClient struct {
	resp  *apitype.WhoIsResponse
	err   error
	calls int
}

func (m *mockClient) WhoIs(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
	m.calls++
	return m.resp, m.err
}

func TestResolve(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name: "mynode.tail1234.ts.net.",
				Tags: []string{"tag:web", "tag:prod"},
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.1.1:12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.NodeName != "mynode.tail1234.ts.net" {
		t.Errorf("NodeName = %q, want %q", id.NodeName, "mynode.tail1234.ts.net")
	}
	if id.TailscaleIP != "100.64.1.1" {
		t.Errorf("TailscaleIP = %q, want %q", id.TailscaleIP, "100.64.1.1")
	}
	if !id.IsTagged {
		t.Error("expected IsTagged=true for tagged node")
	}
	if len(id.Tags) != 2 || id.Tags[0] != "tag:web" || id.Tags[1] != "tag:prod" {
		t.Errorf("Tags = %v, want [tag:web tag:prod]", id.Tags)
	}
	// Tagged nodes should not expose UserLogin.
	if id.UserLogin != "" {
		t.Errorf("UserLogin = %q, want empty for tagged node", id.UserLogin)
	}
}

func TestResolveCache(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name: "node.ts.net.",
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "bob@example.com",
			},
		},
	}

	r := NewResolver(mc)

	// First call should hit the client.
	_, err := r.Resolve(context.Background(), "100.64.2.2:443")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if mc.calls != 1 {
		t.Fatalf("expected 1 call, got %d", mc.calls)
	}

	// Second call with same IP should use cache.
	id2, err := r.Resolve(context.Background(), "100.64.2.2:8080")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if mc.calls != 1 {
		t.Errorf("expected 1 call (cached), got %d", mc.calls)
	}
	if id2.NodeName != "node.ts.net" {
		t.Errorf("cached NodeName = %q", id2.NodeName)
	}

	// CachedIdentity should also return the entry.
	cached := r.CachedIdentity("100.64.2.2:9999")
	if cached == nil {
		t.Fatal("CachedIdentity returned nil for cached IP")
	}
	if cached.UserLogin != "bob@example.com" {
		t.Errorf("CachedIdentity UserLogin = %q", cached.UserLogin)
	}
}

func TestResolveCacheExpiry(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "n.ts.net."},
		},
	}

	now := time.Now()
	r := NewResolver(mc)
	r.now = func() time.Time { return now }

	_, err := r.Resolve(context.Background(), "100.64.3.3:80")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if mc.calls != 1 {
		t.Fatalf("expected 1 call, got %d", mc.calls)
	}

	// Advance time past TTL.
	r.now = func() time.Time { return now.Add(cacheTTL + time.Second) }

	_, err = r.Resolve(context.Background(), "100.64.3.3:80")
	if err != nil {
		t.Fatalf("resolve after expiry: %v", err)
	}
	if mc.calls != 2 {
		t.Errorf("expected 2 calls after expiry, got %d", mc.calls)
	}

	// CachedIdentity should return nil for expired entries.
	// The second Resolve re-cached at cacheTTL+1s, so expiry is 2*cacheTTL+1s.
	r.now = func() time.Time { return now.Add(2*cacheTTL + 2*time.Second) }
	if r.CachedIdentity("100.64.3.3:80") != nil {
		t.Error("CachedIdentity should return nil for expired entry")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{"ip:port", "100.64.1.1:8080", "100.64.1.1", true},
		{"bare ipv4", "100.64.1.2", "100.64.1.2", true},
		{"ipv6 with port", "[fd7a:115c:a1e0::1]:443", "fd7a:115c:a1e0::1", true},
		{"bare ipv6", "fd7a:115c:a1e0::2", "fd7a:115c:a1e0::2", true},
		{"invalid", "not-an-ip", "", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIP(tt.input)
			if tt.valid {
				if !got.IsValid() {
					t.Fatalf("extractIP(%q) returned invalid, want %s", tt.input, tt.want)
				}
				want := netip.MustParseAddr(tt.want)
				if got != want {
					t.Errorf("extractIP(%q) = %s, want %s", tt.input, got, want)
				}
			} else {
				if got.IsValid() {
					t.Errorf("extractIP(%q) = %s, want invalid", tt.input, got)
				}
			}
		})
	}
}

func TestResolveIdentityFields(t *testing.T) {
	// Tagged node without user profile.
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name: "server.tail9999.ts.net.",
				Tags: []string{"tag:infra"},
			},
			// No UserProfile set.
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.10.10:22")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !id.IsTagged {
		t.Error("expected IsTagged=true")
	}
	if id.UserLogin != "" {
		t.Errorf("UserLogin = %q, want empty", id.UserLogin)
	}
	if id.NodeName != "server.tail9999.ts.net" {
		t.Errorf("NodeName = %q", id.NodeName)
	}
	if len(id.Tags) != 1 || id.Tags[0] != "tag:infra" {
		t.Errorf("Tags = %v", id.Tags)
	}
}

func TestResolveError(t *testing.T) {
	mc := &mockClient{
		err: errors.New("whois unavailable"),
	}

	r := NewResolver(mc)
	_, err := r.Resolve(context.Background(), "100.64.5.5:80")
	if err == nil {
		t.Fatal("expected error")
	}
	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("expected *ResolveError, got %T", err)
	}
	if re.Addr != "100.64.5.5:80" {
		t.Errorf("ResolveError.Addr = %q", re.Addr)
	}
}

func TestResolveInvalidAddr(t *testing.T) {
	r := NewResolver(&mockClient{})
	_, err := r.Resolve(context.Background(), "garbage")
	if err == nil {
		t.Fatal("expected error for invalid addr")
	}
}

func TestStripPort(t *testing.T) {
	if got := StripPort("100.64.1.1:8080"); got != "100.64.1.1" {
		t.Errorf("StripPort = %q, want 100.64.1.1", got)
	}
	if got := StripPort("100.64.1.1"); got != "100.64.1.1" {
		t.Errorf("StripPort bare = %q", got)
	}
	if got := StripPort("not-valid"); got != "not-valid" {
		t.Errorf("StripPort invalid = %q, want passthrough", got)
	}
}
