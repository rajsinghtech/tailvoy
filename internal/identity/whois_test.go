package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/rajsinghtech/tailvoy/internal/policy"
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

// atomicMockClient is a thread-safe WhoIsClient for concurrent tests.
type atomicMockClient struct {
	resp  *apitype.WhoIsResponse
	err   error
	mu    sync.Mutex
	calls int
}

func (m *atomicMockClient) WhoIs(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return m.resp, m.err
}

func (m *atomicMockClient) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestConcurrentResolveSameIP(t *testing.T) {
	mc := &atomicMockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "concurrent@example.com",
			},
		},
	}

	r := NewResolver(mc)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			id, err := r.Resolve(context.Background(), "100.64.1.1:12345")
			if err != nil {
				errs <- err
				return
			}
			if id.UserLogin != "concurrent@example.com" {
				errs <- fmt.Errorf("unexpected UserLogin: %q", id.UserLogin)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// The mock client should have been called at least once. Due to races, it may
	// be called more than once but should not be called goroutines times since
	// the cache should serve most requests.
	if mc.CallCount() == 0 {
		t.Fatal("expected at least 1 WhoIs call")
	}
}

func TestCacheManyEntries(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "many@example.com",
			},
		},
	}

	r := NewResolver(mc)

	// Populate cache with 100 distinct IPs.
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("100.64.%d.%d:80", i/256, i%256)
		_, err := r.Resolve(context.Background(), addr)
		if err != nil {
			t.Fatalf("resolve %s: %v", addr, err)
		}
	}

	if mc.calls != 100 {
		t.Fatalf("expected 100 WhoIs calls, got %d", mc.calls)
	}

	// All entries should be cached now. Resolving them again should not
	// increase call count.
	for i := 0; i < 100; i++ {
		addr := fmt.Sprintf("100.64.%d.%d:80", i/256, i%256)
		_, err := r.Resolve(context.Background(), addr)
		if err != nil {
			t.Fatalf("re-resolve %s: %v", addr, err)
		}
	}

	if mc.calls != 100 {
		t.Fatalf("expected still 100 WhoIs calls after cache hits, got %d", mc.calls)
	}
}

func TestResolveIPv6Address(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "v6node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "ipv6@example.com",
			},
		},
	}

	r := NewResolver(mc)

	// IPv6 with port.
	id, err := r.Resolve(context.Background(), "[fd7a:115c:a1e0::1]:443")
	if err != nil {
		t.Fatalf("resolve IPv6 with port: %v", err)
	}
	if id.TailscaleIP != "fd7a:115c:a1e0::1" {
		t.Errorf("TailscaleIP = %q, want fd7a:115c:a1e0::1", id.TailscaleIP)
	}
	if id.UserLogin != "ipv6@example.com" {
		t.Errorf("UserLogin = %q, want ipv6@example.com", id.UserLogin)
	}
	if id.NodeName != "v6node.ts.net" {
		t.Errorf("NodeName = %q, want v6node.ts.net", id.NodeName)
	}

	// Bare IPv6 (no port).
	mc.calls = 0
	id2, err := r.Resolve(context.Background(), "fd7a:115c:a1e0::1")
	if err != nil {
		t.Fatalf("resolve bare IPv6: %v", err)
	}
	// Should be served from cache since it's the same IP.
	if mc.calls != 0 {
		t.Errorf("expected 0 additional WhoIs calls (cached), got %d", mc.calls)
	}
	if id2.TailscaleIP != "fd7a:115c:a1e0::1" {
		t.Errorf("bare IPv6 TailscaleIP = %q", id2.TailscaleIP)
	}
}

func TestResolveAddressNoPort(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "noport.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "noport@example.com",
			},
		},
	}

	r := NewResolver(mc)

	// Bare IPv4 address without port.
	id, err := r.Resolve(context.Background(), "100.64.5.5")
	if err != nil {
		t.Fatalf("resolve bare IP: %v", err)
	}
	if id.TailscaleIP != "100.64.5.5" {
		t.Errorf("TailscaleIP = %q, want 100.64.5.5", id.TailscaleIP)
	}
	if id.UserLogin != "noport@example.com" {
		t.Errorf("UserLogin = %q, want noport@example.com", id.UserLogin)
	}
	if mc.calls != 1 {
		t.Errorf("expected 1 WhoIs call, got %d", mc.calls)
	}

	// Resolving the same IP with a port should use cache.
	_, err = r.Resolve(context.Background(), "100.64.5.5:8080")
	if err != nil {
		t.Fatalf("resolve with port: %v", err)
	}
	if mc.calls != 1 {
		t.Errorf("expected 1 WhoIs call (cached), got %d", mc.calls)
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

// ---------------------------------------------------------------------------
// Cap rule parsing (toIdentity)
// ---------------------------------------------------------------------------

// tailvoyCapMap builds a PeerCapMap from TailvoyCapRule values.
func tailvoyCapMap(rules ...TailvoyCapRule) tailcfg.PeerCapMap {
	var msgs []tailcfg.RawMessage
	for _, r := range rules {
		b, _ := json.Marshal(r)
		msgs = append(msgs, tailcfg.RawMessage(b))
	}
	return tailcfg.PeerCapMap{CapTailvoy: msgs}
}

func TestToIdentity_MultiDimensionalCap(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
			CapMap: tailvoyCapMap(TailvoyCapRule{
				Listeners: []string{"https"},
				Routes:    []string{"/api/*"},
				Hostnames: []string{"app.example.com"},
			}),
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.1:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	rule := id.Rules[0]
	if len(rule.Listeners) != 1 || rule.Listeners[0] != "https" {
		t.Errorf("Listeners = %v, want [https]", rule.Listeners)
	}
	if len(rule.Routes) != 1 || rule.Routes[0] != "/api/*" {
		t.Errorf("Routes = %v, want [/api/*]", rule.Routes)
	}
	if len(rule.Hostnames) != 1 || rule.Hostnames[0] != "app.example.com" {
		t.Errorf("Hostnames = %v, want [app.example.com]", rule.Hostnames)
	}
}

func TestToIdentity_EmptyCapRule(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
			CapMap: tailvoyCapMap(TailvoyCapRule{}),
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.2:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Empty cap rule {} should produce one rule with all dimensions empty
	// (unrestricted).
	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	rule := id.Rules[0]
	if len(rule.Listeners) != 0 || len(rule.Routes) != 0 || len(rule.Hostnames) != 0 {
		t.Errorf("empty cap rule should produce empty CapRule, got %+v", rule)
	}
}

func TestToIdentity_MultipleCapRules(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
			CapMap: tailvoyCapMap(
				TailvoyCapRule{
					Listeners: []string{"https"},
					Routes:    []string{"/api/*"},
				},
				TailvoyCapRule{
					Listeners: []string{"grpc"},
					Hostnames: []string{"*.internal.com"},
				},
			),
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.3:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(id.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(id.Rules))
	}

	want := []policy.CapRule{
		{Listeners: []string{"https"}, Routes: []string{"/api/*"}},
		{Listeners: []string{"grpc"}, Hostnames: []string{"*.internal.com"}},
	}
	for i, r := range id.Rules {
		w := want[i]
		if fmt.Sprintf("%v", r.Listeners) != fmt.Sprintf("%v", w.Listeners) {
			t.Errorf("rule[%d].Listeners = %v, want %v", i, r.Listeners, w.Listeners)
		}
		if fmt.Sprintf("%v", r.Routes) != fmt.Sprintf("%v", w.Routes) {
			t.Errorf("rule[%d].Routes = %v, want %v", i, r.Routes, w.Routes)
		}
		if fmt.Sprintf("%v", r.Hostnames) != fmt.Sprintf("%v", w.Hostnames) {
			t.Errorf("rule[%d].Hostnames = %v, want %v", i, r.Hostnames, w.Hostnames)
		}
	}
}

func TestToIdentity_HostnamesOnly(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
			CapMap: tailvoyCapMap(TailvoyCapRule{
				Hostnames: []string{"app.example.com", "*.internal.com"},
			}),
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.4:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	rule := id.Rules[0]
	if len(rule.Hostnames) != 2 {
		t.Errorf("expected 2 hostnames, got %v", rule.Hostnames)
	}
	if rule.Hostnames[0] != "app.example.com" || rule.Hostnames[1] != "*.internal.com" {
		t.Errorf("Hostnames = %v", rule.Hostnames)
	}
}

func TestToIdentity_NoCap(t *testing.T) {
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "bob@example.com",
			},
			// No CapMap -- peer on tailnet but no tailvoy grant.
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.5:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(id.Rules) != 0 {
		t.Errorf("expected 0 rules for peer without cap, got %d", len(id.Rules))
	}
}

func TestToIdentity_RoutesOnlyCap(t *testing.T) {
	// Backwards-compatible: old-style cap with only routes.
	mc := &mockClient{
		resp: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{Name: "node.ts.net."},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "alice@example.com",
			},
			CapMap: tailvoyCapMap(TailvoyCapRule{
				Routes: []string{"/api/*", "/health"},
			}),
		},
	}

	r := NewResolver(mc)
	id, err := r.Resolve(context.Background(), "100.64.20.6:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if len(id.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(id.Rules))
	}
	rule := id.Rules[0]
	if len(rule.Routes) != 2 || rule.Routes[0] != "/api/*" || rule.Routes[1] != "/health" {
		t.Errorf("Routes = %v, want [/api/* /health]", rule.Routes)
	}
	if len(rule.Listeners) != 0 || len(rule.Hostnames) != 0 {
		t.Errorf("expected empty listeners/hostnames, got L=%v H=%v", rule.Listeners, rule.Hostnames)
	}
}
