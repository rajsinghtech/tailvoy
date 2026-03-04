package policy

import (
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// HasAccess — L4 gating
// ---------------------------------------------------------------------------

func TestHasAccess_EmptyRuleFullAccess(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{}}} // empty rule = unrestricted
	if !e.HasAccess("https", "app.example.com", id) {
		t.Error("empty rule should grant full access")
	}
}

func TestHasAccess_ListenerMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Listeners: []string{"https"}}}}
	if !e.HasAccess("https", "", id) {
		t.Error("expected match for listener=https")
	}
}

func TestHasAccess_ListenerMismatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Listeners: []string{"https"}}}}
	if e.HasAccess("http", "", id) {
		t.Error("expected deny for listener=http when rule requires https")
	}
}

func TestHasAccess_HostnameExactMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"app.example.com"}}}}
	if !e.HasAccess("https", "app.example.com", id) {
		t.Error("expected hostname exact match")
	}
}

func TestHasAccess_HostnameMismatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"app.example.com"}}}}
	if e.HasAccess("https", "other.example.com", id) {
		t.Error("expected deny for hostname mismatch")
	}
}

func TestHasAccess_HostnameWildcard(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"*.example.com"}}}}

	if !e.HasAccess("https", "app.example.com", id) {
		t.Error("expected wildcard match for app.example.com")
	}
	if !e.HasAccess("https", "deep.sub.example.com", id) {
		t.Error("expected wildcard match for deep.sub.example.com")
	}
	// Wildcard should NOT match the bare domain.
	if e.HasAccess("https", "example.com", id) {
		t.Error("*.example.com should not match example.com")
	}
}

func TestHasAccess_ListenerAndHostnameAND(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"https"},
		Hostnames: []string{"app.example.com"},
	}}}

	if !e.HasAccess("https", "app.example.com", id) {
		t.Error("both dimensions match, should allow")
	}
	if e.HasAccess("http", "app.example.com", id) {
		t.Error("listener mismatch, should deny")
	}
	if e.HasAccess("https", "other.example.com", id) {
		t.Error("hostname mismatch, should deny")
	}
}

func TestHasAccess_NoRulesDeny(t *testing.T) {
	e := NewEngine()
	id := &Identity{}
	if e.HasAccess("https", "app.example.com", id) {
		t.Error("no rules should deny access")
	}
}

func TestHasAccess_MultipleRulesOR(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{
		{Listeners: []string{"https"}, Hostnames: []string{"app.example.com"}},
		{Listeners: []string{"grpc"}, Hostnames: []string{"api.example.com"}},
	}}

	if !e.HasAccess("https", "app.example.com", id) {
		t.Error("first rule should match")
	}
	if !e.HasAccess("grpc", "api.example.com", id) {
		t.Error("second rule should match")
	}
	if e.HasAccess("grpc", "app.example.com", id) {
		t.Error("mixed dimensions should deny")
	}
}

func TestHasAccess_PlainTCPWithHostnameRule(t *testing.T) {
	e := NewEngine()
	// Rule requires specific hostname, but SNI is empty (plain TCP).
	id := &Identity{Rules: []CapRule{{Hostnames: []string{"app.example.com"}}}}
	if e.HasAccess("https", "", id) {
		t.Error("plain TCP (empty sni) with hostname rule should NOT match")
	}
}

func TestHasAccess_EmptyIdentityDeny(t *testing.T) {
	e := NewEngine()
	if e.HasAccess("https", "app.example.com", nil) {
		t.Error("nil identity should deny")
	}
	if e.HasAccess("https", "app.example.com", &Identity{}) {
		t.Error("zero-value identity should deny")
	}
}

func TestHasAccess_EmptyRuleNoSNI(t *testing.T) {
	e := NewEngine()
	// Empty rule = all dimensions unrestricted, including hostname.
	id := &Identity{Rules: []CapRule{{}}}
	if !e.HasAccess("tcp", "", id) {
		t.Error("empty rule should match even with no SNI")
	}
}

// ---------------------------------------------------------------------------
// CheckAccess — L7 gating
// ---------------------------------------------------------------------------

func TestCheckAccess_ListenerAndRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"https"},
		Routes:    []string{"/api/*"},
	}}}

	if !e.CheckAccess("https", "app.example.com", "/api/v1/users", id) {
		t.Error("listener+route match, should allow")
	}
	if e.CheckAccess("http", "app.example.com", "/api/v1/users", id) {
		t.Error("listener mismatch, should deny")
	}
	if e.CheckAccess("https", "app.example.com", "/admin/settings", id) {
		t.Error("route mismatch, should deny")
	}
}

func TestCheckAccess_HostnameAndRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Hostnames: []string{"app.example.com"},
		Routes:    []string{"/api/*"},
	}}}

	if !e.CheckAccess("https", "app.example.com", "/api/data", id) {
		t.Error("hostname+route match, should allow")
	}
	if e.CheckAccess("https", "other.example.com", "/api/data", id) {
		t.Error("hostname mismatch, should deny")
	}
}

func TestCheckAccess_AllThreeDimensions(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{
		Listeners: []string{"https"},
		Hostnames: []string{"app.example.com"},
		Routes:    []string{"/api/*"},
	}}}

	if !e.CheckAccess("https", "app.example.com", "/api/v1", id) {
		t.Error("all three match, should allow")
	}
	if e.CheckAccess("http", "app.example.com", "/api/v1", id) {
		t.Error("listener mismatch, should deny")
	}
	if e.CheckAccess("https", "other.example.com", "/api/v1", id) {
		t.Error("hostname mismatch, should deny")
	}
	if e.CheckAccess("https", "app.example.com", "/admin", id) {
		t.Error("route mismatch, should deny")
	}
}

func TestCheckAccess_EmptyRuleFullAccess(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{}}}

	paths := []string{"/", "/foo", "/foo/bar/baz", "/api/v1/data"}
	for _, p := range paths {
		if !e.CheckAccess("https", "anything.com", p, id) {
			t.Errorf("empty rule should grant full access for path %q", p)
		}
	}
}

func TestCheckAccess_MultipleRulesOR(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{
		{Listeners: []string{"https"}, Routes: []string{"/api/*"}},
		{Listeners: []string{"grpc"}, Routes: []string{"/rpc/*"}},
	}}

	if !e.CheckAccess("https", "", "/api/v1", id) {
		t.Error("first rule should match")
	}
	if !e.CheckAccess("grpc", "", "/rpc/method", id) {
		t.Error("second rule should match")
	}
	if e.CheckAccess("https", "", "/rpc/method", id) {
		t.Error("cross-rule should deny")
	}
}

func TestCheckAccess_NoRulesDeny(t *testing.T) {
	e := NewEngine()
	id := &Identity{}
	if e.CheckAccess("https", "app.com", "/anything", id) {
		t.Error("no rules should deny")
	}
}

func TestCheckAccess_NilIdentity(t *testing.T) {
	e := NewEngine()
	if e.CheckAccess("https", "app.com", "/anything", nil) {
		t.Error("nil identity should deny")
	}
}

func TestCheckAccess_WildcardRoute(t *testing.T) {
	e := NewEngine()
	id := &Identity{Rules: []CapRule{{Routes: []string{"/*"}}}}

	paths := []string{"/", "/foo", "/foo/bar/baz", "/api/v1/data"}
	for _, p := range paths {
		if !e.CheckAccess("https", "app.com", p, id) {
			t.Errorf("wildcard route should match path %q", p)
		}
	}
}

func TestCheckAccess_MergedRoutes(t *testing.T) {
	e := NewEngine()

	// Simulates multiple cap rules from ACL grants.
	id := &Identity{
		UserLogin: "alice@company.com",
		Rules: []CapRule{
			{Routes: []string{"/api/*", "/admin/*"}},
			{Routes: []string{"/health", "/metrics"}},
		},
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/v1/users", true},
		{"/api/", true},
		{"/api", true},
		{"/admin/settings", true},
		{"/admin/deep/nested/path", true},
		{"/health", true},
		{"/metrics", true},
		{"/health/", false},   // exact, no trailing slash
		{"/metrics/", false},  // exact, no trailing slash
		{"/dashboard", false}, // not in any route
		{"/", false},          // root not granted
		{"/apiary", false},    // similar prefix, no match
		{"/administrator", false},
	}

	for _, tt := range tests {
		got := e.CheckAccess("https", "", tt.path, id)
		if got != tt.want {
			t.Errorf("CheckAccess(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// matchPath (unit tests for the internal function)
// ---------------------------------------------------------------------------

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Catch-all
		{"/*", "/", true},
		{"/*", "/foo", true},
		{"/*", "/foo/bar", true},

		// Prefix match
		{"/admin/*", "/admin/", true},
		{"/admin/*", "/admin/settings", true},
		{"/admin/*", "/admin/deep/nested", true},
		{"/admin/*", "/admin", true}, // bare prefix without trailing slash
		{"/admin/*", "/admins", false},
		{"/admin/*", "/other", false},

		{"/api/*", "/api/v1", true},
		{"/api/*", "/api/", true},
		{"/api/*", "/api", true},
		{"/api/*", "/apiary", false},

		// Exact match
		{"/health", "/health", true},
		{"/health", "/health/", false},
		{"/health", "/healthz", false},
		{"/health", "/", false},

		// Edge cases
		{"/", "/", true},
		{"/", "/foo", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestMatchPath_EdgeCases(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Root exact match.
		{"/", "/", true},
		{"/", "", false},

		// Trailing slash differences.
		{"/admin", "/admin/", false},
		{"/admin", "/admin", true},
		{"/admin/", "/admin/", true},
		{"/admin/", "/admin", false},

		// Double slashes are treated literally.
		{"/admin/*", "//admin", false},
		{"//admin/*", "//admin/foo", true},

		// Dot segments are not resolved.
		{"/admin/*", "/public/../admin/secret", false},
		{"/public/*", "/public/../admin/secret", true},

		// Query strings are part of the path string as received.
		{"/public/*", "/public/page?foo=bar", true},
		{"/public/page", "/public/page?foo=bar", false},

		// Empty path -- "/*" is a catch-all.
		{"/*", "", true},
		{"/", "", false},
		{"", "", true},

		// Very long path.
		{"/*", "/" + strings.Repeat("a", 1500), true},
		{"/prefix/*", "/prefix/" + strings.Repeat("x/", 500), true},

		// URL-encoded characters are literal.
		{"/public/*", "/public/hello%20world", true},
		{"/public/hello world", "/public/hello%20world", false},

		// Catch-all wildcard matches everything.
		{"/*", "/a/b/c/d/e/f/g", true},
		{"/*", "/", true},

		// Deep prefix wildcard matches arbitrary depth.
		{"/a/b/*", "/a/b/c/d/e", true},
		{"/a/b/*", "/a/b/", true},
		{"/a/b/*", "/a/b", true},
		{"/a/b/*", "/a/bc", false},
		{"/a/b/*", "/a/", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// matchHostname
// ---------------------------------------------------------------------------

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		want     bool
	}{
		{"app.example.com", "app.example.com", true},
		{"app.example.com", "other.example.com", false},
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"*.com", "example.com", true},
		{"*.com", "com", false},
	}

	for _, tt := range tests {
		got := matchHostname(tt.pattern, tt.hostname)
		if got != tt.want {
			t.Errorf("matchHostname(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases: identity variations
// ---------------------------------------------------------------------------

func TestCheckAccess_TaggedIdentityWithRules(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		Tags:        []string{"tag:server"},
		IsTagged:    true,
		TailscaleIP: "100.64.0.5",
		Rules:       []CapRule{{Routes: []string{"/api/*"}}},
	}
	if !e.HasAccess("https", "", id) {
		t.Error("tagged identity with rules should have access")
	}
	if !e.CheckAccess("https", "", "/api/data", id) {
		t.Error("tagged identity should match /api/data")
	}
}

func TestCheckAccess_TaggedIdentityWithoutRules(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		Tags:        []string{"tag:server"},
		IsTagged:    true,
		TailscaleIP: "100.64.0.5",
	}
	if e.HasAccess("https", "", id) {
		t.Error("tagged identity without rules should not have access")
	}
	if e.CheckAccess("https", "", "/anything", id) {
		t.Error("tagged identity without rules should fail CheckAccess")
	}
}

func TestCheckAccess_IdentityFieldsIgnored(t *testing.T) {
	// The engine only cares about Rules. UserLogin, Tags, etc. are
	// informational and do not affect the policy decision.
	e := NewEngine()

	withRules := &Identity{
		UserLogin:   "",
		NodeName:    "",
		Tags:        nil,
		TailscaleIP: "",
		Rules:       []CapRule{{Routes: []string{"/*"}}},
	}
	if !e.HasAccess("https", "", withRules) {
		t.Error("identity with only Rules should have access")
	}
	if !e.CheckAccess("https", "", "/test", withRules) {
		t.Error("identity with only Rules should pass CheckAccess")
	}
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	e := NewEngine()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := &Identity{Rules: []CapRule{
				{Routes: []string{"/api/*"}},
				{Routes: []string{"/*"}},
			}}
			for j := 0; j < 500; j++ {
				e.HasAccess("https", "app.example.com", id)
				e.CheckAccess("https", "app.example.com", "/api/data", id)
				e.CheckAccess("https", "app.example.com", "/other", id)
			}
		}()
	}
	wg.Wait()
	// If the race detector doesn't fire, concurrent access is safe.
}

func TestConcurrentAccess_DifferentIdentities(t *testing.T) {
	e := NewEngine()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := &Identity{Rules: []CapRule{{Routes: []string{"/api/*"}}}}
			for j := 0; j < 200; j++ {
				e.HasAccess("https", "", id)
				e.CheckAccess("https", "", "/api/v1", id)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := &Identity{} // no rules
			for j := 0; j < 200; j++ {
				e.HasAccess("https", "", id)
				e.CheckAccess("https", "", "/api/v1", id)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Engine construction
// ---------------------------------------------------------------------------

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine() returned nil")
	}
}
