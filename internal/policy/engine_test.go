package policy

import (
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// HasAccess
// ---------------------------------------------------------------------------

func TestHasAccess_WithRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		UserLogin:     "alice@example.com",
		TailscaleIP:   "100.64.0.1",
		AllowedRoutes: []string{"/api/*"},
	}
	if !e.HasAccess(id) {
		t.Error("expected HasAccess=true when AllowedRoutes is non-empty")
	}
}

func TestHasAccess_MultipleRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		AllowedRoutes: []string{"/api/*", "/admin/*", "/health"},
	}
	if !e.HasAccess(id) {
		t.Error("expected HasAccess=true with multiple routes")
	}
}

func TestHasAccess_NilRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		UserLogin:   "bob@example.com",
		TailscaleIP: "100.64.0.2",
	}
	if e.HasAccess(id) {
		t.Error("expected HasAccess=false when AllowedRoutes is nil")
	}
}

func TestHasAccess_EmptyRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		AllowedRoutes: []string{},
	}
	if e.HasAccess(id) {
		t.Error("expected HasAccess=false when AllowedRoutes is empty slice")
	}
}

func TestHasAccess_EmptyIdentity(t *testing.T) {
	e := NewEngine()
	id := &Identity{}
	if e.HasAccess(id) {
		t.Error("expected HasAccess=false for zero-value identity")
	}
}

func TestHasAccess_WildcardRoute(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		AllowedRoutes: []string{"/*"},
	}
	if !e.HasAccess(id) {
		t.Error("expected HasAccess=true for wildcard route")
	}
}

// ---------------------------------------------------------------------------
// CheckAccess
// ---------------------------------------------------------------------------

func TestCheckAccess_SingleRouteMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/api/*"}}

	if !e.CheckAccess("/api/v1/users", id) {
		t.Error("expected CheckAccess=true for /api/v1/users matching /api/*")
	}
	if e.CheckAccess("/admin/settings", id) {
		t.Error("expected CheckAccess=false for /admin/settings not matching /api/*")
	}
}

func TestCheckAccess_MultipleRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/api/*", "/admin/*", "/health"}}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/data", true},
		{"/admin/settings", true},
		{"/health", true},
		{"/health/", false}, // exact match: no trailing slash
		{"/unknown", false},
		{"/", false},
	}

	for _, tt := range tests {
		got := e.CheckAccess(tt.path, id)
		if got != tt.want {
			t.Errorf("CheckAccess(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestCheckAccess_WildcardOnly(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/*"}}

	paths := []string{"/", "/foo", "/foo/bar/baz", "/api/v1/data"}
	for _, p := range paths {
		if !e.CheckAccess(p, id) {
			t.Errorf("expected CheckAccess(%q)=true for wildcard route /*", p)
		}
	}
}

func TestCheckAccess_NoRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{}

	if e.CheckAccess("/anything", id) {
		t.Error("expected CheckAccess=false when identity has no routes")
	}
}

func TestCheckAccess_EmptyRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{}}

	if e.CheckAccess("/anything", id) {
		t.Error("expected CheckAccess=false when AllowedRoutes is empty")
	}
}

func TestCheckAccess_ExactRouteMatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/health"}}

	if !e.CheckAccess("/health", id) {
		t.Error("expected exact match for /health")
	}
	if e.CheckAccess("/healthz", id) {
		t.Error("expected no match for /healthz against exact /health")
	}
	if e.CheckAccess("/health/", id) {
		t.Error("expected no match for /health/ against exact /health")
	}
}

func TestCheckAccess_PrefixDoesNotOvermatch(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/admin/*"}}

	if !e.CheckAccess("/admin/settings", id) {
		t.Error("expected match for /admin/settings")
	}
	if e.CheckAccess("/admins", id) {
		t.Error("/admin/* should not match /admins (different prefix)")
	}
}

func TestCheckAccess_FirstMatchReturns(t *testing.T) {
	e := NewEngine()
	// If the first route already matches, we should return true
	// regardless of later routes.
	id := &Identity{AllowedRoutes: []string{"/*", "/restricted/*"}}

	if !e.CheckAccess("/anything", id) {
		t.Error("expected first wildcard route to match")
	}
}

func TestCheckAccess_PathTraversal(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/public/*"}}

	// No path normalization: dot segments are literal.
	if !e.CheckAccess("/public/../admin/secret", id) {
		t.Error("expected literal match on /public/* for dot-segment path")
	}
	if e.CheckAccess("/admin/secret", id) {
		t.Error("expected no match on /public/* for /admin/secret")
	}
}

func TestCheckAccess_VeryLongPath(t *testing.T) {
	e := NewEngine()
	id := &Identity{AllowedRoutes: []string{"/*"}}

	longPath := "/" + strings.Repeat("segment/", 500)
	if !e.CheckAccess(longPath, id) {
		t.Error("expected wildcard to match very long path")
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

		// Empty path — "/*" is a catch-all.
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
// Edge cases: identity variations
// ---------------------------------------------------------------------------

func TestCheckAccess_TaggedIdentityWithRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		Tags:          []string{"tag:server"},
		IsTagged:      true,
		TailscaleIP:   "100.64.0.5",
		AllowedRoutes: []string{"/api/*"},
	}
	if !e.HasAccess(id) {
		t.Error("tagged identity with routes should have access")
	}
	if !e.CheckAccess("/api/data", id) {
		t.Error("tagged identity should match /api/data")
	}
}

func TestCheckAccess_TaggedIdentityWithoutRoutes(t *testing.T) {
	e := NewEngine()
	id := &Identity{
		Tags:        []string{"tag:server"},
		IsTagged:    true,
		TailscaleIP: "100.64.0.5",
	}
	if e.HasAccess(id) {
		t.Error("tagged identity without routes should not have access")
	}
	if e.CheckAccess("/anything", id) {
		t.Error("tagged identity without routes should fail CheckAccess")
	}
}

func TestCheckAccess_IdentityFieldsIgnored(t *testing.T) {
	// The engine only cares about AllowedRoutes. UserLogin, Tags, etc. are
	// informational and do not affect the policy decision.
	e := NewEngine()

	withRoutes := &Identity{
		UserLogin:     "",
		NodeName:      "",
		Tags:          nil,
		TailscaleIP:   "",
		AllowedRoutes: []string{"/*"},
	}
	if !e.HasAccess(withRoutes) {
		t.Error("identity with only AllowedRoutes should have access")
	}
	if !e.CheckAccess("/test", withRoutes) {
		t.Error("identity with only AllowedRoutes should pass CheckAccess")
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
			id := &Identity{AllowedRoutes: []string{"/api/*", "/*"}}
			for j := 0; j < 500; j++ {
				e.HasAccess(id)
				e.CheckAccess("/api/data", id)
				e.CheckAccess("/other", id)
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
			// Each goroutine uses its own identity.
			id := &Identity{AllowedRoutes: []string{"/api/*"}}
			for j := 0; j < 200; j++ {
				e.HasAccess(id)
				e.CheckAccess("/api/v1", id)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := &Identity{} // no routes
			for j := 0; j < 200; j++ {
				e.HasAccess(id)
				e.CheckAccess("/api/v1", id)
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

// ---------------------------------------------------------------------------
// Table-driven CheckAccess with merged routes
// ---------------------------------------------------------------------------

func TestCheckAccess_MergedRoutes(t *testing.T) {
	e := NewEngine()

	// Simulates a peer whose caps were merged from multiple ACL grants,
	// resulting in a combined set of allowed route patterns.
	id := &Identity{
		UserLogin: "alice@company.com",
		AllowedRoutes: []string{
			"/api/*",
			"/admin/*",
			"/health",
			"/metrics",
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
		got := e.CheckAccess(tt.path, id)
		if got != tt.want {
			t.Errorf("CheckAccess(%q) = %v, want %v (routes: %v)", tt.path, got, tt.want, id.AllowedRoutes)
		}
	}
}
