package policy

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

// testConfig builds a Config suitable for policy tests. It has two listeners:
// "web" (L7-enabled) and "db" (L4-only), with configurable rules and default.
func testConfig(l4 []config.Rule, l7 []config.Rule, defaultPolicy string) *config.Config {
	if defaultPolicy == "" {
		defaultPolicy = "deny"
	}
	return &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":443", Forward: "localhost:8080", L7Policy: true},
			{Name: "db", Protocol: "tcp", Listen: ":5432", Forward: "localhost:5432"},
		},
		L4Rules: l4,
		L7Rules: l7,
		Default: defaultPolicy,
	}
}

func TestCheckL4_AnyTailscale(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "anyone@example.com", TailscaleIP: "100.64.0.1"}
	if !e.CheckL4("web", id) {
		t.Error("expected L4 allow for any_tailscale")
	}
}

func TestCheckL4_AllowByTag(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "db"},
			Allow: config.AllowSpec{Tags: []string{"tag:db-access"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	allowed := &Identity{Tags: []string{"tag:db-access"}, IsTagged: true, TailscaleIP: "100.64.0.2"}
	if !e.CheckL4("db", allowed) {
		t.Error("expected L4 allow for matching tag")
	}

	denied := &Identity{Tags: []string{"tag:other"}, IsTagged: true, TailscaleIP: "100.64.0.3"}
	if e.CheckL4("db", denied) {
		t.Error("expected L4 deny for non-matching tag")
	}
}

func TestCheckL4_AllowByUser(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "db"},
			Allow: config.AllowSpec{Users: []string{"dba@company.com"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	allowed := &Identity{UserLogin: "dba@company.com", TailscaleIP: "100.64.0.4"}
	if !e.CheckL4("db", allowed) {
		t.Error("expected L4 allow for matching user")
	}

	// Case-insensitive match.
	upper := &Identity{UserLogin: "DBA@Company.com", TailscaleIP: "100.64.0.5"}
	if !e.CheckL4("db", upper) {
		t.Error("expected L4 allow for case-insensitive user match")
	}
}

func TestCheckL4_DenyUnmatched(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "db"},
			Allow: config.AllowSpec{Tags: []string{"tag:db-access"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "nobody@example.com", TailscaleIP: "100.64.0.6"}
	if e.CheckL4("db", id) {
		t.Error("expected L4 deny for unmatched identity")
	}

	// No rule for "web" listener — should fall through to default deny.
	if e.CheckL4("web", id) {
		t.Error("expected L4 deny when no rule matches the listener")
	}
}

func TestCheckL4_DefaultAllow(t *testing.T) {
	cfg := testConfig(nil, nil, "allow")
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "anyone@example.com", TailscaleIP: "100.64.0.1"}
	if !e.CheckL4("web", id) {
		t.Error("expected L4 allow with default=allow and no rules")
	}
}

func TestCheckL7_AdminPathByUser(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/admin/*"},
			Allow: config.AllowSpec{Users: []string{"alice@company.com"}},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	alice := &Identity{UserLogin: "alice@company.com", TailscaleIP: "100.64.0.10"}
	if !e.CheckL7("web", "/admin/settings", "", "", alice) {
		t.Error("expected L7 allow for alice on /admin/settings")
	}

	bob := &Identity{UserLogin: "bob@company.com", TailscaleIP: "100.64.0.11"}
	if e.CheckL7("web", "/admin/settings", "", "", bob) {
		t.Error("expected L7 deny for bob on /admin/settings")
	}
}

func TestCheckL7_APIPathByTag(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/api/*"},
			Allow: config.AllowSpec{Tags: []string{"tag:api-client"}},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	client := &Identity{Tags: []string{"tag:api-client"}, IsTagged: true, TailscaleIP: "100.64.0.12"}
	if !e.CheckL7("web", "/api/v1/data", "", "", client) {
		t.Error("expected L7 allow for tagged node on /api/v1/data")
	}

	rando := &Identity{UserLogin: "rando@example.com", TailscaleIP: "100.64.0.13"}
	if e.CheckL7("web", "/api/v1/data", "", "", rando) {
		t.Error("expected L7 deny for untagged user on /api/v1/data")
	}
}

func TestCheckL7_CatchAll(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{
			{
				Match: config.RuleMatch{Listener: "web", Path: "/admin/*"},
				Allow: config.AllowSpec{Users: []string{"alice@company.com"}},
			},
			{
				Match: config.RuleMatch{Listener: "web", Path: "/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		"deny",
	)
	e := NewEngine(cfg)

	// Random user should hit the catch-all.
	id := &Identity{UserLogin: "bob@company.com", TailscaleIP: "100.64.0.14"}
	if !e.CheckL7("web", "/public/page", "", "", id) {
		t.Error("expected L7 allow on catch-all for /public/page")
	}

	// Admin path should be restricted (first-match wins).
	if e.CheckL7("web", "/admin/secret", "", "", id) {
		t.Error("expected L7 deny for bob on /admin/secret (first-match rule)")
	}
}

func TestCheckL7_DefaultDeny(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/api/*"},
			Allow: config.AllowSpec{Tags: []string{"tag:api"}},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	// Path that matches no rule at all.
	id := &Identity{UserLogin: "someone@example.com", TailscaleIP: "100.64.0.15"}
	if e.CheckL7("web", "/unknown", "", "", id) {
		t.Error("expected L7 deny for path with no matching rule")
	}
}

func TestCheckL7_WrongListener(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/*"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "someone@example.com", TailscaleIP: "100.64.0.16"}
	if e.CheckL7("db", "/anything", "", "", id) {
		t.Error("expected L7 deny when no rules match the listener")
	}
}

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

func TestReload(t *testing.T) {
	denyAll := testConfig(nil, nil, "deny")
	e := NewEngine(denyAll)

	id := &Identity{UserLogin: "someone@example.com", TailscaleIP: "100.64.0.20"}

	if e.CheckL4("web", id) {
		t.Error("expected deny before reload")
	}

	// Reload with a config that allows everything on "web".
	allowWeb := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		nil, "deny",
	)
	e.Reload(allowWeb)

	if !e.CheckL4("web", id) {
		t.Error("expected allow after reload")
	}
}

func TestMatchesAllow_Groups(t *testing.T) {
	allow := &config.AllowSpec{Groups: []string{"group:engineering"}}

	// Node whose tags include the group name.
	id := &Identity{Tags: []string{"group:engineering"}, IsTagged: true}
	if !matchesAllow(allow, id) {
		t.Error("expected group match")
	}

	other := &Identity{Tags: []string{"group:sales"}, IsTagged: true}
	if matchesAllow(allow, other) {
		t.Error("expected no group match")
	}
}

// ---------------------------------------------------------------------------
// Path matching edge cases
// ---------------------------------------------------------------------------

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

		// Double slashes are treated literally — no normalization.
		{"/admin/*", "//admin", false},
		{"//admin/*", "//admin/foo", true},

		// Dot segments are not resolved — passed through literally.
		{"/admin/*", "/public/../admin/secret", false},
		{"/public/*", "/public/../admin/secret", true},

		// Query strings are part of the path string as received.
		{"/public/*", "/public/page?foo=bar", true},
		{"/public/page", "/public/page?foo=bar", false},

		// Empty path — "/*" is a catch-all (returns true unconditionally).
		{"/*", "", true},
		{"/", "", false},
		{"", "", true},

		// Very long path — should not panic or hang.
		{"/*", "/" + strings.Repeat("a", 1500), true},
		{"/prefix/*", "/prefix/" + strings.Repeat("x/", 500), true},

		// URL-encoded characters are literal — no decoding.
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
// CheckL4 edge cases
// ---------------------------------------------------------------------------

func TestCheckL4_EmptyIdentity(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{Users: []string{"someone@company.com"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	// Identity with no user, no tags, no node.
	empty := &Identity{}
	if e.CheckL4("web", empty) {
		t.Error("expected deny for empty identity")
	}
}

func TestCheckL4_ManyTags(t *testing.T) {
	tags := make([]string, 150)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag:noise-%d", i)
	}
	// Put the matching tag at the end.
	tags = append(tags, "tag:target")

	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "db"},
			Allow: config.AllowSpec{Tags: []string{"tag:target"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	id := &Identity{Tags: tags, IsTagged: true}
	if !e.CheckL4("db", id) {
		t.Error("expected allow when matching tag is present among 150+ tags")
	}

	// Same many tags but without the target.
	noMatch := &Identity{Tags: tags[:150], IsTagged: true}
	if e.CheckL4("db", noMatch) {
		t.Error("expected deny when target tag missing from 150 tags")
	}
}

func TestCheckL4_EmptyAllowSpec(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{}, // no users, no tags, no groups, any_tailscale=false
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "anyone@example.com", Tags: []string{"tag:foo"}, TailscaleIP: "100.64.0.1"}
	if e.CheckL4("web", id) {
		t.Error("expected deny for empty allow spec (nothing matches)")
	}
}

func TestCheckL4_AnyTailscaleFalse(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{AnyTailscale: false},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "user@example.com", TailscaleIP: "100.64.0.1"}
	if e.CheckL4("web", id) {
		t.Error("any_tailscale=false should not match anything extra")
	}
}

func TestCheckL4_TagCaseSensitivity(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "db"},
			Allow: config.AllowSpec{Tags: []string{"tag:admin"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	// Tags are case-sensitive (unlike users).
	exact := &Identity{Tags: []string{"tag:admin"}, IsTagged: true}
	if !e.CheckL4("db", exact) {
		t.Error("expected allow for exact tag match")
	}

	wrongCase := &Identity{Tags: []string{"Tag:Admin"}, IsTagged: true}
	if e.CheckL4("db", wrongCase) {
		t.Error("expected deny: tags should be case-sensitive")
	}

	upperCase := &Identity{Tags: []string{"TAG:ADMIN"}, IsTagged: true}
	if e.CheckL4("db", upperCase) {
		t.Error("expected deny: tags should be case-sensitive")
	}
}

func TestCheckL4_UserCaseSensitivity(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web"},
			Allow: config.AllowSpec{Users: []string{"Alice@Company.com"}},
		}},
		nil, "deny",
	)
	e := NewEngine(cfg)

	tests := []struct {
		login string
		want  bool
	}{
		{"Alice@Company.com", true},
		{"alice@company.com", true},
		{"ALICE@COMPANY.COM", true},
		{"aLiCe@cOmPaNy.CoM", true},
	}

	for _, tt := range tests {
		id := &Identity{UserLogin: tt.login}
		got := e.CheckL4("web", id)
		if got != tt.want {
			t.Errorf("CheckL4 with user %q = %v, want %v", tt.login, got, tt.want)
		}
	}
}

func TestCheckL4_FirstMatchWins(t *testing.T) {
	cfg := testConfig(
		[]config.Rule{
			{
				// First rule: allow only alice.
				Match: config.RuleMatch{Listener: "web"},
				Allow: config.AllowSpec{Users: []string{"alice@company.com"}},
			},
			{
				// Second rule: allow any tailscale user.
				Match: config.RuleMatch{Listener: "web"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		nil, "deny",
	)
	e := NewEngine(cfg)

	// Alice matches the first rule.
	alice := &Identity{UserLogin: "alice@company.com"}
	if !e.CheckL4("web", alice) {
		t.Error("expected allow for alice (first rule match)")
	}

	// Bob doesn't match first rule but matches second (any_tailscale).
	bob := &Identity{UserLogin: "bob@company.com"}
	if !e.CheckL4("web", bob) {
		t.Error("expected allow for bob via second any_tailscale rule")
	}
}

// ---------------------------------------------------------------------------
// CheckL7 edge cases
// ---------------------------------------------------------------------------

func TestCheckL7_NoL7Rules(t *testing.T) {
	// No L7 rules at all — should fall through to default.
	cfgDeny := testConfig(nil, nil, "deny")
	eDeny := NewEngine(cfgDeny)

	id := &Identity{UserLogin: "someone@example.com"}
	if eDeny.CheckL7("web", "/anything", "", "", id) {
		t.Error("expected deny when no L7 rules and default=deny")
	}

	cfgAllow := testConfig(nil, nil, "allow")
	eAllow := NewEngine(cfgAllow)

	if !eAllow.CheckL7("web", "/anything", "", "", id) {
		t.Error("expected allow when no L7 rules and default=allow")
	}
}

func TestCheckL7_ManyRules(t *testing.T) {
	// Build 200 L7 rules — only the last one matches.
	rules := make([]config.Rule, 200)
	for i := range rules {
		rules[i] = config.Rule{
			Match: config.RuleMatch{Listener: "web", Path: fmt.Sprintf("/path-%d/*", i)},
			Allow: config.AllowSpec{Tags: []string{fmt.Sprintf("tag:group-%d", i)}},
		}
	}
	// The final catch-all.
	rules = append(rules, config.Rule{
		Match: config.RuleMatch{Listener: "web", Path: "/*"},
		Allow: config.AllowSpec{AnyTailscale: true},
	})

	cfg := testConfig(nil, rules, "deny")
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "someone@example.com"}

	start := time.Now()
	if !e.CheckL7("web", "/unmatched-path", "", "", id) {
		t.Error("expected allow via catch-all after 200 non-matching rules")
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("CheckL7 with 200+ rules took %v, expected < 100ms", elapsed)
	}
}

func TestCheckL7_FirstMatchWins_MultiplePathRules(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{
			{
				// Rule 0: /data/* only for admins.
				Match: config.RuleMatch{Listener: "web", Path: "/data/*"},
				Allow: config.AllowSpec{Tags: []string{"tag:admin"}},
			},
			{
				// Rule 1: /data/* for anyone (would be catch-all for this path).
				Match: config.RuleMatch{Listener: "web", Path: "/data/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		"deny",
	)
	e := NewEngine(cfg)

	// Admin tag matches rule 0.
	admin := &Identity{Tags: []string{"tag:admin"}, IsTagged: true}
	if !e.CheckL7("web", "/data/secret", "", "", admin) {
		t.Error("expected allow for admin on /data/secret")
	}

	// Non-admin: rule 0 path matches but identity doesn't — first match wins, deny.
	user := &Identity{UserLogin: "user@example.com"}
	if e.CheckL7("web", "/data/secret", "", "", user) {
		t.Error("expected deny for non-admin on /data/secret (first-match-wins)")
	}
}

func TestCheckL7_GroupsMatching(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/internal/*"},
			Allow: config.AllowSpec{Groups: []string{"group:engineering", "group:ops"}},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	eng := &Identity{Tags: []string{"group:engineering"}, IsTagged: true}
	if !e.CheckL7("web", "/internal/dashboard", "", "", eng) {
		t.Error("expected allow for group:engineering")
	}

	ops := &Identity{Tags: []string{"group:ops"}, IsTagged: true}
	if !e.CheckL7("web", "/internal/dashboard", "", "", ops) {
		t.Error("expected allow for group:ops")
	}

	sales := &Identity{Tags: []string{"group:sales"}, IsTagged: true}
	if e.CheckL7("web", "/internal/dashboard", "", "", sales) {
		t.Error("expected deny for group:sales")
	}
}

func TestCheckL7_EmptyAllowSpec(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/*"},
			Allow: config.AllowSpec{}, // empty: no users, tags, groups; any_tailscale=false
		}},
		"deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "someone@example.com", Tags: []string{"tag:foo"}}
	if e.CheckL7("web", "/anything", "", "", id) {
		t.Error("expected deny for empty allow spec")
	}
}

func TestCheckL7_PathWithQueryString(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/public/*"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "user@example.com"}
	if !e.CheckL7("web", "/public/page?foo=bar&baz=1", "", "", id) {
		t.Error("expected path with query string to match /public/* prefix")
	}
}

func TestCheckL7_PathDotSegments(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{
			{
				Match: config.RuleMatch{Listener: "web", Path: "/admin/*"},
				Allow: config.AllowSpec{Users: []string{"admin@company.com"}},
			},
			{
				Match: config.RuleMatch{Listener: "web", Path: "/public/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		"deny",
	)
	e := NewEngine(cfg)

	// Path traversal string — no normalization means it matches /public/* literally.
	id := &Identity{UserLogin: "sneaky@example.com"}
	if !e.CheckL7("web", "/public/../admin/secret", "", "", id) {
		t.Error("expected match on /public/* for literal dot-segment path (no normalization)")
	}
}

func TestCheckL7_VeryLongPath(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/*"},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	longPath := "/" + strings.Repeat("segment/", 200)
	id := &Identity{UserLogin: "user@example.com"}
	if !e.CheckL7("web", longPath, "", "", id) {
		t.Error("expected allow for very long path under catch-all")
	}
}

// ---------------------------------------------------------------------------
// Reload edge cases
// ---------------------------------------------------------------------------

func TestReload_NilConfig(t *testing.T) {
	cfg := testConfig(nil, nil, "deny")
	e := NewEngine(cfg)

	// Reload with nil — subsequent calls should panic if dereferenced, which
	// confirms Reload actually swaps the config. We just verify no panic in
	// the Reload call itself.
	e.Reload(nil)

	// Accessing after nil reload will panic — that's expected behavior.
	// We don't call CheckL4/CheckL7 here because the contract requires a
	// valid config.
}

func TestReload_ConcurrentAccess(t *testing.T) {
	initial := testConfig(nil, nil, "deny")
	e := NewEngine(initial)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Spawn readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := &Identity{UserLogin: "user@example.com"}
			for {
				select {
				case <-stop:
					return
				default:
					e.CheckL4("web", id)
					e.CheckL7("web", "/test", "", "", id)
				}
			}
		}()
	}

	// Spawn a writer that reloads repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			var dflt string
			if i%2 == 0 {
				dflt = "allow"
			} else {
				dflt = "deny"
			}
			e.Reload(testConfig(
				[]config.Rule{{
					Match: config.RuleMatch{Listener: "web"},
					Allow: config.AllowSpec{AnyTailscale: true},
				}},
				nil, dflt,
			))
		}
		close(stop)
	}()

	wg.Wait()
	// If the race detector doesn't fire, the concurrent access is safe.
}

// ---------------------------------------------------------------------------
// Host matching
// ---------------------------------------------------------------------------

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Empty pattern matches any host.
		{"", "anything.com", true},
		{"", "", true},

		// Exact match (case insensitive).
		{"exact.com", "exact.com", true},
		{"exact.com", "EXACT.COM", true},
		{"exact.com", "other.com", false},

		// Port is stripped from host.
		{"exact.com", "exact.com:8080", true},

		// Wildcard suffix.
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "other.com", false},
		{"*.example.com", "SUB.EXAMPLE.COM", true},
	}

	for _, tt := range tests {
		got := matchHost(tt.pattern, tt.host)
		if got != tt.want {
			t.Errorf("matchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Method matching
// ---------------------------------------------------------------------------

func TestMatchMethod(t *testing.T) {
	tests := []struct {
		methods []string
		method  string
		want    bool
	}{
		// nil matches any method.
		{nil, "GET", true},
		{nil, "POST", true},

		// Empty slice matches any method.
		{[]string{}, "DELETE", true},

		// Single method match.
		{[]string{"GET"}, "GET", true},
		{[]string{"GET"}, "get", true}, // case insensitive

		// Multiple methods.
		{[]string{"GET", "POST"}, "POST", true},

		// No match.
		{[]string{"GET"}, "DELETE", false},
	}

	for _, tt := range tests {
		got := matchMethod(tt.methods, tt.method)
		if got != tt.want {
			t.Errorf("matchMethod(%v, %q) = %v, want %v", tt.methods, tt.method, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CheckL7 with host matching
// ---------------------------------------------------------------------------

func TestCheckL7_HostMatching(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{
			{
				// Only alice on admin.example.com.
				Match: config.RuleMatch{Listener: "web", Path: "/*", Host: "admin.example.com"},
				Allow: config.AllowSpec{Users: []string{"alice@company.com"}},
			},
			{
				// Catch-all: any tailscale user on any host.
				Match: config.RuleMatch{Listener: "web", Path: "/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		"deny",
	)
	e := NewEngine(cfg)

	alice := &Identity{UserLogin: "alice@company.com"}
	if !e.CheckL7("web", "/", "admin.example.com", "", alice) {
		t.Error("expected allow for alice on admin.example.com")
	}

	bob := &Identity{UserLogin: "bob@company.com"}
	if e.CheckL7("web", "/", "admin.example.com", "", bob) {
		t.Error("expected deny for bob on admin.example.com (first-match-wins)")
	}

	if !e.CheckL7("web", "/", "other.example.com", "", bob) {
		t.Error("expected allow for bob on other.example.com (falls through to catch-all)")
	}
}

// ---------------------------------------------------------------------------
// CheckL7 with method matching
// ---------------------------------------------------------------------------

func TestCheckL7_MethodMatching(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{{
			Match: config.RuleMatch{Listener: "web", Path: "/*", Methods: []string{"GET", "HEAD"}},
			Allow: config.AllowSpec{AnyTailscale: true},
		}},
		"deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "user@example.com"}

	if !e.CheckL7("web", "/page", "", "GET", id) {
		t.Error("expected allow for GET")
	}
	if !e.CheckL7("web", "/page", "", "HEAD", id) {
		t.Error("expected allow for HEAD")
	}
	if e.CheckL7("web", "/page", "", "POST", id) {
		t.Error("expected deny for POST (falls through to default deny)")
	}
}

// ---------------------------------------------------------------------------
// CheckL7 with host + method combined
// ---------------------------------------------------------------------------

func TestCheckL7_HostAndMethodCombined(t *testing.T) {
	cfg := testConfig(nil,
		[]config.Rule{
			{
				// GET only on api.example.com.
				Match: config.RuleMatch{Listener: "web", Path: "/*", Host: "api.example.com", Methods: []string{"GET"}},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
			{
				// Catch-all for everything else.
				Match: config.RuleMatch{Listener: "web", Path: "/*"},
				Allow: config.AllowSpec{AnyTailscale: true},
			},
		},
		"deny",
	)
	e := NewEngine(cfg)

	id := &Identity{UserLogin: "user@example.com"}

	// GET to api.example.com matches first rule.
	if !e.CheckL7("web", "/resource", "api.example.com", "GET", id) {
		t.Error("expected allow for GET to api.example.com")
	}

	// POST to api.example.com skips first rule (method mismatch), hits catch-all.
	if !e.CheckL7("web", "/resource", "api.example.com", "POST", id) {
		t.Error("expected allow for POST to api.example.com (falls through to catch-all)")
	}

	// GET to other.com skips first rule (host mismatch), hits catch-all.
	if !e.CheckL7("web", "/resource", "other.com", "GET", id) {
		t.Error("expected allow for GET to other.com (falls through to catch-all)")
	}
}
