package policy

import (
	"testing"

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
	if !e.CheckL7("web", "/admin/settings", alice) {
		t.Error("expected L7 allow for alice on /admin/settings")
	}

	bob := &Identity{UserLogin: "bob@company.com", TailscaleIP: "100.64.0.11"}
	if e.CheckL7("web", "/admin/settings", bob) {
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
	if !e.CheckL7("web", "/api/v1/data", client) {
		t.Error("expected L7 allow for tagged node on /api/v1/data")
	}

	rando := &Identity{UserLogin: "rando@example.com", TailscaleIP: "100.64.0.13"}
	if e.CheckL7("web", "/api/v1/data", rando) {
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
	if !e.CheckL7("web", "/public/page", id) {
		t.Error("expected L7 allow on catch-all for /public/page")
	}

	// Admin path should be restricted (first-match wins).
	if e.CheckL7("web", "/admin/secret", id) {
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
	if e.CheckL7("web", "/unknown", id) {
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
	if e.CheckL7("db", "/anything", id) {
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
