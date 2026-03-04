package policy

import (
	"slices"
	"strings"
)

// Engine evaluates access based on peer capabilities.
// Authorization data comes from the Identity (populated via WhoIs CapMap),
// not from config rules.
type Engine struct{}

// NewEngine creates a policy engine.
func NewEngine() *Engine {
	return &Engine{}
}

// HasAccess returns true if any rule in the identity grants L4 access
// for the given listener and SNI. Empty SNI means plain TCP (no TLS).
func (e *Engine) HasAccess(listener string, sni string, id *Identity) bool {
	if id == nil || len(id.Rules) == 0 {
		return false
	}
	for _, r := range id.Rules {
		if ruleMatchesL4(r, listener, sni) {
			return true
		}
	}
	return false
}

// CheckAccess returns true if any rule in the identity grants L7 access
// for the given listener, hostname, and request path.
func (e *Engine) CheckAccess(listener string, hostname string, path string, id *Identity) bool {
	if id == nil || len(id.Rules) == 0 {
		return false
	}
	for _, r := range id.Rules {
		if ruleMatchesL7(r, listener, hostname, path) {
			return true
		}
	}
	return false
}

// ruleMatchesL4 checks listener + hostname dimensions for L4 gating.
func ruleMatchesL4(rule CapRule, listener, sni string) bool {
	return matchDimension(rule.Listeners, listener) &&
		matchHostnameDimension(rule.Hostnames, sni)
}

// ruleMatchesL7 checks all three dimensions for L7 gating.
func ruleMatchesL7(rule CapRule, listener, hostname, path string) bool {
	return matchDimension(rule.Listeners, listener) &&
		matchHostnameDimension(rule.Hostnames, hostname) &&
		matchRouteDimension(rule.Routes, path)
}

// matchDimension returns true if values is empty (unrestricted) or target
// appears in values.
func matchDimension(values []string, target string) bool {
	return len(values) == 0 || slices.Contains(values, target)
}

// matchHostnameDimension returns true if patterns is empty (unrestricted) or
// any pattern matches the hostname. Supports exact match and *.domain wildcards.
func matchHostnameDimension(patterns []string, hostname string) bool {
	if len(patterns) == 0 {
		return true
	}
	if hostname == "" {
		return false
	}
	for _, p := range patterns {
		if matchHostname(p, hostname) {
			return true
		}
	}
	return false
}

// matchHostname checks a single pattern against a hostname.
// Exact match or *.example.com wildcard (matches foo.example.com but NOT example.com).
func matchHostname(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// hostname must end with suffix AND have something before the suffix
		// (i.e. "foo.example.com" matches, "example.com" does not).
		return strings.HasSuffix(hostname, suffix) && len(hostname) > len(suffix)
	}
	return false
}

// matchRouteDimension returns true if patterns is empty (unrestricted) or any
// pattern matches the path using matchPath().
func matchRouteDimension(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

// matchPath checks whether reqPath matches the given pattern.
// Supported patterns:
//   - "/*"         -- matches everything
//   - "/prefix/*"  -- matches any path starting with "/prefix/"
//   - "/exact"     -- exact match only
func matchPath(pattern, reqPath string) bool {
	if pattern == "/*" {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1] // e.g. "/api/*" → "/api/"
		return strings.HasPrefix(reqPath, prefix) || reqPath == pattern[:len(pattern)-2]
	}

	return pattern == reqPath
}
