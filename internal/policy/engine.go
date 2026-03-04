package policy

import (
	"strings"
	"sync"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

// Engine evaluates access policy rules against caller identity.
type Engine struct {
	mu     sync.RWMutex
	config *config.Config
}

// NewEngine creates a policy engine using the given config.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{config: cfg}
}

// Reload swaps the config atomically under a write lock.
func (e *Engine) Reload(cfg *config.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}

// CheckL4 evaluates L4 rules for the given listener against the caller identity.
// First matching rule wins. Falls through to the default policy if no rule matches.
func (e *Engine) CheckL4(listenerName string, id *Identity) bool {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	for _, rule := range cfg.L4Rules {
		if rule.Match.Listener != listenerName {
			continue
		}
		if matchesAllow(&rule.Allow, id) {
			return true
		}
	}

	return cfg.Default == "allow"
}

// CheckL7 evaluates L7 rules for the given listener and request path against the
// caller identity. First matching rule wins. Falls through to the default policy
// if no rule matches.
func (e *Engine) CheckL7(listenerName, reqPath string, id *Identity) bool {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	for _, rule := range cfg.L7Rules {
		if rule.Match.Listener != listenerName {
			continue
		}
		if !matchPath(rule.Match.Path, reqPath) {
			continue
		}
		if matchesAllow(&rule.Allow, id) {
			return true
		}
		// Path matched but identity didn't — first match wins, deny.
		return cfg.Default == "allow"
	}

	return cfg.Default == "allow"
}

// matchesAllow checks whether the identity satisfies the allow spec.
func matchesAllow(allow *config.AllowSpec, id *Identity) bool {
	if allow.AnyTailscale {
		return true
	}

	for _, u := range allow.Users {
		if strings.EqualFold(u, id.UserLogin) {
			return true
		}
	}

	for _, allowTag := range allow.Tags {
		for _, nodeTag := range id.Tags {
			if allowTag == nodeTag {
				return true
			}
		}
	}

	// Groups are resolved externally via Tailscale ACLs; for now we treat
	// group membership as a tag-like match where the group name appears in
	// the identity's tags.
	for _, g := range allow.Groups {
		for _, nodeTag := range id.Tags {
			if g == nodeTag {
				return true
			}
		}
	}

	return false
}

// matchPath checks whether reqPath matches the given pattern.
// Supported patterns:
//   - "/*"         — matches everything
//   - "/prefix/*"  — matches any path starting with "/prefix/"
//   - "/exact"     — exact match only
func matchPath(pattern, reqPath string) bool {
	if pattern == "/*" {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(reqPath, prefix) || reqPath == strings.TrimSuffix(prefix, "/")
	}

	return pattern == reqPath
}
