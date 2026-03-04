package policy

import "strings"

// Engine evaluates access based on peer capabilities.
// Authorization data comes from the Identity (populated via WhoIs CapMap),
// not from config rules.
type Engine struct{}

// NewEngine creates a policy engine.
func NewEngine() *Engine {
	return &Engine{}
}

// HasAccess returns true if the identity has any tailvoy capability grant.
// Used for L4 gating — having the cap at all means the peer can connect.
func (e *Engine) HasAccess(id *Identity) bool {
	return len(id.AllowedRoutes) > 0
}

// CheckAccess returns true if the request path matches any of the identity's
// allowed route patterns. Returns false if the identity has no capabilities.
func (e *Engine) CheckAccess(path string, id *Identity) bool {
	for _, route := range id.AllowedRoutes {
		if matchPath(route, path) {
			return true
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
