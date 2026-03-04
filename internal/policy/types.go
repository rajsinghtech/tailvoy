package policy

// CapRule defines a single tailvoy capability rule.
// AND within a rule (all specified dimensions must match),
// OR across rules (any matching rule grants access).
type CapRule struct {
	Listeners []string
	Routes    []string
	Hostnames []string
}

// Identity represents a resolved Tailscale identity for a connecting peer.
type Identity struct {
	UserLogin   string
	NodeName    string
	Tags        []string
	IsTagged    bool
	TailscaleIP string
	Rules       []CapRule // discrete cap rules (not merged)
}
