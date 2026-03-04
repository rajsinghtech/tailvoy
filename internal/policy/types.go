package policy

// Identity represents a resolved Tailscale identity for a connecting peer.
type Identity struct {
	UserLogin   string
	NodeName    string
	Tags        []string
	IsTagged    bool
	TailscaleIP string
}
