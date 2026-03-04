package identity

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// CapTailvoy is the peer capability key for tailvoy access rules.
// Define grants in your tailnet ACL policy to populate this.
const CapTailvoy tailcfg.PeerCapability = "rajsingh.info/cap/tailvoy"

// TailvoyCapRule defines the structure of the capability value.
type TailvoyCapRule struct {
	Listeners []string `json:"listeners,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

const cacheTTL = 5 * time.Minute

// WhoIsClient is the interface for Tailscale WhoIs lookups.
type WhoIsClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// ResolveError is returned when identity resolution fails.
type ResolveError struct {
	Addr   string
	Reason string
}

func (e *ResolveError) Error() string {
	return fmt.Sprintf("identity resolve %s: %s", e.Addr, e.Reason)
}

type cacheEntry struct {
	identity  *policy.Identity
	expiresAt time.Time
}

// Resolver wraps WhoIs lookups with a cache keyed by Tailscale IP.
type Resolver struct {
	client WhoIsClient
	mu     sync.RWMutex
	cache  map[netip.Addr]*cacheEntry
	now    func() time.Time // for testing
	done   chan struct{}
}

// NewResolver creates a Resolver backed by the given WhoIsClient.
// It starts a background goroutine that evicts expired cache entries.
// Call Close to stop the background goroutine.
func NewResolver(client WhoIsClient) *Resolver {
	r := &Resolver{
		client: client,
		cache:  make(map[netip.Addr]*cacheEntry),
		now:    time.Now,
		done:   make(chan struct{}),
	}
	go r.evictLoop()
	return r
}

// Close stops the background eviction goroutine.
func (r *Resolver) Close() {
	close(r.done)
}

// evictLoop periodically removes expired cache entries.
func (r *Resolver) evictLoop() {
	ticker := time.NewTicker(cacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.mu.Lock()
			now := r.now()
			for k, v := range r.cache {
				if now.After(v.expiresAt) {
					delete(r.cache, k)
				}
			}
			r.mu.Unlock()
		}
	}
}

// Resolve performs a WhoIs lookup for the given remote address, using a cached
// result if available and not expired.
func (r *Resolver) Resolve(ctx context.Context, remoteAddr string) (*policy.Identity, error) {
	ip := extractIP(remoteAddr)
	if !ip.IsValid() {
		return nil, &ResolveError{Addr: remoteAddr, Reason: "invalid address"}
	}

	// Check cache under read lock.
	r.mu.RLock()
	if entry, ok := r.cache[ip]; ok && r.now().Before(entry.expiresAt) {
		id := entry.identity
		r.mu.RUnlock()
		return id, nil
	}
	r.mu.RUnlock()

	resp, err := r.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, &ResolveError{Addr: remoteAddr, Reason: err.Error()}
	}

	id := toIdentity(resp, ip)

	r.mu.Lock()
	r.cache[ip] = &cacheEntry{
		identity:  id,
		expiresAt: r.now().Add(cacheTTL),
	}
	r.mu.Unlock()

	return id, nil
}

// CachedIdentity returns the cached identity for the given address, or nil if
// there is no unexpired cache entry.
func (r *Resolver) CachedIdentity(remoteAddr string) *policy.Identity {
	ip := extractIP(remoteAddr)
	if !ip.IsValid() {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.cache[ip]
	if !ok || r.now().After(entry.expiresAt) {
		return nil
	}
	return entry.identity
}

// StripPort extracts the IP portion from an "IP:port" string. If the address
// has no port, it is returned as-is.
func StripPort(addr string) string {
	ip := extractIP(addr)
	if !ip.IsValid() {
		return addr
	}
	return ip.String()
}

// extractIP parses a Tailscale IP from an "IP:port" or bare IP string.
func extractIP(addr string) netip.Addr {
	// Try as AddrPort first (handles "IP:port" and "[IPv6]:port").
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr()
	}
	// Try bare IP (handles IPv4 and IPv6 without port).
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip
	}
	// Handle bracket-wrapped IPv6 without port, e.g. "[::1]".
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		if ip, err := netip.ParseAddr(addr[1 : len(addr)-1]); err == nil {
			return ip
		}
	}
	return netip.Addr{}
}

// toIdentity converts a WhoIsResponse into a policy.Identity.
func toIdentity(resp *apitype.WhoIsResponse, ip netip.Addr) *policy.Identity {
	id := &policy.Identity{
		TailscaleIP: ip.String(),
	}

	if resp.Node != nil {
		// Node.Name is FQDN with trailing dot; trim it.
		id.NodeName = strings.TrimSuffix(resp.Node.Name, ".")
		if len(resp.Node.Tags) > 0 {
			id.Tags = resp.Node.Tags
			id.IsTagged = true
		}
	}

	if resp.UserProfile != nil && !id.IsTagged {
		id.UserLogin = resp.UserProfile.LoginName
	}

	// Convert tailvoy peer capability grants to discrete cap rules.
	capRules, _ := tailcfg.UnmarshalCapJSON[TailvoyCapRule](resp.CapMap, CapTailvoy)
	for _, cr := range capRules {
		id.Rules = append(id.Rules, policy.CapRule{
			Listeners: cr.Listeners,
			Routes:    cr.Routes,
			Hostnames: cr.Hostnames,
		})
	}

	return id
}
