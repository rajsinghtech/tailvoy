package bridge

import (
	"context"
	"log/slog"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

// DeviceInfo represents a discovered machine on the source tailnet.
type DeviceInfo struct {
	FQDN      string
	Addresses []string // Tailscale IPs (v4 + v6)
	Ports     []int    // union of ports from all matching rules
}

// DevicesClient abstracts the Tailscale Devices API for testing.
type DevicesClient interface {
	List(ctx context.Context) ([]Device, error)
}

// Device is the subset of tailscale device fields we need.
type Device struct {
	Name      string   // FQDN (e.g. "web-1.tail1234.ts.net")
	Addresses []string // Tailscale IPs
	Tags      []string // ACL tags (e.g. ["tag:web", "tag:server"])
}

// Discoverer polls the Devices API and filters by tags from bridge rules.
type Discoverer struct {
	client   DevicesClient
	rules    []config.BridgeRule
	logger   *slog.Logger
	previous map[string]DeviceInfo
}

func NewDiscoverer(client DevicesClient, rules []config.BridgeRule, logger *slog.Logger) *Discoverer {
	return &Discoverer{
		client: client,
		rules:  rules,
		logger: logger,
	}
}

// Poll fetches devices, filters by tags, merges ports from matching rules,
// and returns the current device map plus lists of added/removed FQDNs.
func (d *Discoverer) Poll(ctx context.Context) (current map[string]DeviceInfo, added, removed []string, err error) {
	devices, err := d.client.List(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	current = make(map[string]DeviceInfo, len(devices))
	for _, dev := range devices {
		ports := matchedPorts(dev.Tags, d.rules)
		if len(ports) == 0 {
			continue
		}
		current[dev.Name] = DeviceInfo{
			FQDN:      dev.Name,
			Addresses: dev.Addresses,
			Ports:     ports,
		}
	}

	for fqdn := range current {
		if _, ok := d.previous[fqdn]; !ok {
			added = append(added, fqdn)
		}
	}
	for fqdn := range d.previous {
		if _, ok := current[fqdn]; !ok {
			removed = append(removed, fqdn)
		}
	}

	d.previous = current
	return current, added, removed, nil
}

// matchedPorts returns the deduplicated union of ports from all rules whose
// tags overlap with the device's tags. Returns nil if no rules match.
func matchedPorts(deviceTags []string, rules []config.BridgeRule) []int {
	tagSet := make(map[string]struct{}, len(deviceTags))
	for _, t := range deviceTags {
		tagSet[t] = struct{}{}
	}

	seen := map[int]struct{}{}
	var ports []int
	for _, rule := range rules {
		matched := false
		for _, rt := range rule.Discover.Tags {
			if _, ok := tagSet[rt]; ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, p := range rule.Discover.Ports {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	return ports
}
