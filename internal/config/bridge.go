package config

import (
	"fmt"
	"regexp"
	"time"
)

var tailnetNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

type BridgeConfig struct {
	Tailnets     map[string]BridgeTailnet   `yaml:"tailnets"`
	Directions   map[string]BridgeDirection `yaml:"directions"`
	Rules        []BridgeRule               `yaml:"rules"`
	PollInterval string                     `yaml:"pollInterval,omitempty"`
	DialTimeout  string                     `yaml:"dialTimeout,omitempty"`
}

type BridgeTailnet struct {
	ClientID     string   `yaml:"clientId"`
	ClientSecret string   `yaml:"clientSecret"`
	Tags         []string `yaml:"tags"`
}

type BridgeDirection struct {
	Prefix      string           `yaml:"prefix,omitempty"`
	ServiceTags []string         `yaml:"serviceTags"`
	DNS         *BridgeDNSConfig `yaml:"dns,omitempty"`
}

type BridgeDNSConfig struct {
	Enabled           bool `yaml:"enabled"`
	SplitDns          bool `yaml:"splitDns"`
	CleanupOnShutdown bool `yaml:"cleanupOnShutdown"`
}

type BridgeRule struct {
	From     string         `yaml:"from"`
	To       string         `yaml:"to"`
	Discover BridgeDiscover `yaml:"discover"`
}

type BridgeDiscover struct {
	Tags  []string `yaml:"tags"`
	Ports []int    `yaml:"ports"`
}

func (b *BridgeConfig) ParsedPollInterval() time.Duration {
	if b.PollInterval == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(b.PollInterval)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

func (b *BridgeConfig) ParsedDialTimeout() time.Duration {
	if b.DialTimeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(b.DialTimeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// DirectionKey returns the canonical key for a from/to pair.
// Uses ">" as separator for YAML compatibility.
func DirectionKey(from, to string) string {
	return from + ">" + to
}

func (b *BridgeConfig) validate() error {
	for name := range b.Tailnets {
		if !tailnetNameRe.MatchString(name) {
			return fmt.Errorf("tailnet name %q must match [a-z0-9-]+", name)
		}
	}

	for name, tn := range b.Tailnets {
		if tn.ClientID == "" {
			return fmt.Errorf("tailnet %q: clientId is required", name)
		}
		if tn.ClientSecret == "" {
			return fmt.Errorf("tailnet %q: clientSecret is required", name)
		}
		if len(tn.Tags) == 0 {
			return fmt.Errorf("tailnet %q: tags is required", name)
		}
	}

	if len(b.Rules) == 0 {
		return fmt.Errorf("at least one bridge rule is required")
	}

	if b.PollInterval != "" {
		d, err := time.ParseDuration(b.PollInterval)
		if err != nil {
			return fmt.Errorf("bridge.pollInterval: %w", err)
		}
		if d < 5*time.Second {
			return fmt.Errorf("bridge.pollInterval must be at least 5s")
		}
	}

	if b.DialTimeout != "" {
		if _, err := time.ParseDuration(b.DialTimeout); err != nil {
			return fmt.Errorf("bridge.dialTimeout: %w", err)
		}
	}

	seenDirections := map[string]bool{}
	for _, r := range b.Rules {
		if _, ok := b.Tailnets[r.From]; !ok {
			return fmt.Errorf("rule from=%q: unknown tailnet", r.From)
		}
		if _, ok := b.Tailnets[r.To]; !ok {
			return fmt.Errorf("rule to=%q: unknown tailnet", r.To)
		}
		if r.From == r.To {
			return fmt.Errorf("rule from=%q to=%q: from and to must be different", r.From, r.To)
		}
		if len(r.Discover.Tags) == 0 {
			return fmt.Errorf("rule %s>%s: discover.tags must be non-empty", r.From, r.To)
		}
		if len(r.Discover.Ports) == 0 {
			return fmt.Errorf("rule %s>%s: discover.ports must be non-empty", r.From, r.To)
		}
		for _, p := range r.Discover.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("rule %s>%s: port %d must be between 1 and 65535", r.From, r.To, p)
			}
		}
		dk := DirectionKey(r.From, r.To)
		seenDirections[dk] = true
	}

	for dk := range seenDirections {
		if _, ok := b.Directions[dk]; !ok {
			return fmt.Errorf("no direction entry for %q; add it to bridge.directions", dk)
		}
	}

	for dk, dir := range b.Directions {
		if len(dir.ServiceTags) == 0 {
			return fmt.Errorf("direction %q: serviceTags is required", dk)
		}
	}

	return nil
}
