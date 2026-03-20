package bridge

import (
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

// groupRulesByDirection mirrors the logic in Run() for testing.
func groupRulesByDirection(rules []config.BridgeRule) map[string][]config.BridgeRule {
	m := make(map[string][]config.BridgeRule)
	for _, r := range rules {
		dk := config.DirectionKey(r.From, r.To)
		m[dk] = append(m[dk], r)
	}
	return m
}

func TestBridgeManager_GroupsRulesByDirection(t *testing.T) {
	cfg := &config.BridgeConfig{
		Tailnets: map[string]config.BridgeTailnet{
			"prod": {ClientID: "id1", ClientSecret: "sec1", Tags: []string{"tag:prod"}},
			"dev":  {ClientID: "id2", ClientSecret: "sec2", Tags: []string{"tag:dev"}},
		},
		Directions: map[string]config.BridgeDirection{
			"prod>dev": {ServiceTags: []string{"tag:bridge"}, Prefix: "pd-"},
			"dev>prod": {ServiceTags: []string{"tag:bridge"}, Prefix: "dp-"},
		},
		Rules: []config.BridgeRule{
			{
				From:     "prod",
				To:       "dev",
				Discover: config.BridgeDiscover{Tags: []string{"tag:web"}, Ports: []int{80}},
			},
			{
				From:     "prod",
				To:       "dev",
				Discover: config.BridgeDiscover{Tags: []string{"tag:db"}, Ports: []int{5432}},
			},
			{
				From:     "dev",
				To:       "prod",
				Discover: config.BridgeDiscover{Tags: []string{"tag:svc"}, Ports: []int{8080}},
			},
		},
		PollInterval: "30s",
	}

	groups := groupRulesByDirection(cfg.Rules)

	if len(groups) != 2 {
		t.Fatalf("expected 2 direction groups, got %d", len(groups))
	}

	pdRules, ok := groups["prod>dev"]
	if !ok {
		t.Fatal("missing prod>dev direction group")
	}
	if len(pdRules) != 2 {
		t.Errorf("prod>dev: expected 2 rules, got %d", len(pdRules))
	}

	dpRules, ok := groups["dev>prod"]
	if !ok {
		t.Fatal("missing dev>prod direction group")
	}
	if len(dpRules) != 1 {
		t.Errorf("dev>prod: expected 1 rule, got %d", len(dpRules))
	}
}

func TestBridgeManager_NewBridgeManager(t *testing.T) {
	cfg := &config.BridgeConfig{
		Tailnets: map[string]config.BridgeTailnet{
			"alpha": {ClientID: "cid", ClientSecret: "csec", Tags: []string{"tag:bridge"}},
		},
		Directions: map[string]config.BridgeDirection{
			"alpha>alpha": {ServiceTags: []string{"tag:svc"}, Prefix: "br-"},
		},
		Rules: []config.BridgeRule{
			{
				From:     "alpha",
				To:       "alpha",
				Discover: config.BridgeDiscover{Tags: []string{"tag:svc"}, Ports: []int{443}},
			},
		},
	}

	bm := NewBridgeManager(cfg, nil)
	if bm == nil {
		t.Fatal("NewBridgeManager returned nil")
	}
	if bm.cfg != cfg {
		t.Error("cfg not stored correctly")
	}
}

func TestBridgeManager_AdapterInterfaces(t *testing.T) {
	// Verify that our adapter types satisfy the internal interfaces at compile time.
	// These are interface satisfaction checks.
	var _ AdvertisementClient = (*noopAdvertiser)(nil)
	var _ ServiceListener = (*tsnetServiceListener)(nil)
	var _ Dialer = (*tsnetDialer)(nil)
	var _ DevicesClient = (*tsDevicesClient)(nil)
	var _ DNSClient = (*tsDNSClient)(nil)
}
