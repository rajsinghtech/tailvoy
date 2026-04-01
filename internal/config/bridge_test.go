package config

import (
	"strings"
	"testing"
)

func TestParseBridge_Valid(t *testing.T) {
	t.Setenv("T1_ID", "id1")
	t.Setenv("T1_SEC", "sec1")
	t.Setenv("T2_ID", "id2")
	t.Setenv("T2_SEC", "sec2")

	data := []byte(`
bridge:
  tailnets:
    tailnet1:
      clientId: ${T1_ID}
      clientSecret: ${T1_SEC}
      tags: ["tag:bridge"]
    tailnet2:
      clientId: ${T2_ID}
      clientSecret: ${T2_SEC}
      tags: ["tag:bridge"]
  directions:
    "tailnet1>tailnet2":
      serviceTags: ["tag:t1-svc"]
      dns:
        enabled: true
        splitDns: true
  rules:
    - from: tailnet1
      to: tailnet2
      discover:
        tags: ["tag:web"]
        ports: [80, 443]
  pollInterval: 30s
  dialTimeout: 10s
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Bridge == nil {
		t.Fatal("expected bridge config")
	}
	if len(cfg.Bridge.Tailnets) != 2 {
		t.Errorf("tailnets = %d, want 2", len(cfg.Bridge.Tailnets))
	}
	if cfg.Bridge.Tailnets["tailnet1"].ClientID != "id1" {
		t.Errorf("clientId not expanded")
	}
	if len(cfg.Bridge.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(cfg.Bridge.Rules))
	}
}

func TestParseBridge_Validation(t *testing.T) {
	t.Setenv("T1_ID", "id1")
	t.Setenv("T1_SEC", "sec1")
	t.Setenv("T2_ID", "id2")
	t.Setenv("T2_SEC", "sec2")

	base := `
bridge:
  tailnets:
    tailnet1:
      clientId: ${T1_ID}
      clientSecret: ${T1_SEC}
      tags: ["tag:bridge"]
    tailnet2:
      clientId: ${T2_ID}
      clientSecret: ${T2_SEC}
      tags: ["tag:bridge"]
  directions:
    "tailnet1>tailnet2":
      serviceTags: ["tag:svc"]
`

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "no rules",
			yaml:    base,
			wantErr: "at least one bridge rule",
		},
		{
			name:    "rule references unknown tailnet",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: unknown\n      discover:\n        tags: [tag:x]\n        ports: [80]\n",
			wantErr: "unknown tailnet",
		},
		{
			name:    "from equals to",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: tailnet1\n      discover:\n        tags: [tag:x]\n        ports: [80]\n",
			wantErr: "must be different",
		},
		{
			name:    "empty discover tags",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: tailnet2\n      discover:\n        tags: []\n        ports: [80]\n",
			wantErr: "discover.tags",
		},
		{
			name:    "empty discover ports",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: tailnet2\n      discover:\n        tags: [tag:x]\n        ports: []\n",
			wantErr: "discover.ports",
		},
		{
			name:    "port out of range",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: tailnet2\n      discover:\n        tags: [tag:x]\n        ports: [0]\n",
			wantErr: "between 1 and 65535",
		},
		{
			name:    "missing direction entry",
			yaml:    "bridge:\n  tailnets:\n    t1:\n      clientId: ${T1_ID}\n      clientSecret: ${T1_SEC}\n      tags: [tag:b]\n    t2:\n      clientId: ${T2_ID}\n      clientSecret: ${T2_SEC}\n      tags: [tag:b]\n  rules:\n    - from: t1\n      to: t2\n      discover:\n        tags: [tag:x]\n        ports: [80]\n",
			wantErr: "no direction entry",
		},
		{
			name:    "invalid tailnet name",
			yaml:    "bridge:\n  tailnets:\n    INVALID_NAME:\n      clientId: ${T1_ID}\n      clientSecret: ${T1_SEC}\n      tags: [tag:b]\n  rules: []\n",
			wantErr: "must match",
		},
		{
			name:    "poll interval too low",
			yaml:    base + "  rules:\n    - from: tailnet1\n      to: tailnet2\n      discover:\n        tags: [tag:x]\n        ports: [80]\n  pollInterval: 1s\n",
			wantErr: "at least 5s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
