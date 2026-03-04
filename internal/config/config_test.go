package config

import (
	"os"
	"path/filepath"
	"testing"
)

func testdataPath(name string) string {
	// Tests run with cwd set to the package directory; testdata is at repo root.
	return filepath.Join("..", "..", "testdata", name)
}

func TestLoadFromFile(t *testing.T) {
	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Tailscale.Hostname != "tailvoy-test" {
		t.Errorf("hostname = %q, want %q", cfg.Tailscale.Hostname, "tailvoy-test")
	}
	if !cfg.Tailscale.Ephemeral {
		t.Error("ephemeral should be true")
	}
	if got := len(cfg.Listeners); got != 2 {
		t.Errorf("len(listeners) = %d, want 2", got)
	}
	if got := len(cfg.L4Rules); got != 2 {
		t.Errorf("len(l4_rules) = %d, want 2", got)
	}
	if got := len(cfg.L7Rules); got != 2 {
		t.Errorf("len(l7_rules) = %d, want 2", got)
	}
	if cfg.Default != "deny" {
		t.Errorf("default = %q, want %q", cfg.Default, "deny")
	}
}

func TestEnvVarExpansion(t *testing.T) {
	const key = "tskey-auth-test-12345"
	t.Setenv("TS_AUTHKEY", key)

	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tailscale.AuthKey != key {
		t.Errorf("authkey = %q, want %q", cfg.Tailscale.AuthKey, key)
	}
}

func TestParseMinimal(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "minimal"
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:8080"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.Hostname != "minimal" {
		t.Errorf("hostname = %q, want %q", cfg.Tailscale.Hostname, "minimal")
	}
	if cfg.Default != "deny" {
		t.Errorf("default = %q, want %q (should default to deny)", cfg.Default, "deny")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string // substring expected in the error
	}{
		{
			name: "missing hostname",
			yaml: `
tailscale: {}
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`,
			want: "tailscale.hostname is required",
		},
		{
			name: "duplicate listener name",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
  - name: web
    protocol: tcp
    listen: ":81"
    forward: "localhost:81"
`,
			want: "duplicate listener name",
		},
		{
			name: "unknown listener in l4 rule",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
l4_rules:
  - match:
      listener: ghost
    allow:
      any_tailscale: true
`,
			want: "unknown listener",
		},
		{
			name: "unknown listener in l7 rule",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
l7_rules:
  - match:
      listener: ghost
      path: "/"
    allow:
      any_tailscale: true
`,
			want: "unknown listener",
		},
		{
			name: "l7 rule missing path",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
l7_rules:
  - match:
      listener: web
    allow:
      any_tailscale: true
`,
			want: "path is required",
		},
		{
			name: "invalid default value",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
default: maybe
`,
			want: `must be "allow" or "deny"`,
		},
		{
			name: "missing listener protocol",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    listen: ":80"
    forward: "localhost:80"
`,
			want: "protocol is required",
		},
		{
			name: "missing listener listen",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    forward: "localhost:80"
`,
			want: "listen is required",
		},
		{
			name: "missing listener forward",
			yaml: `
tailscale:
  hostname: test
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
`,
			want: "forward is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); !contains(got, tt.want) {
				t.Errorf("error = %q, want substring %q", got, tt.want)
			}
		})
	}
}

func TestListenerByName(t *testing.T) {
	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if l := cfg.ListenerByName("https"); l == nil {
		t.Error("ListenerByName(\"https\") returned nil")
	} else if l.Forward != "envoy:443" {
		t.Errorf("https forward = %q, want %q", l.Forward, "envoy:443")
	}

	if l := cfg.ListenerByName("nonexistent"); l != nil {
		t.Errorf("ListenerByName(\"nonexistent\") = %+v, want nil", l)
	}
}

func TestListenerPort(t *testing.T) {
	tests := []struct {
		listen string
		want   string
	}{
		{":443", "443"},
		{"0.0.0.0:8080", "8080"},
		{":5432", "5432"},
		{"80", "80"}, // edge case: no colon
	}

	for _, tt := range tests {
		l := Listener{Listen: tt.listen}
		if got := l.Port(); got != tt.want {
			t.Errorf("Listener{Listen: %q}.Port() = %q, want %q", tt.listen, got, tt.want)
		}
	}
}

func TestL7Listeners(t *testing.T) {
	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	l7 := cfg.L7Listeners()
	if len(l7) != 1 {
		t.Fatalf("len(L7Listeners) = %d, want 1", len(l7))
	}
	if l7[0].Name != "https" {
		t.Errorf("L7Listeners()[0].Name = %q, want %q", l7[0].Name, "https")
	}
}

// Ensure Load returns an error for a nonexistent file.
func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(os.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
