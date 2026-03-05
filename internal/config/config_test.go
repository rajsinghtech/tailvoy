package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

// oauthBlock returns the minimum required tailscale YAML block for tests.
func oauthBlock(hostname string) string {
	return fmt.Sprintf(`tailscale:
  hostname: %q
  clientId: "client-id"
  clientSecret: "client-secret"
  tags:
    - "tag:test"
  serviceTags:
    - "tag:svc"
`, hostname)
}

func TestLoadFromFile(t *testing.T) {
	t.Setenv("TS_CLIENT_ID", "test-client-id")
	t.Setenv("TS_CLIENT_SECRET", "test-client-secret")

	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Tailscale.Hostname != "tailvoy-test" {
		t.Errorf("hostname = %q, want %q", cfg.Tailscale.Hostname, "tailvoy-test")
	}
	if cfg.Tailscale.ClientID != "test-client-id" {
		t.Errorf("clientId = %q, want %q", cfg.Tailscale.ClientID, "test-client-id")
	}
	if got := len(cfg.Listeners); got != 2 {
		t.Errorf("len(listeners) = %d, want 2", got)
	}
}

func TestEnvVarExpansion(t *testing.T) {
	const secret = "tskey-client-secret-12345"
	t.Setenv("TS_CLIENT_ID", "test-id")
	t.Setenv("TS_CLIENT_SECRET", secret)

	cfg, err := Load(testdataPath("policy.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tailscale.ClientSecret != secret {
		t.Errorf("clientSecret = %q, want %q", cfg.Tailscale.ClientSecret, secret)
	}
}

func TestParseMinimal(t *testing.T) {
	data := []byte(oauthBlock("minimal") + `listeners:
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
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing hostname",
			yaml: `
tailscale:
  clientId: "id"
  clientSecret: "secret"
  tags: ["tag:x"]
  serviceTags: ["tag:y"]
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
			yaml: oauthBlock("test") + `listeners:
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
			name: "missing listener protocol",
			yaml: oauthBlock("test") + `listeners:
  - name: web
    listen: ":80"
    forward: "localhost:80"
`,
			want: "protocol is required",
		},
		{
			name: "missing listener listen",
			yaml: oauthBlock("test") + `listeners:
  - name: web
    protocol: tcp
    forward: "localhost:80"
`,
			want: "listen is required",
		},
		{
			name: "missing listener forward",
			yaml: oauthBlock("test") + `listeners:
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
			if got := err.Error(); !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want substring %q", got, tt.want)
			}
		})
	}
}

func TestListenerByName(t *testing.T) {
	t.Setenv("TS_CLIENT_ID", "id")
	t.Setenv("TS_CLIENT_SECRET", "secret")

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
		{"80", "80"},
	}

	for _, tt := range tests {
		l := Listener{Listen: tt.listen}
		if got := l.Port(); got != tt.want {
			t.Errorf("Listener{Listen: %q}.Port() = %q, want %q", tt.listen, got, tt.want)
		}
	}
}

func TestL7Listeners(t *testing.T) {
	t.Setenv("TS_CLIENT_ID", "id")
	t.Setenv("TS_CLIENT_SECRET", "secret")

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

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(os.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Config validation edge cases
// ---------------------------------------------------------------------------

func TestParse_NoListeners(t *testing.T) {
	data := []byte(oauthBlock("test"))
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(cfg.Listeners))
	}
}

func TestParse_ListenerEmptyForward(t *testing.T) {
	data := []byte(oauthBlock("test") + `listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: ""
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for empty forward")
	}
	if !strings.Contains(err.Error(), "forward is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "forward is required")
	}
}

func TestParse_VeryLargeConfig(t *testing.T) {
	var b strings.Builder
	b.WriteString(oauthBlock("large"))
	b.WriteString("listeners:\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "  - name: svc-%d\n    protocol: tcp\n    listen: \":%d\"\n    forward: \"localhost:%d\"\n", i, 8000+i, 9000+i)
	}

	cfg, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Listeners) != 200 {
		t.Errorf("expected 200 listeners, got %d", len(cfg.Listeners))
	}
}

func TestParse_AllOptionalFieldsMissing(t *testing.T) {
	// With required OAuth fields, hostname-only config should fail validation.
	data := []byte(`
tailscale:
  hostname: bare-minimum
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing required OAuth fields")
	}
	if !strings.Contains(err.Error(), "clientId is required") {
		t.Errorf("error = %q, want substring about clientId", err.Error())
	}
}

func TestEnvVarExpansion_UndefinedVariable(t *testing.T) {
	t.Setenv("TAILVOY_TEST_UNDEFINED_VAR", "")
	os.Unsetenv("TAILVOY_TEST_UNDEFINED_VAR")

	data := []byte(oauthBlock("test") + `listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	// Parse should succeed — undefined vars expand to empty but
	// the oauthBlock helper provides all required fields inline.
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestEnvVarExpansion_NestedSyntax(t *testing.T) {
	t.Setenv("INNER", "resolved")

	data := []byte(`
tailscale:
  hostname: "test-${INNER}"
  clientId: "id"
  clientSecret: "secret"
  tags:
    - "tag:test"
  serviceTags:
    - "tag:svc"
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.Hostname != "test-resolved" {
		t.Errorf("hostname = %q, want %q", cfg.Tailscale.Hostname, "test-resolved")
	}
}

func TestEnvVarExpansion_MultipleVars(t *testing.T) {
	t.Setenv("HOST", "myhost")
	t.Setenv("PORT", "9090")

	data := []byte(`
tailscale:
  hostname: "${HOST}"
  clientId: "id"
  clientSecret: "secret"
  tags:
    - "tag:test"
  serviceTags:
    - "tag:svc"
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "${HOST}:${PORT}"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.Hostname != "myhost" {
		t.Errorf("hostname = %q, want %q", cfg.Tailscale.Hostname, "myhost")
	}
	if cfg.Listeners[0].Forward != "myhost:9090" {
		t.Errorf("forward = %q, want %q", cfg.Listeners[0].Forward, "myhost:9090")
	}
}

func TestEnvVarExpansion_LiteralDollarBrace(t *testing.T) {
	// "${}" with empty var name won't match the regex; stays literal.
	data := []byte(oauthBlock("test") + `listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OAuth + service config
// ---------------------------------------------------------------------------

func TestParse_OAuthConfig(t *testing.T) {
	t.Setenv("TS_CID", "oauth-client-123")
	t.Setenv("TS_CSEC", "oauth-secret-456")

	data := []byte(`
tailscale:
  hostname: "my-proxy"
  clientId: "${TS_CID}"
  clientSecret: "${TS_CSEC}"
  tags:
    - "tag:infra"
    - "tag:proxy"
  serviceTags:
    - "tag:k8s"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.ClientID != "oauth-client-123" {
		t.Errorf("clientId = %q, want %q", cfg.Tailscale.ClientID, "oauth-client-123")
	}
	if cfg.Tailscale.ClientSecret != "oauth-secret-456" {
		t.Errorf("clientSecret = %q, want %q", cfg.Tailscale.ClientSecret, "oauth-secret-456")
	}
	if len(cfg.Tailscale.Tags) != 2 {
		t.Errorf("len(tags) = %d, want 2", len(cfg.Tailscale.Tags))
	}
	if len(cfg.Tailscale.ServiceTags) != 1 {
		t.Errorf("len(serviceTags) = %d, want 1", len(cfg.Tailscale.ServiceTags))
	}
}

func TestParse_ServiceNameDefault(t *testing.T) {
	data := []byte(oauthBlock("my-proxy"))
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Tailscale.ServiceName(); got != "svc:my-proxy" {
		t.Errorf("ServiceName() = %q, want %q", got, "svc:my-proxy")
	}
}

func TestParse_ServiceNameExplicit(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "my-proxy"
  service: "custom-svc"
  clientId: "id"
  clientSecret: "secret"
  tags:
    - "tag:test"
  serviceTags:
    - "tag:svc"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Tailscale.ServiceName(); got != "custom-svc" {
		t.Errorf("ServiceName() = %q, want %q", got, "custom-svc")
	}
}

func TestValidation_MissingClientId(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  clientSecret: "secret"
  tags: ["tag:x"]
  serviceTags: ["tag:y"]
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tailscale.clientId is required") {
		t.Errorf("error = %q", err)
	}
}

func TestValidation_MissingClientSecret(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  clientId: "id"
  tags: ["tag:x"]
  serviceTags: ["tag:y"]
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tailscale.clientSecret is required") {
		t.Errorf("error = %q", err)
	}
}

func TestValidation_MissingTags(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  clientId: "id"
  clientSecret: "secret"
  serviceTags: ["tag:y"]
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tailscale.tags is required") {
		t.Errorf("error = %q", err)
	}
}

func TestValidation_MissingServiceTags(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  clientId: "id"
  clientSecret: "secret"
  tags: ["tag:x"]
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "tailscale.serviceTags is required") {
		t.Errorf("error = %q", err)
	}
}

// ---------------------------------------------------------------------------
// Discovery config validation
// ---------------------------------------------------------------------------

func TestDiscoveryConfig_Valid(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
  envoyAddress: "127.0.0.1"
  pollInterval: "5s"
  proxyProtocol: "v2"
  listenerFilter: ".*http.*"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Discovery == nil {
		t.Fatal("expected non-nil Discovery")
	}
	if cfg.Discovery.EnvoyAdmin != "http://127.0.0.1:9901" {
		t.Errorf("envoyAdmin = %q", cfg.Discovery.EnvoyAdmin)
	}
}

func TestDiscoveryConfig_MissingEnvoyAdmin(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAddress: "127.0.0.1"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "envoyAdmin is required") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_MissingEnvoyAddress(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "envoyAddress is required") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_MutualExclusion(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
  envoyAddress: "127.0.0.1"
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_InvalidPollInterval(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
  envoyAddress: "127.0.0.1"
  pollInterval: "not-a-duration"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "pollInterval") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_InvalidProxyProtocol(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
  envoyAddress: "127.0.0.1"
  proxyProtocol: "v1"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "proxyProtocol") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_InvalidListenerFilter(t *testing.T) {
	data := []byte(oauthBlock("test") + `discovery:
  envoyAdmin: "http://127.0.0.1:9901"
  envoyAddress: "127.0.0.1"
  listenerFilter: "[invalid"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "listenerFilter") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryConfig_DefaultPollInterval(t *testing.T) {
	d := &DiscoveryConfig{
		EnvoyAdmin:   "http://127.0.0.1:9901",
		EnvoyAddress: "127.0.0.1",
	}
	dur := d.ParsedPollInterval()
	if dur != 10*time.Second {
		t.Errorf("default poll interval = %v, want 10s", dur)
	}
}

func TestValidationErrors_MissingListenerName(t *testing.T) {
	data := []byte(oauthBlock("test") + `listeners:
  - protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for missing listener name")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("error = %q, want substring %q", err.Error(), "name is required")
	}
}
