package envoy

import (
	"strings"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

func TestGenerateStandaloneConfig(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{
				Name:     "web",
				Protocol: "tcp",
				Listen:   ":8080",
				Forward:  "127.0.0.1:80",
				L7Policy: true,
			},
			{
				Name:     "db",
				Protocol: "tcp",
				Listen:   ":5432",
				Forward:  "127.0.0.1:5432",
				L7Policy: false,
			},
		},
		Default: "deny",
	}

	out, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatalf("GenerateStandaloneConfig: %v", err)
	}

	for _, want := range []string{
		"ext_authz",
		"tailvoy_ext_authz",
		"web_backend",
		"db_backend",
		"proxy_protocol",
		"http_connection_manager",
		"tcp_proxy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Verify admin is present
	if !strings.Contains(out, "9901") {
		t.Error("output missing admin port 9901")
	}

	t.Logf("Generated config:\n%s", out)
}

func TestInjectExtAuthz(t *testing.T) {
	// Minimal bootstrap with a single HCM listener and a router filter.
	input := `
static_resources:
  listeners:
    - name: test_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatalf("InjectExtAuthz: %v", err)
	}

	if !strings.Contains(out, "ext_authz") {
		t.Error("output missing ext_authz filter")
	}

	// ext_authz should appear before router
	authzIdx := strings.Index(out, "ext_authz")
	routerIdx := strings.Index(out, "envoy.filters.http.router")
	if authzIdx >= routerIdx {
		t.Error("ext_authz should appear before router filter in output")
	}

	t.Logf("Injected config:\n%s", out)
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"127.0.0.1:8080", "127.0.0.1", "8080"},
		{":9901", "", "9901"},
		{"[::1]:443", "::1", "443"},
		{"localhost:80", "localhost", "80"},
	}
	for _, tt := range tests {
		host, port := splitHostPort(tt.input)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)",
				tt.input, host, port, tt.wantHost, tt.wantPort)
		}
	}
}
