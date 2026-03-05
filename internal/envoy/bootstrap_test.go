package envoy

import (
	"strings"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

// testFlat builds a Config from listeners, computes FlatListeners, and returns the flat map.
func testFlat(listeners map[string]config.Listener) map[string]config.FlatListener {
	cfg := &config.Config{Listeners: listeners}
	return cfg.FlatListeners()
}

func mustGenerate(t *testing.T, flat map[string]config.FlatListener) *GenerateStandaloneResult {
	t.Helper()
	result, err := GenerateStandaloneConfig(flat, "127.0.0.1:10000")
	if err != nil {
		t.Fatalf("GenerateStandaloneConfig: %v", err)
	}
	return result
}

func mustParse(t *testing.T, yamlStr string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlStr), &m); err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}
	return m
}

func getListeners(t *testing.T, bootstrap map[string]interface{}) []interface{} {
	t.Helper()
	sr := bootstrap["static_resources"].(map[string]interface{})
	return sr["listeners"].([]interface{})
}

func getClusters(t *testing.T, bootstrap map[string]interface{}) []interface{} {
	t.Helper()
	sr := bootstrap["static_resources"].(map[string]interface{})
	return sr["clusters"].([]interface{})
}

// --- Test: HTTP with hostname/path routing ---

func TestHTTPWithHostnamePathRouting(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     8080,
			Protocol: "http",
			Routes: []config.Route{
				{
					Hostname: "app.example.com",
					Paths: map[string]string{
						"/api": "127.0.0.1:3000",
						"/web": "127.0.0.1:3001",
					},
				},
				{
					Backend: "127.0.0.1:4000",
				},
			},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)

	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(listeners))
	}

	l := listeners[0].(map[string]interface{})
	if l["name"] != "web" {
		t.Errorf("listener name = %v, want web", l["name"])
	}

	// Verify internal port.
	addr := l["address"].(map[string]interface{})
	sa := addr["socket_address"].(map[string]interface{})
	if sa["port_value"] != 18080 {
		t.Errorf("port_value = %v, want 18080", sa["port_value"])
	}

	// Dig into virtual hosts.
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})
	rc := tc["route_config"].(map[string]interface{})
	vhosts := rc["virtual_hosts"].([]interface{})

	if len(vhosts) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %d", len(vhosts))
	}

	// Catch-all should have domain "*" and one route.
	foundCatchAll := false
	foundHostname := false
	for _, raw := range vhosts {
		vh := raw.(map[string]interface{})
		domains := vh["domains"].([]interface{})
		routes := vh["routes"].([]interface{})

		if domains[0] == "*" {
			foundCatchAll = true
			if len(routes) != 1 {
				t.Errorf("catch-all virtual host should have 1 route, got %d", len(routes))
			}
		}
		if domains[0] == "app.example.com" {
			foundHostname = true
			if len(routes) != 2 {
				t.Errorf("hostname virtual host should have 2 routes (paths), got %d", len(routes))
			}
		}
	}

	if !foundCatchAll {
		t.Error("missing catch-all virtual host")
	}
	if !foundHostname {
		t.Error("missing app.example.com virtual host")
	}

	// Verify override.
	ov, ok := result.Overrides["web"]
	if !ok {
		t.Fatal("missing override for web listener")
	}
	if ov.Forward != "127.0.0.1:18080" {
		t.Errorf("forward = %q, want 127.0.0.1:18080", ov.Forward)
	}
}

// --- Test: HTTPS with TLS ---

func TestHTTPSWithTLS(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"secure": {
			Port:     443,
			Protocol: "https",
			TLS:      &config.TLSConfig{Cert: "/certs/tls.crt", Key: "/certs/tls.key"},
			Routes: []config.Route{
				{Backend: "127.0.0.1:8080"},
			},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})

	// Verify transport_socket exists.
	ts, ok := fc["transport_socket"].(map[string]interface{})
	if !ok {
		t.Fatal("HTTPS listener missing transport_socket")
	}
	if ts["name"] != "envoy.transport_sockets.tls" {
		t.Errorf("transport_socket name = %v", ts["name"])
	}

	tc := ts["typed_config"].(map[string]interface{})
	ctx := tc["common_tls_context"].(map[string]interface{})
	certs := ctx["tls_certificates"].([]interface{})
	cert := certs[0].(map[string]interface{})

	chain := cert["certificate_chain"].(map[string]interface{})
	if chain["filename"] != "/certs/tls.crt" {
		t.Errorf("cert filename = %v", chain["filename"])
	}
	key := cert["private_key"].(map[string]interface{})
	if key["filename"] != "/certs/tls.key" {
		t.Errorf("key filename = %v", key["filename"])
	}
}

// --- Test: HTTPS with per-hostname TLS override ---

func TestHTTPSWithPerHostnameTLSOverride(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"multi": {
			Port:     443,
			Protocol: "https",
			TLS:      &config.TLSConfig{Cert: "/certs/default.crt", Key: "/certs/default.key"},
			Routes: []config.Route{
				{
					Hostname: "api.example.com",
					TLS:      &config.TLSConfig{Cert: "/certs/api.crt", Key: "/certs/api.key"},
					Backend:  "127.0.0.1:3000",
				},
				{
					Hostname: "web.example.com",
					TLS:      &config.TLSConfig{Cert: "/certs/web.crt", Key: "/certs/web.key"},
					Backend:  "127.0.0.1:3001",
				},
				{
					Backend: "127.0.0.1:4000",
				},
			},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})

	// Should have 3 filter chains: api override, web override, default.
	if len(fcs) != 3 {
		t.Fatalf("expected 3 filter chains, got %d", len(fcs))
	}

	// First two should have filter_chain_match with server_names.
	for i := 0; i < 2; i++ {
		fc := fcs[i].(map[string]interface{})
		match, ok := fc["filter_chain_match"].(map[string]interface{})
		if !ok {
			t.Fatalf("filter chain %d missing filter_chain_match", i)
		}
		sn := match["server_names"].([]interface{})
		if len(sn) != 1 {
			t.Errorf("filter chain %d: expected 1 server_name, got %d", i, len(sn))
		}
	}

	// Last chain is the default (no filter_chain_match).
	lastFC := fcs[2].(map[string]interface{})
	if _, ok := lastFC["filter_chain_match"]; ok {
		t.Error("default filter chain should not have filter_chain_match")
	}
	// Default chain should have transport_socket with default cert.
	ts := lastFC["transport_socket"].(map[string]interface{})
	tc := ts["typed_config"].(map[string]interface{})
	ctx := tc["common_tls_context"].(map[string]interface{})
	certs := ctx["tls_certificates"].([]interface{})
	cert := certs[0].(map[string]interface{})
	chain := cert["certificate_chain"].(map[string]interface{})
	if chain["filename"] != "/certs/default.crt" {
		t.Errorf("default cert = %v, want /certs/default.crt", chain["filename"])
	}
}

// --- Test: gRPC ---

func TestGRPC(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"grpc": {
			Port:     9090,
			Protocol: "grpc",
			TLS:      &config.TLSConfig{Cert: "/certs/grpc.crt", Key: "/certs/grpc.key"},
			Routes: []config.Route{
				{Backend: "127.0.0.1:50051"},
			},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)

	if len(listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(listeners))
	}

	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})

	// gRPC terminates TLS.
	if _, ok := fc["transport_socket"]; !ok {
		t.Error("gRPC listener should have transport_socket")
	}

	// Should have HCM filter.
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	if hcm["name"] != "envoy.filters.network.http_connection_manager" {
		t.Errorf("filter name = %v, want http_connection_manager", hcm["name"])
	}

	// Verify override.
	if _, ok := result.Overrides["grpc"]; !ok {
		t.Error("missing override for grpc listener")
	}
}

// --- Test: Mixed L7 + simple (only L7 produces Envoy config) ---

func TestMixedL7AndSimple(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     8080,
			Protocol: "http",
			Routes:   []config.Route{{Backend: "127.0.0.1:3000"}},
		},
		"db": {
			Port:     5432,
			Protocol: "tcp",
			Backend:  "127.0.0.1:5432",
		},
		"dns": {
			Port:     53,
			Protocol: "udp",
			Backend:  "127.0.0.1:53",
		},
		"passthru": {
			Port:     8443,
			Protocol: "tls",
			Routes:   []config.Route{{Hostname: "a.example.com", Backend: "127.0.0.1:443"}},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)

	// Only the HTTP listener should produce an Envoy listener.
	if len(listeners) != 1 {
		t.Fatalf("expected 1 envoy listener (L7 only), got %d", len(listeners))
	}

	l := listeners[0].(map[string]interface{})
	if l["name"] != "web" {
		t.Errorf("listener name = %v, want web", l["name"])
	}

	// Only L7 listener should have an override.
	if len(result.Overrides) != 1 {
		t.Errorf("expected 1 override, got %d", len(result.Overrides))
	}
	if _, ok := result.Overrides["web"]; !ok {
		t.Error("missing override for web")
	}

	// No tcp_proxy in output.
	if strings.Contains(result.BootstrapYAML, "tcp_proxy") {
		t.Error("output should not contain tcp_proxy")
	}
}

// --- Test: Cluster deduplication ---

func TestClusterDeduplication(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"a": {
			Port:     8080,
			Protocol: "http",
			Routes: []config.Route{
				{Hostname: "x.example.com", Backend: "127.0.0.1:3000"},
				{Hostname: "y.example.com", Backend: "127.0.0.1:3000"},
			},
		},
		"b": {
			Port:     8081,
			Protocol: "http",
			Routes: []config.Route{
				{Backend: "127.0.0.1:3000"},
			},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	clusters := getClusters(t, bootstrap)

	// 1 unique backend cluster + 1 ext_authz cluster = 2.
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters (1 deduped backend + ext_authz), got %d", len(clusters))
	}

	// Verify the backend cluster name is sanitized.
	c := clusters[0].(map[string]interface{})
	if c["name"] != "127_0_0_1_3000" {
		t.Errorf("cluster name = %v, want 127_0_0_1_3000", c["name"])
	}
}

// --- Test: ext_authz context extensions ---

func TestExtAuthzContextExtensions(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"mylistener": {
			Port:     80,
			Protocol: "http",
			Routes:   []config.Route{{Backend: "127.0.0.1:8080"}},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})

	// Verify ext_authz is first HTTP filter.
	httpFilters := tc["http_filters"].([]interface{})
	authzFilter := httpFilters[0].(map[string]interface{})
	if authzFilter["name"] != "envoy.filters.http.ext_authz" {
		t.Errorf("first http_filter = %v, want ext_authz", authzFilter["name"])
	}

	// Verify per-route context_extensions.
	rc := tc["route_config"].(map[string]interface{})
	vhosts := rc["virtual_hosts"].([]interface{})
	vh := vhosts[0].(map[string]interface{})
	routes := vh["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	perFilter := route["typed_per_filter_config"].(map[string]interface{})
	authzPerRoute := perFilter["envoy.filters.http.ext_authz"].(map[string]interface{})
	checkSettings := authzPerRoute["check_settings"].(map[string]interface{})
	ctxExt := checkSettings["context_extensions"].(map[string]interface{})

	if ctxExt["listener"] != "mylistener" {
		t.Errorf("context_extensions listener = %v, want mylistener", ctxExt["listener"])
	}
}

// --- Test: ext_authz cluster has HTTP/2 ---

func TestExtAuthzClusterHTTP2(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     80,
			Protocol: "http",
			Routes:   []config.Route{{Backend: "127.0.0.1:8080"}},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	clusters := getClusters(t, bootstrap)

	var authz map[string]interface{}
	for _, raw := range clusters {
		c := raw.(map[string]interface{})
		if c["name"] == "tailvoy_ext_authz" {
			authz = c
			break
		}
	}
	if authz == nil {
		t.Fatal("tailvoy_ext_authz cluster not found")
	}

	opts := authz["typed_extension_protocol_options"].(map[string]interface{})
	httpOpts := opts["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].(map[string]interface{})
	explicit := httpOpts["explicit_http_config"].(map[string]interface{})
	if _, ok := explicit["http2_protocol_options"]; !ok {
		t.Error("ext_authz cluster missing http2_protocol_options")
	}
}

// --- Test: proxy protocol listener filter ---

func TestProxyProtocolListenerFilter(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     80,
			Protocol: "http",
			Routes:   []config.Route{{Backend: "127.0.0.1:8080"}},
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)
	l := listeners[0].(map[string]interface{})
	lf := l["listener_filters"].([]interface{})

	if len(lf) != 1 {
		t.Fatalf("expected 1 listener_filter, got %d", len(lf))
	}

	f := lf[0].(map[string]interface{})
	if f["name"] != "envoy.filters.listener.proxy_protocol" {
		t.Errorf("listener_filter name = %v, want proxy_protocol", f["name"])
	}
}

// --- Test: admin port ---

func TestAdminPort(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     80,
			Protocol: "http",
			Routes:   []config.Route{{Backend: "127.0.0.1:8080"}},
		},
	})

	result := mustGenerate(t, flat)
	if !strings.Contains(result.BootstrapYAML, "9901") {
		t.Error("output missing admin port 9901")
	}
}

// --- Test: no L7 listeners produces empty listeners list ---

func TestNoL7Listeners(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"db": {
			Port:     5432,
			Protocol: "tcp",
			Backend:  "127.0.0.1:5432",
		},
	})

	result := mustGenerate(t, flat)
	bootstrap := mustParse(t, result.BootstrapYAML)
	listeners := getListeners(t, bootstrap)

	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(listeners))
	}

	if len(result.Overrides) != 0 {
		t.Errorf("expected 0 overrides, got %d", len(result.Overrides))
	}

	// ext_authz cluster should still be present.
	clusters := getClusters(t, bootstrap)
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster (ext_authz only), got %d", len(clusters))
	}
}

// --- Test: YAML round-trip stability ---

func TestYAMLRoundTrip(t *testing.T) {
	flat := testFlat(map[string]config.Listener{
		"web": {
			Port:     443,
			Protocol: "https",
			TLS:      &config.TLSConfig{Cert: "/tls.crt", Key: "/tls.key"},
			Routes: []config.Route{
				{Hostname: "a.example.com", Backend: "127.0.0.1:3000"},
				{Backend: "127.0.0.1:4000"},
			},
		},
	})

	result := mustGenerate(t, flat)

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &parsed); err != nil {
		t.Fatalf("generated YAML is not valid: %v", err)
	}

	out2, err := yaml.Marshal(parsed)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}

	var parsed2 map[string]interface{}
	if err := yaml.Unmarshal(out2, &parsed2); err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
}

// --- Helper function tests ---

func TestEnvoyInternalPort(t *testing.T) {
	tests := []struct {
		port int
		want int
	}{
		{80, 10080},
		{443, 10443},
		{8080, 18080},
		{0, 10000},
	}
	for _, tt := range tests {
		got := envoyInternalPort(tt.port)
		if got != tt.want {
			t.Errorf("envoyInternalPort(%d) = %d, want %d", tt.port, got, tt.want)
		}
	}
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
		{"localhost", "localhost", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		host, port := splitHostPort(tt.input)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)",
				tt.input, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestPortInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"80", 80},
		{"443", 443},
		{"", 0},
		{"abc", 0},
		{"-1", 0},
	}
	for _, tt := range tests {
		got := portInt(tt.input)
		if got != tt.want {
			t.Errorf("portInt(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestClusterKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"127.0.0.1:8080", "127_0_0_1_8080"},
		{"localhost:3000", "localhost_3000"},
		{"10.0.0.1:443", "10_0_0_1_443"},
	}
	for _, tt := range tests {
		got := clusterKey(tt.input)
		if got != tt.want {
			t.Errorf("clusterKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
