package envoy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

// --- GenerateStandaloneConfig tests ---

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

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
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
		if !strings.Contains(result.BootstrapYAML, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Verify admin is present
	if !strings.Contains(result.BootstrapYAML, "9901") {
		t.Error("output missing admin port 9901")
	}

	// Verify overrides for L7 listener
	if ov, ok := result.Overrides["web"]; !ok {
		t.Error("missing override for L7 listener 'web'")
	} else {
		if ov.ProxyProtocol != "v2" {
			t.Errorf("override proxy_protocol = %q, want v2", ov.ProxyProtocol)
		}
	}
	// L4 listener should not have an override
	if _, ok := result.Overrides["db"]; ok {
		t.Error("L4 listener 'db' should not have an override")
	}

	t.Logf("Generated config:\n%s", result.BootstrapYAML)
}

func TestGenerateStandaloneConfigOnlyL7(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "api", Protocol: "tcp", Listen: ":443", Forward: "127.0.0.1:8443", L7Policy: true},
			{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:80", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatalf("generated YAML is not parseable: %v", err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}

	// Verify internal ports are port+10000
	for _, raw := range listeners {
		l := raw.(map[string]interface{})
		addr := l["address"].(map[string]interface{})
		sa := addr["socket_address"].(map[string]interface{})
		port := sa["port_value"].(int)
		name := l["name"].(string)

		var expectedPort int
		switch name {
		case "api":
			expectedPort = 10443
		case "web":
			expectedPort = 18080
		default:
			t.Fatalf("unexpected listener name %q", name)
		}

		if port != expectedPort {
			t.Errorf("listener %q: port_value = %d, want %d", name, port, expectedPort)
		}

		// L7 listeners should bind to 127.0.0.1 since tailvoy forwards to them
		if sa["address"] != "127.0.0.1" {
			t.Errorf("listener %q: address = %v, want 127.0.0.1", name, sa["address"])
		}

		// L7 listeners must have proxy_protocol listener filter
		lf, ok := l["listener_filters"].([]interface{})
		if !ok || len(lf) == 0 {
			t.Errorf("listener %q: missing proxy_protocol listener_filter", name)
		}
	}

	// No tcp_proxy should be present
	if strings.Contains(result.BootstrapYAML, "tcp_proxy") {
		t.Error("L7-only config should not contain tcp_proxy")
	}
}

func TestGenerateStandaloneConfigOnlyL4(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "pg", Protocol: "tcp", Listen: ":5432", Forward: "127.0.0.1:5432", L7Policy: false},
			{Name: "redis", Protocol: "tcp", Listen: ":6379", Forward: "127.0.0.1:6379", L7Policy: false},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatalf("generated YAML not parseable: %v", err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})

	for _, raw := range listeners {
		l := raw.(map[string]interface{})
		addr := l["address"].(map[string]interface{})
		sa := addr["socket_address"].(map[string]interface{})
		port := sa["port_value"].(int)
		name := l["name"].(string)

		// L4 listeners use the actual port, not port+10000
		var expectedPort int
		switch name {
		case "pg":
			expectedPort = 5432
		case "redis":
			expectedPort = 6379
		default:
			t.Fatalf("unexpected listener name %q", name)
		}
		if port != expectedPort {
			t.Errorf("listener %q: port_value = %d, want %d", name, port, expectedPort)
		}

		// L4 listeners should bind to 0.0.0.0
		if sa["address"] != "0.0.0.0" {
			t.Errorf("listener %q: address = %v, want 0.0.0.0", name, sa["address"])
		}

		// L4 listeners must NOT have proxy_protocol listener_filter
		if _, ok := l["listener_filters"]; ok {
			t.Errorf("listener %q: L4 listener should not have listener_filters", name)
		}
	}

	// No http_connection_manager or proxy_protocol should be present
	if strings.Contains(result.BootstrapYAML, "http_connection_manager") {
		t.Error("L4-only config should not contain http_connection_manager")
	}
	if strings.Contains(result.BootstrapYAML, "proxy_protocol") {
		t.Error("L4-only config should not contain proxy_protocol")
	}
}

func TestGenerateStandaloneConfigMixed(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":443", Forward: "127.0.0.1:8443", L7Policy: true},
			{Name: "db", Protocol: "tcp", Listen: ":5432", Forward: "127.0.0.1:5432", L7Policy: false},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatalf("YAML not parseable: %v", err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}

	// Both http_connection_manager and tcp_proxy should be present
	if !strings.Contains(result.BootstrapYAML, "http_connection_manager") {
		t.Error("missing http_connection_manager")
	}
	if !strings.Contains(result.BootstrapYAML, "tcp_proxy") {
		t.Error("missing tcp_proxy")
	}
}

func TestGenerateStandaloneConfigManyListeners(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "l1", Protocol: "tcp", Listen: ":8001", Forward: "127.0.0.1:9001", L7Policy: true},
			{Name: "l2", Protocol: "tcp", Listen: ":8002", Forward: "127.0.0.1:9002", L7Policy: false},
			{Name: "l3", Protocol: "tcp", Listen: ":8003", Forward: "127.0.0.1:9003", L7Policy: true},
			{Name: "l4", Protocol: "tcp", Listen: ":8004", Forward: "127.0.0.1:9004", L7Policy: false},
			{Name: "l5", Protocol: "tcp", Listen: ":8005", Forward: "127.0.0.1:9005", L7Policy: true},
			{Name: "l6", Protocol: "tcp", Listen: ":8006", Forward: "127.0.0.1:9006", L7Policy: false},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatalf("YAML not parseable: %v", err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	if len(listeners) != 6 {
		t.Fatalf("expected 6 listeners, got %d", len(listeners))
	}

	// 6 backend clusters + 1 ext_authz cluster = 7 total
	clusters := sr["clusters"].([]interface{})
	if len(clusters) != 7 {
		t.Fatalf("expected 7 clusters (6 backends + ext_authz), got %d", len(clusters))
	}

	// Verify each listener has a corresponding backend cluster
	for i := 1; i <= 6; i++ {
		wantCluster := "l" + string(rune('0'+i)) + "_backend"
		if !strings.Contains(result.BootstrapYAML, wantCluster) {
			t.Errorf("missing backend cluster %q", wantCluster)
		}
	}
}

func TestGenerateStandaloneConfigExtAuthzCluster(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":80", Forward: "127.0.0.1:8080", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "10.0.0.5:9999")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	clusters := sr["clusters"].([]interface{})

	// Find the ext_authz cluster
	var authzCluster map[string]interface{}
	for _, raw := range clusters {
		c := raw.(map[string]interface{})
		if c["name"] == "tailvoy_ext_authz" {
			authzCluster = c
			break
		}
	}
	if authzCluster == nil {
		t.Fatal("tailvoy_ext_authz cluster not found")
	}

	// Verify the cluster points to the correct address
	la := authzCluster["load_assignment"].(map[string]interface{})
	eps := la["endpoints"].([]interface{})
	lbEps := eps[0].(map[string]interface{})["lb_endpoints"].([]interface{})
	ep := lbEps[0].(map[string]interface{})["endpoint"].(map[string]interface{})
	sa := ep["address"].(map[string]interface{})["socket_address"].(map[string]interface{})

	if sa["address"] != "10.0.0.5" {
		t.Errorf("ext_authz host = %v, want 10.0.0.5", sa["address"])
	}
	if sa["port_value"] != 9999 {
		t.Errorf("ext_authz port = %v, want 9999", sa["port_value"])
	}
}

func TestGenerateStandaloneConfigHTTPListenerHasProxyProtocol(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":80", Forward: "127.0.0.1:8080", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})

	lf := l["listener_filters"].([]interface{})
	if len(lf) != 1 {
		t.Fatalf("expected 1 listener_filter, got %d", len(lf))
	}

	f := lf[0].(map[string]interface{})
	if f["name"] != "envoy.filters.listener.proxy_protocol" {
		t.Errorf("listener_filter name = %v, want envoy.filters.listener.proxy_protocol", f["name"])
	}
}

func TestGenerateStandaloneConfigHTTPListenerHasExtAuthzGRPCFilter(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "mylistener", Protocol: "tcp", Listen: ":80", Forward: "127.0.0.1:8080", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})

	if hcm["name"] != "envoy.filters.network.http_connection_manager" {
		t.Fatal("first filter is not http_connection_manager")
	}

	tc := hcm["typed_config"].(map[string]interface{})
	httpFilters := tc["http_filters"].([]interface{})

	// ext_authz should be the first HTTP filter (before router)
	if len(httpFilters) < 2 {
		t.Fatalf("expected at least 2 http_filters, got %d", len(httpFilters))
	}

	authzFilter := httpFilters[0].(map[string]interface{})
	if authzFilter["name"] != "envoy.filters.http.ext_authz" {
		t.Errorf("first http_filter = %v, want envoy.filters.http.ext_authz", authzFilter["name"])
	}

	// Verify it uses grpc_service (not http_service)
	authzTC := authzFilter["typed_config"].(map[string]interface{})
	if _, ok := authzTC["grpc_service"]; !ok {
		t.Error("ext_authz filter should use grpc_service")
	}
	if _, ok := authzTC["http_service"]; ok {
		t.Error("ext_authz filter should not have http_service")
	}

	// Verify grpc_service points to the correct cluster
	grpcSvc := authzTC["grpc_service"].(map[string]interface{})
	envoyGrpc := grpcSvc["envoy_grpc"].(map[string]interface{})
	if envoyGrpc["cluster_name"] != "tailvoy_ext_authz" {
		t.Errorf("cluster_name = %v, want tailvoy_ext_authz", envoyGrpc["cluster_name"])
	}

	// Verify transport_api_version is V3
	if authzTC["transport_api_version"] != "V3" {
		t.Errorf("transport_api_version = %v, want V3", authzTC["transport_api_version"])
	}

	// Verify per-route context_extensions with listener name
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

	// Second filter should be the router
	routerFilter := httpFilters[1].(map[string]interface{})
	if routerFilter["name"] != "envoy.filters.http.router" {
		t.Errorf("second http_filter = %v, want envoy.filters.http.router", routerFilter["name"])
	}
}

func TestGenerateStandaloneConfigExtAuthzClusterHasHTTP2(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":80", Forward: "127.0.0.1:8080", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	clusters := sr["clusters"].([]interface{})

	var authzCluster map[string]interface{}
	for _, raw := range clusters {
		c := raw.(map[string]interface{})
		if c["name"] == "tailvoy_ext_authz" {
			authzCluster = c
			break
		}
	}
	if authzCluster == nil {
		t.Fatal("tailvoy_ext_authz cluster not found")
	}

	// Verify HTTP/2 protocol options are present (required for gRPC)
	opts, ok := authzCluster["typed_extension_protocol_options"].(map[string]interface{})
	if !ok {
		t.Fatal("ext_authz cluster missing typed_extension_protocol_options")
	}

	httpOpts, ok := opts["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].(map[string]interface{})
	if !ok {
		t.Fatal("missing HttpProtocolOptions in typed_extension_protocol_options")
	}

	explicitCfg, ok := httpOpts["explicit_http_config"].(map[string]interface{})
	if !ok {
		t.Fatal("missing explicit_http_config")
	}

	if _, ok := explicitCfg["http2_protocol_options"]; !ok {
		t.Error("missing http2_protocol_options in explicit_http_config")
	}
}

func TestGenerateStandaloneConfigYAMLRoundTrip(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "web", Protocol: "tcp", Listen: ":443", Forward: "127.0.0.1:8443", L7Policy: true},
			{Name: "db", Protocol: "tcp", Listen: ":5432", Forward: "127.0.0.1:5432", L7Policy: false},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	// Verify generated YAML can be round-tripped
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &parsed); err != nil {
		t.Fatalf("generated YAML is not valid: %v", err)
	}

	// Re-marshal and re-parse to verify stability
	out2, err := yaml.Marshal(parsed)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}

	var parsed2 map[string]interface{}
	if err := yaml.Unmarshal(out2, &parsed2); err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
}

func TestGenerateStandaloneConfigPort0(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{
			{Name: "ephemeral", Protocol: "tcp", Listen: ":0", Forward: "127.0.0.1:8080", L7Policy: true},
		},
		Default: "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	addr := l["address"].(map[string]interface{})
	sa := addr["socket_address"].(map[string]interface{})

	// port 0 + 10000 = 10000
	if sa["port_value"] != 10000 {
		t.Errorf("port_value = %v, want 10000 (0 + 10000)", sa["port_value"])
	}
}

func TestGenerateStandaloneConfigNoListeners(t *testing.T) {
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{Hostname: "test"},
		Listeners: []config.Listener{},
		Default:   "deny",
	}

	result, err := GenerateStandaloneConfig(cfg, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.BootstrapYAML), &bootstrap); err != nil {
		t.Fatalf("YAML not parseable: %v", err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	if len(listeners) != 0 {
		t.Errorf("expected 0 listeners, got %d", len(listeners))
	}

	// Should still have the ext_authz cluster
	clusters := sr["clusters"].([]interface{})
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster (ext_authz), got %d", len(clusters))
	}
}

// --- InjectExtAuthz tests ---

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

func TestInjectExtAuthzMultipleHTTPListeners(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: listener_a
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: a
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: listener_b
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: b
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})

	for _, raw := range listeners {
		l := raw.(map[string]interface{})
		name := l["name"].(string)
		fcs := l["filter_chains"].([]interface{})
		fc := fcs[0].(map[string]interface{})
		filters := fc["filters"].([]interface{})
		hcm := filters[0].(map[string]interface{})
		tc := hcm["typed_config"].(map[string]interface{})
		httpFilters := tc["http_filters"].([]interface{})

		if len(httpFilters) < 2 {
			t.Errorf("listener %q: expected at least 2 http_filters, got %d", name, len(httpFilters))
			continue
		}

		first := httpFilters[0].(map[string]interface{})
		if first["name"] != "envoy.filters.http.ext_authz" {
			t.Errorf("listener %q: first filter = %v, want ext_authz", name, first["name"])
		}
	}
}

func TestInjectExtAuthzMixedHTTPAndTCP(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: http_listener
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    - name: tcp_listener
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: tcp
                cluster: backend
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})

	for _, raw := range listeners {
		l := raw.(map[string]interface{})
		name := l["name"].(string)
		fcs := l["filter_chains"].([]interface{})
		fc := fcs[0].(map[string]interface{})
		filters := fc["filters"].([]interface{})
		f := filters[0].(map[string]interface{})

		switch name {
		case "http_listener":
			// HTTP listener should get ext_authz injected
			tc := f["typed_config"].(map[string]interface{})
			httpFilters := tc["http_filters"].([]interface{})
			first := httpFilters[0].(map[string]interface{})
			if first["name"] != "envoy.filters.http.ext_authz" {
				t.Errorf("HTTP listener: first filter = %v, want ext_authz", first["name"])
			}
		case "tcp_listener":
			// TCP listener should NOT get ext_authz
			if f["name"] != "envoy.filters.network.tcp_proxy" {
				t.Errorf("TCP listener: filter = %v, want tcp_proxy", f["name"])
			}
			tc := f["typed_config"].(map[string]interface{})
			if _, ok := tc["http_filters"]; ok {
				t.Error("TCP listener should not have http_filters")
			}
		}
	}
}

func TestInjectExtAuthzNoListeners(t *testing.T) {
	input := `
static_resources:
  listeners: []
  clusters: []
`
	// Empty listeners list is valid YAML; InjectExtAuthz just has nothing to inject into.
	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	// ext_authz cluster should still be added
	sr := bootstrap["static_resources"].(map[string]interface{})
	clusters := sr["clusters"].([]interface{})
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster (ext_authz), got %d", len(clusters))
	}
	c := clusters[0].(map[string]interface{})
	if c["name"] != "tailvoy_ext_authz" {
		t.Errorf("cluster name = %v, want tailvoy_ext_authz", c["name"])
	}
}

func TestInjectExtAuthzInvalidYAML(t *testing.T) {
	_, err := InjectExtAuthz("{{invalid yaml!!", "127.0.0.1:10000")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestInjectExtAuthzNoStaticResources(t *testing.T) {
	input := `
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
`
	_, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err == nil {
		t.Fatal("expected error for missing static_resources")
	}
	if !strings.Contains(err.Error(), "static_resources") {
		t.Errorf("error should mention static_resources, got: %v", err)
	}
}

func TestInjectExtAuthzClusterAdded(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: test
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: envoy.filters.http.router
  clusters:
    - name: existing_cluster
      connect_timeout: 5s
`

	out, err := InjectExtAuthz(input, "10.0.0.1:5555")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	clusters := sr["clusters"].([]interface{})

	// Should have the original cluster + the ext_authz cluster
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}

	last := clusters[len(clusters)-1].(map[string]interface{})
	if last["name"] != "tailvoy_ext_authz" {
		t.Errorf("last cluster name = %v, want tailvoy_ext_authz", last["name"])
	}
}

func TestInjectExtAuthzPrependedBeforeRouter(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: test
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: envoy.filters.http.cors
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})
	httpFilters := tc["http_filters"].([]interface{})

	// Should have: ext_authz, cors, router (3 total)
	if len(httpFilters) != 3 {
		t.Fatalf("expected 3 http_filters, got %d", len(httpFilters))
	}

	names := make([]string, len(httpFilters))
	for i, raw := range httpFilters {
		f := raw.(map[string]interface{})
		names[i] = f["name"].(string)
	}

	want := []string{
		"envoy.filters.http.ext_authz",
		"envoy.filters.http.cors",
		"envoy.filters.http.router",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("http_filter order = %v, want %v", names, want)
	}
}

func TestInjectExtAuthzListenerNameInContextExtensions(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: my_custom_listener
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                route_config:
                  virtual_hosts:
                    - name: default
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: /
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})
	rc := tc["route_config"].(map[string]interface{})
	vhosts := rc["virtual_hosts"].([]interface{})
	vh := vhosts[0].(map[string]interface{})
	routes := vh["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	perFilter := route["typed_per_filter_config"].(map[string]interface{})
	authzPerRoute := perFilter["envoy.filters.http.ext_authz"].(map[string]interface{})
	checkSettings := authzPerRoute["check_settings"].(map[string]interface{})
	ctxExt := checkSettings["context_extensions"].(map[string]interface{})

	if ctxExt["listener"] != "my_custom_listener" {
		t.Errorf("context_extensions listener = %v, want my_custom_listener", ctxExt["listener"])
	}
}

func TestInjectExtAuthzDefaultListenerName(t *testing.T) {
	// Listener without a name should use "default" in context_extensions
	input := `
static_resources:
  listeners:
    - filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                route_config:
                  virtual_hosts:
                    - name: default
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: /
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
  clusters: []
`

	out, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &bootstrap); err != nil {
		t.Fatal(err)
	}

	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})
	rc := tc["route_config"].(map[string]interface{})
	vhosts := rc["virtual_hosts"].([]interface{})
	vh := vhosts[0].(map[string]interface{})
	routes := vh["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	perFilter := route["typed_per_filter_config"].(map[string]interface{})
	authzPerRoute := perFilter["envoy.filters.http.ext_authz"].(map[string]interface{})
	checkSettings := authzPerRoute["check_settings"].(map[string]interface{})
	ctxExt := checkSettings["context_extensions"].(map[string]interface{})

	if ctxExt["listener"] != "default" {
		t.Errorf("unnamed listener context_extensions listener = %v, want default", ctxExt["listener"])
	}
}

func TestInjectExtAuthzIdempotencyNoCrash(t *testing.T) {
	input := `
static_resources:
  listeners:
    - name: test
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: envoy.filters.http.router
  clusters: []
`

	// First injection
	out1, err := InjectExtAuthz(input, "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	// Second injection into already-injected config
	out2, err := InjectExtAuthz(out1, "127.0.0.1:10000")
	if err != nil {
		t.Fatalf("second injection should not crash: %v", err)
	}

	// Verify it's still valid YAML
	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(out2), &bootstrap); err != nil {
		t.Fatalf("double-injected YAML not parseable: %v", err)
	}

	// It will have duplicate ext_authz filters, but it shouldn't crash
	sr := bootstrap["static_resources"].(map[string]interface{})
	listeners := sr["listeners"].([]interface{})
	l := listeners[0].(map[string]interface{})
	fcs := l["filter_chains"].([]interface{})
	fc := fcs[0].(map[string]interface{})
	filters := fc["filters"].([]interface{})
	hcm := filters[0].(map[string]interface{})
	tc := hcm["typed_config"].(map[string]interface{})
	httpFilters := tc["http_filters"].([]interface{})

	// Should have: ext_authz, ext_authz, router (3 total after double injection)
	if len(httpFilters) != 3 {
		t.Errorf("expected 3 http_filters after double injection, got %d", len(httpFilters))
	}
}

// --- EnvoyInternalPort tests ---

func TestEnvoyInternalPort(t *testing.T) {
	tests := []struct {
		port string
		want int
	}{
		{"80", 10080},
		{"443", 10443},
		{"8080", 18080},
		{"8443", 18443},
		{"3000", 13000},
		{"0", 10000},
		{"1", 10001},
		{"65535", 75535},
	}

	for _, tt := range tests {
		got := envoyInternalPort(tt.port)
		if got != tt.want {
			t.Errorf("envoyInternalPort(%q) = %d, want %d", tt.port, got, tt.want)
		}
	}
}

// --- ParseArgs additional edge cases ---

func TestParseArgsAdditional(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantTV    []string
		wantEnvoy []string
	}{
		{
			name:      "multiple separators uses first",
			input:     []string{"-a", "--", "-b", "--", "-c"},
			wantTV:    []string{"-a"},
			wantEnvoy: []string{"-b", "--", "-c"},
		},
		{
			name:      "nil input",
			input:     nil,
			wantTV:    nil,
			wantEnvoy: nil,
		},
		{
			name:      "separator at end",
			input:     []string{"-a", "-b", "--"},
			wantTV:    []string{"-a", "-b"},
			wantEnvoy: []string{},
		},
		{
			name:      "single arg no separator",
			input:     []string{"--config"},
			wantTV:    []string{"--config"},
			wantEnvoy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTV, gotEnvoy := ParseArgs(tt.input)
			if !reflect.DeepEqual(gotTV, tt.wantTV) {
				t.Errorf("tailvoyArgs = %v, want %v", gotTV, tt.wantTV)
			}
			if !reflect.DeepEqual(gotEnvoy, tt.wantEnvoy) {
				t.Errorf("envoyArgs = %v, want %v", gotEnvoy, tt.wantEnvoy)
			}
		})
	}
}

// --- Helper function tests ---

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
		// IPv6 without brackets (fallback finds last colon at index 1)
		{"::1", ":", "1"},
		// No port
		{"localhost", "localhost", ""},
		// Empty string
		{"", "", ""},
		// IPv6 with brackets and port
		{"[2001:db8::1]:8080", "2001:db8::1", "8080"},
		// Host with high port
		{"10.0.0.1:65535", "10.0.0.1", "65535"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := splitHostPort(tt.input)
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)",
					tt.input, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestPortInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"80", 80},
		{"443", 443},
		{"8080", 8080},
		{"0", 0},
		{"65535", 65535},
		// Empty string returns 0
		{"", 0},
		// Non-numeric returns 0
		{"abc", 0},
		// Leading zeros are treated as decimal
		{"0080", 80},
		// Negative-looking string returns 0 (the '-' is not 0-9)
		{"-1", 0},
		// Very large number (no overflow protection in portInt, just computes)
		{"99999", 99999},
		// Mixed content returns 0 at first non-digit
		{"80abc", 0},
		// Whitespace returns 0
		{" 80", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := portInt(tt.input)
			if got != tt.want {
				t.Errorf("portInt(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
