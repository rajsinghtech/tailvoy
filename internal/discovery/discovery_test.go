package discovery

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

const sampleConfigDump = `{
  "configs": [
    {
      "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
      "dynamic_listeners": [
        {
          "name": "default/http-gateway/http",
          "active_state": {
            "listener": {
              "name": "default/http-gateway/http",
              "address": {
                "socket_address": {
                  "address": "0.0.0.0",
                  "port_value": 8080
                }
              },
              "filter_chains": [
                {
                  "filters": [
                    {
                      "name": "envoy.filters.network.http_connection_manager"
                    }
                  ]
                }
              ]
            }
          }
        },
        {
          "name": "default/tcp-gateway/tcp",
          "active_state": {
            "listener": {
              "name": "default/tcp-gateway/tcp",
              "address": {
                "socket_address": {
                  "address": "0.0.0.0",
                  "port_value": 8443
                }
              },
              "filter_chains": [
                {
                  "filters": [
                    {
                      "name": "envoy.filters.network.tcp_proxy"
                    }
                  ]
                }
              ]
            }
          }
        },
        {
          "name": "warming-only",
          "active_state": null
        }
      ]
    }
  ]
}`

func TestDiscover_ParsesListeners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(listeners) != 2 {
		t.Fatalf("got %d listeners, want 2", len(listeners))
	}

	// Sorted by name: http first, then tcp.
	httpL := listeners[0]
	if httpL.Name != "default/http-gateway/http" {
		t.Errorf("name = %q", httpL.Name)
	}
	if httpL.Port != 8080 {
		t.Errorf("port = %d, want 8080", httpL.Port)
	}
	if httpL.Forward != "127.0.0.1:8080" {
		t.Errorf("forward = %q", httpL.Forward)
	}
	if !httpL.IsL7 {
		t.Error("expected IsL7=true for HTTP listener")
	}
	if httpL.Protocol != "http" {
		t.Errorf("protocol = %q, want http", httpL.Protocol)
	}

	tcpL := listeners[1]
	if tcpL.Name != "default/tcp-gateway/tcp" {
		t.Errorf("name = %q", tcpL.Name)
	}
	if tcpL.IsL7 {
		t.Error("expected IsL7=false for TCP listener")
	}
}

func TestDiscover_FilterRegex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:     srv.URL,
		EnvoyAddress:   "127.0.0.1",
		ListenerFilter: ".*http.*",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1 (filtered)", len(listeners))
	}
	if listeners[0].Name != "default/http-gateway/http" {
		t.Errorf("name = %q", listeners[0].Name)
	}
}

func TestDiscover_ProxyProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:    srv.URL,
		EnvoyAddress:  "127.0.0.1",
		ProxyProtocol: "v2",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, l := range listeners {
		if !l.ProxyProtocol {
			t.Errorf("listener %s proxy_protocol = false, want true", l.Name)
		}
	}
}

func TestDiscover_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestDiscover_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{broken`))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDiscover_EmptyDynamicListeners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"configs":[{"dynamic_listeners":[]}]}`))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 0 {
		t.Errorf("got %d listeners, want 0", len(listeners))
	}
}

func TestWatch_SendsOnChange(t *testing.T) {
	call := 0
	configResponses := []string{
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}}]}]}`,
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}}]}]}`,
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}},{"name":"b","active_state":{"listener":{"name":"b","address":{"socket_address":{"address":"0.0.0.0","port_value":9090}},"filter_chains":[]}}}]}]}`,
	}
	clusterResp := `{"cluster_statuses":[]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/clusters") {
			w.Write([]byte(clusterResp))
			return
		}
		idx := call
		if idx >= len(configResponses) {
			idx = len(configResponses) - 1
		}
		call++
		w.Write([]byte(configResponses[idx]))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
		PollInterval: "50ms",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := d.Watch(ctx)

	select {
	case result := <-ch:
		if len(result.Listeners) != 1 {
			t.Fatalf("initial: got %d listeners, want 1", len(result.Listeners))
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for initial discovery")
	}

	select {
	case result := <-ch:
		if len(result.Listeners) != 2 {
			t.Fatalf("update: got %d listeners, want 2", len(result.Listeners))
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("timeout waiting for change notification")
	}
}

func TestDiscover_FullConfigDumpWithOtherEntries(t *testing.T) {
	fullDump := `{
		"configs": [
			{"@type": "type.googleapis.com/envoy.admin.v3.BootstrapConfigDump"},
			{"@type": "type.googleapis.com/envoy.admin.v3.ClustersConfigDump", "dynamic_active_clusters": []},
			{"@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump", "dynamic_listeners": [
				{"name": "default/eg/http", "active_state": {"listener": {"name": "default/eg/http", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}}, "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager"}]}]}}}
			]},
			{"@type": "type.googleapis.com/envoy.admin.v3.RoutesConfigDump"}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fullDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1", len(listeners))
	}
	if listeners[0].Name != "default/eg/http" {
		t.Errorf("name = %q", listeners[0].Name)
	}
}

func TestFlatListenersEqual(t *testing.T) {
	a := []config.FlatListener{{Name: "x", Port: 80}}
	b := []config.FlatListener{{Name: "x", Port: 80}}
	if !flatListenersEqual(a, b) {
		t.Error("expected equal")
	}

	c := []config.FlatListener{{Name: "x", Port: 81}}
	if flatListenersEqual(a, c) {
		t.Error("expected not equal")
	}

	if flatListenersEqual(a, nil) {
		t.Error("expected not equal for nil")
	}
}

func TestParseClusterHealth(t *testing.T) {
	body := `{
		"cluster_statuses": [
			{
				"name": "cluster_a",
				"host_statuses": [
					{"health_status": {"eds_health_status": "HEALTHY"}},
					{"health_status": {"eds_health_status": "UNHEALTHY"}}
				]
			},
			{
				"name": "cluster_b",
				"host_statuses": [
					{"health_status": {"eds_health_status": "DEGRADED"}}
				]
			},
			{
				"name": "cluster_c",
				"host_statuses": []
			}
		]
	}`

	result, err := parseClusterHealth([]byte(body))
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Fatalf("got %d clusters, want 3", len(result))
	}
	if result["cluster_a"].HealthyHosts != 1 {
		t.Errorf("cluster_a healthy = %d, want 1", result["cluster_a"].HealthyHosts)
	}
	if result["cluster_a"].TotalHosts != 2 {
		t.Errorf("cluster_a total = %d, want 2", result["cluster_a"].TotalHosts)
	}
	if result["cluster_b"].HealthyHosts != 1 {
		t.Errorf("cluster_b healthy = %d, want 1 (DEGRADED counts as healthy)", result["cluster_b"].HealthyHosts)
	}
	if result["cluster_c"].HealthyHosts != 0 {
		t.Errorf("cluster_c healthy = %d, want 0", result["cluster_c"].HealthyHosts)
	}
}

func TestExtractClusters_TCPProxy(t *testing.T) {
	dumpJSON := `{
		"configs": [
			{
				"@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
				"dynamic_listeners": [
					{
						"name": "tcp-listener",
						"active_state": {
							"listener": {
								"name": "tcp-listener",
								"address": {"socket_address": {"address": "0.0.0.0", "port_value": 8443}},
								"filter_chains": [
									{
										"filters": [
											{
												"name": "envoy.filters.network.tcp_proxy",
												"typed_config": {"cluster": "backend_cluster"}
											}
										]
									}
								]
							}
						}
					}
				]
			}
		]
	}`

	d := &Discoverer{envoyAddr: "127.0.0.1"}
	listeners, listenerClusters, err := d.parseConfigDump([]byte(dumpJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1", len(listeners))
	}
	clusters := listenerClusters["tcp-listener"]
	if len(clusters) != 1 || clusters[0] != "backend_cluster" {
		t.Errorf("clusters = %v, want [backend_cluster]", clusters)
	}
}

func TestExtractClusters_HTTPInlineRoute(t *testing.T) {
	dumpJSON := `{
		"configs": [
			{
				"@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
				"dynamic_listeners": [
					{
						"name": "http-listener",
						"active_state": {
							"listener": {
								"name": "http-listener",
								"address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
								"filter_chains": [
									{
										"filters": [
											{
												"name": "envoy.filters.network.http_connection_manager",
												"typed_config": {
													"route_config": {
														"name": "local_route",
														"virtual_hosts": [
															{
																"routes": [
																	{"route": {"cluster": "web_cluster"}},
																	{"route": {"weighted_clusters": {"clusters": [{"name": "canary_cluster"}]}}}
																]
															}
														]
													}
												}
											}
										]
									}
								]
							}
						}
					}
				]
			}
		]
	}`

	d := &Discoverer{envoyAddr: "127.0.0.1"}
	_, listenerClusters, err := d.parseConfigDump([]byte(dumpJSON))
	if err != nil {
		t.Fatal(err)
	}
	clusters := listenerClusters["http-listener"]
	if len(clusters) != 2 {
		t.Fatalf("got %d clusters, want 2, got %v", len(clusters), clusters)
	}
	// Sorted: canary_cluster, web_cluster
	if clusters[0] != "canary_cluster" || clusters[1] != "web_cluster" {
		t.Errorf("clusters = %v, want [canary_cluster web_cluster]", clusters)
	}
}

func TestExtractClusters_RDSReference(t *testing.T) {
	dumpJSON := `{
		"configs": [
			{
				"@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
				"dynamic_listeners": [
					{
						"name": "rds-listener",
						"active_state": {
							"listener": {
								"name": "rds-listener",
								"address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
								"filter_chains": [
									{
										"filters": [
											{
												"name": "envoy.filters.network.http_connection_manager",
												"typed_config": {
													"rds": {"route_config_name": "my_route"}
												}
											}
										]
									}
								]
							}
						}
					}
				]
			},
			{
				"@type": "type.googleapis.com/envoy.admin.v3.RoutesConfigDump",
				"dynamic_route_configs": [
					{
						"route_config": {
							"name": "my_route",
							"virtual_hosts": [
								{
									"routes": [
										{"route": {"cluster": "rds_backend"}}
									]
								}
							]
						}
					}
				]
			}
		]
	}`

	d := &Discoverer{envoyAddr: "127.0.0.1"}
	_, listenerClusters, err := d.parseConfigDump([]byte(dumpJSON))
	if err != nil {
		t.Fatal(err)
	}
	clusters := listenerClusters["rds-listener"]
	if len(clusters) != 1 || clusters[0] != "rds_backend" {
		t.Errorf("clusters = %v, want [rds_backend]", clusters)
	}
}
