package envoy

import (
	"fmt"
	"net"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

// GenerateStandaloneConfig produces a complete Envoy bootstrap YAML for
// standalone mode (no xDS). Each listener in cfg gets an Envoy listener and
// backend cluster. L7 listeners use HTTP Connection Manager with ext_authz;
// L4 listeners use TCP proxy.
func GenerateStandaloneConfig(cfg *config.Config, authzAddr string) (string, error) {
	authzHost, authzPort := splitHostPort(authzAddr)

	listeners := make([]map[string]interface{}, 0, len(cfg.Listeners))
	clusters := make([]map[string]interface{}, 0, len(cfg.Listeners)+1)

	for _, l := range cfg.Listeners {
		backendName := l.Name + "_backend"
		fwdHost, fwdPort := splitHostPort(l.Forward)

		if l.L7Policy {
			listener := buildHTTPListener(l, backendName)
			listeners = append(listeners, listener)
		} else {
			listener := buildTCPListener(l, backendName)
			listeners = append(listeners, listener)
		}

		clusters = append(clusters, map[string]interface{}{
			"name":            backendName,
			"connect_timeout": "5s",
			"type":            "STRICT_DNS",
			"load_assignment": map[string]interface{}{
				"cluster_name": backendName,
				"endpoints": []interface{}{
					map[string]interface{}{
						"lb_endpoints": []interface{}{
							map[string]interface{}{
								"endpoint": map[string]interface{}{
									"address": map[string]interface{}{
										"socket_address": map[string]interface{}{
											"address":    fwdHost,
											"port_value": portInt(fwdPort),
										},
									},
								},
							},
						},
					},
				},
			},
		})
	}

	// ext_authz cluster
	clusters = append(clusters, map[string]interface{}{
		"name":            "tailvoy_ext_authz",
		"connect_timeout": "1s",
		"type":            "STRICT_DNS",
		"load_assignment": map[string]interface{}{
			"cluster_name": "tailvoy_ext_authz",
			"endpoints": []interface{}{
				map[string]interface{}{
					"lb_endpoints": []interface{}{
						map[string]interface{}{
							"endpoint": map[string]interface{}{
								"address": map[string]interface{}{
									"socket_address": map[string]interface{}{
										"address":    authzHost,
										"port_value": portInt(authzPort),
									},
								},
							},
						},
					},
				},
			},
		},
	})

	bootstrap := map[string]interface{}{
		"admin": map[string]interface{}{
			"address": map[string]interface{}{
				"socket_address": map[string]interface{}{
					"address":    "127.0.0.1",
					"port_value": 9901,
				},
			},
		},
		"static_resources": map[string]interface{}{
			"listeners": listeners,
			"clusters":  clusters,
		},
	}

	out, err := yaml.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("marshal envoy bootstrap: %w", err)
	}
	return string(out), nil
}

// InjectExtAuthz takes existing Envoy bootstrap YAML and injects an ext_authz
// HTTP filter into every HTTP Connection Manager found in static_resources.
func InjectExtAuthz(bootstrapYAML string, authzAddr string) (string, error) {
	var bootstrap map[string]interface{}
	if err := yaml.Unmarshal([]byte(bootstrapYAML), &bootstrap); err != nil {
		return "", fmt.Errorf("unmarshal bootstrap: %w", err)
	}

	sr, ok := bootstrap["static_resources"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("static_resources not found or invalid")
	}

	listeners, ok := sr["listeners"].([]interface{})
	if !ok {
		return "", fmt.Errorf("listeners not found or invalid")
	}

	authzFilter := buildExtAuthzFilter(authzAddr)

	for _, rawL := range listeners {
		l, ok := rawL.(map[string]interface{})
		if !ok {
			continue
		}
		fcs, ok := l["filter_chains"].([]interface{})
		if !ok {
			continue
		}
		for _, rawFC := range fcs {
			fc, ok := rawFC.(map[string]interface{})
			if !ok {
				continue
			}
			filters, ok := fc["filters"].([]interface{})
			if !ok {
				continue
			}
			for _, rawF := range filters {
				f, ok := rawF.(map[string]interface{})
				if !ok {
					continue
				}
				if f["name"] != "envoy.filters.network.http_connection_manager" {
					continue
				}
				tc, ok := f["typed_config"].(map[string]interface{})
				if !ok {
					continue
				}
				existing, _ := tc["http_filters"].([]interface{})
				injected := make([]interface{}, 0, len(existing)+1)
				injected = append(injected, authzFilter)
				injected = append(injected, existing...)
				tc["http_filters"] = injected
			}
		}
	}

	out, err := yaml.Marshal(bootstrap)
	if err != nil {
		return "", fmt.Errorf("marshal modified bootstrap: %w", err)
	}
	return string(out), nil
}

func buildHTTPListener(l config.Listener, backendCluster string) map[string]interface{} {
	return map[string]interface{}{
		"name": l.Name,
		"address": map[string]interface{}{
			"socket_address": map[string]interface{}{
				"address":    "0.0.0.0",
				"port_value": portInt(l.Port()),
			},
		},
		"listener_filters": []interface{}{
			map[string]interface{}{
				"name": "envoy.filters.listener.proxy_protocol",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol",
				},
			},
		},
		"filter_chains": []interface{}{
			map[string]interface{}{
				"filters": []interface{}{
					map[string]interface{}{
						"name": "envoy.filters.network.http_connection_manager",
						"typed_config": map[string]interface{}{
							"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
							"stat_prefix": l.Name,
							"route_config": map[string]interface{}{
								"virtual_hosts": []interface{}{
									map[string]interface{}{
										"name":    l.Name,
										"domains": []interface{}{"*"},
										"routes": []interface{}{
											map[string]interface{}{
												"match": map[string]interface{}{
													"prefix": "/",
												},
												"route": map[string]interface{}{
													"cluster": backendCluster,
												},
											},
										},
									},
								},
							},
							"http_filters": []interface{}{
								buildExtAuthzFilter(""),
								map[string]interface{}{
									"name": "envoy.filters.http.router",
									"typed_config": map[string]interface{}{
										"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func buildTCPListener(l config.Listener, backendCluster string) map[string]interface{} {
	return map[string]interface{}{
		"name": l.Name,
		"address": map[string]interface{}{
			"socket_address": map[string]interface{}{
				"address":    "0.0.0.0",
				"port_value": portInt(l.Port()),
			},
		},
		"filter_chains": []interface{}{
			map[string]interface{}{
				"filters": []interface{}{
					map[string]interface{}{
						"name": "envoy.filters.network.tcp_proxy",
						"typed_config": map[string]interface{}{
							"@type":       "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
							"stat_prefix": l.Name,
							"cluster":     backendCluster,
						},
					},
				},
			},
		},
	}
}

func buildExtAuthzFilter(authzAddr string) map[string]interface{} {
	filter := map[string]interface{}{
		"name": "envoy.filters.http.ext_authz",
		"typed_config": map[string]interface{}{
			"@type":              "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
			"transport_api_version": "V3",
			"failure_mode_allow": false,
			"grpc_service": map[string]interface{}{
				"envoy_grpc": map[string]interface{}{
					"cluster_name": "tailvoy_ext_authz",
				},
			},
		},
	}
	_ = authzAddr // cluster reference is by name, addr used at cluster level
	return filter
}

// splitHostPort splits an address of the form "host:port" into its components.
func splitHostPort(addr string) (host, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		// Fallback: try to find last colon
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				return addr[:i], addr[i+1:]
			}
		}
		return addr, ""
	}
	return h, p
}

// portInt converts a port string to an integer for Envoy config. Returns 0 on
// parse failure, which will surface as an Envoy validation error.
func portInt(port string) int {
	var n int
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
