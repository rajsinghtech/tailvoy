package envoy

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"gopkg.in/yaml.v3"
)

// envoyInternalPort returns the internal port Envoy should listen on for a
// given listener in standalone mode. Uses port + 10000 to avoid conflicts.
func envoyInternalPort(port int) int {
	return port + 10000
}

// StandaloneOverride describes the forward address that the tsnet listener
// should use when routing through Envoy in standalone mode.
type StandaloneOverride struct {
	Forward string
}

// GenerateStandaloneResult holds the Envoy bootstrap YAML and per-listener
// forwarding overrides for standalone mode.
type GenerateStandaloneResult struct {
	BootstrapYAML string
	Overrides     map[string]StandaloneOverride
}

var clusterKeyReplacer = strings.NewReplacer(":", "_", ".", "_")

// clusterKey sanitizes a backend address into a valid Envoy cluster name.
func clusterKey(addr string) string {
	return clusterKeyReplacer.Replace(addr)
}

// GenerateStandaloneConfig produces a complete Envoy bootstrap YAML from
// pre-computed flat listeners. Only L7 listeners (http/https/grpc) produce
// Envoy listeners; tls/tcp/udp are handled directly by tailvoy.
func GenerateStandaloneConfig(flat map[string]config.FlatListener, authzAddr string) (*GenerateStandaloneResult, error) {
	listeners := make([]map[string]interface{}, 0)
	clusterMap := make(map[string]map[string]interface{}) // clusterKey -> cluster
	h2Clusters := make(map[string]bool)                   // clusters needing HTTP/2 (gRPC)
	overrides := make(map[string]StandaloneOverride)

	// Sort listener names for deterministic output.
	names := make([]string, 0, len(flat))
	for name := range flat {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fl := flat[name]
		if !fl.IsL7 {
			continue
		}

		// Collect all backend addresses and build virtual hosts.
		vhosts, routeClusters := buildVirtualHosts(fl)

		// Register clusters. Mark gRPC backend clusters for HTTP/2.
		for addr := range routeClusters {
			key := clusterKey(addr)
			if _, exists := clusterMap[key]; !exists {
				host, port := splitHostPort(addr)
				clusterMap[key] = buildCluster(key, host, port, "5s")
			}
			if fl.Protocol == config.ProtocolGRPC {
				h2Clusters[key] = true
			}
		}

		// Build the HCM filter.
		hcm := map[string]interface{}{
			"@type":              "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
			"stat_prefix":        name,
			"codec_type":         "AUTO",
			"use_remote_address": true,
			"route_config": map[string]interface{}{
				"virtual_hosts": vhosts,
			},
			"http_filters": []interface{}{
				buildExtAuthzFilter(),
				map[string]interface{}{
					"name": "envoy.filters.http.router",
					"typed_config": map[string]interface{}{
						"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
					},
				},
			},
		}

		hcmFilter := map[string]interface{}{
			"name":         "envoy.filters.network.http_connection_manager",
			"typed_config": hcm,
		}

		filterChains := buildFilterChains(fl, hcmFilter)

		envoyPort := envoyInternalPort(fl.Port)
		listener := map[string]interface{}{
			"name": name,
			"address": map[string]interface{}{
				"socket_address": map[string]interface{}{
					"address":    "127.0.0.1",
					"port_value": envoyPort,
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
			"filter_chains": filterChains,
		}

		listeners = append(listeners, listener)
		overrides[name] = StandaloneOverride{
			Forward: fmt.Sprintf("127.0.0.1:%d", envoyPort),
		}
	}

	// Build sorted cluster list.
	clusters := make([]map[string]interface{}, 0, len(clusterMap)+1)
	clusterNames := make([]string, 0, len(clusterMap))
	for k := range clusterMap {
		clusterNames = append(clusterNames, k)
	}
	sort.Strings(clusterNames)
	for _, k := range clusterNames {
		c := clusterMap[k]
		if h2Clusters[k] {
			c["typed_extension_protocol_options"] = map[string]interface{}{
				"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
					"explicit_http_config": map[string]interface{}{
						"http2_protocol_options": map[string]interface{}{},
					},
				},
			}
		}
		clusters = append(clusters, c)
	}
	clusters = append(clusters, buildExtAuthzCluster(authzAddr))

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
		return nil, fmt.Errorf("marshal envoy bootstrap: %w", err)
	}
	return &GenerateStandaloneResult{
		BootstrapYAML: string(out),
		Overrides:     overrides,
	}, nil
}

// buildVirtualHosts groups routes into Envoy virtual hosts and returns the
// set of backend addresses referenced.
func buildVirtualHosts(fl config.FlatListener) ([]interface{}, map[string]bool) {
	type vhostEntry struct {
		domains []string
		routes  []map[string]interface{}
	}

	byHost := make(map[string]*vhostEntry) // "" key = catch-all
	backends := make(map[string]bool)

	for _, r := range fl.Routes {
		key := r.Hostname
		ve, ok := byHost[key]
		if !ok {
			ve = &vhostEntry{}
			if key == "" {
				ve.domains = []string{"*"}
			} else {
				ve.domains = []string{key}
			}
			byHost[key] = ve
		}

		if len(r.Paths) > 0 {
			// Sort paths for deterministic output.
			paths := make([]string, 0, len(r.Paths))
			for p := range r.Paths {
				paths = append(paths, p)
			}
			sort.Strings(paths)

			for _, p := range paths {
				addr := r.Paths[p]
				backends[addr] = true
				// Convert glob patterns to Envoy match: /foo/* → prefix /foo/
				envoyMatch := pathToEnvoyMatch(p)
				ve.routes = append(ve.routes, map[string]interface{}{
					"match": envoyMatch,
					"route": map[string]interface{}{
						"cluster": clusterKey(addr),
					},
					"typed_per_filter_config": perRouteExtAuthz(fl.Name),
				})
			}
		} else if r.Backend != "" {
			backends[r.Backend] = true
			ve.routes = append(ve.routes, map[string]interface{}{
				"match": map[string]interface{}{
					"prefix": "/",
				},
				"route": map[string]interface{}{
					"cluster": clusterKey(r.Backend),
				},
				"typed_per_filter_config": perRouteExtAuthz(fl.Name),
			})
		}
	}

	// Sort host keys for deterministic output; catch-all ("") sorts first.
	hostKeys := make([]string, 0, len(byHost))
	for k := range byHost {
		hostKeys = append(hostKeys, k)
	}
	sort.Strings(hostKeys)

	vhosts := make([]interface{}, 0, len(byHost))
	for _, key := range hostKeys {
		ve := byHost[key]
		vhName := key
		if vhName == "" {
			vhName = "catch_all"
		}

		domains := make([]interface{}, len(ve.domains))
		for i, d := range ve.domains {
			domains[i] = d
		}

		routes := make([]interface{}, len(ve.routes))
		for i, r := range ve.routes {
			routes[i] = r
		}

		vhosts = append(vhosts, map[string]interface{}{
			"name":    vhName,
			"domains": domains,
			"routes":  routes,
		})
	}

	return vhosts, backends
}

// buildFilterChains constructs filter chains for an L7 listener. If the
// listener terminates TLS, per-hostname TLS overrides produce separate
// filter chains with server_names matching.
func buildFilterChains(fl config.FlatListener, hcmFilter map[string]interface{}) []interface{} {
	if !fl.TerminateTLS {
		return []interface{}{
			map[string]interface{}{
				"filters": []interface{}{hcmFilter},
			},
		}
	}

	// Collect per-hostname TLS overrides.
	type tlsOverride struct {
		hostname string
		tls      *config.TLSConfig
	}
	var overrides []tlsOverride
	for _, r := range fl.Routes {
		if r.TLS != nil && r.Hostname != "" {
			overrides = append(overrides, tlsOverride{hostname: r.Hostname, tls: r.TLS})
		}
	}

	// Default filter chain with listener-level TLS.
	defaultChain := map[string]interface{}{
		"filters": []interface{}{hcmFilter},
	}
	if fl.TLS != nil {
		defaultChain["transport_socket"] = buildDownstreamTLS(fl.TLS)
	}

	if len(overrides) == 0 {
		return []interface{}{defaultChain}
	}

	// Sort overrides by hostname for deterministic output.
	sort.Slice(overrides, func(i, j int) bool {
		return overrides[i].hostname < overrides[j].hostname
	})

	chains := make([]interface{}, 0, len(overrides)+1)
	for _, ov := range overrides {
		chains = append(chains, map[string]interface{}{
			"filter_chain_match": map[string]interface{}{
				"server_names": []interface{}{ov.hostname},
			},
			"filters":          []interface{}{hcmFilter},
			"transport_socket": buildDownstreamTLS(ov.tls),
		})
	}
	chains = append(chains, defaultChain)
	return chains
}

// buildDownstreamTLS creates a downstream TLS transport socket config.
func buildDownstreamTLS(tls *config.TLSConfig) map[string]interface{} {
	return map[string]interface{}{
		"name": "envoy.transport_sockets.tls",
		"typed_config": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
			"common_tls_context": map[string]interface{}{
				"tls_certificates": []interface{}{
					map[string]interface{}{
						"certificate_chain": map[string]interface{}{
							"filename": tls.Cert,
						},
						"private_key": map[string]interface{}{
							"filename": tls.Key,
						},
					},
				},
			},
		},
	}
}

// buildCluster creates a STRICT_DNS cluster pointing to host:port.
func buildCluster(name, host, port, timeout string) map[string]interface{} {
	return map[string]interface{}{
		"name":            name,
		"connect_timeout": timeout,
		"type":            "STRICT_DNS",
		"load_assignment": map[string]interface{}{
			"cluster_name": name,
			"endpoints": []interface{}{
				map[string]interface{}{
					"lb_endpoints": []interface{}{
						map[string]interface{}{
							"endpoint": map[string]interface{}{
								"address": map[string]interface{}{
									"socket_address": map[string]interface{}{
										"address":    host,
										"port_value": portInt(port),
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

// buildExtAuthzCluster creates the ext_authz cluster with HTTP/2 for gRPC.
func buildExtAuthzCluster(authzAddr string) map[string]interface{} {
	host, port := splitHostPort(authzAddr)
	c := buildCluster("tailvoy_ext_authz", host, port, "1s")
	c["typed_extension_protocol_options"] = map[string]interface{}{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
			"explicit_http_config": map[string]interface{}{
				"http2_protocol_options": map[string]interface{}{},
			},
		},
	}
	return c
}

func buildExtAuthzFilter() map[string]interface{} {
	return map[string]interface{}{
		"name": "envoy.filters.http.ext_authz",
		"typed_config": map[string]interface{}{
			"@type":              "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
			"failure_mode_allow": false,
			"grpc_service": map[string]interface{}{
				"envoy_grpc": map[string]interface{}{
					"cluster_name": "tailvoy_ext_authz",
				},
				"timeout": "0.25s",
			},
			"transport_api_version": "V3",
		},
	}
}

// perRouteExtAuthz returns a typed_per_filter_config entry that sets
// context_extensions with the listener name for the ext_authz filter.
func perRouteExtAuthz(listenerName string) map[string]interface{} {
	return map[string]interface{}{
		"envoy.filters.http.ext_authz": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
			"check_settings": map[string]interface{}{
				"context_extensions": map[string]interface{}{
					"listener": listenerName,
				},
			},
		},
	}
}

// pathToEnvoyMatch converts a config path pattern to an Envoy route match.
// Glob patterns like /foo/* become prefix matches on /foo/.
// Exact paths like /health become exact matches.
func pathToEnvoyMatch(p string) map[string]interface{} {
	if strings.HasSuffix(p, "/*") {
		return map[string]interface{}{
			"prefix": strings.TrimSuffix(p, "*"),
		}
	}
	if strings.HasSuffix(p, "*") {
		return map[string]interface{}{
			"prefix": strings.TrimSuffix(p, "*"),
		}
	}
	// No wildcard — use prefix match (consistent with "/" catch-all behavior).
	return map[string]interface{}{
		"prefix": p,
	}
}

// splitHostPort splits an address of the form "host:port" into its components.
func splitHostPort(addr string) (host, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			return addr[:i], addr[i+1:]
		}
		return addr, ""
	}
	return h, p
}

// portInt converts a port string to an integer for Envoy config.
func portInt(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
