package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/health"
)

type configDump struct {
	Configs []json.RawMessage `json:"configs"`
}

type listenersConfigDump struct {
	Type             string            `json:"@type"`
	DynamicListeners []dynamicListener `json:"dynamic_listeners"`
}

type dynamicListener struct {
	Name        string       `json:"name"`
	ActiveState *activeState `json:"active_state"`
}

type activeState struct {
	Listener listenerConfig `json:"listener"`
}

type listenerConfig struct {
	Name               string        `json:"name"`
	Address            addressWrap   `json:"address"`
	FilterChains       []filterChain `json:"filter_chains"`
	DefaultFilterChain *filterChain  `json:"default_filter_chain"`
}

type addressWrap struct {
	SocketAddress socketAddress `json:"socket_address"`
}

type socketAddress struct {
	Address   string `json:"address"`
	PortValue int    `json:"port_value"`
	Protocol  string `json:"protocol"`
}

type filterChain struct {
	Filters []filter `json:"filters"`
}

type filter struct {
	Name        string          `json:"name"`
	TypedConfig json.RawMessage `json:"typed_config,omitempty"`
}

// Route config structs for extracting cluster names from listeners.
type routesConfigDump struct {
	Type                string               `json:"@type"`
	DynamicRouteConfigs []dynamicRouteConfig `json:"dynamic_route_configs"`
}

type dynamicRouteConfig struct {
	RouteConfig routeConfigData `json:"route_config"`
}

type routeConfigData struct {
	Name         string        `json:"name"`
	VirtualHosts []virtualHost `json:"virtual_hosts"`
}

type virtualHost struct {
	Routes []routeEntry `json:"routes"`
}

type routeEntry struct {
	Route *routeAction `json:"route"`
}

type routeAction struct {
	Cluster          string            `json:"cluster"`
	WeightedClusters *weightedClusters `json:"weighted_clusters"`
}

type weightedClusters struct {
	Clusters []weightedCluster `json:"clusters"`
}

type weightedCluster struct {
	Name string `json:"name"`
}

type httpConnMgrTypedConfig struct {
	RouteConfig *routeConfigData `json:"route_config"`
	Rds         *rdsReference    `json:"rds"`
}

type rdsReference struct {
	RouteConfigName string `json:"route_config_name"`
}

type tcpProxyTypedConfig struct {
	Cluster string `json:"cluster"`
}

// Cluster health structs for /clusters?format=json endpoint.
type clustersResponse struct {
	ClusterStatuses []clusterStatus `json:"cluster_statuses"`
}

type clusterStatus struct {
	Name         string       `json:"name"`
	HostStatuses []hostStatus `json:"host_statuses"`
}

type hostStatus struct {
	HealthStatus hostHealthStatus `json:"health_status"`
}

type hostHealthStatus struct {
	EdsHealthStatus string `json:"eds_health_status"`
}

// DiscoveryResult bundles listener discovery with cluster health data.
type DiscoveryResult struct {
	Listeners        []config.FlatListener
	ListenerClusters map[string][]string
	ClusterHealth    map[string]health.ClusterHealth
}

type Discoverer struct {
	adminURL       string
	envoyAddr      string
	pollInterval   time.Duration
	listenerFilter *regexp.Regexp
	proxyProtocol  string
	client         *http.Client
	logger         *slog.Logger
}

func New(cfg *config.DiscoveryConfig, logger *slog.Logger) (*Discoverer, error) {
	d := &Discoverer{
		adminURL:      strings.TrimRight(cfg.EnvoyAdmin, "/"),
		envoyAddr:     cfg.EnvoyAddress,
		pollInterval:  cfg.ParsedPollInterval(),
		proxyProtocol: cfg.ProxyProtocol,
		client:        &http.Client{Timeout: 5 * time.Second},
		logger:        logger,
	}
	if cfg.ListenerFilter != "" {
		re, err := regexp.Compile(cfg.ListenerFilter)
		if err != nil {
			return nil, fmt.Errorf("compile listener filter: %w", err)
		}
		d.listenerFilter = re
	}
	return d, nil
}

// fetchAdminEndpoint fetches a raw body from the given Envoy admin path.
func (d *Discoverer) fetchAdminEndpoint(ctx context.Context, path string) ([]byte, error) {
	url := d.adminURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", path, err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s body: %w", path, err)
	}
	return body, nil
}

func (d *Discoverer) Discover(ctx context.Context) ([]config.FlatListener, error) {
	body, err := d.fetchAdminEndpoint(ctx, "/config_dump")
	if err != nil {
		return nil, err
	}
	listeners, _, err := d.parseConfigDump(body)
	return listeners, err
}

// parseConfigDump parses a raw config_dump body into listeners, listener→cluster mappings, and RDS route configs.
func (d *Discoverer) parseConfigDump(body []byte) ([]config.FlatListener, map[string][]string, error) {
	var dump configDump
	if err := json.Unmarshal(body, &dump); err != nil {
		return nil, nil, fmt.Errorf("parse config dump: %w", err)
	}

	// Collect RDS route configs for resolving route_config_name references.
	rdsConfigs := make(map[string]*routeConfigData)
	for _, raw := range dump.Configs {
		var rcd routesConfigDump
		if err := json.Unmarshal(raw, &rcd); err == nil && strings.Contains(rcd.Type, "RoutesConfigDump") {
			for i := range rcd.DynamicRouteConfigs {
				rc := &rcd.DynamicRouteConfigs[i].RouteConfig
				if rc.Name != "" {
					rdsConfigs[rc.Name] = rc
				}
			}
		}
	}

	var dynamicListeners []dynamicListener
	for _, raw := range dump.Configs {
		var lcd listenersConfigDump
		if err := json.Unmarshal(raw, &lcd); err == nil && len(lcd.DynamicListeners) > 0 {
			dynamicListeners = append(dynamicListeners, lcd.DynamicListeners...)
			continue
		}
		var dl dynamicListener
		if err := json.Unmarshal(raw, &dl); err == nil && dl.ActiveState != nil {
			dynamicListeners = append(dynamicListeners, dl)
		}
	}

	listenerClusters := make(map[string][]string)
	var listeners []config.FlatListener
	for _, dl := range dynamicListeners {
		if dl.ActiveState == nil {
			continue
		}
		lc := dl.ActiveState.Listener
		sa := lc.Address.SocketAddress
		port := sa.PortValue

		if port == 0 {
			continue
		}

		name := dl.Name
		if name == "" {
			name = lc.Name
		}

		if d.listenerFilter != nil && !d.listenerFilter.MatchString(name) {
			continue
		}

		transport := config.ProtocolTCP
		if strings.EqualFold(sa.Protocol, "UDP") {
			transport = config.ProtocolUDP
		}

		allChains := append([]filterChain(nil), lc.FilterChains...)
		if lc.DefaultFilterChain != nil {
			allChains = append(allChains, *lc.DefaultFilterChain)
		}
		isL7 := d.hasHTTPConnectionManager(allChains)

		// Extract cluster names from filter chains.
		clusters := d.extractClusters(allChains, rdsConfigs)
		if len(clusters) > 0 {
			listenerClusters[name] = clusters
		}

		fl := config.FlatListener{
			Name:      name,
			Port:      port,
			Transport: transport,
			IsL7:      isL7,
			Forward:   fmt.Sprintf("%s:%d", d.envoyAddr, port),
		}

		if isL7 {
			fl.Protocol = config.ProtocolHTTP
		} else if transport == config.ProtocolUDP {
			fl.Protocol = config.ProtocolUDP
		} else {
			fl.Protocol = config.ProtocolTCP
		}

		if d.proxyProtocol == "v2" {
			fl.ProxyProtocol = true
		}

		listeners = append(listeners, fl)
	}

	sort.Slice(listeners, func(i, j int) bool {
		return listeners[i].Name < listeners[j].Name
	})
	return listeners, listenerClusters, nil
}

// extractClusters extracts cluster names from filter chains by inspecting typed_config.
func (d *Discoverer) extractClusters(chains []filterChain, rdsConfigs map[string]*routeConfigData) []string {
	seen := make(map[string]bool)
	for _, fc := range chains {
		for _, f := range fc.Filters {
			if len(f.TypedConfig) == 0 {
				continue
			}

			if strings.Contains(f.Name, "http_connection_manager") {
				var hcm httpConnMgrTypedConfig
				if err := json.Unmarshal(f.TypedConfig, &hcm); err != nil {
					continue
				}
				// Inline route_config.
				if hcm.RouteConfig != nil {
					d.collectClustersFromRouteConfig(hcm.RouteConfig, seen)
				}
				// RDS reference.
				if hcm.Rds != nil && hcm.Rds.RouteConfigName != "" {
					if rc, ok := rdsConfigs[hcm.Rds.RouteConfigName]; ok {
						d.collectClustersFromRouteConfig(rc, seen)
					}
				}
			} else if strings.Contains(f.Name, "tcp_proxy") {
				var tcp tcpProxyTypedConfig
				if err := json.Unmarshal(f.TypedConfig, &tcp); err != nil {
					continue
				}
				if tcp.Cluster != "" {
					seen[tcp.Cluster] = true
				}
			}
		}
	}

	clusters := make([]string, 0, len(seen))
	for c := range seen {
		clusters = append(clusters, c)
	}
	sort.Strings(clusters)
	return clusters
}

func (d *Discoverer) collectClustersFromRouteConfig(rc *routeConfigData, seen map[string]bool) {
	for _, vh := range rc.VirtualHosts {
		for _, re := range vh.Routes {
			if re.Route == nil {
				continue
			}
			if re.Route.Cluster != "" {
				seen[re.Route.Cluster] = true
			}
			if re.Route.WeightedClusters != nil {
				for _, wc := range re.Route.WeightedClusters.Clusters {
					if wc.Name != "" {
						seen[wc.Name] = true
					}
				}
			}
		}
	}
}

// FetchClusterHealth fetches health status from Envoy /clusters?format=json endpoint.
func (d *Discoverer) FetchClusterHealth(ctx context.Context) (map[string]health.ClusterHealth, error) {
	body, err := d.fetchAdminEndpoint(ctx, "/clusters?format=json")
	if err != nil {
		return nil, err
	}
	return parseClusterHealth(body)
}

func parseClusterHealth(body []byte) (map[string]health.ClusterHealth, error) {
	var cr clustersResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, fmt.Errorf("parse cluster health: %w", err)
	}

	result := make(map[string]health.ClusterHealth, len(cr.ClusterStatuses))
	for _, cs := range cr.ClusterStatuses {
		ch := health.ClusterHealth{
			Name:       cs.Name,
			TotalHosts: len(cs.HostStatuses),
		}
		for _, hs := range cs.HostStatuses {
			status := hs.HealthStatus.EdsHealthStatus
			if status == "HEALTHY" || status == "DEGRADED" {
				ch.HealthyHosts++
			}
		}
		result[cs.Name] = ch
	}
	return result, nil
}

func (d *Discoverer) hasHTTPConnectionManager(chains []filterChain) bool {
	for _, fc := range chains {
		for _, f := range fc.Filters {
			if strings.Contains(f.Name, "http_connection_manager") {
				return true
			}
		}
	}
	return false
}

func (d *Discoverer) Watch(ctx context.Context) <-chan DiscoveryResult {
	ch := make(chan DiscoveryResult, 1)
	go func() {
		defer close(ch)

		var prevListeners []config.FlatListener
		var prevHealth map[string]health.ClusterHealth
		var prevListenerClusters map[string][]string

		send := func() {
			result, err := d.discoverFull(ctx)
			if err != nil {
				d.logger.Error("discovery failed", "err", err)
				return
			}
			listenersChanged := !flatListenersEqual(prevListeners, result.Listeners)
			healthChanged := !clusterHealthEqual(prevHealth, result.ClusterHealth)
			clustersChanged := !listenerClustersEqual(prevListenerClusters, result.ListenerClusters)
			if prevListeners == nil || listenersChanged || healthChanged || clustersChanged {
				if listenersChanged {
					d.logger.Info("discovered listener change",
						"prev", len(prevListeners), "new", len(result.Listeners))
				}
				prevListeners = result.Listeners
				prevHealth = result.ClusterHealth
				prevListenerClusters = result.ListenerClusters
				select {
				case ch <- result:
				case <-ctx.Done():
				}
			}
		}

		send()

		ticker := time.NewTicker(d.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				send()
			}
		}
	}()
	return ch
}

// discoverFull fetches config_dump and cluster health concurrently.
func (d *Discoverer) discoverFull(ctx context.Context) (DiscoveryResult, error) {
	type configResult struct {
		body []byte
		err  error
	}
	type healthResult struct {
		health map[string]health.ClusterHealth
		err    error
	}

	configCh := make(chan configResult, 1)
	healthCh := make(chan healthResult, 1)

	go func() {
		body, err := d.fetchAdminEndpoint(ctx, "/config_dump")
		configCh <- configResult{body, err}
	}()
	go func() {
		h, err := d.FetchClusterHealth(ctx)
		healthCh <- healthResult{h, err}
	}()

	cr := <-configCh
	if cr.err != nil {
		return DiscoveryResult{}, cr.err
	}

	listeners, listenerClusters, err := d.parseConfigDump(cr.body)
	if err != nil {
		return DiscoveryResult{}, err
	}

	hr := <-healthCh
	clusterHealth := hr.health
	if hr.err != nil {
		d.logger.Warn("failed to fetch cluster health, treating as unknown", "err", hr.err)
		clusterHealth = make(map[string]health.ClusterHealth)
	}

	return DiscoveryResult{
		Listeners:        listeners,
		ListenerClusters: listenerClusters,
		ClusterHealth:    clusterHealth,
	}, nil
}

func clusterHealthEqual(a, b map[string]health.ClusterHealth) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av.TotalHosts != bv.TotalHosts || av.HealthyHosts != bv.HealthyHosts {
			return false
		}
	}
	return true
}

func listenerClustersEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}

func flatListenersEqual(a, b []config.FlatListener) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Port != b[i].Port ||
			a[i].Protocol != b[i].Protocol || a[i].Forward != b[i].Forward ||
			a[i].IsL7 != b[i].IsL7 || a[i].Transport != b[i].Transport {
			return false
		}
	}
	return true
}
