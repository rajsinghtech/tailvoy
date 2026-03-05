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
	Name string `json:"name"`
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

func (d *Discoverer) Discover(ctx context.Context) ([]config.FlatListener, error) {
	url := d.adminURL + "/config_dump"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch config dump: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config dump returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return d.parse(body)
}

func (d *Discoverer) parse(body []byte) ([]config.FlatListener, error) {
	var dump configDump
	if err := json.Unmarshal(body, &dump); err != nil {
		return nil, fmt.Errorf("parse config dump: %w", err)
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
	return listeners, nil
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

func (d *Discoverer) Watch(ctx context.Context) <-chan []config.FlatListener {
	ch := make(chan []config.FlatListener, 1)
	go func() {
		defer close(ch)

		var prev []config.FlatListener

		if listeners, err := d.Discover(ctx); err != nil {
			d.logger.Error("initial discovery failed", "err", err)
		} else {
			prev = listeners
			select {
			case ch <- listeners:
			case <-ctx.Done():
				return
			}
		}

		ticker := time.NewTicker(d.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				listeners, err := d.Discover(ctx)
				if err != nil {
					d.logger.Error("discovery poll failed", "err", err)
					continue
				}
				d.logger.Debug("discovery poll completed", "count", len(listeners))
				if !flatListenersEqual(prev, listeners) {
					d.logger.Info("discovered listener change",
						"prev", len(prev), "new", len(listeners))
					prev = listeners
					select {
					case ch <- listeners:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return ch
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
