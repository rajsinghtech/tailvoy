package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
	ProtocolGRPC  = "grpc"
	ProtocolTLS   = "tls"
	ProtocolTCP   = "tcp"
	ProtocolUDP   = "udp"
)

var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvVars(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		return os.Getenv(name)
	})
}

type Config struct {
	Tailscale TailscaleConfig     `yaml:"tailscale"`
	Listeners map[string]Listener `yaml:"listeners"`
	Discovery *DiscoveryConfig    `yaml:"discovery,omitempty"`
}

type DiscoveryConfig struct {
	EnvoyAdmin     string `yaml:"envoyAdmin"`
	EnvoyAddress   string `yaml:"envoyAddress"`
	PollInterval   string `yaml:"pollInterval"`
	ListenerFilter string `yaml:"listenerFilter"`
	ProxyProtocol  string `yaml:"proxyProtocol"`
}

func (d *DiscoveryConfig) ParsedPollInterval() time.Duration {
	if d.PollInterval == "" {
		return 10 * time.Second
	}
	dur, err := time.ParseDuration(d.PollInterval)
	if err != nil {
		return 10 * time.Second
	}
	return dur
}

type TailscaleConfig struct {
	Service      string   `yaml:"service"`
	Tags         []string `yaml:"tags"`
	ServiceTags  []string `yaml:"serviceTags"`
	ClientID     string   `yaml:"-"`
	ClientSecret string   `yaml:"-"`
}

func (t *TailscaleConfig) Hostname() string    { return t.Service + "-tailvoy" }
func (t *TailscaleConfig) ServiceName() string { return "svc:" + t.Service }

type Listener struct {
	Port     int        `yaml:"port"`
	Protocol string     `yaml:"protocol"`
	TLS      *TLSConfig `yaml:"tls,omitempty"`
	Backend  string     `yaml:"backend,omitempty"`
	Routes   []Route    `yaml:"routes,omitempty"`
}

type Route struct {
	Hostname string            `yaml:"hostname,omitempty"`
	TLS      *TLSConfig        `yaml:"tls,omitempty"`
	Backend  string            `yaml:"backend,omitempty"`
	Paths    map[string]string `yaml:"paths,omitempty"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

func validateBackendAddr(context, addr string) error {
	if !strings.Contains(addr, ":") {
		return fmt.Errorf("%s: backend %q must be host:port format", context, addr)
	}
	return nil
}

var validProtocols = map[string]bool{
	ProtocolHTTP: true, ProtocolHTTPS: true, ProtocolGRPC: true,
	ProtocolTLS: true, ProtocolTCP: true, ProtocolUDP: true,
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	expanded := expandEnvVars(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	cfg.Tailscale.ClientID = os.Getenv("TS_CLIENT_ID")
	cfg.Tailscale.ClientSecret = os.Getenv("TS_CLIENT_SECRET")

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	ts := &c.Tailscale
	if ts.Service == "" {
		return fmt.Errorf("tailscale.service is required")
	}
	if len(ts.Tags) == 0 {
		return fmt.Errorf("tailscale.tags is required")
	}
	if len(ts.ServiceTags) == 0 {
		return fmt.Errorf("tailscale.serviceTags is required")
	}
	if ts.ClientID == "" {
		return fmt.Errorf("TS_CLIENT_ID env var is required")
	}
	if ts.ClientSecret == "" {
		return fmt.Errorf("TS_CLIENT_SECRET env var is required")
	}

	if c.Discovery != nil && len(c.Listeners) > 0 {
		return fmt.Errorf("discovery and listeners are mutually exclusive")
	}
	if c.Discovery != nil {
		return c.Discovery.validate()
	}

	if len(c.Listeners) == 0 {
		return fmt.Errorf("at least one listener is required")
	}

	names := make([]string, 0, len(c.Listeners))
	for name := range c.Listeners {
		names = append(names, name)
	}
	sort.Strings(names)

	usedPorts := make(map[int]string)
	for _, name := range names {
		if err := validateListener(name, c.Listeners[name], usedPorts); err != nil {
			return err
		}
	}
	return nil
}

func validateListener(name string, l Listener, usedPorts map[int]string) error {
	prefix := fmt.Sprintf("listener %q", name)

	if l.Port < 1 || l.Port > 65535 {
		return fmt.Errorf("%s: port must be between 1 and 65535", prefix)
	}
	if prev, dup := usedPorts[l.Port]; dup {
		return fmt.Errorf("%s: duplicate port %d (already used by %q)", prefix, l.Port, prev)
	}
	usedPorts[l.Port] = name

	if !validProtocols[l.Protocol] {
		return fmt.Errorf("%s: protocol must be one of: http, https, grpc, tls, tcp, udp", prefix)
	}

	switch l.Protocol {
	case ProtocolTCP, ProtocolUDP:
		if err := validateStreamListener(prefix, l); err != nil {
			return err
		}
	case ProtocolHTTP, ProtocolGRPC:
		if err := validateHTTPListener(prefix, l); err != nil {
			return err
		}
	case ProtocolHTTPS:
		if err := validateTLSHTTPListener(prefix, l); err != nil {
			return err
		}
	case ProtocolTLS:
		if err := validateTLSPassthrough(prefix, l); err != nil {
			return err
		}
	}

	return nil
}

func validateStreamListener(prefix string, l Listener) error {
	if len(l.Routes) > 0 {
		return fmt.Errorf("%s: %s listener must not have routes", prefix, l.Protocol)
	}
	if l.Backend == "" {
		return fmt.Errorf("%s: %s listener must have backend", prefix, l.Protocol)
	}
	if err := validateBackendAddr(prefix, l.Backend); err != nil {
		return err
	}
	if l.TLS != nil {
		return fmt.Errorf("%s: %s listener must not have TLS config", prefix, l.Protocol)
	}
	return nil
}

func validateHTTPListener(prefix string, l Listener) error {
	if l.Backend != "" {
		return fmt.Errorf("%s: %s listener must not have backend directly", prefix, l.Protocol)
	}
	if len(l.Routes) == 0 {
		return fmt.Errorf("%s: %s listener must have routes", prefix, l.Protocol)
	}
	if l.Protocol == ProtocolHTTP && l.TLS != nil {
		return fmt.Errorf("%s: http listener must not have TLS config", prefix)
	}
	for i, r := range l.Routes {
		if l.Protocol == ProtocolHTTP && r.TLS != nil {
			return fmt.Errorf("%s: per-route TLS override only allowed for https/grpc (route %d)", prefix, i)
		}
		if err := validateRoute(prefix, i, r); err != nil {
			return err
		}
	}
	return nil
}

func validateTLSHTTPListener(prefix string, l Listener) error {
	if l.Backend != "" {
		return fmt.Errorf("%s: %s listener must not have backend directly", prefix, l.Protocol)
	}
	if len(l.Routes) == 0 {
		return fmt.Errorf("%s: %s listener must have routes", prefix, l.Protocol)
	}
	// TLS required: either at listener level or every route must have it
	if l.TLS == nil {
		for i, r := range l.Routes {
			if r.TLS == nil {
				return fmt.Errorf("%s: TLS config is required (set at listener level or on every route, missing on route %d)", prefix, i)
			}
		}
	}
	for i, r := range l.Routes {
		if err := validateRoute(prefix, i, r); err != nil {
			return err
		}
	}
	return nil
}

func validateTLSPassthrough(prefix string, l Listener) error {
	if l.Backend != "" {
		return fmt.Errorf("%s: tls listener must not have backend directly", prefix)
	}
	if len(l.Routes) == 0 {
		return fmt.Errorf("%s: tls listener must have routes", prefix)
	}
	for i, r := range l.Routes {
		if r.Hostname == "" {
			return fmt.Errorf("%s: tls route %d: hostname is required for SNI matching", prefix, i)
		}
		if len(r.Paths) > 0 {
			return fmt.Errorf("%s: tls route %d: must not have paths", prefix, i)
		}
		if r.Backend == "" {
			return fmt.Errorf("%s: tls route %d: backend is required", prefix, i)
		}
		if err := validateBackendAddr(fmt.Sprintf("%s tls route %d", prefix, i), r.Backend); err != nil {
			return err
		}
	}
	return nil
}

func validateRoute(prefix string, idx int, r Route) error {
	rp := fmt.Sprintf("%s route %d", prefix, idx)

	hasPaths := len(r.Paths) > 0
	hasBackend := r.Backend != ""

	if hasBackend && hasPaths {
		return fmt.Errorf("%s: must have either backend or paths, not both", rp)
	}
	if !hasBackend && !hasPaths {
		return fmt.Errorf("%s: must have either backend or paths", rp)
	}

	if hasBackend {
		if err := validateBackendAddr(rp, r.Backend); err != nil {
			return err
		}
	}

	for path, addr := range r.Paths {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("%s: path %q must start with /", rp, path)
		}
		if err := validateBackendAddr(fmt.Sprintf("%s path %q", rp, path), addr); err != nil {
			return err
		}
	}

	return nil
}

func (d *DiscoveryConfig) validate() error {
	if d.EnvoyAdmin == "" {
		return fmt.Errorf("discovery.envoyAdmin is required")
	}
	if d.EnvoyAddress == "" {
		return fmt.Errorf("discovery.envoyAddress is required")
	}
	if d.PollInterval != "" {
		if _, err := time.ParseDuration(d.PollInterval); err != nil {
			return fmt.Errorf("discovery.pollInterval is invalid: %w", err)
		}
	}
	switch d.ProxyProtocol {
	case "", "v2":
	default:
		return fmt.Errorf("discovery.proxyProtocol must be empty or \"v2\", got %q", d.ProxyProtocol)
	}
	if d.ListenerFilter != "" {
		if _, err := regexp.Compile(d.ListenerFilter); err != nil {
			return fmt.Errorf("discovery.listenerFilter is invalid regex: %w", err)
		}
	}
	return nil
}

type FlatListener struct {
	Name           string
	Port           int
	Protocol       string
	Transport      string
	IsL7           bool
	TerminateTLS   bool
	SNIPassthrough bool
	DefaultBackend string
	TLS            *TLSConfig
	Routes         []Route
	Forward        string // populated at runtime: envoy override for L7, DefaultBackend for L4
	ProxyProtocol  bool   // populated at runtime: true for L7 (envoy expects PROXY v2)
}

func (c *Config) FlatListeners() map[string]FlatListener {
	out := make(map[string]FlatListener, len(c.Listeners))
	for name, l := range c.Listeners {
		fl := FlatListener{
			Name:     name,
			Port:     l.Port,
			Protocol: l.Protocol,
			TLS:      l.TLS,
			Routes:   l.Routes,
		}
		switch l.Protocol {
		case ProtocolHTTP:
			fl.Transport = ProtocolTCP
			fl.IsL7 = true
		case ProtocolHTTPS:
			fl.Transport = ProtocolTCP
			fl.IsL7 = true
			fl.TerminateTLS = true
		case ProtocolGRPC:
			fl.Transport = ProtocolTCP
			fl.IsL7 = true
			fl.TerminateTLS = l.TLS != nil
		case ProtocolTLS:
			fl.Transport = ProtocolTCP
			fl.SNIPassthrough = true
		case ProtocolTCP:
			fl.Transport = ProtocolTCP
			fl.DefaultBackend = l.Backend
		case ProtocolUDP:
			fl.Transport = ProtocolUDP
			fl.DefaultBackend = l.Backend
		}
		out[name] = fl
	}
	return out
}
