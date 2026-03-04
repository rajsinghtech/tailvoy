package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Tailscale TailscaleConfig `yaml:"tailscale"`
	Listeners []Listener      `yaml:"listeners"`
	L4Rules   []Rule          `yaml:"l4_rules"`
	L7Rules   []Rule          `yaml:"l7_rules"`
	Default   string          `yaml:"default"`
}

type TailscaleConfig struct {
	Hostname  string `yaml:"hostname"`
	AuthKey   string `yaml:"authkey"`
	Ephemeral bool   `yaml:"ephemeral"`
}

type Listener struct {
	Name          string `yaml:"name"`
	Protocol      string `yaml:"protocol"`
	Listen        string `yaml:"listen"`
	Forward       string `yaml:"forward"`
	ProxyProtocol string `yaml:"proxy_protocol"`
	L7Policy      bool   `yaml:"l7_policy"`
}

type Rule struct {
	Match RuleMatch `yaml:"match"`
	Allow AllowSpec `yaml:"allow"`
}

type RuleMatch struct {
	Listener string `yaml:"listener"`
	Path     string `yaml:"path"`
}

type AllowSpec struct {
	AnyTailscale bool     `yaml:"any_tailscale"`
	Users        []string `yaml:"users"`
	Tags         []string `yaml:"tags"`
	Groups       []string `yaml:"groups"`
}

var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// Load reads and parses a YAML config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

// Parse parses raw YAML bytes into a validated Config.
func Parse(data []byte) (*Config, error) {
	expanded := expandEnvVars(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// expandEnvVars replaces ${VAR} references with their environment variable values.
func expandEnvVars(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		name := envVarRe.FindStringSubmatch(match)[1]
		return os.Getenv(name)
	})
}

func (c *Config) validate() error {
	if c.Tailscale.Hostname == "" {
		return fmt.Errorf("tailscale.hostname is required")
	}

	listenerNames := make(map[string]struct{}, len(c.Listeners))
	for i, l := range c.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listeners[%d].name is required", i)
		}
		if l.Protocol == "" {
			return fmt.Errorf("listeners[%d].protocol is required", i)
		}
		if l.Listen == "" {
			return fmt.Errorf("listeners[%d].listen is required", i)
		}
		if l.Forward == "" {
			return fmt.Errorf("listeners[%d].forward is required", i)
		}
		switch l.ProxyProtocol {
		case "", "v2":
			// valid
		default:
			return fmt.Errorf("listeners[%d].proxy_protocol must be empty or \"v2\", got %q", i, l.ProxyProtocol)
		}
		if _, exists := listenerNames[l.Name]; exists {
			return fmt.Errorf("duplicate listener name: %q", l.Name)
		}
		listenerNames[l.Name] = struct{}{}
	}

	for i, r := range c.L4Rules {
		if _, ok := listenerNames[r.Match.Listener]; !ok {
			return fmt.Errorf("l4_rules[%d].match.listener references unknown listener: %q", i, r.Match.Listener)
		}
	}

	for i, r := range c.L7Rules {
		if _, ok := listenerNames[r.Match.Listener]; !ok {
			return fmt.Errorf("l7_rules[%d].match.listener references unknown listener: %q", i, r.Match.Listener)
		}
		if r.Match.Path == "" {
			return fmt.Errorf("l7_rules[%d].match.path is required", i)
		}
	}

	switch c.Default {
	case "":
		c.Default = "deny"
	case "allow", "deny":
		// valid
	default:
		return fmt.Errorf("default must be \"allow\" or \"deny\", got %q", c.Default)
	}

	return nil
}

// ListenerByName returns the listener with the given name, or nil if not found.
func (c *Config) ListenerByName(name string) *Listener {
	for i := range c.Listeners {
		if c.Listeners[i].Name == name {
			return &c.Listeners[i]
		}
	}
	return nil
}

// L7Listeners returns all listeners that have L7 policy enabled.
func (c *Config) L7Listeners() []Listener {
	var out []Listener
	for _, l := range c.Listeners {
		if l.L7Policy {
			out = append(out, l)
		}
	}
	return out
}

// Port extracts the port number from the listen address (e.g., ":443" -> "443").
func (l *Listener) Port() string {
	addr := l.Listen
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[idx+1:]
	}
	return addr
}
