package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/rajsinghtech/tailvoy/internal/authz"
	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/discovery"
	"github.com/rajsinghtech/tailvoy/internal/envoy"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
	"github.com/rajsinghtech/tailvoy/internal/proxy"
	"github.com/rajsinghtech/tailvoy/internal/service"
	tailscale "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// tsnetAdapter wraps *tsnet.Server to satisfy proxy.TSNetServer.
type tsnetAdapter struct {
	*tsnet.Server
}

func (a *tsnetAdapter) ListenTCPService(name string, port uint16) (net.Listener, error) {
	return a.ListenService(name, tsnet.ServiceModeTCP{Port: port})
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tailvoy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	tailvoyArgs, envoyArgs := envoy.ParseArgs(args)

	fs := flag.NewFlagSet("tailvoy", flag.ContinueOnError)
	policyPath := fs.String("policy", "policy.yaml", "path to policy YAML")
	authzAddr := fs.String("authz-addr", "127.0.0.1:9001", "ext_authz listen address")
	logLevel := fs.String("log-level", "info", "log level (debug/info/warn/error)")
	standalone := fs.Bool("standalone", false, "generate envoy config from policy")
	if err := fs.Parse(tailvoyArgs); err != nil {
		return err
	}

	// Setup logger.
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("unknown log level %q", *logLevel)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Load policy config.
	cfg, err := config.Load(*policyPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Context with signal handling.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build Tailscale API client for VIP service management.
	// Tailnet is always "-" (current tailnet) since we auth via OAuth.
	tsClient := &tailscale.Client{
		Tailnet: "-",
		Auth: &tailscale.OAuth{
			ClientID:     cfg.Tailscale.ClientID,
			ClientSecret: cfg.Tailscale.ClientSecret,
		},
	}

	// Start tsnet with OAuth credentials.
	ts := &tsnet.Server{
		Hostname:      cfg.Tailscale.Hostname,
		AuthKey:       cfg.Tailscale.ClientSecret,
		Ephemeral:     true,
		AdvertiseTags: cfg.Tailscale.Tags,
	}
	defer func() { _ = ts.Close() }()

	logger.Info("connecting to tailnet", "hostname", cfg.Tailscale.Hostname)
	if _, err := ts.Up(ctx); err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	// Build components.
	svcMgr := service.New(tsClient, cfg.Tailscale.ServiceName(), cfg.Tailscale.ServiceTags, logger)
	engine := policy.NewEngine()
	resolver := identity.NewResolver(lc)
	defer resolver.Close()
	l4proxy := proxy.NewL4Proxy(logger)
	udpProxy := proxy.NewUDPProxy(logger)
	listenerMgr := proxy.NewListenerManager(engine, resolver, l4proxy, logger)
	authzServer := authz.NewServer(engine, resolver, logger)

	var wg sync.WaitGroup

	// Start ext_authz server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := authzServer.ListenAndServe(ctx, *authzAddr); err != nil {
			logger.Error("ext_authz server error", "err", err)
		}
	}()
	logger.Info("ext_authz server starting", "addr", *authzAddr)

	// Standalone mode: generate envoy config and apply overrides BEFORE
	// starting listeners so they use the correct forward addresses.
	if *standalone {
		result, err := envoy.GenerateStandaloneConfig(cfg, *authzAddr)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("generate envoy config: %w", err)
		}

		for i := range cfg.Listeners {
			if ov, ok := result.Overrides[cfg.Listeners[i].Name]; ok {
				cfg.Listeners[i].Forward = ov.Forward
				cfg.Listeners[i].ProxyProtocol = ov.ProxyProtocol
				logger.Info("standalone: routing L7 listener through envoy",
					"name", cfg.Listeners[i].Name,
					"envoy_addr", ov.Forward,
				)
			}
		}

		tmpFile, err := os.CreateTemp("", "tailvoy-envoy-*.yaml")
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("create temp config: %w", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		if _, err := tmpFile.WriteString(result.BootstrapYAML); err != nil {
			tmpFile.Close()
			cancel()
			wg.Wait()
			return fmt.Errorf("write envoy config: %w", err)
		}
		tmpFile.Close()

		envoyArgs = append([]string{"-c", tmpFile.Name()}, envoyArgs...)
		logger.Info("generated standalone envoy config", "path", tmpFile.Name())
	}

	// Get the tailscale IPv4 for UDP listeners (ListenPacket requires an IP).
	ip4, _ := ts.TailscaleIPs()
	var tsIP string
	if ip4.IsValid() {
		tsIP = ip4.String()
	}

	if cfg.Discovery != nil {
		// Discovery mode: poll Envoy admin API and reconcile listeners dynamically.
		disc, err := discovery.New(cfg.Discovery, logger)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("discovery setup: %w", err)
		}
		dynMgr := proxy.NewDynamicListenerManager(&tsnetAdapter{ts}, listenerMgr, udpProxy, svcMgr, cfg.Tailscale.ServiceName(), logger, tsIP)

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer dynMgr.StopAll()
			for listeners := range disc.Watch(ctx) {
				if err := dynMgr.Reconcile(ctx, listeners); err != nil {
					logger.Error("reconcile error", "err", err)
				}
			}
		}()
	} else {
		// Static mode: start listeners via ListenService.
		svcName := cfg.Tailscale.ServiceName()

		// Collect TCP ports, warn and skip UDP.
		var tcpPorts []string
		var tcpListeners []*config.Listener
		for i := range cfg.Listeners {
			l := &cfg.Listeners[i]
			if l.Protocol == "udp" {
				logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
				continue
			}
			tcpPorts = append(tcpPorts, l.Port())
			tcpListeners = append(tcpListeners, l)
		}

		// Create/update VIP service with discovered ports.
		if len(tcpPorts) > 0 {
			if err := svcMgr.Ensure(ctx, tcpPorts); err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("ensure VIP service: %w", err)
			}
		}

		// Start TCP listeners via ListenService.
		for _, l := range tcpListeners {
			l := l
			port, err := strconv.ParseUint(l.Port(), 10, 16)
			if err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("invalid port for %s: %w", l.Name, err)
			}
			ln, err := ts.ListenService(svcName, tsnet.ServiceModeTCP{Port: uint16(port)})
			if err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("listen service %s (port %d): %w", l.Name, port, err)
			}
			logger.Info("service listener started", "name", l.Name, "service", svcName, "port", port)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := listenerMgr.Serve(ctx, ln, l); err != nil {
					logger.Error("listener error", "name", l.Name, "err", err)
				}
			}()
		}

	}

	// Start envoy if args are present.
	if len(envoyArgs) > 0 {
		envoyMgr := envoy.NewManager(logger)
		if err := envoyMgr.Start(ctx, envoyArgs); err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("envoy start: %w", err)
		}

		// Forward signals to envoy.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range sigCh {
				_ = envoyMgr.Signal(sig)
			}
		}()

		// Wait for envoy to exit; cancel context if it dies unexpectedly.
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := envoyMgr.Wait(); err != nil {
				logger.Error("envoy exited", "err", err)
			}
			signal.Stop(sigCh)
			close(sigCh)
			cancel()
		}()
	}

	logger.Info("tailvoy running")
	<-ctx.Done()
	logger.Info("shutting down")
	wg.Wait()
	return nil
}
