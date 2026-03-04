package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rajsinghtech/tailvoy/internal/authz"
	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/envoy"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
	"github.com/rajsinghtech/tailvoy/internal/proxy"
	"tailscale.com/tsnet"
)

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

	// Start tsnet.
	ts := &tsnet.Server{
		Hostname:  cfg.Tailscale.Hostname,
		AuthKey:   cfg.Tailscale.AuthKey,
		Ephemeral: cfg.Tailscale.Ephemeral,
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
	engine := policy.NewEngine(cfg)
	resolver := identity.NewResolver(lc)
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

	// Get the tailscale IPv4 for UDP listeners (ListenPacket requires an IP).
	ip4, _ := ts.TailscaleIPs()
	var tsIP string
	if ip4.IsValid() {
		tsIP = ip4.String()
	}

	// Start tsnet listeners for each configured listener.
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		switch l.Protocol {
		case "udp":
			if tsIP == "" {
				cancel()
				wg.Wait()
				return fmt.Errorf("no tailscale IPv4 for UDP listener %s", l.Name)
			}
			pc, err := ts.ListenPacket("udp", fmt.Sprintf("%s:%s", tsIP, l.Port()))
			if err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("listen udp %s (%s): %w", l.Name, l.Listen, err)
			}
			logger.Info("udp listener started", "name", l.Name, "addr", l.Listen)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := udpProxy.Serve(ctx, pc, l.Forward, resolver, engine, l.Name); err != nil {
					logger.Error("udp listener error", "name", l.Name, "err", err)
				}
			}()
		default: // tcp
			ln, err := ts.Listen("tcp", l.Listen)
			if err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("listen %s (%s): %w", l.Name, l.Listen, err)
			}
			logger.Info("listener started", "name", l.Name, "addr", l.Listen)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := listenerMgr.Serve(ctx, ln, l); err != nil {
					logger.Error("listener error", "name", l.Name, "err", err)
				}
			}()
		}
	}

	// Standalone mode: generate envoy bootstrap config from policy.
	if *standalone {
		result, err := envoy.GenerateStandaloneConfig(cfg, *authzAddr)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("generate envoy config: %w", err)
		}

		// Apply L7 forwarding overrides so tsnet routes through Envoy.
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
			cancel()
		}()
	}

	logger.Info("tailvoy running")
	<-ctx.Done()
	logger.Info("shutting down")
	wg.Wait()
	return nil
}
