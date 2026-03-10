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

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/rajsinghtech/tailvoy/internal/authz"
	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/discovery"
	"github.com/rajsinghtech/tailvoy/internal/envoy"
	"github.com/rajsinghtech/tailvoy/internal/health"
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
	return a.ListenService(name, tsnet.ServiceModeTCP{
		Port:                 port,
		PROXYProtocolVersion: 2,
	})
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
	configPath := fs.String("config", "config.yaml", "path to config YAML")
	authzAddr := fs.String("authz-addr", "127.0.0.1:9001", "ext_authz listen address")
	logLevel := fs.String("log-level", "info", "log level (debug/info/warn/error)")
	if err := fs.Parse(tailvoyArgs); err != nil {
		return err
	}

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

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tsClient := &tailscale.Client{
		Tailnet: "-",
		Auth: &tailscale.OAuth{
			ClientID:     cfg.Tailscale.ClientID,
			ClientSecret: cfg.Tailscale.ClientSecret,
		},
	}

	ts := &tsnet.Server{
		Hostname:      cfg.Tailscale.Hostname(),
		AuthKey:       cfg.Tailscale.ClientSecret,
		Ephemeral:     true,
		AdvertiseTags: cfg.Tailscale.Tags,
	}
	defer func() { _ = ts.Close() }()

	logger.Info("connecting to tailnet", "hostname", cfg.Tailscale.Hostname())
	if _, err := ts.Up(ctx); err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}

	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(lc)
	defer resolver.Close()
	l4proxy := proxy.NewL4Proxy(logger)
	udpProxy := proxy.NewUDPProxy(logger)
	listenerMgr := proxy.NewListenerManager(engine, resolver, l4proxy, logger)
	authzServer := authz.NewServer(engine, resolver, logger)

	var wg sync.WaitGroup

	// Start ext_authz gRPC server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := authzServer.ListenAndServe(ctx, *authzAddr); err != nil {
			logger.Error("ext_authz server error", "err", err)
		}
	}()
	logger.Info("ext_authz server starting", "addr", *authzAddr)

	// Get the tailscale IPv4 for UDP listeners.
	ip4, _ := ts.TailscaleIPs()
	var tsIP string
	if ip4.IsValid() {
		tsIP = ip4.String()
	}

	listenerToService := cfg.Tailscale.ListenerServiceMap()

	if cfg.Discovery != nil {
		disc, err := discovery.New(cfg.Discovery, logger)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("discovery setup: %w", err)
		}

		svcMgr := service.NewMultiManager(tsClient, cfg.Tailscale.ServiceTags, logger)
		dynMgr := proxy.NewDynamicListenerManager(&tsnetAdapter{ts}, listenerMgr, listenerToService, logger)
		advMgr := service.NewAdvertisementManager(lc, logger)
		healthPolicy := health.Policy(cfg.Discovery.ParsedHealthPolicy())
		tracker := health.NewTracker(cfg.Discovery.ParsedUnhealthyThreshold())

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer dynMgr.StopAll()
			for result := range disc.Watch(ctx) {
				// Ensure VIP services for discovered listeners.
				portsByService := make(map[string][]int)
				for _, fl := range result.Listeners {
					if fl.Transport == config.ProtocolUDP {
						continue
					}
					svc := listenerToService[fl.Name]
					if svc == "" {
						continue // unmapped listeners are warned about in Reconcile
					}
					portsByService[svc] = append(portsByService[svc], fl.Port)
				}
				if err := svcMgr.EnsureAll(ctx, portsByService); err != nil {
					logger.Error("ensure VIP services error", "err", err)
				}

				// Evaluate health and toggle advertisement.
				svcHealth := health.Evaluate(listenerToService, result.ListenerClusters, result.ClusterHealth, healthPolicy)
				toAdvertise, toUnadvertise := tracker.Update(svcHealth)

				if len(toUnadvertise) > 0 {
					logger.Warn("unadvertising unhealthy services", "services", toUnadvertise)
					if err := advMgr.Unadvertise(ctx, toUnadvertise); err != nil {
						logger.Error("unadvertise error", "err", err)
					}
				}
				if len(toAdvertise) > 0 {
					logger.Info("readvertising recovered services", "services", toAdvertise)
					if err := advMgr.Readvertise(ctx, toAdvertise); err != nil {
						logger.Error("readvertise error", "err", err)
					}
				}

				if err := dynMgr.Reconcile(ctx, result.Listeners); err != nil {
					logger.Error("reconcile error", "err", err)
				}
			}
		}()
	} else {
		// Static standalone mode: generate envoy config and start listeners.
		flat := cfg.FlatListeners()
		result, err := envoy.GenerateStandaloneConfig(flat, *authzAddr)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("generate envoy config: %w", err)
		}

		for name, fl := range flat {
			if ov, ok := result.Overrides[name]; ok && fl.IsL7 {
				fl.Forward = ov.Forward
				fl.ProxyProtocol = true
				logger.Info("routing L7 listener through envoy",
					"name", name, "envoy_addr", ov.Forward)
			} else {
				fl.Forward = fl.DefaultBackend
				fl.ProxyProtocol = false
			}
			flat[name] = fl
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

		// Build per-service port mappings and separate UDP listeners.
		portsByService := make(map[string][]int)
		var udpFLs []config.FlatListener
		type tcpEntry struct {
			name    string
			fl      config.FlatListener
			svcName string
		}
		var tcpEntries []tcpEntry

		for name, fl := range flat {
			if fl.Transport == config.ProtocolUDP {
				logger.Warn("UDP listener has no VIP service support, node IP only", "listener", fl.Name)
				udpFLs = append(udpFLs, fl)
				continue
			}
			svc := listenerToService[name]
			portsByService[svc] = append(portsByService[svc], fl.Port)
			tcpEntries = append(tcpEntries, tcpEntry{name: name, fl: fl, svcName: svc})
		}

		// Ensure all VIP services.
		svcMgr := service.NewMultiManager(tsClient, cfg.Tailscale.ServiceTags, logger)
		if err := svcMgr.EnsureAll(ctx, portsByService); err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("ensure VIP services: %w", err)
		}

		// Start TCP listeners with per-service VIPs.
		for _, entry := range tcpEntries {
			fl := entry.fl
			svcName := entry.svcName
			port := uint16(fl.Port)

			rawSvcLn, err := ts.ListenService(svcName, tsnet.ServiceModeTCP{
				Port:                 port,
				PROXYProtocolVersion: 2,
			})
			if err != nil {
				cancel()
				wg.Wait()
				return fmt.Errorf("listen service %s (port %d): %w", fl.Name, port, err)
			}
			svcLn := &proxyproto.Listener{Listener: rawSvcLn}
			logger.Info("service listener started", "name", fl.Name, "service", svcName, "port", port)

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := listenerMgr.Serve(ctx, svcLn, &fl); err != nil {
					logger.Error("service listener error", "name", fl.Name, "err", err)
				}
			}()

			portStr := strconv.Itoa(fl.Port)
			nodeLn, err := ts.Listen("tcp", ":"+portStr)
			if err != nil {
				logger.Warn("node listener failed, VIP-only", "name", fl.Name, "port", port, "err", err)
			} else {
				logger.Info("node listener started", "name", fl.Name, "port", port)
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := listenerMgr.Serve(ctx, nodeLn, &fl); err != nil {
						logger.Error("node listener error", "name", fl.Name, "err", err)
					}
				}()
			}
		}

		if tsIP != "" {
			for _, fl := range udpFLs {
				fl := fl
				addr := tsIP + ":" + strconv.Itoa(fl.Port)
				pc, err := ts.ListenPacket("udp", addr)
				if err != nil {
					logger.Error("udp listener error", "name", fl.Name, "err", err)
					continue
				}
				logger.Info("udp listener started", "name", fl.Name, "addr", addr)
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := udpProxy.Serve(ctx, pc, fl.Forward, resolver, engine, fl.Name); err != nil {
						logger.Error("udp serve error", "name", fl.Name, "err", err)
					}
				}()
			}
		} else if len(udpFLs) > 0 {
			logger.Warn("no tailscale IPv4, skipping UDP listeners")
		}

	}

	// Start Envoy if args are present (both standalone and discovery/EG modes).
	if len(envoyArgs) > 0 {
		envoyMgr := envoy.NewManager(logger)
		if err := envoyMgr.Start(ctx, envoyArgs); err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("envoy start: %w", err)
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range sigCh {
				_ = envoyMgr.Signal(sig)
			}
		}()

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
