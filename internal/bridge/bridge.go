package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/rajsinghtech/tailvoy/internal/config"
	tailscale "tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
)

// BridgeManager orchestrates cross-tailnet bridging.
type BridgeManager struct {
	cfg    *config.BridgeConfig
	logger *slog.Logger
}

func NewBridgeManager(cfg *config.BridgeConfig, logger *slog.Logger) *BridgeManager {
	return &BridgeManager{cfg: cfg, logger: logger}
}

// noopAdvertiser satisfies AdvertisementClient; advertisement is handled by ListenService.
type noopAdvertiser struct{}

func (n *noopAdvertiser) AdvertiseServices(_ context.Context, _ []string) error { return nil }

// tsnetServiceListener wraps tsnet.Server to implement ServiceListener.
type tsnetServiceListener struct {
	srv *tsnet.Server
}

func (t *tsnetServiceListener) ListenService(name string, port uint16) (net.Listener, error) {
	return t.srv.ListenService(name, tsnet.ServiceModeTCP{
		Port:                 port,
		PROXYProtocolVersion: 2,
	})
}

// tsnetDialer wraps tsnet.Server to implement Dialer.
type tsnetDialer struct {
	srv *tsnet.Server
}

func (t *tsnetDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.srv.Dial(ctx, network, addr)
}

// tsDevicesClient adapts tailscale.DevicesResource to our DevicesClient interface.
type tsDevicesClient struct {
	r *tailscale.DevicesResource
}

func (c *tsDevicesClient) List(ctx context.Context) ([]Device, error) {
	devs, err := c.r.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(devs))
	for _, d := range devs {
		out = append(out, Device{
			Name:      d.Name,
			Addresses: d.Addresses,
			Tags:      d.Tags,
		})
	}
	return out, nil
}

// tsDNSClient adapts tailscale.DNSResource to our DNSClient interface.
type tsDNSClient struct {
	r *tailscale.DNSResource
}

func (c *tsDNSClient) SplitDNS(ctx context.Context) (map[string][]string, error) {
	resp, err := c.r.SplitDNS(ctx)
	if err != nil {
		return nil, err
	}
	return map[string][]string(resp), nil
}

func (c *tsDNSClient) UpdateSplitDNS(ctx context.Context, req map[string][]string) (map[string][]string, error) {
	resp, err := c.r.UpdateSplitDNS(ctx, tailscale.SplitDNSRequest(req))
	if err != nil {
		return nil, err
	}
	return map[string][]string(resp), nil
}

type directionState struct {
	from, to   string
	dir        config.BridgeDirection
	rules      []config.BridgeRule
	discoverer *Discoverer
	reconciler *Reconciler
	forwarder  *Forwarder
	dnsServer  *DNSServer
	splitDNS   *SplitDNSConfigurator
}

// Run starts all tsnet servers, then runs the poll loop for each direction.
// Blocks until ctx is cancelled.
func (bm *BridgeManager) Run(ctx context.Context) error {
	servers := make(map[string]*tsnet.Server)
	clients := make(map[string]*tailscale.Client)

	for name, tn := range bm.cfg.Tailnets {
		srv := &tsnet.Server{
			Dir:           filepath.Join(".tailvoy", "bridge", name),
			Hostname:      "tailvoy-bridge-" + name,
			AuthKey:       tn.ClientSecret,
			Ephemeral:     true,
			AdvertiseTags: tn.Tags,
		}
		bm.logger.Info("connecting to tailnet", "name", name, "hostname", srv.Hostname)
		if _, err := srv.Up(ctx); err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			return fmt.Errorf("tsnet %s: %w", name, err)
		}
		defer func() { _ = srv.Close() }()
		servers[name] = srv

		clients[name] = &tailscale.Client{
			Tailnet: "-",
			Auth: &tailscale.OAuth{
				ClientID:     tn.ClientID,
				ClientSecret: tn.ClientSecret,
			},
		}
	}

	// Log peer status for each tsnet server.
	for name, srv := range servers {
		lc, err := srv.LocalClient()
		if err != nil {
			bm.logger.Warn("could not get local client for status", "tailnet", name, "err", err)
			continue
		}
		st, err := lc.Status(ctx)
		if err != nil {
			bm.logger.Warn("status failed", "tailnet", name, "err", err)
			continue
		}
		bm.logger.Info("tsnet status", "tailnet", name, "self", st.Self.HostName, "ips", st.Self.TailscaleIPs, "peers", len(st.Peer))
		for _, peer := range st.Peer {
			bm.logger.Info("tsnet peer", "tailnet", name, "peer", peer.HostName, "ips", peer.TailscaleIPs, "online", peer.Online, "relay", peer.Relay, "curAddr", peer.CurAddr)
		}
	}

	// Group rules by direction key.
	dirRules := make(map[string][]config.BridgeRule)
	for _, rule := range bm.cfg.Rules {
		dk := config.DirectionKey(rule.From, rule.To)
		dirRules[dk] = append(dirRules[dk], rule)
	}

	directions := make([]*directionState, 0, len(dirRules))
	for dk, rules := range dirRules {
		from, to := rules[0].From, rules[0].To
		dir := bm.cfg.Directions[dk]

		srcSrv := servers[from]
		dstSrv := servers[to]

		srcDevicesClient := &tsDevicesClient{r: clients[from].Devices()}
		dstVIPClient := clients[to].VIPServices()

		discoverer := NewDiscoverer(srcDevicesClient, rules, bm.logger)
		reconciler := NewReconciler(dstVIPClient, &noopAdvertiser{}, dir.ServiceTags, dir.Prefix, bm.logger)
		forwarder := NewForwarder(
			&tsnetServiceListener{srv: dstSrv},
			&tsnetDialer{srv: srcSrv},
			dir.Prefix,
			bm.cfg.ParsedDialTimeout(),
			bm.logger,
		)

		ds := &directionState{
			from:       from,
			to:         to,
			dir:        dir,
			rules:      rules,
			discoverer: discoverer,
			reconciler: reconciler,
			forwarder:  forwarder,
		}

		if dir.DNS != nil && dir.DNS.Enabled {
			ds.dnsServer = NewDNSServer("", bm.logger)

			// Create the DNS VIP service on the destination tailnet.
			dnsSvcName := DNSServiceName(from, to)
			dnsSvc := tailscale.VIPService{
				Name:    dnsSvcName,
				Tags:    dir.ServiceTags,
				Ports:   []string{"tcp:53"},
				Comment: "Managed by tailvoy bridge",
			}
			bm.logger.Info("creating DNS VIP service", "name", dnsSvcName)
			if err := clients[to].VIPServices().CreateOrUpdate(ctx, dnsSvc); err != nil {
				bm.logger.Error("failed to create DNS VIP service", "name", dnsSvcName, "err", err)
			}

			// Start DNS server on the VIP service listener (TCP port 53).
			dnsLn, err := dstSrv.ListenService(dnsSvcName, tsnet.ServiceModeTCP{
				Port:                 53,
				PROXYProtocolVersion: 2,
			})
			if err != nil {
				bm.logger.Error("failed to listen DNS VIP service", "name", dnsSvcName, "err", err)
			} else {
				bm.logger.Info("DNS server listening", "name", dnsSvcName)
				go func() {
					if srvErr := ds.dnsServer.ListenAndServeTCP(&proxyproto.Listener{Listener: dnsLn}); srvErr != nil {
						bm.logger.Error("DNS server error", "err", srvErr)
					}
				}()
			}

			if dir.DNS.SplitDns {
				ds.splitDNS = NewSplitDNSConfigurator(
					&tsDNSClient{r: clients[to].DNS()},
					dir.DNS.CleanupOnShutdown,
					bm.logger,
				)
			}
		}

		directions = append(directions, ds)
	}

	bm.logger.Info("bridge initialized", "directions", len(directions))

	var wg sync.WaitGroup
	for _, ds := range directions {
		ds := ds
		wg.Add(1)
		go func() {
			defer wg.Done()
			bm.runDirection(ctx, ds, clients)
		}()
	}
	wg.Wait()
	return nil
}

func (bm *BridgeManager) runDirection(ctx context.Context, ds *directionState, clients map[string]*tailscale.Client) {
	ticker := time.NewTicker(bm.cfg.ParsedPollInterval())
	defer ticker.Stop()

	for {
		devices, added, removed, err := ds.discoverer.Poll(ctx)
		if err != nil {
			bm.logger.Error("discovery poll failed", "direction", ds.from+">"+ds.to, "err", err)
			goto wait
		}

		bm.logger.Info("poll complete",
			"direction", ds.from+">"+ds.to,
			"devices", len(devices),
			"added", len(added),
			"removed", len(removed),
		)

		{
			vipAddrs, err := ds.reconciler.Reconcile(ctx, devices)
			if err != nil {
				bm.logger.Error("reconcile failed", "direction", ds.from+">"+ds.to, "err", err)
			}

			if err := ds.forwarder.Reconcile(ctx, devices); err != nil {
				bm.logger.Error("forwarder reconcile failed", "direction", ds.from+">"+ds.to, "err", err)
			}

			if ds.dnsServer != nil && vipAddrs != nil {
				records := make(map[string][]net.IP)
				for _, dev := range devices {
					svcName := ServiceName(dev.FQDN, ds.dir.Prefix)
					if ips, ok := vipAddrs[svcName]; ok {
						var netIPs []net.IP
						for _, ipStr := range ips {
							if ip := net.ParseIP(ipStr); ip != nil {
								netIPs = append(netIPs, ip)
							}
						}
						fqdn := dev.FQDN
						if !strings.HasSuffix(fqdn, ".") {
							fqdn += "."
						}
						records[fqdn] = netIPs
					}
				}
				ds.dnsServer.SetRecords(records)
			}

			if ds.splitDNS != nil && len(devices) > 0 {
				fqdns := make([]string, 0, len(devices))
				for _, dev := range devices {
					fqdns = append(fqdns, dev.FQDN)
				}
				zone := ExtractZone(fqdns)
				if zone != "" {
					dnsSvcName := DNSServiceName(ds.from, ds.to)
					dnsSvc, err := clients[ds.to].VIPServices().Get(ctx, dnsSvcName)
					if err != nil {
						bm.logger.Warn("DNS VIP not ready", "svc", dnsSvcName, "err", err)
					} else if len(dnsSvc.Addrs) == 0 {
						bm.logger.Warn("DNS VIP has no addresses yet", "svc", dnsSvcName)
					} else {
						if cfgErr := ds.splitDNS.Configure(ctx, zone, dnsSvc.Addrs[0]); cfgErr != nil {
							bm.logger.Error("split-dns configure failed", "direction", ds.from+">"+ds.to, "err", cfgErr)
						}
					}
				}
			}
		}

	wait:
		select {
		case <-ctx.Done():
			ds.forwarder.StopAll()
			if ds.splitDNS != nil {
				if err := ds.splitDNS.Cleanup(ctx); err != nil {
					bm.logger.Error("split-dns cleanup failed", "direction", ds.from+">"+ds.to, "err", err)
				}
			}
			return
		case <-ticker.C:
		}
	}
}
