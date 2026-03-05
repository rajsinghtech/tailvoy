package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/service"
)

// TSNetServer abstracts the tsnet.Server methods used by DynamicListenerManager.
type TSNetServer interface {
	Listen(network, addr string) (net.Listener, error)
	ListenPacket(network, addr string) (net.PacketConn, error)
	ListenTCPService(name string, port uint16) (net.Listener, error)
}

// DynamicListenerManager reconciles tsnet listeners against a desired set
// of config.Listener entries, starting and stopping listeners as needed.
type DynamicListenerManager struct {
	ts          TSNetServer
	listenerMgr *ListenerManager
	udpProxy    *UDPProxy
	svcMgr      *service.Manager // may be nil in tests
	svcName     string
	logger      *slog.Logger
	tsIP        string // tailscale IPv4 for UDP listeners

	mu     sync.Mutex
	active map[string]*dynamicListener
}

type dynamicListener struct {
	cfg    config.Listener
	cancel context.CancelFunc
}

// NewDynamicListenerManager creates a manager that can start/stop listeners dynamically.
func NewDynamicListenerManager(ts TSNetServer, lm *ListenerManager, udp *UDPProxy, svcMgr *service.Manager, svcName string, logger *slog.Logger, tsIP string) *DynamicListenerManager {
	return &DynamicListenerManager{
		ts:          ts,
		listenerMgr: lm,
		udpProxy:    udp,
		svcMgr:      svcMgr,
		svcName:     svcName,
		logger:      logger,
		tsIP:        tsIP,
		active:      make(map[string]*dynamicListener),
	}
}

// Reconcile starts/stops listeners to match the desired set.
func (dm *DynamicListenerManager) Reconcile(ctx context.Context, desired []config.Listener) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Filter UDP — VIP services don't support UDP yet.
	var tcpDesired []config.Listener
	for _, l := range desired {
		if l.Protocol == "udp" {
			dm.logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
			continue
		}
		tcpDesired = append(tcpDesired, l)
	}

	// Sync VIP service ports.
	if dm.svcMgr != nil && len(tcpDesired) > 0 {
		var ports []string
		for _, l := range tcpDesired {
			ports = append(ports, l.Port())
		}
		if err := dm.svcMgr.Ensure(ctx, ports); err != nil {
			return fmt.Errorf("ensure VIP service: %w", err)
		}
	}

	desiredMap := make(map[string]config.Listener, len(tcpDesired))
	for _, l := range tcpDesired {
		desiredMap[l.Name] = l
	}

	// Stop listeners not in desired set or changed.
	for name, dl := range dm.active {
		want, exists := desiredMap[name]
		if !exists {
			dm.logger.Info("stopping removed listener", "name", name)
			dl.cancel()
			delete(dm.active, name)
			continue
		}
		if dl.cfg != want {
			dm.logger.Info("restarting changed listener", "name", name)
			dl.cancel()
			delete(dm.active, name)
		}
	}

	// Start listeners in desired but not active.
	var errs []error
	for _, l := range tcpDesired {
		if _, exists := dm.active[l.Name]; exists {
			continue
		}
		if err := dm.startListener(ctx, l); err != nil {
			errs = append(errs, fmt.Errorf("start %s: %w", l.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d listener(s) failed to start: %v", len(errs), errs)
	}
	return nil
}

func (dm *DynamicListenerManager) startListener(parentCtx context.Context, l config.Listener) error {
	lctx, cancel := context.WithCancel(parentCtx)
	cfg := l // copy

	switch l.Protocol {
	case "udp":
		if dm.tsIP == "" {
			cancel()
			return fmt.Errorf("no tailscale IPv4 for UDP listener %s", l.Name)
		}
		pc, err := dm.ts.ListenPacket("udp", fmt.Sprintf("%s:%s", dm.tsIP, l.Port()))
		if err != nil {
			cancel()
			return fmt.Errorf("listen udp %s: %w", l.Name, err)
		}
		dm.logger.Info("dynamic udp listener started", "name", l.Name, "addr", l.Listen)
		go func() {
			<-lctx.Done()
			_ = pc.Close()
		}()
		go func() {
			if err := dm.udpProxy.Serve(lctx, pc, cfg.Forward, dm.listenerMgr.resolver, dm.listenerMgr.engine, cfg.Name); err != nil {
				dm.logger.Debug("dynamic udp listener ended", "name", cfg.Name, "err", err)
			}
		}()
	default: // tcp
		port, err := strconv.ParseUint(l.Port(), 10, 16)
		if err != nil {
			cancel()
			return fmt.Errorf("invalid port for %s: %w", l.Name, err)
		}

		// VIP service listener — reachable via the service's virtual IP.
		// tsnet's internal proxy injects a PROXY v2 header with the real
		// client address; wrap with proxyproto.Listener to parse it so
		// conn.RemoteAddr() returns the original caller's tailscale IP.
		rawSvcLn, err := dm.ts.ListenTCPService(dm.svcName, uint16(port))
		if err != nil {
			cancel()
			return fmt.Errorf("listen service tcp %s: %w", l.Name, err)
		}
		svcLn := &proxyproto.Listener{Listener: rawSvcLn}
		dm.logger.Info("service listener started", "name", l.Name, "service", dm.svcName, "port", port)
		go func() {
			if err := dm.listenerMgr.Serve(lctx, svcLn, &cfg); err != nil {
				dm.logger.Debug("service listener ended", "name", cfg.Name, "err", err)
			}
		}()

		// Node IP listener — reachable via the node's direct tailscale IP.
		nodeLn, err := dm.ts.Listen("tcp", ":"+l.Port())
		if err != nil {
			dm.logger.Warn("node listener failed, VIP-only", "name", l.Name, "port", port, "err", err)
		} else {
			dm.logger.Info("node listener started", "name", l.Name, "port", port)
			go func() {
				if err := dm.listenerMgr.Serve(lctx, nodeLn, &cfg); err != nil {
					dm.logger.Debug("node listener ended", "name", cfg.Name, "err", err)
				}
			}()
		}
	}

	dm.active[l.Name] = &dynamicListener{cfg: l, cancel: cancel}
	return nil
}

// StopAll cancels all active dynamic listeners.
// The VIP service is intentionally NOT deleted — multiple replicas may share it.
func (dm *DynamicListenerManager) StopAll() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	for name, dl := range dm.active {
		dm.logger.Info("stopping dynamic listener", "name", name)
		dl.cancel()
	}
	dm.active = make(map[string]*dynamicListener)
}
