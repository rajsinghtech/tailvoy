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
)

// TSNetServer abstracts the tsnet.Server methods used by DynamicListenerManager.
type TSNetServer interface {
	Listen(network, addr string) (net.Listener, error)
	ListenTCPService(name string, port uint16) (net.Listener, error)
}

// DynamicListenerManager reconciles tsnet listeners against a desired set
// of FlatListener entries, starting and stopping listeners as needed.
type DynamicListenerManager struct {
	ts                TSNetServer
	listenerMgr       *ListenerManager
	listenerToService map[string]string
	logger            *slog.Logger

	mu     sync.Mutex
	active map[string]*dynamicListener
}

type dynamicListener struct {
	fl     config.FlatListener
	cancel context.CancelFunc
}

func NewDynamicListenerManager(ts TSNetServer, lm *ListenerManager, listenerToService map[string]string, logger *slog.Logger) *DynamicListenerManager {
	return &DynamicListenerManager{
		ts:                ts,
		listenerMgr:       lm,
		listenerToService: listenerToService,
		logger:            logger,
		active:            make(map[string]*dynamicListener),
	}
}

func (dm *DynamicListenerManager) Reconcile(ctx context.Context, desired []config.FlatListener) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	var tcpDesired []config.FlatListener
	for _, fl := range desired {
		if fl.Transport == config.ProtocolUDP {
			dm.logger.Warn("UDP listener skipped, not supported in discovery mode", "listener", fl.Name)
			continue
		}
		tcpDesired = append(tcpDesired, fl)
	}

	desiredMap := make(map[string]config.FlatListener, len(tcpDesired))
	for _, fl := range tcpDesired {
		desiredMap[fl.Name] = fl
	}

	for name, dl := range dm.active {
		want, exists := desiredMap[name]
		if !exists {
			dm.logger.Info("stopping removed listener", "name", name)
			dl.cancel()
			delete(dm.active, name)
			continue
		}
		if dl.fl.Port != want.Port || dl.fl.Forward != want.Forward || dl.fl.IsL7 != want.IsL7 {
			dm.logger.Info("restarting changed listener", "name", name)
			dl.cancel()
			delete(dm.active, name)
		}
	}

	var errs []error
	for _, fl := range tcpDesired {
		if _, exists := dm.active[fl.Name]; exists {
			continue
		}
		svcName := dm.listenerToService[fl.Name]
		if svcName == "" {
			dm.logger.Warn("unmapped listener skipped", "name", fl.Name)
			continue
		}
		if err := dm.startListener(ctx, fl, svcName); err != nil {
			errs = append(errs, fmt.Errorf("start %s: %w", fl.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d listener(s) failed to start: %v", len(errs), errs)
	}
	return nil
}

func (dm *DynamicListenerManager) startListener(parentCtx context.Context, fl config.FlatListener, svcName string) error {
	lctx, cancel := context.WithCancel(parentCtx)

	port := uint16(fl.Port)

	rawSvcLn, err := dm.ts.ListenTCPService(svcName, port)
	if err != nil {
		cancel()
		return fmt.Errorf("listen service tcp %s: %w", fl.Name, err)
	}
	svcLn := &proxyproto.Listener{Listener: rawSvcLn}
	dm.logger.Info("service listener started", "name", fl.Name, "service", svcName, "port", port)
	go func() {
		if err := dm.listenerMgr.Serve(lctx, svcLn, &fl); err != nil {
			dm.logger.Debug("service listener ended", "name", fl.Name, "err", err)
		}
	}()

	nodeLn, err := dm.ts.Listen("tcp", ":"+strconv.Itoa(fl.Port))
	if err != nil {
		dm.logger.Warn("node listener failed, VIP-only", "name", fl.Name, "port", port, "err", err)
	} else {
		dm.logger.Info("node listener started", "name", fl.Name, "port", port)
		go func() {
			if err := dm.listenerMgr.Serve(lctx, nodeLn, &fl); err != nil {
				dm.logger.Debug("node listener ended", "name", fl.Name, "err", err)
			}
		}()
	}

	dm.active[fl.Name] = &dynamicListener{fl: fl, cancel: cancel}
	return nil
}

func (dm *DynamicListenerManager) StopAll() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	for name, dl := range dm.active {
		dm.logger.Info("stopping dynamic listener", "name", name)
		dl.cancel()
	}
	dm.active = make(map[string]*dynamicListener)
}
