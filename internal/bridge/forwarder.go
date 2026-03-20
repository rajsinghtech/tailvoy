package bridge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Dialer abstracts srcServer.Dial for testing.
type Dialer interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

// ServiceListener abstracts destServer.ListenService for testing.
type ServiceListener interface {
	ListenService(name string, port uint16) (net.Listener, error)
}

// Forwarder manages per-device VIP service listeners.
type Forwarder struct {
	destListener ServiceListener
	srcDialer    Dialer
	prefix       string
	dialTimeout  time.Duration
	logger       *slog.Logger
	mu           sync.Mutex
	active       map[string]context.CancelFunc // key: activeKey(fqdn, port)
}

func NewForwarder(dest ServiceListener, src Dialer, prefix string, dialTimeout time.Duration, logger *slog.Logger) *Forwarder {
	return &Forwarder{
		destListener: dest,
		srcDialer:    src,
		prefix:       prefix,
		dialTimeout:  dialTimeout,
		logger:       logger,
		active:       make(map[string]context.CancelFunc),
	}
}

func (f *Forwarder) activeKey(fqdn string, port int) string {
	return fmt.Sprintf("%s:%d", ServiceName(fqdn, f.prefix), port)
}

// Reconcile starts/stops listeners based on desired device set.
func (f *Forwarder) Reconcile(ctx context.Context, devices map[string]DeviceInfo) error {
	// Build desired set.
	desired := make(map[string]struct{})
	for _, dev := range devices {
		for _, port := range dev.Ports {
			desired[f.activeKey(dev.FQDN, port)] = struct{}{}
		}
	}

	f.mu.Lock()
	// Stop listeners not in desired set.
	for key, cancel := range f.active {
		if _, ok := desired[key]; !ok {
			cancel()
			delete(f.active, key)
		}
	}
	f.mu.Unlock()

	// Start new listeners.
	for _, dev := range devices {
		addr := ""
		if len(dev.Addresses) > 0 {
			addr = dev.Addresses[0]
		}
		for _, port := range dev.Ports {
			key := f.activeKey(dev.FQDN, port)

			f.mu.Lock()
			_, exists := f.active[key]
			f.mu.Unlock()
			if exists {
				continue
			}

			svcName := ServiceName(dev.FQDN, f.prefix)
			ln, err := f.destListener.ListenService(svcName, uint16(port))
			if err != nil {
				return fmt.Errorf("listen service %s:%d: %w", svcName, port, err)
			}

			lctx, cancel := context.WithCancel(ctx)

			f.mu.Lock()
			f.active[key] = cancel
			f.mu.Unlock()

			go f.acceptLoop(lctx, ln, addr, port)
		}
	}
	return nil
}

func (f *Forwarder) acceptLoop(lctx context.Context, ln net.Listener, addr string, port int) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if lctx.Err() != nil {
				return
			}
			continue
		}
		go func() {
			defer conn.Close()
			dialCtx, dialCancel := context.WithTimeout(lctx, f.dialTimeout)
			defer dialCancel()
			backend, err := f.srcDialer.Dial(dialCtx, "tcp", fmt.Sprintf("%s:%d", addr, port))
			if err != nil {
				f.logger.Error("bridge dial failed", "target", addr, "port", port, "err", err)
				return
			}
			defer backend.Close()
			biCopy(lctx, conn, backend)
		}()
	}
}

// StopAll cancels all active listeners.
func (f *Forwarder) StopAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, cancel := range f.active {
		cancel()
		delete(f.active, key)
	}
}

// biCopy copies data bidirectionally between two connections.
func biCopy(ctx context.Context, a, b net.Conn) {
	go func() {
		<-ctx.Done()
		a.Close()
		b.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}
