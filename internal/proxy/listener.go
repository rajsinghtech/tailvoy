package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// Acceptor abstracts over tsnet.Listen vs net.Listen for testing.
type Acceptor interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// ListenerManager manages a tsnet listener, resolving identities and gating
// connections through L4 policy before forwarding via L4Proxy.
type ListenerManager struct {
	engine   *policy.Engine
	resolver *identity.Resolver
	l4proxy  *L4Proxy
	logger   *slog.Logger
}

// NewListenerManager creates a ListenerManager with the given dependencies.
func NewListenerManager(engine *policy.Engine, resolver *identity.Resolver, l4proxy *L4Proxy, logger *slog.Logger) *ListenerManager {
	return &ListenerManager{
		engine:   engine,
		resolver: resolver,
		l4proxy:  l4proxy,
		logger:   logger,
	}
}

// Serve runs the accept loop on ln, spawning a goroutine per connection.
// It returns when ctx is cancelled or the listener is closed.
func (lm *ListenerManager) Serve(ctx context.Context, ln Acceptor, listenerCfg *config.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	// Close the listener when context is cancelled to unblock Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			lm.logger.Error("accept error", "listener", listenerCfg.Name, "err", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			lm.handleConn(ctx, conn, listenerCfg)
		}()
	}
}

// handleConn resolves the caller identity, checks L4 policy, and forwards
// the connection if allowed.
func (lm *ListenerManager) handleConn(ctx context.Context, conn net.Conn, listenerCfg *config.Listener) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	id, err := lm.resolver.Resolve(ctx, remoteAddr)
	if err != nil {
		lm.logger.Warn("identity resolution failed",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"err", err,
		)
		return
	}

	// For non-L7 TCP listeners, peek TLS ClientHello for SNI.
	var sni string
	if !listenerCfg.L7Policy && listenerCfg.Protocol == "tcp" {
		var reader io.Reader
		sni, reader, _ = PeekSNI(conn)
		if reader != nil {
			conn = &readerConn{Conn: conn, reader: reader}
		}
	}

	if !lm.engine.HasAccess(listenerCfg.Name, sni, id) {
		lm.logger.Info("connection denied by L4 policy",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"sni", sni,
			"identity", id.UserLogin,
			"node", id.NodeName,
		)
		return
	}

	useProxyProto := listenerCfg.ProxyProtocol == "v2"

	if err := lm.l4proxy.Forward(ctx, conn, listenerCfg.Forward, conn.RemoteAddr(), useProxyProto); err != nil {
		lm.logger.Debug("forward ended",
			"listener", listenerCfg.Name,
			"remote", remoteAddr,
			"err", err,
		)
	}
}
