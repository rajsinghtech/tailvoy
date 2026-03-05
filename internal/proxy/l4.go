package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

const dialTimeout = 10 * time.Second

// L4Proxy forwards raw TCP connections with optional PROXY protocol v2 headers.
type L4Proxy struct {
	logger *slog.Logger
	dialer net.Dialer
}

func NewL4Proxy(logger *slog.Logger) *L4Proxy {
	return &L4Proxy{
		logger: logger,
		dialer: net.Dialer{Timeout: dialTimeout},
	}
}

// Forward dials backendAddr, optionally writes a PROXY protocol v2 header
// conveying srcAddr, then bidirectionally copies data between client and the
// backend until one side closes or ctx is cancelled.
func (p *L4Proxy) Forward(ctx context.Context, client net.Conn, backendAddr string, srcAddr net.Addr, useProxyProto bool) error {
	backend, err := p.dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("dial backend %s: %w", backendAddr, err)
	}
	defer backend.Close()

	if useProxyProto && srcAddr != nil {
		if err := writeProxyHeader(backend, srcAddr, backend.LocalAddr()); err != nil {
			return fmt.Errorf("write proxy header: %w", err)
		}
	}

	// Context cancellation: close both sides to unblock io.Copy goroutines.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
			backend.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// client -> backend
	go func() {
		defer wg.Done()
		_, err := io.Copy(backend, client)
		if err != nil {
			p.logger.Debug("client->backend copy ended", "err", err)
		}
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// backend -> client
	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		if err != nil {
			p.logger.Debug("backend->client copy ended", "err", err)
		}
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	close(done)
	return nil
}

// writeProxyHeader sends a PROXY protocol v2 header on dst.
func writeProxyHeader(dst net.Conn, srcAddr, dstAddr net.Addr) error {
	src, ok := srcAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("srcAddr is not *net.TCPAddr: %T", srcAddr)
	}
	d, ok := dstAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("dstAddr is not *net.TCPAddr: %T", dstAddr)
	}

	tp := proxyproto.TCPv4
	if src.IP.To4() == nil {
		tp = proxyproto.TCPv6
	}

	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: tp,
		SourceAddr:        src,
		DestinationAddr:   d,
	}
	_, err := h.WriteTo(dst)
	return err
}
