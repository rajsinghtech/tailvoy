package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// mockWhoIs implements identity.WhoIsClient with a static response map keyed by IP.
type mockWhoIs struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockWhoIs) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	ip := identity.StripPort(addr)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("not found: %s", ip)
}

// tailvoyCapMap builds a PeerCapMap with the tailvoy capability containing
// the given route patterns. Use "/*" for full access.
func tailvoyCapMap(routes ...string) tailcfg.PeerCapMap {
	rule := identity.TailvoyCapRule{Routes: routes}
	b, _ := json.Marshal(rule)
	return tailcfg.PeerCapMap{
		identity.CapTailvoy: []tailcfg.RawMessage{tailcfg.RawMessage(b)},
	}
}

func tcpFlatListener(name, backend string) *config.FlatListener {
	return &config.FlatListener{
		Name:           name,
		Protocol:       "tcp",
		Transport:      "tcp",
		IsL7:           false,
		DefaultBackend: backend,
		Forward:        backend,
		ProxyProtocol:  false,
	}
}

func TestListenerManagerAllowAndForward(t *testing.T) {
	backend := startEchoServer(t)

	fl := tcpFlatListener("echo", backend.Addr().String())

	whois := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node: &tailcfg.Node{
					Name: "testnode.tail1234.ts.net.",
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName: "user@example.com",
				},
				CapMap: tailvoyCapMap("/*"),
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- lm.Serve(ctx, ln, fl)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello listener manager")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	conn.Close()
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return in time")
	}
}

func TestListenerManagerRapidConnectDisconnect(t *testing.T) {
	backend := startEchoServer(t)
	fl := tcpFlatListener("rapid", backend.Addr().String())

	whois := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node:        &tailcfg.Node{Name: "node.ts.net."},
				UserProfile: &tailcfg.UserProfile{LoginName: "user@example.com"},
				CapMap:      tailvoyCapMap("/*"),
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go lm.Serve(ctx, ln, fl)

	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
	cancel()
}

func TestListenerManagerConcurrentConnections(t *testing.T) {
	backend := startEchoServer(t)
	fl := tcpFlatListener("concurrent", backend.Addr().String())

	whois := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node:        &tailcfg.Node{Name: "node.ts.net."},
				UserProfile: &tailcfg.UserProfile{LoginName: "user@example.com"},
				CapMap:      tailvoyCapMap("/*"),
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go lm.Serve(ctx, ln, fl)

	const numConns = 10
	var wg sync.WaitGroup
	wg.Add(numConns)

	for i := 0; i < numConns; i++ {
		go func(idx int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Errorf("conn %d: dial: %v", idx, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("hello-%d", idx)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Errorf("conn %d: write: %v", idx, err)
				return
			}

			buf := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Errorf("conn %d: read: %v", idx, err)
				return
			}

			if string(buf) != msg {
				t.Errorf("conn %d: got %q, want %q", idx, buf, msg)
			}
		}(i)
	}

	wg.Wait()
	cancel()
}

// slowWhoIs implements identity.WhoIsClient with an artificial delay.
type slowWhoIs struct {
	delay     time.Duration
	responses map[string]*apitype.WhoIsResponse
}

func (m *slowWhoIs) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	select {
	case <-time.After(m.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ip := identity.StripPort(addr)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("not found: %s", ip)
}

func TestListenerManagerSlowIdentityResolution(t *testing.T) {
	backend := startEchoServer(t)
	fl := tcpFlatListener("slow", backend.Addr().String())

	whois := &slowWhoIs{
		delay: 500 * time.Millisecond,
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node:        &tailcfg.Node{Name: "node.ts.net."},
				UserProfile: &tailcfg.UserProfile{LoginName: "user@example.com"},
				CapMap:      tailvoyCapMap("/*"),
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go lm.Serve(ctx, ln, fl)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("after-slow-resolve")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	conn.Close()
	cancel()
}

func TestListenerManagerContextCancellationDuringServe(t *testing.T) {
	backend := startEchoServer(t)
	fl := tcpFlatListener("canceltest", backend.Addr().String())

	whois := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node:        &tailcfg.Node{Name: "node.ts.net."},
				UserProfile: &tailcfg.UserProfile{LoginName: "user@example.com"},
				CapMap:      tailvoyCapMap("/*"),
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- lm.Serve(ctx, ln, fl)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("pre-cancel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return in time after cancellation")
	}
}

func TestListenerManagerDeny(t *testing.T) {
	backend := startEchoServer(t)
	fl := tcpFlatListener("restricted", backend.Addr().String())

	whois := &mockWhoIs{
		responses: map[string]*apitype.WhoIsResponse{
			"127.0.0.1": {
				Node: &tailcfg.Node{
					Name: "rando.tail5678.ts.net.",
				},
				UserProfile: &tailcfg.UserProfile{
					LoginName: "nobody@example.com",
				},
			},
		},
	}

	engine := policy.NewEngine()
	resolver := identity.NewResolver(whois)
	l4proxy := NewL4Proxy(slog.Default())
	lm := NewListenerManager(engine, resolver, l4proxy, slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go lm.Serve(ctx, ln, fl)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("should be denied"))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Fatalf("expected no data back on denied connection, got %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected error (EOF/closed) on denied connection read")
	}

	cancel()
}
