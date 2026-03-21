package bridge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeServiceListener creates real local TCP listeners keyed by name:port.
type fakeServiceListener struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
}

func newFakeServiceListener() *fakeServiceListener {
	return &fakeServiceListener{listeners: make(map[string]net.Listener)}
}

func (f *fakeServiceListener) ListenService(name string, port uint16) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.listeners[fmt.Sprintf("%s:%d", name, port)] = ln
	f.mu.Unlock()
	return ln, nil
}

// directDialer dials real TCP connections (used to reach the echo server).
type directDialer struct{}

func (d *directDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// blockingDialer blocks until the context is cancelled.
type blockingDialer struct{}

func (b *blockingDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// startEchoServer starts a TCP server that echoes data back and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(conn, conn)
		}
	}()
	return ln.Addr().String()
}

func TestBiCopy(t *testing.T) {
	// Use four pipe halves: two client-facing, two server-facing.
	// clientA <-> sideA <--biCopy--> sideB <-> clientB
	clientA, sideA := net.Pipe()
	clientB, sideB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		biCopy(ctx, sideA, sideB)
	}()

	buf := make([]byte, 5)

	// a→b: write to clientA, read from clientB.
	if _, err := clientA.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	clientB.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(clientB, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected hello, got %q", buf)
	}

	// b→a: write to clientB, read from clientA.
	if _, err := clientB.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	clientA.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(clientA, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("expected world, got %q", buf)
	}

	// Close clientA; clientB should eventually get EOF.
	clientA.Close()
	clientB.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := clientB.Read(buf)
	if n != 0 || err == nil {
		t.Fatalf("expected EOF after close, got n=%d err=%v", n, err)
	}

	// biCopy should finish once both directions are done; cancel ctx to unblock.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("biCopy did not return after context cancel")
	}
}

func TestForwarder_Lifecycle(t *testing.T) {
	echoAddr := startEchoServer(t)

	// Use a directDialer pointing at our echo server by overriding addr in DeviceInfo.
	host, port, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = port

	// Parse port as int.
	var echoPort int
	fmt.Sscan(port, &echoPort)

	sl := newFakeServiceListener()
	logger := slog.Default()
	fwd := NewForwarder(sl, &directDialer{}, "br-", 5*time.Second, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	devices := map[string]DeviceInfo{
		"web-1.tail.ts.net": {
			FQDN:      "web-1.tail.ts.net",
			Addresses: []string{host},
			Ports:     []int{echoPort},
		},
	}

	if err := fwd.Reconcile(ctx, devices); err != nil {
		t.Fatal(err)
	}

	fwd.mu.Lock()
	if len(fwd.active) != 1 {
		t.Fatalf("expected 1 active listener, got %d", len(fwd.active))
	}
	fwd.mu.Unlock()

	// Find the listener address.
	sl.mu.Lock()
	var lnAddr string
	for _, ln := range sl.listeners {
		lnAddr = ln.Addr().String()
	}
	sl.mu.Unlock()

	conn, err := net.DialTimeout("tcp", lnAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected ping echo, got %q", buf)
	}
}

func TestForwarder_DialTimeout(t *testing.T) {
	sl := newFakeServiceListener()
	logger := slog.Default()
	fwd := NewForwarder(sl, &blockingDialer{}, "br-", 100*time.Millisecond, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	devices := map[string]DeviceInfo{
		"slow.tail.ts.net": {
			FQDN:      "slow.tail.ts.net",
			Addresses: []string{"127.0.0.1"},
			Ports:     []int{9999},
		},
	}

	if err := fwd.Reconcile(ctx, devices); err != nil {
		t.Fatal(err)
	}

	sl.mu.Lock()
	var lnAddr string
	for _, ln := range sl.listeners {
		lnAddr = ln.Addr().String()
	}
	sl.mu.Unlock()

	conn, err := net.DialTimeout("tcp", lnAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Dial timeout is 100ms; connection should be closed well within 2s.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after dial timeout")
	}
}

func TestForwarder_Reconcile(t *testing.T) {
	sl := newFakeServiceListener()
	logger := slog.Default()
	fwd := NewForwarder(sl, &directDialer{}, "br-", 5*time.Second, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First reconcile: device A port 80.
	devA := map[string]DeviceInfo{
		"a.tail.ts.net": {
			FQDN:      "a.tail.ts.net",
			Addresses: []string{"127.0.0.1"},
			Ports:     []int{80},
		},
	}
	if err := fwd.Reconcile(ctx, devA); err != nil {
		t.Fatal(err)
	}

	fwd.mu.Lock()
	if len(fwd.active) != 1 {
		t.Fatalf("after first reconcile: expected 1 active, got %d", len(fwd.active))
	}
	keyA := fwd.activeKey("a.tail.ts.net", 80)
	if _, ok := fwd.active[keyA]; !ok {
		t.Fatalf("expected key %q in active", keyA)
	}
	fwd.mu.Unlock()

	// Second reconcile: device B port 443 (device A should be removed).
	devB := map[string]DeviceInfo{
		"b.tail.ts.net": {
			FQDN:      "b.tail.ts.net",
			Addresses: []string{"127.0.0.1"},
			Ports:     []int{443},
		},
	}
	if err := fwd.Reconcile(ctx, devB); err != nil {
		t.Fatal(err)
	}

	// Give the goroutine a moment to process the cancellation.
	time.Sleep(50 * time.Millisecond)

	fwd.mu.Lock()
	if len(fwd.active) != 1 {
		t.Fatalf("after second reconcile: expected 1 active, got %d", len(fwd.active))
	}
	keyB := fwd.activeKey("b.tail.ts.net", 443)
	if _, ok := fwd.active[keyB]; !ok {
		t.Fatalf("expected key %q in active", keyB)
	}
	if _, ok := fwd.active[keyA]; ok {
		t.Fatalf("key %q should have been removed", keyA)
	}
	fwd.mu.Unlock()
}
