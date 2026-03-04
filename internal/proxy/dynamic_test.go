package proxy

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// fakeTSNet implements TSNetServer for testing.
type fakeTSNet struct {
	listeners map[string]net.Listener
}

func newFakeTSNet() *fakeTSNet {
	return &fakeTSNet{listeners: make(map[string]net.Listener)}
}

func (f *fakeTSNet) Listen(network, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.listeners[addr] = ln
	return ln, nil
}

func (f *fakeTSNet) ListenPacket(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func testDynLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestDynMgr() (*DynamicListenerManager, *fakeTSNet) {
	ts := newFakeTSNet()
	engine := policy.NewEngine()
	// Use a nil local client resolver — we won't actually resolve identities in these tests.
	var resolver *identity.Resolver
	l4 := NewL4Proxy(testDynLogger())
	udp := NewUDPProxy(testDynLogger())
	lm := NewListenerManager(engine, resolver, l4, testDynLogger())
	return NewDynamicListenerManager(ts, lm, udp, testDynLogger(), "100.64.0.1"), ts
}

func TestReconcile_AddNewListeners(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
		{Name: "api", Protocol: "tcp", Listen: ":9090", Forward: "127.0.0.1:9090"},
	}

	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	dm.mu.Unlock()

	if count != 2 {
		t.Errorf("active count = %d, want 2", count)
	}
}

func TestReconcile_RemoveListeners(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with two.
	initial := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
		{Name: "api", Protocol: "tcp", Listen: ":9090", Forward: "127.0.0.1:9090"},
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

	// Remove one.
	reduced := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
	}
	if err := dm.Reconcile(ctx, reduced); err != nil {
		t.Fatal(err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	_, apiExists := dm.active["api"]
	dm.mu.Unlock()

	if count != 1 {
		t.Errorf("active count = %d, want 1", count)
	}
	if apiExists {
		t.Error("api listener should have been removed")
	}
}

func TestReconcile_ChangeListener(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

	// Change port.
	changed := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":9090", Forward: "127.0.0.1:9090"},
	}
	if err := dm.Reconcile(ctx, changed); err != nil {
		t.Fatal(err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	active := dm.active["web"]
	dm.mu.Unlock()

	if count != 1 {
		t.Errorf("active count = %d, want 1", count)
	}
	if active.cfg.Listen != ":9090" {
		t.Errorf("listen = %q, want :9090", active.cfg.Listen)
	}
}

func TestReconcile_NoopOnUnchanged(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
	}
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatal(err)
	}

	// Same desired set — should be a no-op.
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatal(err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	dm.mu.Unlock()

	if count != 1 {
		t.Errorf("active count = %d, want 1", count)
	}
}

func TestStopAll(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
		{Name: "api", Protocol: "tcp", Listen: ":9090", Forward: "127.0.0.1:9090"},
	}
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatal(err)
	}

	dm.StopAll()

	// Give goroutines a moment to wind down.
	time.Sleep(10 * time.Millisecond)

	dm.mu.Lock()
	count := len(dm.active)
	dm.mu.Unlock()

	if count != 0 {
		t.Errorf("active count = %d, want 0 after StopAll", count)
	}
}

func TestReconcile_EmptyDesired(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial := []config.Listener{
		{Name: "web", Protocol: "tcp", Listen: ":8080", Forward: "127.0.0.1:8080"},
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

	// Reconcile with empty desired — all should be stopped.
	if err := dm.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	dm.mu.Unlock()

	if count != 0 {
		t.Errorf("active count = %d, want 0", count)
	}
}
