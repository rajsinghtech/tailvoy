package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

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

func (f *fakeTSNet) ListenTCPService(name string, port uint16) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%s:%d", name, port)
	f.listeners[key] = ln
	return ln, nil
}

func testDynLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestDynMgr() (*DynamicListenerManager, *fakeTSNet) {
	ts := newFakeTSNet()
	engine := policy.NewEngine()
	var resolver *identity.Resolver
	l4 := NewL4Proxy(testDynLogger())
	lm := NewListenerManager(engine, resolver, l4, testDynLogger())
	return NewDynamicListenerManager(ts, lm, nil, "svc:test", testDynLogger()), ts
}

func flatListener(name string, port int, forward string) config.FlatListener {
	return config.FlatListener{
		Name:      name,
		Port:      port,
		Protocol:  "tcp",
		Transport: "tcp",
		Forward:   forward,
	}
}

func TestReconcile_AddNewListeners(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
		flatListener("api", 9090, "127.0.0.1:9090"),
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

	initial := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
		flatListener("api", 9090, "127.0.0.1:9090"),
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

	reduced := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
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

	initial := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

	changed := []config.FlatListener{
		flatListener("web", 9090, "127.0.0.1:9090"),
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
	if active.fl.Port != 9090 {
		t.Errorf("port = %d, want 9090", active.fl.Port)
	}
}

func TestReconcile_NoopOnUnchanged(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
	}
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatal(err)
	}

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

	desired := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
		flatListener("api", 9090, "127.0.0.1:9090"),
	}
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatal(err)
	}

	dm.StopAll()
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

	initial := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
	}
	if err := dm.Reconcile(ctx, initial); err != nil {
		t.Fatal(err)
	}

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

func TestReconcile_SkipsUDPListeners(t *testing.T) {
	dm, _ := newTestDynMgr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	desired := []config.FlatListener{
		flatListener("web", 8080, "127.0.0.1:8080"),
		{Name: "dns", Port: 53, Protocol: "udp", Transport: "udp", Forward: "127.0.0.1:53"},
	}
	if err := dm.Reconcile(ctx, desired); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	dm.mu.Lock()
	count := len(dm.active)
	_, udpExists := dm.active["dns"]
	dm.mu.Unlock()

	if count != 1 {
		t.Errorf("active count = %d, want 1 (UDP should be skipped)", count)
	}
	if udpExists {
		t.Error("UDP listener should have been skipped")
	}
}
