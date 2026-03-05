# OAuth + ListenService Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace authkey auth with OAuth client credentials and switch all TCP listeners from `tsnet.Listen` to `tsnet.ListenService` backed by VIP services.

**Architecture:** tsnet.Server gets OAuth client secret (tskey-client-*) via AuthKey field with AdvertiseTags. A separate tailscale-client-go-v2 Client manages VIP service lifecycle (create/update/delete). ListenService returns local net.Listeners that tailscaled routes VIP traffic to. UDP stays in codebase but is skipped at runtime with a warning since VIP services don't support UDP yet.

**Tech Stack:** Go, tsnet, tailscale-client-go-v2 (rajsinghtech/vip-services branch), VIP Services API

---

### Task 1: Add tailscale-client-go-v2 dependency

**Files:**
- Modify: `go.mod`

**Step 1: Add the dependency**

Run:
```bash
cd /Users/rajsingh/Documents/GitHub/tailvoy
go get tailscale.com/client/tailscale/v2@rajsinghtech/vip-services
go mod tidy
```

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: clean build

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "Add tailscale-client-go-v2 dependency for VIP service management"
```

---

### Task 2: Update config — replace authkey with OAuth fields

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `testdata/policy.yaml`

**Step 1: Write failing tests for new config fields**

Add to `internal/config/config_test.go`:

```go
func TestParse_OAuthConfig(t *testing.T) {
	t.Setenv("TS_CLIENT_ID", "k123")
	t.Setenv("TS_CLIENT_SECRET", "tskey-client-k123-secret")

	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:web"
  serviceTags:
    - "tag:k8s"
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.Tailnet != "example.com" {
		t.Errorf("tailnet = %q, want %q", cfg.Tailscale.Tailnet, "example.com")
	}
	if cfg.Tailscale.ClientID != "k123" {
		t.Errorf("clientId = %q", cfg.Tailscale.ClientID)
	}
	if cfg.Tailscale.ClientSecret != "tskey-client-k123-secret" {
		t.Errorf("clientSecret = %q", cfg.Tailscale.ClientSecret)
	}
	if len(cfg.Tailscale.Tags) != 1 || cfg.Tailscale.Tags[0] != "tag:web" {
		t.Errorf("tags = %v", cfg.Tailscale.Tags)
	}
	if len(cfg.Tailscale.ServiceTags) != 1 || cfg.Tailscale.ServiceTags[0] != "tag:k8s" {
		t.Errorf("serviceTags = %v", cfg.Tailscale.ServiceTags)
	}
}

func TestParse_ServiceNameDefault(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "my-gateway"
  tailnet: "example.com"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.ServiceName() != "svc:my-gateway" {
		t.Errorf("ServiceName() = %q, want %q", cfg.Tailscale.ServiceName(), "svc:my-gateway")
	}
}

func TestParse_ServiceNameExplicit(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "my-gateway"
  service: "svc:custom-name"
  tailnet: "example.com"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
listeners:
  - name: web
    protocol: tcp
    listen: ":80"
    forward: "localhost:80"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Tailscale.ServiceName() != "svc:custom-name" {
		t.Errorf("ServiceName() = %q, want %q", cfg.Tailscale.ServiceName(), "svc:custom-name")
	}
}

func TestValidation_MissingTailnet(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "tailnet is required") {
		t.Errorf("expected tailnet required error, got: %v", err)
	}
}

func TestValidation_MissingClientId(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "clientId is required") {
		t.Errorf("expected clientId required error, got: %v", err)
	}
}

func TestValidation_MissingClientSecret(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientId: "k123"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "clientSecret is required") {
		t.Errorf("expected clientSecret required error, got: %v", err)
	}
}

func TestValidation_MissingTags(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  serviceTags: ["tag:k8s"]
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "tags is required") {
		t.Errorf("expected tags required error, got: %v", err)
	}
}

func TestValidation_MissingServiceTags(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
`)
	_, err := Parse(data)
	if err == nil || !strings.Contains(err.Error(), "serviceTags is required") {
		t.Errorf("expected serviceTags required error, got: %v", err)
	}
}

func TestValidation_UDPListenerWarning(t *testing.T) {
	data := []byte(`
tailscale:
  hostname: "test"
  tailnet: "example.com"
  clientId: "k123"
  clientSecret: "tskey-client-k123-secret"
  tags: ["tag:web"]
  serviceTags: ["tag:k8s"]
listeners:
  - name: dns
    protocol: udp
    listen: ":53"
    forward: "localhost:53"
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// UDP listeners should parse but will be warned/skipped at runtime.
	if len(cfg.Listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(cfg.Listeners))
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && go test ./internal/config/ -run "TestParse_OAuth|TestParse_ServiceName|TestValidation_Missing" -v`
Expected: FAIL (fields don't exist yet)

**Step 3: Update TailscaleConfig struct and validation**

Replace `TailscaleConfig` in `internal/config/config.go`:

```go
type TailscaleConfig struct {
	Hostname     string   `yaml:"hostname"`
	Service      string   `yaml:"service"`
	Tailnet      string   `yaml:"tailnet"`
	ClientID     string   `yaml:"clientId"`
	ClientSecret string   `yaml:"clientSecret"`
	Tags         []string `yaml:"tags"`
	ServiceTags  []string `yaml:"serviceTags"`
}

// ServiceName returns the VIP service name, defaulting to "svc:<hostname>".
func (t *TailscaleConfig) ServiceName() string {
	if t.Service != "" {
		return t.Service
	}
	return "svc:" + t.Hostname
}
```

Update `validate()` — replace the hostname-only check with:

```go
func (c *Config) validate() error {
	if c.Tailscale.Hostname == "" {
		return fmt.Errorf("tailscale.hostname is required")
	}
	if c.Tailscale.Tailnet == "" {
		return fmt.Errorf("tailscale.tailnet is required")
	}
	if c.Tailscale.ClientID == "" {
		return fmt.Errorf("tailscale.clientId is required")
	}
	if c.Tailscale.ClientSecret == "" {
		return fmt.Errorf("tailscale.clientSecret is required")
	}
	if len(c.Tailscale.Tags) == 0 {
		return fmt.Errorf("tailscale.tags is required (node must be tagged for ListenService)")
	}
	if len(c.Tailscale.ServiceTags) == 0 {
		return fmt.Errorf("tailscale.serviceTags is required (VIP service needs at least one tag)")
	}
	// ... rest of validation unchanged (discovery/listeners)
```

**Step 4: Update testdata/policy.yaml**

```yaml
tailscale:
  hostname: "tailvoy-test"
  tailnet: "test.ts.net"
  clientId: "${TS_CLIENT_ID}"
  clientSecret: "${TS_CLIENT_SECRET}"
  tags:
    - "tag:test"
  serviceTags:
    - "tag:k8s"

listeners:
  - name: https
    protocol: tcp
    listen: ":443"
    forward: "envoy:443"
    proxy_protocol: v2
    l7_policy: true

  - name: postgres
    protocol: tcp
    listen: ":5432"
    forward: "db-server:5432"
    l7_policy: false
```

**Step 5: Fix existing tests that reference old fields**

Update tests that use `AuthKey`, `Ephemeral`, etc. In `TestLoadFromFile`:
- Remove `if !cfg.Tailscale.Ephemeral` check
- Remove/update `TestEnvVarExpansion` to check `ClientSecret` instead of `AuthKey`
- Update `TestParse_AllOptionalFieldsMissing` — now `tailnet`, `clientId`, etc. are required, so this test needs the full config or should expect an error
- Update `TestParse_MinimalConfig` to include required OAuth fields
- Update `TestEnvVarExpansion_UndefinedVariable` to use `clientSecret` instead of `authkey`

**Step 6: Run all config tests**

Run: `go test ./internal/config/ -v`
Expected: all PASS

**Step 7: Run full test suite to find other breakage**

Run: `go test ./... 2>&1 | head -50`
Expected: config tests pass; other packages may fail (will fix in later tasks)

**Step 8: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go testdata/policy.yaml
git commit -m "Replace authkey config with OAuth client credentials and service tags"
```

---

### Task 3: Create VIP service manager package

**Files:**
- Create: `internal/service/service.go`
- Create: `internal/service/service_test.go`

**Step 1: Write failing tests**

Create `internal/service/service_test.go`:

```go
package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeAPI records API calls and returns canned responses.
type fakeAPI struct {
	mu      sync.Mutex
	calls   []apiCall
	handler http.Handler
}

type apiCall struct {
	Method string
	Path   string
	Body   string
}

func newFakeAPI() *fakeAPI {
	f := &fakeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tailnet/test.ts.net/vip-services/", func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		f.mu.Lock()
		f.calls = append(f.calls, apiCall{Method: r.Method, Path: r.URL.Path, Body: body})
		f.mu.Unlock()

		switch r.Method {
		case "PUT":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"name": "svc:test"})
		case "DELETE":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	f.handler = mux
	return f
}

func (f *fakeAPI) getCalls() []apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apiCall{}, f.calls...)
}

func TestManager_Ensure(t *testing.T) {
	fake := newFakeAPI()
	srv := httptest.NewServer(fake.handler)
	defer srv.Close()

	client := &tailscale.Client{
		Tailnet: "test.ts.net",
		BaseURL: srv.URL,
		Auth: &tailscale.OAuth{
			ClientID:     "k123",
			ClientSecret: "tskey-client-k123-secret",
		},
	}

	mgr := New(client, "svc:test", []string{"tag:k8s"}, testLogger())
	if err := mgr.Ensure(context.Background(), []string{"443", "8080"}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	calls := fake.getCalls()
	// Should have at least the OAuth token call and the PUT call
	var putCalls []apiCall
	for _, c := range calls {
		if c.Method == "PUT" {
			putCalls = append(putCalls, c)
		}
	}
	if len(putCalls) != 1 {
		t.Fatalf("expected 1 PUT call, got %d: %+v", len(putCalls), calls)
	}
	if !strings.Contains(putCalls[0].Body, `"tag:k8s"`) {
		t.Errorf("PUT body missing serviceTags: %s", putCalls[0].Body)
	}
	if !strings.Contains(putCalls[0].Body, "Managed by Tailvoy") {
		t.Errorf("PUT body missing comment: %s", putCalls[0].Body)
	}
}

func TestManager_Delete(t *testing.T) {
	fake := newFakeAPI()
	srv := httptest.NewServer(fake.handler)
	defer srv.Close()

	client := &tailscale.Client{
		Tailnet: "test.ts.net",
		BaseURL: srv.URL,
		Auth: &tailscale.OAuth{
			ClientID:     "k123",
			ClientSecret: "tskey-client-k123-secret",
		},
	}

	mgr := New(client, "svc:test", []string{"tag:k8s"}, testLogger())
	if err := mgr.Delete(context.Background()); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	calls := fake.getCalls()
	var delCalls []apiCall
	for _, c := range calls {
		if c.Method == "DELETE" {
			delCalls = append(delCalls, c)
		}
	}
	if len(delCalls) != 1 {
		t.Fatalf("expected 1 DELETE call, got %d", len(delCalls))
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/service/ -v`
Expected: FAIL (package doesn't exist)

**Step 3: Implement service manager**

Create `internal/service/service.go`:

```go
package service

import (
	"context"
	"fmt"
	"log/slog"

	tailscale "tailscale.com/client/tailscale/v2"
)

// Manager handles VIP service lifecycle via the Tailscale API.
type Manager struct {
	client      *tailscale.Client
	serviceName string
	serviceTags []string
	logger      *slog.Logger
}

// New creates a VIP service manager.
func New(client *tailscale.Client, svcName string, tags []string, logger *slog.Logger) *Manager {
	return &Manager{
		client:      client,
		serviceName: svcName,
		serviceTags: tags,
		logger:      logger,
	}
}

// Ensure creates or updates the VIP service with the given ports.
func (m *Manager) Ensure(ctx context.Context, ports []string) error {
	svc := tailscale.VIPService{
		Name:    m.serviceName,
		Tags:    m.serviceTags,
		Ports:   ports,
		Comment: "Managed by Tailvoy",
	}

	m.logger.Info("ensuring VIP service", "name", m.serviceName, "ports", ports, "tags", m.serviceTags)
	if err := m.client.VIPServices().CreateOrUpdate(ctx, svc); err != nil {
		return fmt.Errorf("create/update VIP service %s: %w", m.serviceName, err)
	}
	return nil
}

// Delete removes the VIP service.
func (m *Manager) Delete(ctx context.Context) error {
	m.logger.Info("deleting VIP service", "name", m.serviceName)
	if err := m.client.VIPServices().Delete(ctx, m.serviceName); err != nil {
		return fmt.Errorf("delete VIP service %s: %w", m.serviceName, err)
	}
	return nil
}

// ServiceName returns the service name.
func (m *Manager) ServiceName() string {
	return m.serviceName
}
```

**Step 4: Run tests**

Run: `go test ./internal/service/ -v`
Expected: PASS

Note: The tests might need adjustment based on the exact Go client API surface. If `BaseURL` isn't a public field on `tailscale.Client`, we may need to use the `tailscale.Client` constructor or set up the HTTP transport differently. Verify against the actual client struct and adjust accordingly.

**Step 5: Commit**

```bash
git add internal/service/
git commit -m "Add VIP service lifecycle manager"
```

---

### Task 4: Update DynamicListenerManager for ListenService

**Files:**
- Modify: `internal/proxy/dynamic.go`
- Modify: `internal/proxy/dynamic_test.go`

**Step 1: Update TSNetServer interface**

In `internal/proxy/dynamic.go`, update the interface and struct:

```go
// TSNetServer abstracts the tsnet.Server methods used by DynamicListenerManager.
type TSNetServer interface {
	Listen(network, addr string) (net.Listener, error)
	ListenPacket(network, addr string) (net.PacketConn, error)
	ListenService(name string, mode tsnet.ServiceMode) (*tsnet.ServiceListener, error)
}
```

Add `svcMgr` and `svcName` fields to `DynamicListenerManager`:

```go
type DynamicListenerManager struct {
	ts          TSNetServer
	listenerMgr *ListenerManager
	udpProxy    *UDPProxy
	svcMgr      *service.Manager
	svcName     string
	logger      *slog.Logger
	tsIP        string

	mu     sync.Mutex
	active map[string]*dynamicListener
}
```

Update `NewDynamicListenerManager` signature to accept `svcMgr` and `svcName`.

**Step 2: Update startListener to use ListenService**

Replace the TCP branch in `startListener`:

```go
case "tcp":
	port, err := strconv.ParseUint(l.Port(), 10, 16)
	if err != nil {
		cancel()
		return fmt.Errorf("invalid port for %s: %w", l.Name, err)
	}
	svcLn, err := dm.ts.ListenService(dm.svcName, tsnet.ServiceModeTCP{Port: uint16(port)})
	if err != nil {
		cancel()
		return fmt.Errorf("listen service tcp %s: %w", l.Name, err)
	}
	dm.logger.Info("service listener started", "name", l.Name, "service", dm.svcName, "port", port)
	go func() {
		if err := dm.listenerMgr.Serve(lctx, svcLn, &cfg); err != nil {
			dm.logger.Debug("service listener ended", "name", cfg.Name, "err", err)
		}
	}()
```

**Step 3: Add VIP service sync to Reconcile**

Before the start/stop loop in `Reconcile`, add:

```go
// Collect TCP ports for VIP service update.
var tcpPorts []string
for _, l := range desired {
	if l.Protocol == "udp" {
		dm.logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
		continue
	}
	tcpPorts = append(tcpPorts, l.Port())
}

if dm.svcMgr != nil && len(tcpPorts) > 0 {
	if err := dm.svcMgr.Ensure(ctx, tcpPorts); err != nil {
		return fmt.Errorf("ensure VIP service: %w", err)
	}
}
```

Filter UDP out of the desired slice before the existing start/stop logic.

**Step 4: Update StopAll to delete VIP service**

```go
func (dm *DynamicListenerManager) StopAll() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	for name, dl := range dm.active {
		dm.logger.Info("stopping dynamic listener", "name", name)
		dl.cancel()
	}
	dm.active = make(map[string]*dynamicListener)

	if dm.svcMgr != nil {
		if err := dm.svcMgr.Delete(context.Background()); err != nil {
			dm.logger.Error("failed to delete VIP service on shutdown", "err", err)
		}
	}
}
```

**Step 5: Update fakeTSNet in tests**

In `internal/proxy/dynamic_test.go`, add `ListenService` to `fakeTSNet`:

```go
func (f *fakeTSNet) ListenService(name string, mode tsnet.ServiceMode) (*tsnet.ServiceListener, error) {
	// For testing, create a local TCP listener and return a ServiceListener-like wrapper.
	// Since ServiceListener embeds net.Listener, we need to return something compatible.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.listeners[name] = ln
	// We can't construct a real *tsnet.ServiceListener in tests since its fields
	// are internal. We'll need to adjust the interface to return net.Listener instead.
	return nil, fmt.Errorf("not implemented in fake")
}
```

**Important design note:** `tsnet.ServiceListener` is a concrete struct we can't easily construct in tests. We have two options:
1. Change the interface to return `net.Listener` (since `ServiceListener` embeds it)
2. Create a wrapper interface

Option 1 is cleaner — change `ListenService` in the interface to:

```go
type TSNetServer interface {
	Listen(network, addr string) (net.Listener, error)
	ListenPacket(network, addr string) (net.PacketConn, error)
	ListenTCPService(name string, port uint16) (net.Listener, error)
}
```

Then create a thin adapter in `cmd/tailvoy/main.go`:

```go
type tsnetAdapter struct {
	*tsnet.Server
}

func (a *tsnetAdapter) ListenTCPService(name string, port uint16) (net.Listener, error) {
	return a.Server.ListenService(name, tsnet.ServiceModeTCP{Port: port})
}
```

Update `fakeTSNet` accordingly:

```go
func (f *fakeTSNet) ListenTCPService(name string, port uint16) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f.listeners[fmt.Sprintf("%s:%d", name, port)] = ln
	return ln, nil
}
```

Update `newTestDynMgr` to pass `nil` for svcMgr (unit tests don't need VIP service calls):

```go
func newTestDynMgr() (*DynamicListenerManager, *fakeTSNet) {
	ts := newFakeTSNet()
	engine := policy.NewEngine()
	var resolver *identity.Resolver
	l4 := NewL4Proxy(testDynLogger())
	udp := NewUDPProxy(testDynLogger())
	lm := NewListenerManager(engine, resolver, l4, testDynLogger())
	return NewDynamicListenerManager(ts, lm, udp, nil, "", testDynLogger(), "100.64.0.1"), ts
}
```

**Step 6: Run tests**

Run: `go test ./internal/proxy/ -v -run TestReconcile`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/proxy/dynamic.go internal/proxy/dynamic_test.go
git commit -m "Switch DynamicListenerManager to ListenService with VIP service sync"
```

---

### Task 5: Wire OAuth + ListenService in main.go

**Files:**
- Modify: `cmd/tailvoy/main.go`

**Step 1: Update tsnet.Server construction**

Replace the current tsnet block:

```go
// Build Tailscale API client for VIP service management.
tsClient := &tailscale.Client{
	Tailnet: cfg.Tailscale.Tailnet,
	Auth: &tailscale.OAuth{
		ClientID:     cfg.Tailscale.ClientID,
		ClientSecret: cfg.Tailscale.ClientSecret,
	},
}

// Start tsnet with OAuth credentials.
ts := &tsnet.Server{
	Hostname:      cfg.Tailscale.Hostname,
	AuthKey:       cfg.Tailscale.ClientSecret,
	Ephemeral:     true,
	AdvertiseTags: cfg.Tailscale.Tags,
}
defer func() { _ = ts.Close() }()
```

Add imports for `tailscale.com/client/tailscale/v2` and `github.com/rajsinghtech/tailvoy/internal/service`.

**Step 2: Create tsnet adapter**

Add after the tsnet block:

```go
tsAdapter := &tsnetAdapter{Server: ts}
```

And define the adapter type:

```go
type tsnetAdapter struct {
	*tsnet.Server
}

func (a *tsnetAdapter) ListenTCPService(name string, port uint16) (net.Listener, error) {
	return a.Server.ListenService(name, tsnet.ServiceModeTCP{Port: port})
}
```

**Step 3: Create VIP service manager**

```go
svcMgr := service.New(tsClient, cfg.Tailscale.ServiceName(), cfg.Tailscale.ServiceTags, logger)
```

**Step 4: Update discovery mode wiring**

Replace the discovery block to pass `svcMgr` and `svcName`:

```go
if cfg.Discovery != nil {
	disc, err := discovery.New(cfg.Discovery, logger)
	if err != nil {
		cancel()
		wg.Wait()
		return fmt.Errorf("discovery setup: %w", err)
	}
	dynMgr := proxy.NewDynamicListenerManager(tsAdapter, listenerMgr, udpProxy, svcMgr, cfg.Tailscale.ServiceName(), logger, tsIP)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer dynMgr.StopAll()
		for listeners := range disc.Watch(ctx) {
			if err := dynMgr.Reconcile(ctx, listeners); err != nil {
				logger.Error("reconcile error", "err", err)
			}
		}
	}()
}
```

**Step 5: Update static mode wiring**

Replace the static listener loop:

```go
} else {
	// Collect TCP ports for VIP service.
	var tcpPorts []string
	var tcpListeners []*config.Listener
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.Protocol == "udp" {
			logger.Warn("UDP listeners not supported with VIP services, skipping", "name", l.Name)
			continue
		}
		tcpPorts = append(tcpPorts, l.Port())
		tcpListeners = append(tcpListeners, l)
	}

	// Create/update VIP service.
	if len(tcpPorts) > 0 {
		if err := svcMgr.Ensure(ctx, tcpPorts); err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("ensure VIP service: %w", err)
		}
	}

	svcName := cfg.Tailscale.ServiceName()

	// Start TCP listeners via ListenService.
	for _, l := range tcpListeners {
		l := l
		port, err := strconv.ParseUint(l.Port(), 10, 16)
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("invalid port for %s: %w", l.Name, err)
		}

		ln, err := ts.ListenService(svcName, tsnet.ServiceModeTCP{Port: uint16(port)})
		if err != nil {
			cancel()
			wg.Wait()
			return fmt.Errorf("listen service %s (port %d): %w", l.Name, port, err)
		}
		logger.Info("service listener started", "name", l.Name, "service", svcName, "port", port)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := listenerMgr.Serve(ctx, ln, l); err != nil {
				logger.Error("listener error", "name", l.Name, "err", err)
			}
		}()
	}

	// Register cleanup: delete VIP service on shutdown.
	defer func() {
		if err := svcMgr.Delete(context.Background()); err != nil {
			logger.Error("failed to delete VIP service on shutdown", "err", err)
		}
	}()
}
```

**Step 6: Verify it compiles**

Run: `go build ./...`
Expected: clean build

**Step 7: Commit**

```bash
git add cmd/tailvoy/main.go
git commit -m "Wire OAuth client, VIP service manager, and ListenService into startup"
```

---

### Task 6: Update standalone/envoy mode for compatibility

**Files:**
- Modify: `cmd/tailvoy/main.go`
- Potentially modify: `internal/envoy/bootstrap.go`

**Step 1: Verify standalone mode still works**

The standalone mode generates Envoy config and overrides listener `Forward` addresses. With ListenService, the listeners accept on `localhost:ephemeral` — the existing `Forward` override logic should still work since we're forwarding to Envoy at `127.0.0.1:offset_port`.

Review: Does `GenerateStandaloneConfig` need changes? It reads `cfg.Listeners` which still exist with the same structure. The only difference is how we create listeners (ListenService vs Listen), which happens after config generation.

If no changes needed, note this in a comment and move on.

**Step 2: Commit if changes needed**

---

### Task 7: Update integration tests for OAuth

**Files:**
- Modify: `integration_test/kind/run-kind-tests.sh`
- Modify: `integration_test/kind/manifests/tailvoy-config.yaml`
- Modify: `integration_test/kind/manifests/envoy-proxy.yaml`

**Step 1: Update the test script**

Replace `TS_AUTHKEY` loading with `TS_CLIENT_ID` and `TS_CLIENT_SECRET`:

```bash
# --- Load OAuth credentials ---
if [ -z "${TS_CLIENT_ID:-}" ] || [ -z "${TS_CLIENT_SECRET:-}" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
    elif [ -f "$SCRIPT_DIR/../.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
    else
        echo "FATAL: TS_CLIENT_ID/TS_CLIENT_SECRET not set and no .env file found"
        exit 1
    fi
fi
if [ -z "${TS_CLIENT_ID:-}" ]; then
    echo "FATAL: TS_CLIENT_ID is empty"
    exit 1
fi
if [ -z "${TS_CLIENT_SECRET:-}" ]; then
    echo "FATAL: TS_CLIENT_SECRET is empty"
    exit 1
fi
```

Update secret creation:

```bash
kubectl create secret generic tailvoy-oauth \
    -n envoy-gateway-system \
    --from-literal=TS_CLIENT_ID="$TS_CLIENT_ID" \
    --from-literal=TS_CLIENT_SECRET="$TS_CLIENT_SECRET"
```

**Step 2: Update tailvoy-config.yaml ConfigMap**

```yaml
data:
  policy.yaml: |
    tailscale:
      hostname: "tailvoy-kind-test"
      tailnet: "${TS_TAILNET}"
      clientId: "${TS_CLIENT_ID}"
      clientSecret: "${TS_CLIENT_SECRET}"
      tags:
        - "tag:kind"
      serviceTags:
        - "tag:kind"
    discovery:
      envoyAdmin: "http://127.0.0.1:19000"
      envoyAddress: "127.0.0.1"
      pollInterval: "5s"
      proxyProtocol: v2
```

**Step 3: Update envoy-proxy.yaml**

Update the env vars in the container spec:

```yaml
env:
  - name: TS_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: tailvoy-oauth
        key: TS_CLIENT_ID
  - name: TS_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: tailvoy-oauth
        key: TS_CLIENT_SECRET
  - name: TS_TAILNET
    value: "-"
```

Remove the old `TS_AUTHKEY` env var reference.

**Step 4: Update the VIP service name expectation**

The test currently waits for `tailvoy-kind-test` hostname. With VIP services, the service FQDN will be different. Update the tailnet join check:

The hostname in `tailscale status` will still be `tailvoy-kind-test` (that's the node hostname). The VIP service name `svc:tailvoy-kind-test` will have its own IPs, but for testing we can still connect to the node's Tailscale IP or the service's VIP. We may need to look up the service VIP.

For the initial migration, keep testing against the node's TS IP since that's simpler. The VIP routing should be transparent once ListenService is set up.

Actually, with ListenService, traffic must go through the VIP service address, not the node's direct IP. We need to discover the VIP service IP. Options:
- Use `tailscale status --json` to find the service
- Use the Go client to get the service and its addrs
- Use the service's MagicDNS name

Simplest: after the node joins, wait for the VIP service to appear and use its MagicDNS name or IP. The test script can use `tailscale status --json` and look for the service, or curl the service's DNS name.

Update the test to resolve the VIP service:
```bash
# Wait for VIP service
SVC_NAME="svc:tailvoy-kind-test"
SVC_FQDN="tailvoy-kind-test.${TS_TAILNET_DOMAIN}"
# Or look up via tailscale status for the service IP
```

This may require iterating — we'll adjust during implementation based on what `tailscale status` shows for services.

**Step 5: Update ACL policy for integration tests**

The hujson policy needs `autoApprovers.services` for the test service, and grants targeting the service name. This is outside this repo but needs to be coordinated.

**Step 6: Run integration tests**

Run: `cd /Users/rajsingh/Documents/GitHub/tailvoy && bash integration_test/kind/run-kind-tests.sh`
Expected: All tests pass

**Step 7: Commit**

```bash
git add integration_test/
git commit -m "Update integration tests for OAuth and VIP service model"
```

---

### Task 8: Update README and docs

**Files:**
- Modify: `README.md`

**Step 1: Update config examples**

Replace all authkey references with OAuth config. Update the "Getting started" config example, discovery mode example, and deployment mode docs.

**Step 2: Add VIP service section**

Document:
- OAuth client credentials setup
- Required ACL: tagOwners, autoApprovers.services, grants
- Service tag vs node tag distinction
- UDP limitation note

**Step 3: Commit**

```bash
git add README.md
git commit -m "Update README for OAuth and VIP service model"
```

---

### Task 9: Clean up deprecated code

**Files:**
- Modify: `internal/config/config.go` (if any authkey remnants)
- Modify: `Dockerfile` (if HOME/state dir setup needs changes)

**Step 1: Review for dead code**

Search for any remaining references to `authkey`, `AuthKey`, `Ephemeral` in the codebase. Remove them.

**Step 2: Update Dockerfile if needed**

The Dockerfile sets `HOME=/tmp/tailvoy` for tsnet state. This should still work with OAuth since tsnet stores state in `$HOME/.local/share/tsnet-*`.

**Step 3: Run full test suite**

Run: `go test ./... -v`
Expected: All pass

**Step 4: Run linter**

Run: `golangci-lint run ./...`
Expected: Clean

**Step 5: Commit**

```bash
git add -A
git commit -m "Clean up deprecated authkey references"
```
