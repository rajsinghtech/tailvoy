package bridge

import (
	"context"
	"errors"
	"sync"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
)

// fakeVIPClient is an in-memory mock for VIPServicesClient.
type fakeVIPClient struct {
	mu       sync.Mutex
	services map[string]tailscale.VIPService
	// per-name error injection
	createErr map[string]error
	getErr    map[string]error
	deleteErr map[string]error
	// call tracking
	created []string
	updated []string
	deleted []string
}

func newFakeVIPClient() *fakeVIPClient {
	return &fakeVIPClient{
		services:  make(map[string]tailscale.VIPService),
		createErr: make(map[string]error),
		getErr:    make(map[string]error),
		deleteErr: make(map[string]error),
	}
}

func (f *fakeVIPClient) CreateOrUpdate(ctx context.Context, svc tailscale.VIPService) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.createErr[svc.Name]; err != nil {
		return err
	}
	if _, exists := f.services[svc.Name]; exists {
		f.updated = append(f.updated, svc.Name)
	} else {
		f.created = append(f.created, svc.Name)
		// Simulate IP allocation on first create.
		svc.Addrs = []string{"100.64.0.1"}
	}
	f.services[svc.Name] = svc
	return nil
}

func (f *fakeVIPClient) Get(ctx context.Context, name string) (*tailscale.VIPService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.getErr[name]; err != nil {
		return nil, err
	}
	svc, ok := f.services[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &svc, nil
}

func (f *fakeVIPClient) Delete(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.deleteErr[name]; err != nil {
		return err
	}
	delete(f.services, name)
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeVIPClient) List(ctx context.Context) ([]tailscale.VIPService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]tailscale.VIPService, 0, len(f.services))
	for _, svc := range f.services {
		out = append(out, svc)
	}
	return out, nil
}

// fakeAdvertiser tracks AdvertiseServices calls.
type fakeAdvertiser struct {
	mu   sync.Mutex
	last []string
	err  error
}

func (a *fakeAdvertiser) AdvertiseServices(ctx context.Context, services []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = services
	return a.err
}

func newReconciler(vip *fakeVIPClient, adv *fakeAdvertiser) *Reconciler {
	return NewReconciler(vip, adv, []string{"tag:bridge"}, "br-", nil)
}

func TestReconciler_CreateOnAdd(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	desired := map[string]DeviceInfo{
		"web-1.tail1234.ts.net": {FQDN: "web-1.tail1234.ts.net", Ports: []int{80, 443}},
	}
	_, err := r.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svcName := ServiceName("web-1.tail1234.ts.net", "br-")
	if len(vip.created) != 1 || vip.created[0] != svcName {
		t.Errorf("expected 1 created service %q, got %v", svcName, vip.created)
	}

	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.last) != 1 || adv.last[0] != svcName {
		t.Errorf("expected advertiser called with [%q], got %v", svcName, adv.last)
	}
}

func TestReconciler_DeleteOnRemove(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	// First reconcile: add device.
	desired := map[string]DeviceInfo{
		"web-1.tail1234.ts.net": {FQDN: "web-1.tail1234.ts.net", Ports: []int{80}},
	}
	if _, err := r.Reconcile(context.Background(), desired); err != nil {
		t.Fatalf("first reconcile error: %v", err)
	}
	svcName := ServiceName("web-1.tail1234.ts.net", "br-")

	// Second reconcile: device gone.
	if _, err := r.Reconcile(context.Background(), map[string]DeviceInfo{}); err != nil {
		t.Fatalf("second reconcile error: %v", err)
	}

	if len(vip.deleted) != 1 || vip.deleted[0] != svcName {
		t.Errorf("expected %q deleted, got %v", svcName, vip.deleted)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.last) != 0 {
		t.Errorf("expected empty advertiser list after removal, got %v", adv.last)
	}
}

func TestReconciler_UpdatePorts(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	fqdn := "web-1.tail1234.ts.net"
	svcName := ServiceName(fqdn, "br-")

	// Seed the client with an existing service (simulates prior state).
	vip.services[svcName] = tailscale.VIPService{
		Name:    svcName,
		Addrs:   []string{"100.64.0.5"},
		Ports:   []string{"tcp:80"},
		Comment: managedComment,
	}
	r.current[fqdn] = svcName

	desired := map[string]DeviceInfo{
		fqdn: {FQDN: fqdn, Ports: []int{80, 443}},
	}
	_, err := r.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vip.updated) != 1 || vip.updated[0] != svcName {
		t.Errorf("expected service to be updated, got created=%v updated=%v", vip.created, vip.updated)
	}

	// Addrs should be preserved.
	got := vip.services[svcName]
	if len(got.Addrs) == 0 || got.Addrs[0] != "100.64.0.5" {
		t.Errorf("expected addrs preserved, got %v", got.Addrs)
	}
}

func TestReconciler_PartialFailure(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	svcA := ServiceName("web-a.tail1234.ts.net", "br-")
	svcB := ServiceName("web-b.tail1234.ts.net", "br-")
	vip.createErr[svcA] = errors.New("api error")

	desired := map[string]DeviceInfo{
		"web-a.tail1234.ts.net": {FQDN: "web-a.tail1234.ts.net", Ports: []int{80}},
		"web-b.tail1234.ts.net": {FQDN: "web-b.tail1234.ts.net", Ports: []int{80}},
	}
	_, err := r.Reconcile(context.Background(), desired)
	if err == nil {
		t.Fatal("expected error for failed create, got nil")
	}

	// web-b should still be created.
	if _, ok := vip.services[svcB]; !ok {
		t.Errorf("expected %q to be created despite other failure", svcB)
	}
}

func TestReconciler_OrphanCleanup(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	// Pre-populate VIP services, some orphaned.
	keep := ServiceName("web-1.tail1234.ts.net", "br-")
	orphan := ServiceName("old-device.tail1234.ts.net", "br-")
	unrelated := "svc:some-other-service"

	vip.services[keep] = tailscale.VIPService{Name: keep, Comment: managedComment}
	vip.services[orphan] = tailscale.VIPService{Name: orphan, Comment: managedComment}
	vip.services[unrelated] = tailscale.VIPService{Name: unrelated, Comment: "other tool"}

	desired := map[string]DeviceInfo{
		"web-1.tail1234.ts.net": {FQDN: "web-1.tail1234.ts.net", Ports: []int{80}},
	}
	if err := r.CleanupOrphans(context.Background(), desired); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := vip.services[keep]; !ok {
		t.Errorf("expected %q to be kept", keep)
	}
	if _, ok := vip.services[orphan]; ok {
		t.Errorf("expected %q to be deleted", orphan)
	}
	if _, ok := vip.services[unrelated]; !ok {
		t.Errorf("expected %q (unmanaged) to be kept", unrelated)
	}
}

func TestReconciler_ReturnsVIPAddrs(t *testing.T) {
	vip := newFakeVIPClient()
	adv := &fakeAdvertiser{}
	r := newReconciler(vip, adv)

	fqdn := "web-1.tail1234.ts.net"
	svcName := ServiceName(fqdn, "br-")

	desired := map[string]DeviceInfo{
		fqdn: {FQDN: fqdn, Ports: []int{80}},
	}
	result, err := r.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrs, ok := result[svcName]
	if !ok {
		t.Fatalf("expected result to contain %q, got keys: %v", svcName, keys(result))
	}
	if len(addrs) == 0 {
		t.Errorf("expected non-empty addrs for %q", svcName)
	}
}

func keys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
