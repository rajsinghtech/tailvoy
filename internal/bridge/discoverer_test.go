package bridge

import (
	"context"
	"sort"
	"testing"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

type mockDevicesClient struct {
	calls   int
	devices [][]Device
}

func (m *mockDevicesClient) List(_ context.Context) ([]Device, error) {
	idx := m.calls
	if idx >= len(m.devices) {
		idx = len(m.devices) - 1
	}
	m.calls++
	return m.devices[idx], nil
}

func TestDiscoverer_FilterByTags(t *testing.T) {
	client := &mockDevicesClient{devices: [][]Device{{
		{Name: "web-1.ts.net", Addresses: []string{"100.1.0.1"}, Tags: []string{"tag:web"}},
		{Name: "db-1.ts.net", Addresses: []string{"100.1.0.2"}, Tags: []string{"tag:db"}},
		{Name: "combo.ts.net", Addresses: []string{"100.1.0.3"}, Tags: []string{"tag:web", "tag:db"}},
	}}}
	rules := []config.BridgeRule{
		{Discover: config.BridgeDiscover{Tags: []string{"tag:web"}, Ports: []int{80}}},
	}
	d := NewDiscoverer(client, rules, nil)
	current, _, _, err := d.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := current["web-1.ts.net"]; !ok {
		t.Error("expected web-1.ts.net to be included")
	}
	if _, ok := current["db-1.ts.net"]; ok {
		t.Error("expected db-1.ts.net to be excluded")
	}
	if _, ok := current["combo.ts.net"]; !ok {
		t.Error("expected combo.ts.net to be included")
	}
	if len(current) != 2 {
		t.Errorf("expected 2 devices, got %d", len(current))
	}
}

func TestDiscoverer_MergePortsAcrossRules(t *testing.T) {
	client := &mockDevicesClient{devices: [][]Device{{
		{Name: "multi.ts.net", Addresses: []string{"100.1.0.1"}, Tags: []string{"tag:web", "tag:db"}},
	}}}
	rules := []config.BridgeRule{
		{Discover: config.BridgeDiscover{Tags: []string{"tag:web"}, Ports: []int{80, 443}}},
		{Discover: config.BridgeDiscover{Tags: []string{"tag:db"}, Ports: []int{5432}}},
	}
	d := NewDiscoverer(client, rules, nil)
	current, _, _, err := d.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, ok := current["multi.ts.net"]
	if !ok {
		t.Fatal("expected multi.ts.net in results")
	}
	got := append([]int{}, info.Ports...)
	sort.Ints(got)
	want := []int{80, 443, 5432}
	if len(got) != len(want) {
		t.Fatalf("expected ports %v, got %v", want, got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("port[%d]: want %d, got %d", i, p, got[i])
		}
	}
}

func TestDiscoverer_Diff(t *testing.T) {
	client := &mockDevicesClient{devices: [][]Device{
		{
			{Name: "a.ts.net", Addresses: []string{"100.1.0.1"}, Tags: []string{"tag:web"}},
			{Name: "b.ts.net", Addresses: []string{"100.1.0.2"}, Tags: []string{"tag:web"}},
		},
		{
			{Name: "b.ts.net", Addresses: []string{"100.1.0.2"}, Tags: []string{"tag:web"}},
			{Name: "c.ts.net", Addresses: []string{"100.1.0.3"}, Tags: []string{"tag:web"}},
		},
	}}
	rules := []config.BridgeRule{
		{Discover: config.BridgeDiscover{Tags: []string{"tag:web"}, Ports: []int{80}}},
	}
	d := NewDiscoverer(client, rules, nil)

	_, added, removed, err := d.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(added)
	if len(removed) != 0 {
		t.Errorf("first poll: expected no removed, got %v", removed)
	}
	wantAdded := []string{"a.ts.net", "b.ts.net"}
	if len(added) != len(wantAdded) {
		t.Fatalf("first poll: expected added %v, got %v", wantAdded, added)
	}
	for i, v := range wantAdded {
		if added[i] != v {
			t.Errorf("first poll added[%d]: want %s, got %s", i, v, added[i])
		}
	}

	_, added, removed, err = d.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "c.ts.net" {
		t.Errorf("second poll: expected added=[c.ts.net], got %v", added)
	}
	if len(removed) != 1 || removed[0] != "a.ts.net" {
		t.Errorf("second poll: expected removed=[a.ts.net], got %v", removed)
	}
}

func TestDiscoverer_DeduplicateByFQDN(t *testing.T) {
	client := &mockDevicesClient{devices: [][]Device{{
		{Name: "shared.ts.net", Addresses: []string{"100.1.0.1"}, Tags: []string{"tag:web", "tag:api"}},
	}}}
	rules := []config.BridgeRule{
		{Discover: config.BridgeDiscover{Tags: []string{"tag:web"}, Ports: []int{80}}},
		{Discover: config.BridgeDiscover{Tags: []string{"tag:api"}, Ports: []int{8080}}},
	}
	d := NewDiscoverer(client, rules, nil)
	current, _, _, err := d.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 1 {
		t.Errorf("expected 1 device, got %d", len(current))
	}
	info := current["shared.ts.net"]
	got := append([]int{}, info.Ports...)
	sort.Ints(got)
	want := []int{80, 8080}
	if len(got) != len(want) {
		t.Fatalf("expected ports %v, got %v", want, got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("port[%d]: want %d, got %d", i, p, got[i])
		}
	}
}
