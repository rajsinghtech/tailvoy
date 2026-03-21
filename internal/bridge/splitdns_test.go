package bridge

import (
	"context"
	"log/slog"
	"testing"
)

type fakeDNSClient struct {
	existing    map[string][]string
	updateCalls []map[string][]string
}

func (f *fakeDNSClient) SplitDNS(_ context.Context) (map[string][]string, error) {
	return f.existing, nil
}

func (f *fakeDNSClient) UpdateSplitDNS(_ context.Context, req map[string][]string) (map[string][]string, error) {
	f.updateCalls = append(f.updateCalls, req)
	for k, v := range req {
		f.existing[k] = v
	}
	return f.existing, nil
}

func TestExtractZone(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{"single fqdn", []string{"web-1.tail1234.ts.net"}, "tail1234.ts.net"},
		{"trailing dot", []string{"web-1.tail1234.ts.net."}, "tail1234.ts.net"},
		{"multiple fqdns", []string{"web-1.tail1234.ts.net", "db-1.tail1234.ts.net"}, "tail1234.ts.net"},
		{"no dots", []string{"single"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractZone(tc.input)
			if got != tc.want {
				t.Errorf("ExtractZone(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSplitDNS_Configure(t *testing.T) {
	client := &fakeDNSClient{existing: map[string][]string{}}
	s := NewSplitDNSConfigurator(client, false, slog.Default())

	if err := s.Configure(context.Background(), "tail1234.ts.net", "100.64.0.1"); err != nil {
		t.Fatal(err)
	}

	if len(client.updateCalls) != 1 {
		t.Fatalf("expected 1 UpdateSplitDNS call, got %d", len(client.updateCalls))
	}
	ips := client.updateCalls[0]["tail1234.ts.net"]
	if len(ips) != 1 || ips[0] != "100.64.0.1" {
		t.Errorf("unexpected update payload: %v", client.updateCalls[0])
	}
}

func TestSplitDNS_Idempotent(t *testing.T) {
	client := &fakeDNSClient{
		existing: map[string][]string{
			"tail1234.ts.net": {"100.64.0.1"},
		},
	}
	s := NewSplitDNSConfigurator(client, false, slog.Default())

	if err := s.Configure(context.Background(), "tail1234.ts.net", "100.64.0.1"); err != nil {
		t.Fatal(err)
	}

	if len(client.updateCalls) != 0 {
		t.Errorf("expected no UpdateSplitDNS calls, got %d", len(client.updateCalls))
	}
}

func TestSplitDNS_Cleanup(t *testing.T) {
	client := &fakeDNSClient{existing: map[string][]string{}}
	s := NewSplitDNSConfigurator(client, true, slog.Default())

	if err := s.Configure(context.Background(), "tail1234.ts.net", "100.64.0.1"); err != nil {
		t.Fatal(err)
	}
	client.updateCalls = nil // reset after configure

	if err := s.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(client.updateCalls) != 1 {
		t.Fatalf("expected 1 cleanup call, got %d", len(client.updateCalls))
	}
	ips := client.updateCalls[0]["tail1234.ts.net"]
	if len(ips) != 0 {
		t.Errorf("expected empty slice for cleanup, got %v", ips)
	}
}

func TestSplitDNS_CleanupDisabled(t *testing.T) {
	client := &fakeDNSClient{existing: map[string][]string{}}
	s := NewSplitDNSConfigurator(client, false, slog.Default())

	if err := s.Configure(context.Background(), "tail1234.ts.net", "100.64.0.1"); err != nil {
		t.Fatal(err)
	}
	client.updateCalls = nil

	if err := s.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(client.updateCalls) != 0 {
		t.Errorf("expected no cleanup calls with cleanup=false, got %d", len(client.updateCalls))
	}
}
