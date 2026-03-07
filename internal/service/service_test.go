package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
)

func testClient(t *testing.T, handler http.Handler) *tailscale.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	baseURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &tailscale.Client{
		BaseURL: baseURL,
		APIKey:  "test-key",
		Tailnet: "test.example.com",
	}
}

func TestMultiManager_EnsureAll(t *testing.T) {
	var mu sync.Mutex
	calls := map[string][]string{}

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			var svc tailscale.VIPService
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &svc)
			calls[svc.Name] = svc.Ports
		}
		w.WriteHeader(http.StatusOK)
	}))

	mm := NewMultiManager(client, []string{"tag:svc"}, slog.Default())
	mappings := map[string][]int{
		"svc:web":      {80, 443},
		"svc:postgres": {5432},
	}
	if err := mm.EnsureAll(context.Background(), mappings); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("expected 2 service calls, got %d", len(calls))
	}
	webPorts := calls["svc:web"]
	if len(webPorts) != 2 {
		t.Errorf("web ports = %v, want 2 entries", webPorts)
	}
	pgPorts := calls["svc:postgres"]
	if len(pgPorts) != 1 {
		t.Errorf("postgres ports = %v, want 1 entry", pgPorts)
	}
}

func TestMultiManager_EnsureAll_PartialFailure(t *testing.T) {
	var mu sync.Mutex
	created := map[string]bool{}

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			var svc tailscale.VIPService
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &svc)
			if strings.Contains(svc.Name, "fail") {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			created[svc.Name] = true
		}
		w.WriteHeader(http.StatusOK)
	}))

	mm := NewMultiManager(client, []string{"tag:svc"}, slog.Default())
	mappings := map[string][]int{
		"svc:web":  {80},
		"svc:fail": {5432},
	}
	err := mm.EnsureAll(context.Background(), mappings)
	if err == nil {
		t.Fatal("expected error from partial failure")
	}
	if !strings.Contains(err.Error(), "svc:fail") {
		t.Errorf("error should mention failing service, got: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !created["svc:web"] {
		t.Error("svc:web should have been created despite svc:fail failing")
	}
}
