package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestManager_Ensure(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotBody   bytes.Buffer
	)

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		io.Copy(&gotBody, r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	mgr := New(client, "svc:test-service", []string{"tag:web", "tag:prod"}, slog.Default())
	if err := mgr.Ensure(context.Background(), []string{"tcp:443", "tcp:80"}); err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("expected PUT, got %s", gotMethod)
	}
	if want := "/api/v2/tailnet/test.example.com/vip-services/svc:test-service"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}

	var received tailscale.VIPService
	if err := json.Unmarshal(gotBody.Bytes(), &received); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if received.Comment != "Managed by Tailvoy" {
		t.Errorf("comment = %q, want %q", received.Comment, "Managed by Tailvoy")
	}
	if len(received.Tags) != 2 || received.Tags[0] != "tag:web" || received.Tags[1] != "tag:prod" {
		t.Errorf("tags = %v, want [tag:web tag:prod]", received.Tags)
	}
	if len(received.Ports) != 2 || received.Ports[0] != "tcp:443" || received.Ports[1] != "tcp:80" {
		t.Errorf("ports = %v, want [tcp:443 tcp:80]", received.Ports)
	}
}

func TestManager_Delete(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
	)

	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))

	mgr := New(client, "svc:test-service", nil, slog.Default())
	if err := mgr.Delete(context.Background()); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("expected DELETE, got %s", gotMethod)
	}
	if want := "/api/v2/tailnet/test.example.com/vip-services/svc:test-service"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestManager_ServiceName(t *testing.T) {
	mgr := New(nil, "svc:my-svc", nil, slog.Default())
	if got := mgr.ServiceName(); got != "svc:my-svc" {
		t.Errorf("ServiceName() = %q, want %q", got, "svc:my-svc")
	}
}
