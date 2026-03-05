package discovery

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

const sampleConfigDump = `{
  "configs": [
    {
      "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
      "dynamic_listeners": [
        {
          "name": "default/http-gateway/http",
          "active_state": {
            "listener": {
              "name": "default/http-gateway/http",
              "address": {
                "socket_address": {
                  "address": "0.0.0.0",
                  "port_value": 8080
                }
              },
              "filter_chains": [
                {
                  "filters": [
                    {
                      "name": "envoy.filters.network.http_connection_manager"
                    }
                  ]
                }
              ]
            }
          }
        },
        {
          "name": "default/tcp-gateway/tcp",
          "active_state": {
            "listener": {
              "name": "default/tcp-gateway/tcp",
              "address": {
                "socket_address": {
                  "address": "0.0.0.0",
                  "port_value": 8443
                }
              },
              "filter_chains": [
                {
                  "filters": [
                    {
                      "name": "envoy.filters.network.tcp_proxy"
                    }
                  ]
                }
              ]
            }
          }
        },
        {
          "name": "warming-only",
          "active_state": null
        }
      ]
    }
  ]
}`

func TestDiscover_ParsesListeners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(listeners) != 2 {
		t.Fatalf("got %d listeners, want 2", len(listeners))
	}

	// Sorted by name: http first, then tcp.
	httpL := listeners[0]
	if httpL.Name != "default/http-gateway/http" {
		t.Errorf("name = %q", httpL.Name)
	}
	if httpL.Port != 8080 {
		t.Errorf("port = %d, want 8080", httpL.Port)
	}
	if httpL.Forward != "127.0.0.1:8080" {
		t.Errorf("forward = %q", httpL.Forward)
	}
	if !httpL.IsL7 {
		t.Error("expected IsL7=true for HTTP listener")
	}
	if httpL.Protocol != "http" {
		t.Errorf("protocol = %q, want http", httpL.Protocol)
	}

	tcpL := listeners[1]
	if tcpL.Name != "default/tcp-gateway/tcp" {
		t.Errorf("name = %q", tcpL.Name)
	}
	if tcpL.IsL7 {
		t.Error("expected IsL7=false for TCP listener")
	}
}

func TestDiscover_FilterRegex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:     srv.URL,
		EnvoyAddress:   "127.0.0.1",
		ListenerFilter: ".*http.*",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1 (filtered)", len(listeners))
	}
	if listeners[0].Name != "default/http-gateway/http" {
		t.Errorf("name = %q", listeners[0].Name)
	}
}

func TestDiscover_ProxyProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleConfigDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:    srv.URL,
		EnvoyAddress:  "127.0.0.1",
		ProxyProtocol: "v2",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, l := range listeners {
		if !l.ProxyProtocol {
			t.Errorf("listener %s proxy_protocol = false, want true", l.Name)
		}
	}
}

func TestDiscover_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestDiscover_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{broken`))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDiscover_EmptyDynamicListeners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"configs":[{"dynamic_listeners":[]}]}`))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 0 {
		t.Errorf("got %d listeners, want 0", len(listeners))
	}
}

func TestWatch_SendsOnChange(t *testing.T) {
	call := 0
	responses := []string{
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}}]}]}`,
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}}]}]}`,
		`{"configs":[{"dynamic_listeners":[{"name":"a","active_state":{"listener":{"name":"a","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[]}}},{"name":"b","active_state":{"listener":{"name":"b","address":{"socket_address":{"address":"0.0.0.0","port_value":9090}},"filter_chains":[]}}}]}]}`,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := call
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		call++
		w.Write([]byte(responses[idx]))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
		PollInterval: "50ms",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := d.Watch(ctx)

	select {
	case listeners := <-ch:
		if len(listeners) != 1 {
			t.Fatalf("initial: got %d listeners, want 1", len(listeners))
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for initial discovery")
	}

	select {
	case listeners := <-ch:
		if len(listeners) != 2 {
			t.Fatalf("update: got %d listeners, want 2", len(listeners))
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("timeout waiting for change notification")
	}
}

func TestDiscover_FullConfigDumpWithOtherEntries(t *testing.T) {
	fullDump := `{
		"configs": [
			{"@type": "type.googleapis.com/envoy.admin.v3.BootstrapConfigDump"},
			{"@type": "type.googleapis.com/envoy.admin.v3.ClustersConfigDump", "dynamic_active_clusters": []},
			{"@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump", "dynamic_listeners": [
				{"name": "default/eg/http", "active_state": {"listener": {"name": "default/eg/http", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}}, "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager"}]}]}}}
			]},
			{"@type": "type.googleapis.com/envoy.admin.v3.RoutesConfigDump"}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fullDump))
	}))
	defer srv.Close()

	d, err := New(&config.DiscoveryConfig{
		EnvoyAdmin:   srv.URL,
		EnvoyAddress: "127.0.0.1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 {
		t.Fatalf("got %d listeners, want 1", len(listeners))
	}
	if listeners[0].Name != "default/eg/http" {
		t.Errorf("name = %q", listeners[0].Name)
	}
}

func TestFlatListenersEqual(t *testing.T) {
	a := []config.FlatListener{{Name: "x", Port: 80}}
	b := []config.FlatListener{{Name: "x", Port: 80}}
	if !flatListenersEqual(a, b) {
		t.Error("expected equal")
	}

	c := []config.FlatListener{{Name: "x", Port: 81}}
	if flatListenersEqual(a, c) {
		t.Error("expected not equal")
	}

	if flatListenersEqual(a, nil) {
		t.Error("expected not equal for nil")
	}
}
