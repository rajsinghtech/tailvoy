package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

type mockWhoIs struct {
	responses map[string]*apitype.WhoIsResponse
}

func (m *mockWhoIs) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	ip := identity.StripPort(addr)
	if resp, ok := m.responses[ip]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("not found: %s", ip)
}

// capMap builds a PeerCapMap granting the given routes via the tailvoy capability.
func capMap(routes ...string) tailcfg.PeerCapMap {
	rule := identity.TailvoyCapRule{Routes: routes}
	b, _ := json.Marshal(rule)
	return tailcfg.PeerCapMap{
		identity.CapTailvoy: []tailcfg.RawMessage{tailcfg.RawMessage(b)},
	}
}

// testServer builds a Server with a cap-based policy engine and mock WhoIs responses.
func testServer(t *testing.T, responses map[string]*apitype.WhoIsResponse) *Server {
	t.Helper()
	engine := policy.NewEngine()
	resolver := identity.NewResolver(&mockWhoIs{responses: responses})
	return NewServer(engine, resolver, slog.Default())
}

// startGRPC starts the ext_authz gRPC server on an ephemeral port and returns
// a connected client. The server and connection are cleaned up when t finishes.
func startGRPC(t *testing.T, srv *Server) authv3.AuthorizationClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	go gs.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
		gs.GracefulStop()
	})

	return authv3.NewAuthorizationClient(conn)
}

// checkReq builds a CheckRequest with the given headers and path.
func checkReq(headers map[string]string, path string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: headers,
					Path:    path,
				},
			},
		},
	}
}

// checkReqWithContext builds a CheckRequest with headers, path, and context extensions.
func checkReqWithContext(headers map[string]string, path string, contextExt map[string]string) *authv3.CheckRequest {
	host := headers[":authority"]
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: headers,
					Path:    path,
					Host:    host,
				},
			},
			ContextExtensions: contextExt,
		},
	}
}

// multiCapMap builds a PeerCapMap from full TailvoyCapRule structs.
func multiCapMap(rules ...identity.TailvoyCapRule) tailcfg.PeerCapMap {
	msgs := make([]tailcfg.RawMessage, len(rules))
	for i, r := range rules {
		b, _ := json.Marshal(r)
		msgs[i] = tailcfg.RawMessage(b)
	}
	return tailcfg.PeerCapMap{identity.CapTailvoy: msgs}
}

func isOK(resp *authv3.CheckResponse) bool {
	return resp.GetStatus().GetCode() == int32(codes.OK)
}

func getResponseHeader(resp *authv3.CheckResponse, key string) string {
	ok := resp.GetOkResponse()
	if ok == nil {
		return ""
	}
	for _, h := range ok.GetHeaders() {
		if h.GetHeader().GetKey() == key {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}

// --- WhoIs response fixtures ---

var aliceResp = &apitype.WhoIsResponse{
	Node: &tailcfg.Node{Name: "alice-laptop.tail1234.ts.net."},
	UserProfile: &tailcfg.UserProfile{
		LoginName: "alice@example.com",
	},
	CapMap: capMap("/*"),
}

var aliceRestrictedResp = &apitype.WhoIsResponse{
	Node: &tailcfg.Node{Name: "alice-laptop.tail1234.ts.net."},
	UserProfile: &tailcfg.UserProfile{
		LoginName: "alice@example.com",
	},
	CapMap: capMap("/api/*"),
}

// aliceNoCapResp has no CapMap entry — peer is on the tailnet but has no tailvoy grant.
var aliceNoCapResp = &apitype.WhoIsResponse{
	Node: &tailcfg.Node{Name: "alice-laptop.tail1234.ts.net."},
	UserProfile: &tailcfg.UserProfile{
		LoginName: "alice@example.com",
	},
}

func TestAllowRequest(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/api/data",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(resp) {
		t.Fatalf("expected OK, got code %d", resp.GetStatus().GetCode())
	}
	if got := getResponseHeader(resp, "x-tailscale-user"); got != "alice@example.com" {
		t.Errorf("x-tailscale-user = %q, want alice@example.com", got)
	}
	if got := getResponseHeader(resp, "x-tailscale-node"); got != "alice-laptop.tail1234.ts.net" {
		t.Errorf("x-tailscale-node = %q", got)
	}
	if got := getResponseHeader(resp, "x-tailscale-ip"); got != "100.64.1.1" {
		t.Errorf("x-tailscale-ip = %q", got)
	}
}

func TestDenyRoutesMismatch(t *testing.T) {
	// alice has cap but only for /api/* — request to /admin/settings should be denied.
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceRestrictedResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/admin/settings",
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(resp) {
		t.Fatal("expected deny for path not in allowed routes")
	}
}

func TestDenyNoCap(t *testing.T) {
	// alice is on the tailnet but has no tailvoy capability at all.
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceNoCapResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(resp) {
		t.Fatal("expected deny for peer with no tailvoy cap")
	}
}

func TestNoSourceIP(t *testing.T) {
	srv := testServer(t, nil)
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{}, "/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(resp) {
		t.Fatal("expected deny with no source IP")
	}
}

func TestUnknownIP(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.99.99"},
		"/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(resp) {
		t.Fatal("expected deny for unknown IP")
	}
}

func TestTaggedNodeWithCap(t *testing.T) {
	taggedResp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name: "server.tail1234.ts.net.",
			Tags: []string{"tag:web", "tag:prod"},
		},
		CapMap: capMap("/*"),
	}

	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.5.5": taggedResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.5.5"},
		"/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(resp) {
		t.Fatalf("expected OK for tagged node with cap, got code %d", resp.GetStatus().GetCode())
	}
	if got := getResponseHeader(resp, "x-tailscale-tags"); got != "tag:web,tag:prod" {
		t.Errorf("x-tailscale-tags = %q, want tag:web,tag:prod", got)
	}
	if got := getResponseHeader(resp, "x-tailscale-user"); got != "" {
		t.Errorf("x-tailscale-user = %q, want empty for tagged node", got)
	}
}

func TestOkResponseHeaders(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/",
	))
	if err != nil {
		t.Fatal(err)
	}

	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("expected OkResponse, got nil")
	}

	wantHeaders := map[string]string{
		"x-tailscale-user": "alice@example.com",
		"x-tailscale-node": "alice-laptop.tail1234.ts.net",
		"x-tailscale-ip":   "100.64.1.1",
		"x-tailscale-tags": "",
	}

	got := make(map[string]string)
	for _, h := range ok.GetHeaders() {
		got[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}

	for k, want := range wantHeaders {
		if got[k] != want {
			t.Errorf("header %q = %q, want %q", k, got[k], want)
		}
	}
}

func TestExtractSourceIP(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "single xff",
			headers: map[string]string{"x-forwarded-for": "100.64.1.1"},
			want:    "100.64.1.1",
		},
		{
			name:    "multiple xff picks first",
			headers: map[string]string{"x-forwarded-for": "100.64.1.1, 10.0.0.1, 192.168.1.1"},
			want:    "100.64.1.1",
		},
		{
			name:    "empty xff falls back to envoy header",
			headers: map[string]string{"x-envoy-external-address": "100.64.2.2"},
			want:    "100.64.2.2",
		},
		{
			name:    "no headers returns empty",
			headers: map[string]string{},
			want:    "",
		},
		{
			name:    "xff with port strips it",
			headers: map[string]string{"x-forwarded-for": "100.64.1.1:8080"},
			want:    "100.64.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSourceIP(tt.headers)
			if got != tt.want {
				t.Errorf("extractSourceIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMultipleIPsInXFFUsesFirst(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1, 100.64.2.2"},
		"/data",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(resp) {
		t.Fatalf("expected OK (first IP is alice), got code %d", resp.GetStatus().GetCode())
	}
	if got := getResponseHeader(resp, "x-tailscale-user"); got != "alice@example.com" {
		t.Errorf("x-tailscale-user = %q, want alice@example.com", got)
	}
}

func TestMultipleIPsInXFFFirstUnknown(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.99.99, 100.64.1.1"},
		"/data",
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(resp) {
		t.Fatal("expected deny (first IP is unknown)")
	}
}

func TestGracefulShutdown(t *testing.T) {
	srv := testServer(t, map[string]*apitype.WhoIsResponse{
		"100.64.1.1": aliceResp,
	})

	ctx, cancel := context.WithCancel(context.Background())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	lis.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, addr)
	}()

	// Give server time to start.
	time.Sleep(50 * time.Millisecond)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := authv3.NewAuthorizationClient(conn)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(resp) {
		t.Fatalf("expected OK, got code %d", resp.GetStatus().GetCode())
	}

	conn.Close()
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected nil error from graceful stop, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestGRPCTransportOK(t *testing.T) {
	srv := testServer(t, nil)
	client := startGRPC(t, srv)

	_, err := client.Check(context.Background(), checkReq(
		map[string]string{}, "/",
	))
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("unexpected non-gRPC error: %v", err)
		}
		t.Fatalf("unexpected gRPC status: %v", st)
	}
}

func TestDenyReturnsPermissionDenied(t *testing.T) {
	srv := testServer(t, nil)
	client := startGRPC(t, srv)

	resp, err := client.Check(context.Background(), checkReq(
		map[string]string{}, "/",
	))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Errorf("deny status code = %d, want %d (PermissionDenied)", resp.GetStatus().GetCode(), codes.PermissionDenied)
	}
}

func TestCheckWithListenerContextExtension(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "n.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap: multiCapMap(identity.TailvoyCapRule{
			Listeners: []string{"http"},
			Routes:    []string{"/*"},
		}),
	}
	srv := testServer(t, map[string]*apitype.WhoIsResponse{"100.64.1.1": resp})
	client := startGRPC(t, srv)

	// Matching listener -> allow.
	r, err := client.Check(context.Background(), checkReqWithContext(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/foo",
		map[string]string{"listener": "http"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(r) {
		t.Fatal("expected allow for matching listener")
	}

	// Non-matching listener -> deny.
	r, err = client.Check(context.Background(), checkReqWithContext(
		map[string]string{"x-forwarded-for": "100.64.1.1"},
		"/foo",
		map[string]string{"listener": "grpc"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r) {
		t.Fatal("expected deny for non-matching listener")
	}
}

func TestCheckWithHostHeader(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "n.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap: multiCapMap(identity.TailvoyCapRule{
			Hostnames: []string{"api.example.com"},
			Routes:    []string{"/*"},
		}),
	}
	srv := testServer(t, map[string]*apitype.WhoIsResponse{"100.64.1.1": resp})
	client := startGRPC(t, srv)

	// Matching host -> allow.
	r, err := client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "api.example.com",
		},
		"/anything",
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(r) {
		t.Fatal("expected allow for matching host")
	}

	// Non-matching host -> deny.
	r, err = client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "other.example.com",
		},
		"/anything",
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r) {
		t.Fatal("expected deny for non-matching host")
	}
}

func TestCheckWithAllDimensions(t *testing.T) {
	resp := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "n.ts.net."},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
		CapMap: multiCapMap(identity.TailvoyCapRule{
			Listeners: []string{"http"},
			Hostnames: []string{"api.example.com"},
			Routes:    []string{"/api/*"},
		}),
	}
	srv := testServer(t, map[string]*apitype.WhoIsResponse{"100.64.1.1": resp})
	client := startGRPC(t, srv)

	// All dimensions match -> allow.
	r, err := client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "api.example.com",
		},
		"/api/data",
		map[string]string{"listener": "http"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !isOK(r) {
		t.Fatal("expected allow when all dimensions match")
	}

	// Wrong listener -> deny (AND semantics).
	r, err = client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "api.example.com",
		},
		"/api/data",
		map[string]string{"listener": "grpc"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r) {
		t.Fatal("expected deny when listener doesn't match")
	}

	// Wrong host -> deny.
	r, err = client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "other.example.com",
		},
		"/api/data",
		map[string]string{"listener": "http"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r) {
		t.Fatal("expected deny when host doesn't match")
	}

	// Wrong path -> deny.
	r, err = client.Check(context.Background(), checkReqWithContext(
		map[string]string{
			"x-forwarded-for": "100.64.1.1",
			":authority":      "api.example.com",
		},
		"/admin/settings",
		map[string]string{"listener": "http"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if isOK(r) {
		t.Fatal("expected deny when path doesn't match")
	}
}
