package authz

import (
	"context"
	"log/slog"
	"net"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

type Server struct {
	authv3.UnimplementedAuthorizationServer
	engine   *policy.Engine
	resolver *identity.Resolver
	logger   *slog.Logger
}

func NewServer(engine *policy.Engine, resolver *identity.Resolver, logger *slog.Logger) *Server {
	return &Server{
		engine:   engine,
		resolver: resolver,
		logger:   logger,
	}
}

func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpReq.GetHeaders()

	srcIP := extractSourceIP(headers)
	if srcIP == "" {
		s.logger.Warn("ext_authz: no source IP")
		return denyResponse(), nil
	}

	id, err := s.resolver.Resolve(ctx, srcIP)
	if err != nil {
		s.logger.Warn("ext_authz: identity resolution failed", "ip", srcIP, "err", err)
		return denyResponse(), nil
	}

	path := httpReq.GetPath()

	if !s.engine.CheckAccess(path, id) {
		s.logger.Info("ext_authz: denied", "ip", srcIP, "path", path, "user", id.UserLogin, "node", id.NodeName)
		return denyResponse(), nil
	}

	s.logger.Debug("ext_authz: allowed", "ip", srcIP, "path", path, "user", id.UserLogin, "node", id.NodeName)
	return allowResponse(id), nil
}

func allowResponse(id *policy.Identity) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					header("x-tailscale-user", id.UserLogin),
					header("x-tailscale-node", id.NodeName),
					header("x-tailscale-tags", strings.Join(id.Tags, ",")),
					header("x-tailscale-ip", id.TailscaleIP),
				},
			},
		},
	}
}

func denyResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Headers: []*corev3.HeaderValueOption{
					header("content-type", "application/json"),
				},
				Body: `{"error":"forbidden","message":"access denied by tailvoy policy"}`,
			},
		},
	}
}

func header(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   key,
			Value: value,
		},
	}
}

// extractSourceIP returns the original client IP from Envoy-provided headers.
// Checks x-forwarded-for first (leftmost IP), then x-envoy-external-address.
func extractSourceIP(headers map[string]string) string {
	if xff, ok := headers["x-forwarded-for"]; ok && xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if host, _, err := net.SplitHostPort(ip); err == nil {
			return host
		}
		return ip
	}
	if addr, ok := headers["x-envoy-external-address"]; ok && addr != "" {
		return strings.TrimSpace(addr)
	}
	return ""
}

// ListenAndServe starts the gRPC ext_authz server on addr.
// It shuts down gracefully when ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, s)

	errCh := make(chan error, 1)
	go func() {
		errCh <- gs.Serve(lis)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		gs.GracefulStop()
		return nil
	}
}
