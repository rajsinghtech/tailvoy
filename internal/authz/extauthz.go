package authz

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

// Server implements Envoy's ext_authz HTTP service protocol.
// It resolves Tailscale identities from source IPs and evaluates
// L7 access policy before returning allow/deny decisions.
type Server struct {
	engine   *policy.Engine
	resolver *identity.Resolver
	logger   *slog.Logger
}

// NewServer creates an ext_authz server backed by the given policy engine
// and identity resolver.
func NewServer(engine *policy.Engine, resolver *identity.Resolver, logger *slog.Logger) *Server {
	return &Server{
		engine:   engine,
		resolver: resolver,
		logger:   logger,
	}
}

// ServeHTTP handles ext_authz check requests from Envoy.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srcIP := extractSourceIP(r)
	if srcIP == "" {
		s.logger.Warn("ext_authz: no source IP")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	id, err := s.resolver.Resolve(r.Context(), srcIP)
	if err != nil {
		s.logger.Warn("ext_authz: identity resolution failed", "ip", srcIP, "err", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	path := extractPath(r)
	host := r.Host
	method := r.Method
	listener := r.Header.Get("x-tailvoy-listener")
	if listener == "" {
		listener = "default"
	}

	if !s.engine.CheckL7(listener, path, host, method, id) {
		s.logger.Info("ext_authz: denied", "ip", srcIP, "path", path, "host", host, "method", method, "listener", listener, "user", id.UserLogin, "node", id.NodeName)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("x-tailscale-user", id.UserLogin)
	w.Header().Set("x-tailscale-node", id.NodeName)
	w.Header().Set("x-tailscale-tags", strings.Join(id.Tags, ","))
	w.Header().Set("x-tailscale-ip", id.TailscaleIP)
	w.WriteHeader(http.StatusOK)

	s.logger.Debug("ext_authz: allowed", "ip", srcIP, "path", path, "host", host, "method", method, "listener", listener, "user", id.UserLogin, "node", id.NodeName)
}

// ListenAndServe starts the ext_authz HTTP server on addr.
// It shuts down gracefully when ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return srv.Shutdown(context.Background())
	}
}

// extractSourceIP returns the original client IP from Envoy-provided headers.
// It checks x-forwarded-for first (leftmost IP), then x-envoy-external-address.
func extractSourceIP(r *http.Request) string {
	if xff := r.Header.Get("x-forwarded-for"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		// Strip port if present (unlikely in XFF but be safe).
		if host, _, err := net.SplitHostPort(ip); err == nil {
			return host
		}
		return ip
	}
	if addr := r.Header.Get("x-envoy-external-address"); addr != "" {
		return strings.TrimSpace(addr)
	}
	return ""
}

// extractPath returns the original request path from Envoy-provided headers.
func extractPath(r *http.Request) string {
	if p := r.Header.Get("x-envoy-original-path"); p != "" {
		return p
	}
	return r.URL.Path
}
