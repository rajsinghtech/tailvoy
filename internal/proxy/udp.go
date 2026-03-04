package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rajsinghtech/tailvoy/internal/identity"
	"github.com/rajsinghtech/tailvoy/internal/policy"
)

const (
	udpBufSize    = 65535
	udpIdleExpiry = 30 * time.Second
)

type udpSession struct {
	backend  *net.UDPConn
	lastSeen time.Time
}

// UDPProxy forwards UDP packets between a tsnet PacketConn and a backend.
// It maintains per-source-address sessions with idle timeout cleanup.
type UDPProxy struct {
	logger *slog.Logger
}

func NewUDPProxy(logger *slog.Logger) *UDPProxy {
	return &UDPProxy{logger: logger}
}

// Serve reads packets from pc, resolves identity, checks L4 policy, and
// forwards allowed packets to backendAddr. Reverse packets are sent back
// to the original source. Sessions expire after 30s of inactivity.
func (p *UDPProxy) Serve(ctx context.Context, pc net.PacketConn, backendAddr string,
	resolver *identity.Resolver, engine *policy.Engine, listenerName string) error {

	backendUDP, err := net.ResolveUDPAddr("udp", backendAddr)
	if err != nil {
		return err
	}

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	// Cleanup expired sessions.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.lastSeen) > udpIdleExpiry {
						_ = s.backend.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	// Close all sessions on exit.
	defer func() {
		mu.Lock()
		for _, s := range sessions {
			_ = s.backend.Close()
		}
		mu.Unlock()
	}()

	// Close PacketConn when context is cancelled to unblock ReadFrom.
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, udpBufSize)
	for {
		n, srcAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.logger.Error("udp read error", "listener", listenerName, "err", err)
			continue
		}

		src := srcAddr.String()
		p.logger.Debug("udp packet received", "listener", listenerName, "from", src, "bytes", n)

		// Identity check on first packet from this source.
		mu.Lock()
		sess, exists := sessions[src]
		mu.Unlock()

		if !exists {
			id, err := resolver.Resolve(ctx, src)
			if err != nil {
				p.logger.Warn("udp identity resolution failed",
					"listener", listenerName, "remote", src, "err", err)
				continue
			}
			if !engine.HasAccess(id) {
				p.logger.Info("udp packet denied by L4 policy",
					"listener", listenerName, "remote", src,
					"identity", id.UserLogin, "node", id.NodeName)
				continue
			}

			p.logger.Debug("udp new session", "listener", listenerName,
				"from", src, "backend", backendAddr)

			bc, err := net.DialUDP("udp", nil, backendUDP)
			if err != nil {
				p.logger.Error("udp dial backend failed",
					"listener", listenerName, "backend", backendAddr, "err", err)
				continue
			}

			sess = &udpSession{backend: bc, lastSeen: time.Now()}
			mu.Lock()
			sessions[src] = sess
			mu.Unlock()

			// Reverse path: backend → source.
			go func(s *udpSession, origin net.Addr) {
				rbuf := make([]byte, udpBufSize)
				for {
					_ = s.backend.SetReadDeadline(time.Now().Add(udpIdleExpiry))
					rn, err := s.backend.Read(rbuf)
					if err != nil {
						p.logger.Debug("udp reverse read ended",
							"listener", listenerName, "err", err)
						return
					}
					p.logger.Debug("udp reverse packet", "listener", listenerName,
						"bytes", rn, "to", origin.String())
					mu.Lock()
					s.lastSeen = time.Now()
					mu.Unlock()
					if _, err := pc.WriteTo(rbuf[:rn], origin); err != nil {
						p.logger.Debug("udp reverse write failed",
							"listener", listenerName, "err", err)
						return
					}
				}
			}(sess, srcAddr)
		}

		mu.Lock()
		sess.lastSeen = time.Now()
		mu.Unlock()

		if _, err := sess.backend.Write(buf[:n]); err != nil {
			p.logger.Debug("udp write to backend failed",
				"listener", listenerName, "err", err)
		} else {
			p.logger.Debug("udp forwarded to backend", "listener", listenerName,
				"bytes", n)
		}
	}
}
