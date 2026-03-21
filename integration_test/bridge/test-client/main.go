package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

func main() {
	vipAddr := os.Getenv("BRIDGE_VIP_ADDR")
	vipPort := os.Getenv("BRIDGE_VIP_PORT")
	clientSecret := os.Getenv("TAILNET2_TS_CLIENT_SECRET")

	if vipAddr == "" || vipPort == "" || clientSecret == "" {
		log.Fatal("BRIDGE_VIP_ADDR, BRIDGE_VIP_PORT, TAILNET2_TS_CLIENT_SECRET required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	dir := filepath.Join(os.TempDir(), "bridge-test-client")
	_ = os.MkdirAll(dir, 0o700)

	srv := &tsnet.Server{
		Dir:           dir,
		Hostname:      "bridge-test-client",
		AuthKey:       clientSecret,
		Ephemeral:     true,
		AdvertiseTags: []string{"tag:user"},
	}
	defer func() { _ = srv.Close() }()

	log.Println("connecting to tailnet2...")
	if _, err := srv.Up(ctx); err != nil {
		log.Fatalf("tsnet up: %v", err)
	}
	log.Println("connected to tailnet2")

	// Dump peer status for diagnostics.
	lc, err := srv.LocalClient()
	if err != nil {
		log.Printf("warning: could not get local client: %v", err)
	} else {
		st, err := lc.Status(ctx)
		if err != nil {
			log.Printf("warning: status failed: %v", err)
		} else {
			log.Printf("self: %s (%s)", st.Self.HostName, st.Self.TailscaleIPs)
			for _, peer := range st.Peer {
				log.Printf("peer: %s (%s) online=%v", peer.HostName, peer.TailscaleIPs, peer.Online)
			}
			// Check if VIP address appears in any peer's AllowedIPs
			for _, peer := range st.Peer {
				for _, a := range peer.TailscaleIPs {
					if a.String() == vipAddr {
						log.Printf("VIP %s found in peer %s's IPs", vipAddr, peer.HostName)
					}
				}
			}
		}
	}

	// First test: try to reach the bridge node directly (non-VIP) to confirm
	// basic tailnet connectivity.
	if lc != nil {
		st, _ := lc.Status(ctx)
		if st != nil {
			for _, peer := range st.Peer {
				if strings.Contains(peer.HostName, "bridge") && len(peer.TailscaleIPs) > 0 {
					bridgeIP := peer.TailscaleIPs[0].String()
					log.Printf("testing basic connectivity to bridge node %s (%s)...", peer.HostName, bridgeIP)
					dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
					conn, err := srv.Dial(dialCtx, "tcp", bridgeIP+":80")
					dialCancel()
					if err != nil {
						log.Printf("  basic dial to bridge failed: %v", err)
					} else {
						log.Printf("  basic dial to bridge succeeded!")
						_ = conn.Close()
					}
					break
				}
			}
		}
	}

	log.Printf("target VIP: %s:%s", vipAddr, vipPort)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("  dialing %s via tsnet...", addr)
				conn, err := srv.Dial(dialCtx, network, addr)
				if err != nil {
					return nil, err
				}
				log.Printf("  dial succeeded: local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())
				return conn, nil
			},
		},
		Timeout: 10 * time.Second,
	}

	target := fmt.Sprintf("http://%s:%s/", vipAddr, vipPort)

	// Re-dump status after a few seconds to see if VIP routes appeared.
	time.Sleep(5 * time.Second)
	if lc != nil {
		st, _ := lc.Status(ctx)
		if st != nil {
			log.Printf("=== status after 5s wait ===")
			log.Printf("peers: %d", len(st.Peer))
			for _, peer := range st.Peer {
				log.Printf("  peer: %s ips=%s online=%v", peer.HostName, peer.TailscaleIPs, peer.Online)
			}
			// Dump full status JSON for debugging
			if raw, err := json.Marshal(st); err == nil {
				log.Printf("full status: %s", string(raw))
			}
		}
	}

	var lastErr error
	for attempt := 1; attempt <= 20; attempt++ {
		log.Printf("attempt %d: GET %s", attempt, target)

		req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("  error: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		log.Printf("  status: %d, body: %s", resp.StatusCode, strings.TrimSpace(string(body)))

		if resp.StatusCode == 200 {
			fmt.Println("PASS: cross-tailnet connection test succeeded")
			os.Exit(0)
		}

		lastErr = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		time.Sleep(3 * time.Second)
	}

	log.Fatalf("FAIL: cross-tailnet connection test failed after 20 attempts: %v", lastErr)
}
