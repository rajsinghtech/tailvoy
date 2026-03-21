package main

import (
	"context"
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

	// Use srv.Dial with per-attempt timeouts so we retry if the VIP route
	// hasn't propagated yet, instead of blocking forever.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return srv.Dial(dialCtx, network, addr)
			},
		},
		Timeout: 10 * time.Second,
	}

	target := fmt.Sprintf("http://%s:%s/", vipAddr, vipPort)

	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
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

	log.Fatalf("FAIL: cross-tailnet connection test failed after 30 attempts: %v", lastErr)
}
