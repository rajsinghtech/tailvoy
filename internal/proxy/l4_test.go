package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// startEchoServer listens on 127.0.0.1:0 and echoes back anything received.
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

func TestForwardBasic(t *testing.T) {
	backend := startEchoServer(t)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	p := NewL4Proxy(slog.Default())

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Forward(context.Background(), proxyConn, backend.Addr().String(), nil, false)
	}()

	payload := []byte("hello proxy")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q, want %q", buf, payload)
	}

	clientConn.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Forward returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return in time")
	}
}

func TestForwardContextCancellation(t *testing.T) {
	backend := startEchoServer(t)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	p := NewL4Proxy(slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Forward(ctx, proxyConn, backend.Addr().String(), nil, false)
	}()

	// Send some data to confirm the connection is working.
	payload := []byte("before cancel")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	// Cancel context mid-stream.
	cancel()

	select {
	case <-errCh:
		// Forward returned, which is the expected behavior after cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after context cancellation")
	}
}

func TestForwardBackendImmediateClose(t *testing.T) {
	// Backend that accepts and immediately closes the connection.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backendLn.Close() })

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Use a real TCP listener so that half-close propagates properly.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	p := NewL4Proxy(slog.Default())
	errCh := make(chan error, 1)

	go func() {
		conn, err := proxyLn.Accept()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- p.Forward(context.Background(), conn, backendLn.Addr().String(), nil, false)
	}()

	clientConn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// The backend closes immediately, so reads on the client side should get EOF.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Fatal("expected error (EOF/closed) when backend closes immediately")
	}

	// Close client so that the client->backend copy goroutine also finishes.
	clientConn.Close()

	select {
	case err := <-errCh:
		// Forward may return nil or an error; either is acceptable when
		// the backend closes immediately.
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return in time")
	}
}

func TestForwardBackendUnreachable(t *testing.T) {
	// Use a port that is not listening; dial should fail.
	// Bind to get a free port, then close the listener so it's guaranteed unused.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachableAddr := tmpLn.Addr().String()
	tmpLn.Close()

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	p := NewL4Proxy(slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.Forward(ctx, proxyConn, unreachableAddr, nil, false)
	if err == nil {
		t.Fatal("expected error dialing unreachable backend")
	}
	if !strings.Contains(err.Error(), "dial backend") {
		t.Fatalf("expected dial error, got: %v", err)
	}
}

func TestForwardLargePayload(t *testing.T) {
	backend := startEchoServer(t)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	p := NewL4Proxy(slog.Default())

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Forward(context.Background(), proxyConn, backend.Addr().String(), nil, false)
	}()

	// 1MB payload.
	const payloadSize = 1 << 20
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Write and read concurrently to avoid pipe buffer deadlock.
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(payload)
		writeDone <- err
	}()

	received := make([]byte, payloadSize)
	clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err := io.ReadFull(clientConn, received)
	if err != nil {
		t.Fatalf("read large payload: %v", err)
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("write large payload: %v", err)
	}

	for i := range payload {
		if payload[i] != received[i] {
			t.Fatalf("mismatch at byte %d: got %d, want %d", i, received[i], payload[i])
		}
	}

	clientConn.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Forward returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Forward did not return in time")
	}
}

func TestForwardHalfClose(t *testing.T) {
	// Backend that receives data, sends a response, then waits for client close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read until client closes write side.
		data, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		// Send the length of received data back as a response.
		resp := fmt.Sprintf("received:%d", len(data))
		conn.Write([]byte(resp))
	}()

	clientConn, proxyConn := net.Pipe()
	p := NewL4Proxy(slog.Default())

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Forward(context.Background(), proxyConn, ln.Addr().String(), nil, false)
	}()

	// Write data, then close write side (half-close via full close on pipe).
	payload := []byte("half-close-test")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Close the write direction. net.Pipe doesn't support half-close,
	// so we close the entire connection and let Forward finish.
	clientConn.Close()

	select {
	case err := <-errCh:
		// Forward should return cleanly.
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return in time")
	}

	select {
	case <-backendDone:
	case <-time.After(5 * time.Second):
		t.Fatal("backend handler did not finish in time")
	}
}

func TestForwardWithProxyProtocol(t *testing.T) {
	// Backend that reads the PROXY protocol header, then echoes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	type ppResult struct {
		srcIP   string
		srcPort int
	}
	ppCh := make(chan ppResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Wrap with proxyproto.Conn to parse the PROXY header on first read.
		ppConn := proxyproto.NewConn(conn)

		// Trigger header parsing by reading application data.
		oneByte := make([]byte, 1)
		n, err := ppConn.Read(oneByte)
		if err != nil && err != io.EOF {
			return
		}

		hdr := ppConn.ProxyHeader()
		if hdr != nil {
			src := hdr.SourceAddr.(*net.TCPAddr)
			ppCh <- ppResult{srcIP: src.IP.String(), srcPort: src.Port}
		}

		// Echo the byte we consumed, then the rest.
		if n > 0 {
			conn.Write(oneByte[:n])
		}
		io.Copy(conn, ppConn)
	}()

	srcAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	p := NewL4Proxy(slog.Default())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Forward(context.Background(), proxyConn, ln.Addr().String(), srcAddr, true)
	}()

	payload := []byte("pp-test")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	select {
	case res := <-ppCh:
		if res.srcIP != "203.0.113.50" {
			t.Fatalf("PROXY header srcIP = %q, want 203.0.113.50", res.srcIP)
		}
		if res.srcPort != 12345 {
			t.Fatalf("PROXY header srcPort = %d, want 12345", res.srcPort)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive PROXY protocol header in time")
	}

	clientConn.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Forward returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return in time")
	}
}
