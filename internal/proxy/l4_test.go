package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
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
