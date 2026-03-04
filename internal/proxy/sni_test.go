package proxy

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

func TestPeekSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true,
		})
		tlsConn.Handshake() // will fail, that's fine
	}()

	sni, reader, err := PeekSNI(serverConn)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "app.example.com" {
		t.Errorf("SNI = %q, want app.example.com", sni)
	}

	// Verify the reader replays the peeked bytes.
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	if n == 0 {
		t.Error("expected peeked data to be readable")
	}
	// First byte should be 0x16 (TLS handshake).
	if buf[0] != 0x16 {
		t.Errorf("first byte = %#x, want 0x16", buf[0])
	}
}

func TestPeekSNI_NonTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	sni, reader, err := PeekSNI(serverConn)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "" {
		t.Errorf("expected empty SNI for non-TLS, got %q", sni)
	}

	// Reader should replay the HTTP data.
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "GET /") {
		t.Errorf("expected HTTP data replay, got %q", buf[:n])
	}
}

func TestParseSNI_Truncated(t *testing.T) {
	// Too short to be TLS.
	if sni := parseSNI([]byte{0x16, 0x03}); sni != "" {
		t.Errorf("expected empty SNI for truncated data, got %q", sni)
	}
	// Empty.
	if sni := parseSNI(nil); sni != "" {
		t.Errorf("expected empty SNI for nil data, got %q", sni)
	}
	// Not TLS (wrong content type).
	if sni := parseSNI([]byte{0x15, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}); sni != "" {
		t.Errorf("expected empty SNI for non-handshake, got %q", sni)
	}
}
