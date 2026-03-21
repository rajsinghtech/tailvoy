package bridge

import (
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"
)

const testZone = "tail1234.ts.net."

func startTestDNS(t *testing.T, zone string) (*DNSServer, string) {
	t.Helper()
	d := NewDNSServer(zone, slog.Default())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go d.ListenAndServeUDP(pc)
	t.Cleanup(func() { d.Shutdown() })
	return d, pc.LocalAddr().String()
}

func query(t *testing.T, addr, fqdn string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "udp"}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS query failed: %v", err)
	}
	return resp
}

func TestDNSServer_ARecord(t *testing.T) {
	d, addr := startTestDNS(t, testZone)
	d.AddRecord("web-1.tail1234.ts.net.", []net.IP{net.ParseIP("100.65.1.1")})

	resp := query(t, addr, "web-1.tail1234.ts.net.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("100.65.1.1")) {
		t.Errorf("expected 100.65.1.1, got %s", a.A)
	}
}

func TestDNSServer_AAAARecord(t *testing.T) {
	d, addr := startTestDNS(t, testZone)
	d.AddRecord("web-1.tail1234.ts.net.", []net.IP{net.ParseIP("fd7a:115c:a1e0::1")})

	resp := query(t, addr, "web-1.tail1234.ts.net.", dns.TypeAAAA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
	}
	if !aaaa.AAAA.Equal(net.ParseIP("fd7a:115c:a1e0::1")) {
		t.Errorf("expected fd7a:115c:a1e0::1, got %s", aaaa.AAAA)
	}
}

func TestDNSServer_NXDOMAIN(t *testing.T) {
	_, addr := startTestDNS(t, testZone)

	resp := query(t, addr, "unknown.tail1234.ts.net.", dns.TypeA)

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDNSServer_OutOfZone(t *testing.T) {
	_, addr := startTestDNS(t, testZone)

	resp := query(t, addr, "google.com.", dns.TypeA)

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("expected REFUSED, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDNSServer_DynamicUpdate(t *testing.T) {
	d, addr := startTestDNS(t, testZone)
	fqdn := "web-1.tail1234.ts.net."
	ip := net.ParseIP("100.65.1.1")

	// Add record — query should succeed
	d.AddRecord(fqdn, []net.IP{ip})
	resp := query(t, addr, fqdn, dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("after add: expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}

	// Remove record — query should return NXDOMAIN
	d.RemoveRecord(fqdn)
	resp = query(t, addr, fqdn, dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("after remove: expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}

	// Re-add record — query should succeed again
	d.AddRecord(fqdn, []net.IP{ip})
	resp = query(t, addr, fqdn, dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("after re-add: expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected answer after re-add")
	}
}
