package bridge

import (
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// DNSServer is an authoritative DNS server for bridged zones.
type DNSServer struct {
	zone      string // e.g. "tail1234.ts.net." (with trailing dot)
	mu        sync.RWMutex
	records   map[string][]net.IP // fqdn (with trailing dot) → IPs
	tcpServer *dns.Server
	udpServer *dns.Server
	logger    *slog.Logger
}

func NewDNSServer(zone string, logger *slog.Logger) *DNSServer {
	return &DNSServer{
		zone:    dns.Fqdn(zone),
		records: make(map[string][]net.IP),
		logger:  logger,
	}
}

// SetRecords replaces all records atomically.
func (d *DNSServer) SetRecords(records map[string][]net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records = records
}

// AddRecord adds/updates a single FQDN's IPs.
func (d *DNSServer) AddRecord(fqdn string, ips []net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[dns.Fqdn(fqdn)] = ips
}

// RemoveRecord removes a FQDN.
func (d *DNSServer) RemoveRecord(fqdn string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.records, dns.Fqdn(fqdn))
}

// ServeDNS implements dns.Handler.
func (d *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		name := q.Name // already has trailing dot

		if !dns.IsSubDomain(d.zone, name) {
			msg.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(msg)
			return
		}

		d.mu.RLock()
		ips, ok := d.records[name]
		d.mu.RUnlock()

		if !ok {
			msg.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			w.WriteMsg(msg)
			return
		}

		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && q.Qtype == dns.TypeA {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   ip4,
				})
			} else if ip4 == nil && q.Qtype == dns.TypeAAAA {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
					AAAA: ip,
				})
			}
		}
	}

	w.WriteMsg(msg)
}

// ListenAndServeUDP starts the DNS server on a UDP PacketConn.
func (d *DNSServer) ListenAndServeUDP(pc net.PacketConn) error {
	d.udpServer = &dns.Server{PacketConn: pc, Handler: d}
	return d.udpServer.ActivateAndServe()
}

// Shutdown gracefully stops the server.
func (d *DNSServer) Shutdown() error {
	var errs []error
	if d.udpServer != nil {
		errs = append(errs, d.udpServer.Shutdown())
	}
	if d.tcpServer != nil {
		errs = append(errs, d.tcpServer.Shutdown())
	}
	return errors.Join(errs...)
}
