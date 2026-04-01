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

// SetZone updates the authoritative zone. Safe to call after construction.
func (d *DNSServer) SetZone(zone string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.zone = dns.Fqdn(zone)
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
			_ = w.WriteMsg(msg)
			return
		}

		d.mu.RLock()
		ips, ok := d.records[name]
		d.mu.RUnlock()

		if !ok {
			msg.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			_ = w.WriteMsg(msg)
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

	_ = w.WriteMsg(msg)
}

// ListenAndServeTCP starts the DNS server on a TCP listener.
func (d *DNSServer) ListenAndServeTCP(ln net.Listener) error {
	srv := &dns.Server{Listener: ln, Handler: d}
	d.mu.Lock()
	d.tcpServer = srv
	d.mu.Unlock()
	return srv.ActivateAndServe()
}

// ListenAndServeUDP starts the DNS server on a UDP PacketConn.
func (d *DNSServer) ListenAndServeUDP(pc net.PacketConn) error {
	srv := &dns.Server{PacketConn: pc, Handler: d}
	d.mu.Lock()
	d.udpServer = srv
	d.mu.Unlock()
	return srv.ActivateAndServe()
}

// Shutdown gracefully stops the server.
func (d *DNSServer) Shutdown() error {
	d.mu.RLock()
	udp := d.udpServer
	tcp := d.tcpServer
	d.mu.RUnlock()
	var errs []error
	if udp != nil {
		errs = append(errs, udp.Shutdown())
	}
	if tcp != nil {
		errs = append(errs, tcp.Shutdown())
	}
	return errors.Join(errs...)
}
