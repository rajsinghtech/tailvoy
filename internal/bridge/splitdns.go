package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// DNSClient abstracts the Tailscale DNS API.
type DNSClient interface {
	SplitDNS(ctx context.Context) (map[string][]string, error)
	UpdateSplitDNS(ctx context.Context, req map[string][]string) (map[string][]string, error)
}

type SplitDNSConfigurator struct {
	client     DNSClient
	cleanup    bool
	logger     *slog.Logger
	configured map[string]bool
}

func NewSplitDNSConfigurator(client DNSClient, cleanup bool, logger *slog.Logger) *SplitDNSConfigurator {
	return &SplitDNSConfigurator{
		client:     client,
		cleanup:    cleanup,
		logger:     logger,
		configured: make(map[string]bool),
	}
}

// ExtractZone extracts the MagicDNS zone from a list of FQDNs.
// e.g. ["web-1.tail1234.ts.net", "db-1.tail1234.ts.net"] → "tail1234.ts.net"
// Returns empty string if no FQDNs provided or no common zone found.
func ExtractZone(fqdns []string) string {
	if len(fqdns) == 0 {
		return ""
	}
	fqdn := strings.TrimSuffix(fqdns[0], ".")
	idx := strings.Index(fqdn, ".")
	if idx < 0 {
		return ""
	}
	return fqdn[idx+1:]
}

// Configure ensures split-DNS is set for the zone pointing to the bridge DNS IP.
// Idempotent: checks existing config before writing.
func (s *SplitDNSConfigurator) Configure(ctx context.Context, zone string, dnsIP string) error {
	if s.configured[zone] {
		return nil
	}

	existing, err := s.client.SplitDNS(ctx)
	if err != nil {
		return fmt.Errorf("get split-dns: %w", err)
	}

	if ips, ok := existing[zone]; ok {
		for _, ip := range ips {
			if ip == dnsIP {
				s.configured[zone] = true
				return nil
			}
		}
	}

	_, err = s.client.UpdateSplitDNS(ctx, map[string][]string{
		zone: {dnsIP},
	})
	if err != nil {
		return fmt.Errorf("update split-dns for zone %s: %w", zone, err)
	}

	s.configured[zone] = true
	s.logger.Info("configured split-dns", "zone", zone, "dns_ip", dnsIP)
	return nil
}

// Cleanup removes split-DNS entries for all zones configured by this session.
func (s *SplitDNSConfigurator) Cleanup(ctx context.Context) error {
	if !s.cleanup {
		return nil
	}
	var errs []error
	for zone := range s.configured {
		_, err := s.client.UpdateSplitDNS(ctx, map[string][]string{
			zone: {},
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("cleanup zone %s: %w", zone, err))
		} else {
			s.logger.Info("cleaned up split-dns", "zone", zone)
		}
	}
	return errors.Join(errs...)
}
