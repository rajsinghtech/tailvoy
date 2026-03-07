package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	tailscale "tailscale.com/client/tailscale/v2"
)

// MultiManager manages multiple VIP services.
type MultiManager struct {
	client      *tailscale.Client
	serviceTags []string
	logger      *slog.Logger
}

func NewMultiManager(client *tailscale.Client, tags []string, logger *slog.Logger) *MultiManager {
	return &MultiManager{client: client, serviceTags: tags, logger: logger}
}

// EnsureAll creates or updates all services. mappings is svcName -> list of ports.
// All services are attempted even if some fail; errors are collected and joined.
func (mm *MultiManager) EnsureAll(ctx context.Context, mappings map[string][]int) error {
	var errs []error
	for svcName, ports := range mappings {
		tcpPorts := make([]string, len(ports))
		for i, p := range ports {
			tcpPorts[i] = fmt.Sprintf("tcp:%d", p)
		}

		svc := tailscale.VIPService{
			Name:    svcName,
			Tags:    mm.serviceTags,
			Ports:   tcpPorts,
			Comment: "Managed by Tailvoy",
		}

		existing, err := mm.client.VIPServices().Get(ctx, svcName)
		if err == nil && len(existing.Addrs) > 0 {
			svc.Addrs = existing.Addrs
		}

		mm.logger.Info("ensuring VIP service", "name", svcName, "ports", ports)
		if err := mm.client.VIPServices().CreateOrUpdate(ctx, svc); err != nil {
			errs = append(errs, fmt.Errorf("create/update VIP service %s: %w", svcName, err))
		}
	}
	return errors.Join(errs...)
}
