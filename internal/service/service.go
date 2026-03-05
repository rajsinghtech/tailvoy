package service

import (
	"context"
	"fmt"
	"log/slog"

	tailscale "tailscale.com/client/tailscale/v2"
)

type Manager struct {
	client      *tailscale.Client
	serviceName string
	serviceTags []string
	logger      *slog.Logger
}

func New(client *tailscale.Client, svcName string, tags []string, logger *slog.Logger) *Manager {
	return &Manager{
		client:      client,
		serviceName: svcName,
		serviceTags: tags,
		logger:      logger,
	}
}

func (m *Manager) Ensure(ctx context.Context, ports []string) error {
	svc := tailscale.VIPService{
		Name:    m.serviceName,
		Tags:    m.serviceTags,
		Ports:   ports,
		Comment: "Managed by Tailvoy",
	}
	m.logger.Info("ensuring VIP service", "name", m.serviceName, "ports", ports, "tags", m.serviceTags)
	if err := m.client.VIPServices().CreateOrUpdate(ctx, svc); err != nil {
		return fmt.Errorf("create/update VIP service %s: %w", m.serviceName, err)
	}
	return nil
}

func (m *Manager) Delete(ctx context.Context) error {
	m.logger.Info("deleting VIP service", "name", m.serviceName)
	if err := m.client.VIPServices().Delete(ctx, m.serviceName); err != nil {
		return fmt.Errorf("delete VIP service %s: %w", m.serviceName, err)
	}
	return nil
}

func (m *Manager) ServiceName() string {
	return m.serviceName
}
