package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"tailscale.com/client/local"
	"tailscale.com/ipn"

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

// AdvertisementManager toggles VIP service advertisement via local client prefs.
type AdvertisementManager struct {
	lc         *local.Client
	logger     *slog.Logger
	mu         sync.Mutex
	suppressed map[string]bool
}

func NewAdvertisementManager(lc *local.Client, logger *slog.Logger) *AdvertisementManager {
	return &AdvertisementManager{
		lc:         lc,
		logger:     logger,
		suppressed: make(map[string]bool),
	}
}

// Unadvertise removes the given services from AdvertiseServices prefs.
func (am *AdvertisementManager) Unadvertise(ctx context.Context, services []string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	prefs, err := am.lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}

	remove := make(map[string]bool, len(services))
	for _, s := range services {
		remove[s] = true
	}

	var filtered []string
	for _, s := range prefs.AdvertiseServices {
		if !remove[s] {
			filtered = append(filtered, s)
		}
	}

	_, err = am.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseServices: filtered,
		},
	})
	if err != nil {
		return fmt.Errorf("edit prefs (unadvertise): %w", err)
	}

	for _, s := range services {
		am.suppressed[s] = true
	}
	return nil
}

// Readvertise adds the given services back to AdvertiseServices prefs.
func (am *AdvertisementManager) Readvertise(ctx context.Context, services []string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	prefs, err := am.lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("get prefs: %w", err)
	}

	existing := make(map[string]bool, len(prefs.AdvertiseServices))
	for _, s := range prefs.AdvertiseServices {
		existing[s] = true
	}

	updated := prefs.AdvertiseServices
	for _, s := range services {
		if !existing[s] {
			updated = append(updated, s)
		}
	}

	_, err = am.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseServices: updated,
		},
	})
	if err != nil {
		return fmt.Errorf("edit prefs (readvertise): %w", err)
	}

	for _, s := range services {
		delete(am.suppressed, s)
	}
	return nil
}

// IsSuppressed returns whether a service is currently suppressed from advertisement.
func (am *AdvertisementManager) IsSuppressed(service string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	return am.suppressed[service]
}
