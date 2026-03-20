package bridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

func (r *Reconciler) log() *slog.Logger {
	if r.logger != nil {
		return r.logger
	}
	return slog.Default()
}

const managedComment = "Managed by tailvoy bridge"

// VIPServicesClient abstracts the Tailscale VIP Services API.
type VIPServicesClient interface {
	CreateOrUpdate(ctx context.Context, svc tailscale.VIPService) error
	Get(ctx context.Context, name string) (*tailscale.VIPService, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]tailscale.VIPService, error)
}

// AdvertisementClient manages which services the dest tsnet node advertises.
type AdvertisementClient interface {
	AdvertiseServices(ctx context.Context, services []string) error
}

type Reconciler struct {
	client      VIPServicesClient
	advertiser  AdvertisementClient
	serviceTags []string
	prefix      string
	logger      *slog.Logger
	current     map[string]string // fqdn → svc name
}

func NewReconciler(client VIPServicesClient, advertiser AdvertisementClient, serviceTags []string, prefix string, logger *slog.Logger) *Reconciler {
	return &Reconciler{
		client:      client,
		advertiser:  advertiser,
		serviceTags: serviceTags,
		prefix:      prefix,
		logger:      logger,
		current:     make(map[string]string),
	}
}

// portsForDevice converts DeviceInfo ports to VIP service port strings.
func portsForDevice(info DeviceInfo) []string {
	ports := make([]string, len(info.Ports))
	for i, p := range info.Ports {
		ports[i] = fmt.Sprintf("tcp:%d", p)
	}
	return ports
}

// Reconcile diffs desired vs current state, creates/updates/deletes VIP services.
// After all changes, updates service advertisement on the dest tsnet node.
// Returns a map of svcName → allocated VIP IPs (for DNS record updates).
func (r *Reconciler) Reconcile(ctx context.Context, desired map[string]DeviceInfo) (map[string][]string, error) {
	var errs []error

	// Create or update services for desired devices.
	for fqdn, info := range desired {
		svcName := ServiceName(fqdn, r.prefix)
		wantPorts := portsForDevice(info)

		existing, err := r.client.Get(ctx, svcName)
		if err != nil {
			// Service doesn't exist yet, create it.
			r.log().Info("creating VIP service", "svc", svcName, "fqdn", fqdn)
			svc := tailscale.VIPService{
				Name:    svcName,
				Tags:    r.serviceTags,
				Ports:   wantPorts,
				Comment: managedComment,
			}
			if createErr := r.client.CreateOrUpdate(ctx, svc); createErr != nil {
				errs = append(errs, fmt.Errorf("create %s: %w", svcName, createErr))
				continue
			}
		} else {
			// Check if update is needed (ports changed).
			if !portsEqual(existing.Ports, wantPorts) {
				r.log().Info("updating VIP service ports", "svc", svcName)
				svc := tailscale.VIPService{
					Name:    svcName,
					Addrs:   existing.Addrs, // preserve allocated IPs
					Tags:    r.serviceTags,
					Ports:   wantPorts,
					Comment: managedComment,
				}
				if updateErr := r.client.CreateOrUpdate(ctx, svc); updateErr != nil {
					errs = append(errs, fmt.Errorf("update %s: %w", svcName, updateErr))
					continue
				}
			}
		}
		r.current[fqdn] = svcName
	}

	// Delete services for removed devices.
	for fqdn, svcName := range r.current {
		if _, ok := desired[fqdn]; !ok {
			r.log().Info("deleting VIP service", "svc", svcName, "fqdn", fqdn)
			if delErr := r.client.Delete(ctx, svcName); delErr != nil {
				errs = append(errs, fmt.Errorf("delete %s: %w", svcName, delErr))
				continue
			}
			delete(r.current, fqdn)
		}
	}

	// Advertise all current services.
	svcNames := make([]string, 0, len(r.current))
	for _, name := range r.current {
		svcNames = append(svcNames, name)
	}
	if advErr := r.advertiser.AdvertiseServices(ctx, svcNames); advErr != nil {
		errs = append(errs, fmt.Errorf("advertise services: %w", advErr))
	}

	// Collect VIP IPs for each current service.
	result := make(map[string][]string, len(r.current))
	for _, svcName := range r.current {
		svc, getErr := r.client.Get(ctx, svcName)
		if getErr != nil {
			errs = append(errs, fmt.Errorf("get addrs %s: %w", svcName, getErr))
			continue
		}
		result[svcName] = svc.Addrs
	}

	return result, errors.Join(errs...)
}

// CleanupOrphans lists VIP services matching the bridge's naming pattern,
// deletes those not in the desired state.
func (r *Reconciler) CleanupOrphans(ctx context.Context, desired map[string]DeviceInfo) error {
	svcs, err := r.client.List(ctx)
	if err != nil {
		return fmt.Errorf("list VIP services: %w", err)
	}

	// Build desired svc name set.
	desiredNames := make(map[string]struct{}, len(desired))
	for fqdn := range desired {
		desiredNames[ServiceName(fqdn, r.prefix)] = struct{}{}
	}

	var errs []error
	for _, svc := range svcs {
		if !r.isManagedByBridge(svc) {
			continue
		}
		if _, ok := desiredNames[svc.Name]; ok {
			continue
		}
		r.log().Info("cleaning up orphaned VIP service", "svc", svc.Name)
		if delErr := r.client.Delete(ctx, svc.Name); delErr != nil {
			errs = append(errs, fmt.Errorf("delete orphan %s: %w", svc.Name, delErr))
		}
	}
	return errors.Join(errs...)
}

// isManagedByBridge returns true if the service was created by this bridge.
func (r *Reconciler) isManagedByBridge(svc tailscale.VIPService) bool {
	if svc.Comment == managedComment {
		return true
	}
	// Fallback: match prefix pattern (svc:{prefix}...).
	return strings.HasPrefix(svc.Name, "svc:"+r.prefix)
}

// portsEqual returns true if both slices contain the same port strings (order-insensitive).
func portsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := set[p]; !ok {
			return false
		}
	}
	return true
}
