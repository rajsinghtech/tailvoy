package health

import "sync"

type Policy string

const (
	PolicyAny Policy = "any" // unadvertise if ANY cluster has 0 healthy hosts
	PolicyAll Policy = "all" // unadvertise only if ALL clusters have 0 healthy hosts
)

type ClusterHealth struct {
	Name         string
	TotalHosts   int
	HealthyHosts int
}

type ServiceHealth struct {
	Healthy  bool
	Clusters map[string]ClusterHealth
}

// Evaluate computes per-service health from cluster data.
// listenerToService maps listener name → []"svc:name".
// listenerClusters maps listener name → cluster names.
// clusterHealth maps cluster name → health info.
func Evaluate(
	listenerToService map[string][]string,
	listenerClusters map[string][]string,
	clusterHealth map[string]ClusterHealth,
	policy Policy,
) map[string]ServiceHealth {
	// Group clusters by service.
	serviceClusters := make(map[string]map[string]bool)
	for listener, svcs := range listenerToService {
		clusters := listenerClusters[listener]
		if len(clusters) == 0 {
			continue
		}
		for _, svc := range svcs {
			if serviceClusters[svc] == nil {
				serviceClusters[svc] = make(map[string]bool)
			}
			for _, c := range clusters {
				serviceClusters[svc][c] = true
			}
		}
	}

	result := make(map[string]ServiceHealth, len(serviceClusters))
	for svc, clusterSet := range serviceClusters {
		sh := ServiceHealth{Clusters: make(map[string]ClusterHealth, len(clusterSet))}

		hasAnyUnhealthy := false
		allUnhealthy := true

		for cName := range clusterSet {
			ch, ok := clusterHealth[cName]
			if !ok {
				// Cluster not in health data yet — treat as healthy (startup grace).
				allUnhealthy = false
				continue
			}
			sh.Clusters[cName] = ch
			if ch.HealthyHosts > 0 {
				allUnhealthy = false
			} else {
				hasAnyUnhealthy = true
			}
		}

		switch policy {
		case PolicyAny:
			sh.Healthy = !hasAnyUnhealthy
		case PolicyAll:
			sh.Healthy = !allUnhealthy
		default:
			sh.Healthy = !hasAnyUnhealthy
		}

		result[svc] = sh
	}

	// Services with listeners but no clusters (unmapped) default to healthy.
	for _, svcs := range listenerToService {
		for _, svc := range svcs {
			if _, exists := result[svc]; !exists {
				result[svc] = ServiceHealth{Healthy: true}
			}
		}
	}

	return result
}

// Tracker tracks consecutive unhealthy poll counts per service and determines
// which services should be advertised or unadvertised.
type Tracker struct {
	mu         sync.Mutex
	threshold  int
	counts     map[string]int  // service → consecutive unhealthy polls
	advertised map[string]bool // service → currently advertised
}

const DefaultUnhealthyThreshold = 3

func NewTracker(threshold int) *Tracker {
	if threshold <= 0 {
		threshold = DefaultUnhealthyThreshold
	}
	return &Tracker{
		threshold:  threshold,
		counts:     make(map[string]int),
		advertised: make(map[string]bool),
	}
}

// Update processes health results and returns services to advertise/unadvertise.
func (t *Tracker) Update(health map[string]ServiceHealth) (toAdvertise, toUnadvertise []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for svc, sh := range health {
		// First time seeing this service — assume advertised.
		if _, seen := t.advertised[svc]; !seen {
			t.advertised[svc] = true
			t.counts[svc] = 0
		}

		if sh.Healthy {
			t.counts[svc] = 0
			if !t.advertised[svc] {
				toAdvertise = append(toAdvertise, svc)
				t.advertised[svc] = true
			}
		} else {
			t.counts[svc]++
			if t.counts[svc] >= t.threshold && t.advertised[svc] {
				toUnadvertise = append(toUnadvertise, svc)
				t.advertised[svc] = false
			}
		}
	}

	return toAdvertise, toUnadvertise
}
