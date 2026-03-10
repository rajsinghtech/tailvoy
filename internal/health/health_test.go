package health

import (
	"sort"
	"testing"
)

func TestEvaluate_PolicyAny_AllHealthy(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}, "ln2": {"svc:web"}}
	lc := map[string][]string{"ln1": {"cluster_a"}, "ln2": {"cluster_b"}}
	ch := map[string]ClusterHealth{
		"cluster_a": {Name: "cluster_a", TotalHosts: 2, HealthyHosts: 2},
		"cluster_b": {Name: "cluster_b", TotalHosts: 1, HealthyHosts: 1},
	}

	result := Evaluate(lts, lc, ch, PolicyAny)
	if !result["svc:web"].Healthy {
		t.Error("expected svc:web to be healthy")
	}
}

func TestEvaluate_PolicyAny_OneUnhealthy(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}, "ln2": {"svc:web"}}
	lc := map[string][]string{"ln1": {"cluster_a"}, "ln2": {"cluster_b"}}
	ch := map[string]ClusterHealth{
		"cluster_a": {Name: "cluster_a", TotalHosts: 2, HealthyHosts: 0},
		"cluster_b": {Name: "cluster_b", TotalHosts: 1, HealthyHosts: 1},
	}

	result := Evaluate(lts, lc, ch, PolicyAny)
	if result["svc:web"].Healthy {
		t.Error("expected svc:web to be unhealthy with PolicyAny when one cluster is down")
	}
}

func TestEvaluate_PolicyAll_OneUnhealthy(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}, "ln2": {"svc:web"}}
	lc := map[string][]string{"ln1": {"cluster_a"}, "ln2": {"cluster_b"}}
	ch := map[string]ClusterHealth{
		"cluster_a": {Name: "cluster_a", TotalHosts: 2, HealthyHosts: 0},
		"cluster_b": {Name: "cluster_b", TotalHosts: 1, HealthyHosts: 1},
	}

	result := Evaluate(lts, lc, ch, PolicyAll)
	if !result["svc:web"].Healthy {
		t.Error("expected svc:web to be healthy with PolicyAll when only one cluster is down")
	}
}

func TestEvaluate_PolicyAll_AllUnhealthy(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}}
	lc := map[string][]string{"ln1": {"cluster_a", "cluster_b"}}
	ch := map[string]ClusterHealth{
		"cluster_a": {Name: "cluster_a", TotalHosts: 2, HealthyHosts: 0},
		"cluster_b": {Name: "cluster_b", TotalHosts: 1, HealthyHosts: 0},
	}

	result := Evaluate(lts, lc, ch, PolicyAll)
	if result["svc:web"].Healthy {
		t.Error("expected svc:web to be unhealthy with PolicyAll when all clusters are down")
	}
}

func TestEvaluate_NoClusters_StartupGrace(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}}
	lc := map[string][]string{} // no cluster mappings yet
	ch := map[string]ClusterHealth{}

	result := Evaluate(lts, lc, ch, PolicyAny)
	if !result["svc:web"].Healthy {
		t.Error("expected svc:web to be healthy when no clusters are mapped (startup grace)")
	}
}

func TestEvaluate_ClusterNotInHealth_Grace(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}}
	lc := map[string][]string{"ln1": {"cluster_a"}}
	ch := map[string]ClusterHealth{} // cluster_a not in health data

	result := Evaluate(lts, lc, ch, PolicyAny)
	if !result["svc:web"].Healthy {
		t.Error("expected svc:web to be healthy when cluster not in health data")
	}
}

func TestEvaluate_MultipleServices(t *testing.T) {
	lts := map[string][]string{"ln1": {"svc:web"}, "ln2": {"svc:api"}}
	lc := map[string][]string{"ln1": {"cluster_a"}, "ln2": {"cluster_b"}}
	ch := map[string]ClusterHealth{
		"cluster_a": {Name: "cluster_a", TotalHosts: 1, HealthyHosts: 1},
		"cluster_b": {Name: "cluster_b", TotalHosts: 1, HealthyHosts: 0},
	}

	result := Evaluate(lts, lc, ch, PolicyAny)
	if !result["svc:web"].Healthy {
		t.Error("expected svc:web to be healthy")
	}
	if result["svc:api"].Healthy {
		t.Error("expected svc:api to be unhealthy")
	}
}

func TestTracker_ThresholdBeforeUnadvertise(t *testing.T) {
	tracker := NewTracker(3)
	unhealthySvc := map[string]ServiceHealth{
		"svc:web": {Healthy: false},
	}

	// First two polls: no unadvertise yet.
	for i := 0; i < 2; i++ {
		_, toUnadv := tracker.Update(unhealthySvc)
		if len(toUnadv) > 0 {
			t.Errorf("poll %d: should not unadvertise before threshold", i)
		}
	}

	// Third poll: should trigger unadvertise.
	_, toUnadv := tracker.Update(unhealthySvc)
	if len(toUnadv) != 1 || toUnadv[0] != "svc:web" {
		t.Errorf("expected unadvertise svc:web, got %v", toUnadv)
	}
}

func TestTracker_ImmediateRecovery(t *testing.T) {
	tracker := NewTracker(1)

	// Become unhealthy.
	tracker.Update(map[string]ServiceHealth{"svc:web": {Healthy: false}})

	// Recover immediately.
	toAdv, _ := tracker.Update(map[string]ServiceHealth{"svc:web": {Healthy: true}})
	if len(toAdv) != 1 || toAdv[0] != "svc:web" {
		t.Errorf("expected immediate readvertise, got %v", toAdv)
	}
}

func TestTracker_NoDoubleUnadvertise(t *testing.T) {
	tracker := NewTracker(1)

	// First unhealthy → unadvertise.
	_, toUnadv := tracker.Update(map[string]ServiceHealth{"svc:web": {Healthy: false}})
	if len(toUnadv) != 1 {
		t.Fatalf("expected 1 unadvertise, got %d", len(toUnadv))
	}

	// Second unhealthy → should NOT unadvertise again.
	_, toUnadv = tracker.Update(map[string]ServiceHealth{"svc:web": {Healthy: false}})
	if len(toUnadv) != 0 {
		t.Error("should not unadvertise twice")
	}
}

func TestTracker_NoDoubleAdvertise(t *testing.T) {
	tracker := NewTracker(1)

	// Healthy → starts advertised, no action needed.
	toAdv, _ := tracker.Update(map[string]ServiceHealth{"svc:web": {Healthy: true}})
	if len(toAdv) != 0 {
		t.Error("first healthy poll should not produce advertise action (already default advertised)")
	}
}

func TestTracker_MultipleServices(t *testing.T) {
	tracker := NewTracker(1)

	health := map[string]ServiceHealth{
		"svc:web": {Healthy: false},
		"svc:api": {Healthy: true},
	}

	toAdv, toUnadv := tracker.Update(health)
	sort.Strings(toUnadv)
	if len(toAdv) != 0 {
		t.Error("no advertise expected")
	}
	if len(toUnadv) != 1 || toUnadv[0] != "svc:web" {
		t.Errorf("expected unadvertise svc:web, got %v", toUnadv)
	}
}
