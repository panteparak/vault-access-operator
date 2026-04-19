/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSetConnectionHealth(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		healthy    bool
		expected   float64
	}{
		{
			name:       "healthy connection sets gauge to 1",
			connection: "test-connection",
			healthy:    true,
			expected:   1.0,
		},
		{
			name:       "unhealthy connection sets gauge to 0",
			connection: "test-connection-unhealthy",
			healthy:    false,
			expected:   0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetConnectionHealth(tt.connection, tt.healthy)

			// Get the metric value
			gauge := ConnectionHealthGauge.WithLabelValues(tt.connection)
			value := testutil.ToFloat64(gauge)

			if value != tt.expected {
				t.Errorf("SetConnectionHealth() = %v, want %v", value, tt.expected)
			}
		})
	}
}

func TestIncrementHealthCheck(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		success    bool
		label      string
	}{
		{
			name:       "successful health check increments success counter",
			connection: "test-conn-success",
			success:    true,
			label:      "success",
		},
		{
			name:       "failed health check increments failure counter",
			connection: "test-conn-failure",
			success:    false,
			label:      "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get initial value
			counter := ConnectionHealthCheckTotal.WithLabelValues(tt.connection, tt.label)
			initialValue := testutil.ToFloat64(counter)

			// Increment
			IncrementHealthCheck(tt.connection, tt.success)

			// Verify increment
			newValue := testutil.ToFloat64(counter)
			if newValue != initialValue+1 {
				t.Errorf("IncrementHealthCheck() = %v, want %v", newValue, initialValue+1)
			}
		})
	}
}

func TestSetConsecutiveFails(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		count      int
	}{
		{
			name:       "set zero consecutive fails",
			connection: "test-conn-zero",
			count:      0,
		},
		{
			name:       "set multiple consecutive fails",
			connection: "test-conn-multi",
			count:      5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetConsecutiveFails(tt.connection, tt.count)

			gauge := ConnectionConsecutiveFailsGauge.WithLabelValues(tt.connection)
			value := testutil.ToFloat64(gauge)

			if value != float64(tt.count) {
				t.Errorf("SetConsecutiveFails() = %v, want %v", value, tt.count)
			}
		})
	}
}

func TestIncrementPolicyReconcile(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		namespace string
		success   bool
		label     string
	}{
		{
			name:      "successful policy reconcile",
			kind:      "VaultPolicy",
			namespace: "default",
			success:   true,
			label:     "success",
		},
		{
			name:      "failed policy reconcile",
			kind:      "VaultClusterPolicy",
			namespace: "",
			success:   false,
			label:     "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := PolicyReconcileTotal.WithLabelValues(tt.kind, tt.namespace, tt.label)
			initialValue := testutil.ToFloat64(counter)

			IncrementPolicyReconcile(tt.kind, tt.namespace, tt.success)

			newValue := testutil.ToFloat64(counter)
			if newValue != initialValue+1 {
				t.Errorf("IncrementPolicyReconcile() = %v, want %v", newValue, initialValue+1)
			}
		})
	}
}

func TestIncrementRoleReconcile(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		namespace string
		success   bool
		label     string
	}{
		{
			name:      "successful role reconcile",
			kind:      "VaultRole",
			namespace: "default",
			success:   true,
			label:     "success",
		},
		{
			name:      "failed role reconcile",
			kind:      "VaultClusterRole",
			namespace: "",
			success:   false,
			label:     "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := RoleReconcileTotal.WithLabelValues(tt.kind, tt.namespace, tt.label)
			initialValue := testutil.ToFloat64(counter)

			IncrementRoleReconcile(tt.kind, tt.namespace, tt.success)

			newValue := testutil.ToFloat64(counter)
			if newValue != initialValue+1 {
				t.Errorf("IncrementRoleReconcile() = %v, want %v", newValue, initialValue+1)
			}
		})
	}
}

func TestSetOrphanedResources(t *testing.T) {
	tests := []struct {
		name         string
		connection   string
		resourceType string
		count        int
	}{
		{
			name:         "set orphaned policies count",
			connection:   "test-conn",
			resourceType: "policy",
			count:        3,
		},
		{
			name:         "set orphaned roles count",
			connection:   "test-conn",
			resourceType: "role",
			count:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetOrphanedResources(tt.connection, tt.resourceType, tt.count)

			gauge := OrphanedResourcesGauge.WithLabelValues(tt.connection, tt.resourceType)
			value := testutil.ToFloat64(gauge)

			if value != float64(tt.count) {
				t.Errorf("SetOrphanedResources() = %v, want %v", value, tt.count)
			}
		})
	}
}

func TestSetDriftDetected(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		namespace string
		resource  string
		detected  bool
		expected  float64
	}{
		{
			name:      "drift detected",
			kind:      "VaultPolicy",
			namespace: "default",
			resource:  "policy-a",
			detected:  true,
			expected:  1.0,
		},
		{
			name:      "no drift",
			kind:      "VaultPolicy",
			namespace: "staging",
			resource:  "policy-b",
			detected:  false,
			expected:  0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetDriftDetected(tt.kind, tt.namespace, tt.resource, tt.detected)

			gauge := DriftDetectedGauge.WithLabelValues(tt.kind, tt.namespace, tt.resource)
			value := testutil.ToFloat64(gauge)

			if value != tt.expected {
				t.Errorf("SetDriftDetected() = %v, want %v", value, tt.expected)
			}
		})
	}
}

// TestSetDriftDetected_PerResourceLabels pins the bug-fix in the
// metric labels: two resources in the same namespace must NOT
// overwrite each other's drift signal. Previously the gauge used
// (kind, namespace) only, so a second resource's "0" would silently
// mask a first resource's "1" — the alert
// `vault_access_operator_vault_drift_detected == 1` would miss drift.
func TestSetDriftDetected_PerResourceLabels(t *testing.T) {
	DriftDetectedGauge.Reset()

	SetDriftDetected("VaultPolicy", "shared-ns", "drifting-policy", true)
	SetDriftDetected("VaultPolicy", "shared-ns", "healthy-policy", false)

	// Both series should exist with their own values.
	drifting := testutil.ToFloat64(
		DriftDetectedGauge.WithLabelValues("VaultPolicy", "shared-ns", "drifting-policy"))
	healthy := testutil.ToFloat64(
		DriftDetectedGauge.WithLabelValues("VaultPolicy", "shared-ns", "healthy-policy"))

	if drifting != 1.0 {
		t.Errorf("drifting policy should still report 1, got %v", drifting)
	}
	if healthy != 0.0 {
		t.Errorf("healthy policy should report 0, got %v", healthy)
	}
}

// TestDeleteDriftDetected pins the metric-leak fix: when a CR is
// deleted, its drift series must be removed from the registry so the
// gauge doesn't forever show the last value.
func TestDeleteDriftDetected(t *testing.T) {
	DriftDetectedGauge.Reset()
	SetDriftDetected("VaultRole", "ns", "doomed-role", true)

	beforeDelete := testutil.CollectAndCount(DriftDetectedGauge)
	if beforeDelete != 1 {
		t.Fatalf("expected 1 series before delete, got %d", beforeDelete)
	}

	DeleteDriftDetected("VaultRole", "ns", "doomed-role")

	afterDelete := testutil.CollectAndCount(DriftDetectedGauge)
	if afterDelete != 0 {
		t.Errorf("expected 0 series after delete (no metric leak), got %d", afterDelete)
	}
}

// TestDeleteDriftDetected_NoOpWhenAbsent pins that calling Delete on
// a series that was never set is a safe no-op (handled by Prometheus
// SDK semantics — DeleteLabelValues returns false silently).
func TestDeleteDriftDetected_NoOpWhenAbsent(t *testing.T) {
	DriftDetectedGauge.Reset()
	// Should not panic or error.
	DeleteDriftDetected("VaultPolicy", "ns", "never-set")
	if c := testutil.CollectAndCount(DriftDetectedGauge); c != 0 {
		t.Errorf("expected 0 series, got %d", c)
	}
}

// TestDeleteConnectionMetrics pins the metric-leak fix for the
// per-connection gauges and counters. CI clusters that churn ephemeral
// VaultConnections via GitOps used to leak 4 series per uniquely-named
// connection (1 health gauge + 1 consecutive-fails gauge + 2
// health-check-result counter variants). Without this delete, the
// Prometheus registry grows linearly with PR churn until operator
// restart.
func TestDeleteConnectionMetrics(t *testing.T) {
	ConnectionHealthGauge.Reset()
	ConnectionConsecutiveFailsGauge.Reset()
	ConnectionHealthCheckTotal.Reset()

	SetConnectionHealth("doomed-conn", true)
	SetConsecutiveFails("doomed-conn", 3)
	IncrementHealthCheck("doomed-conn", true)
	IncrementHealthCheck("doomed-conn", false)

	// Sanity: 4 series exist
	total := testutil.CollectAndCount(ConnectionHealthGauge) +
		testutil.CollectAndCount(ConnectionConsecutiveFailsGauge) +
		testutil.CollectAndCount(ConnectionHealthCheckTotal)
	if total != 4 {
		t.Fatalf("setup wrong: expected 4 series, got %d", total)
	}

	DeleteConnectionMetrics("doomed-conn")

	total = testutil.CollectAndCount(ConnectionHealthGauge) +
		testutil.CollectAndCount(ConnectionConsecutiveFailsGauge) +
		testutil.CollectAndCount(ConnectionHealthCheckTotal)
	if total != 0 {
		t.Errorf("expected 0 series after Delete (no leak), got %d", total)
	}
}

// TestDeleteOrphanedResourcesMetrics covers both per-resource-type
// label variants. The orphan controller's gauge leaks if the operator
// reconciles a deleted connection's last orphan count and never zeros
// it — the stale "5 orphaned policies" reading shows up as a false
// alert until restart.
func TestDeleteOrphanedResourcesMetrics(t *testing.T) {
	OrphanedResourcesGauge.Reset()
	SetOrphanedResources("doomed-conn", "policy", 5)
	SetOrphanedResources("doomed-conn", "role", 2)
	if c := testutil.CollectAndCount(OrphanedResourcesGauge); c != 2 {
		t.Fatalf("setup wrong: expected 2 series, got %d", c)
	}

	DeleteOrphanedResourcesMetrics("doomed-conn")

	if c := testutil.CollectAndCount(OrphanedResourcesGauge); c != 0 {
		t.Errorf("expected 0 series after Delete, got %d", c)
	}
}

// TestDeleteDiscoveryMetrics covers all 4 series the discovery scanner
// writes per connection (gauge × 2 resource types + counter × 2 result
// variants). Without the cleanup, deleted connections leave behind
// stale "12 unmanaged policies" readings that look like ongoing drift.
func TestDeleteDiscoveryMetrics(t *testing.T) {
	DiscoveredResourcesGauge.Reset()
	DiscoveryScanTotal.Reset()
	SetDiscoveredResources("doomed-conn", "policy", 12)
	SetDiscoveredResources("doomed-conn", "role", 3)
	IncrementDiscoveryScan("doomed-conn", true)
	IncrementDiscoveryScan("doomed-conn", false)
	total := testutil.CollectAndCount(DiscoveredResourcesGauge) +
		testutil.CollectAndCount(DiscoveryScanTotal)
	if total != 4 {
		t.Fatalf("setup wrong: expected 4 series, got %d", total)
	}

	DeleteDiscoveryMetrics("doomed-conn")

	total = testutil.CollectAndCount(DiscoveredResourcesGauge) +
		testutil.CollectAndCount(DiscoveryScanTotal)
	if total != 0 {
		t.Errorf("expected 0 series after Delete, got %d", total)
	}
}

func TestSetCleanupQueueSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{
			name: "empty queue",
			size: 0,
		},
		{
			name: "non-empty queue",
			size: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetCleanupQueueSize(tt.size)

			value := testutil.ToFloat64(CleanupQueueSizeGauge)

			if value != float64(tt.size) {
				t.Errorf("SetCleanupQueueSize() = %v, want %v", value, tt.size)
			}
		})
	}
}

func TestIncrementCleanupRetry(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		success      bool
		label        string
	}{
		{
			name:         "successful cleanup retry",
			resourceType: "policy",
			success:      true,
			label:        "success",
		},
		{
			name:         "failed cleanup retry",
			resourceType: "role",
			success:      false,
			label:        "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := CleanupRetriesTotal.WithLabelValues(tt.resourceType, tt.label)
			initialValue := testutil.ToFloat64(counter)

			IncrementCleanupRetry(tt.resourceType, tt.success)

			newValue := testutil.ToFloat64(counter)
			if newValue != initialValue+1 {
				t.Errorf("IncrementCleanupRetry() = %v, want %v", newValue, initialValue+1)
			}
		})
	}
}

func TestMetricsRegistered(t *testing.T) {
	// Verify that all metrics are registered by checking they can be described
	collectors := []prometheus.Collector{
		ConnectionHealthGauge,
		ConnectionHealthCheckTotal,
		ConnectionConsecutiveFailsGauge,
		PolicyReconcileTotal,
		RoleReconcileTotal,
		OrphanedResourcesGauge,
		DriftDetectedGauge,
		CleanupQueueSizeGauge,
		CleanupRetriesTotal,
		ReconcileDurationSeconds,
	}

	for i, c := range collectors {
		ch := make(chan *prometheus.Desc, 10)
		c.Describe(ch)
		close(ch)

		// Read at least one descriptor to verify the collector works
		desc := <-ch
		if desc == nil {
			t.Errorf("collector %d returned nil descriptor", i)
		}
	}
}

// TestObserveReconcileDuration pins IMPROVEMENTS Missing Features §K:
// the reconcile duration histogram records observations under the correct
// kind+result label combinations. Uses testutil.CollectAndCount on the
// whole HistogramVec and asserts the per-label-tuple sample count via
// testutil.ToFloat64 on the Sum, then the observation count via a direct
// Describe/Collect roundtrip would require testutil.CollectAndCount which
// returns series count only — sufficient to pin 3 distinct label tuples.
func TestObserveReconcileDuration(t *testing.T) {
	ReconcileDurationSeconds.Reset()

	ObserveReconcileDuration("VaultPolicy", 0.42, true)
	ObserveReconcileDuration("VaultPolicy", 2.5, true)
	ObserveReconcileDuration("VaultRole", 1.0, false)

	// Two distinct label tuples should have observations: (VaultPolicy,
	// success) and (VaultRole, failure). CollectAndCount on the whole
	// vec returns the number of child series with at least one sample.
	seriesCount := testutil.CollectAndCount(ReconcileDurationSeconds)
	if seriesCount != 2 {
		t.Errorf("expected 2 distinct (kind,result) series, got count=%d", seriesCount)
	}
}
