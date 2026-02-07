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
		resName   string
		detected  bool
		expected  float64
	}{
		{
			name:      "drift detected",
			kind:      "VaultPolicy",
			namespace: "default",
			resName:   "my-policy",
			detected:  true,
			expected:  1.0,
		},
		{
			name:      "no drift",
			kind:      "VaultPolicy",
			namespace: "default",
			resName:   "my-policy-no-drift",
			detected:  false,
			expected:  0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetDriftDetected(tt.kind, tt.namespace, tt.resName, tt.detected)

			gauge := DriftDetectedGauge.WithLabelValues(tt.kind, tt.namespace, tt.resName)
			value := testutil.ToFloat64(gauge)

			if value != tt.expected {
				t.Errorf("SetDriftDetected() = %v, want %v", value, tt.expected)
			}
		})
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
