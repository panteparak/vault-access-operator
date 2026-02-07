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

// Package metrics provides Prometheus metrics for the vault-access-operator.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Result labels for metrics.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

var (
	// ConnectionHealthGauge tracks the health status of Vault connections.
	// Value is 1 for healthy, 0 for unhealthy.
	ConnectionHealthGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "connection",
			Name:      "healthy",
			Help:      "Vault connection health status (1=healthy, 0=unhealthy)",
		},
		[]string{"connection"},
	)

	// ConnectionHealthCheckTotal counts the total number of health checks performed.
	ConnectionHealthCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "connection",
			Name:      "health_checks_total",
			Help:      "Total number of health checks performed",
		},
		[]string{"connection", "result"},
	)

	// ConnectionConsecutiveFailsGauge tracks consecutive health check failures.
	ConnectionConsecutiveFailsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "connection",
			Name:      "consecutive_fails",
			Help:      "Number of consecutive health check failures",
		},
		[]string{"connection"},
	)

	// PolicyReconcileTotal counts policy reconciliation operations.
	PolicyReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "policy",
			Name:      "reconcile_total",
			Help:      "Total number of policy reconciliation operations",
		},
		[]string{"kind", "namespace", "result"},
	)

	// RoleReconcileTotal counts role reconciliation operations.
	RoleReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "role",
			Name:      "reconcile_total",
			Help:      "Total number of role reconciliation operations",
		},
		[]string{"kind", "namespace", "result"},
	)

	// OrphanedResourcesGauge tracks the number of orphaned Vault resources.
	OrphanedResourcesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "vault",
			Name:      "orphaned_resources",
			Help:      "Number of orphaned Vault resources by type",
		},
		[]string{"connection", "type"},
	)

	// DriftDetectedGauge tracks resources with detected drift.
	DriftDetectedGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "vault",
			Name:      "drift_detected",
			Help:      "Number of resources with detected drift (1=drift, 0=no drift)",
		},
		[]string{"kind", "namespace", "name"},
	)

	// CleanupQueueSizeGauge tracks the size of the cleanup retry queue.
	CleanupQueueSizeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "cleanup",
			Name:      "queue_size",
			Help:      "Number of items in the cleanup retry queue",
		},
	)

	// CleanupRetriesTotal counts cleanup retry attempts.
	CleanupRetriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "cleanup",
			Name:      "retries_total",
			Help:      "Total number of cleanup retry attempts",
		},
		[]string{"resource_type", "result"},
	)

	// DriftCorrectedTotal counts drift correction operations.
	DriftCorrectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "vault",
			Name:      "drift_corrected_total",
			Help:      "Total number of drift correction operations",
		},
		[]string{"kind", "namespace"},
	)

	// DestructiveBlockedTotal counts blocked destructive operations.
	DestructiveBlockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "safety",
			Name:      "destructive_blocked_total",
			Help:      "Total number of blocked destructive operations (missing allow-destructive annotation)",
		},
		[]string{"kind", "namespace"},
	)

	// AdoptionTotal counts resource adoption operations.
	AdoptionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "discovery",
			Name:      "adoptions_total",
			Help:      "Total number of resource adoption operations",
		},
		[]string{"kind", "namespace", "result"},
	)

	// DiscoveredResourcesGauge tracks unmanaged resources found by discovery.
	DiscoveredResourcesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vault_access_operator",
			Subsystem: "discovery",
			Name:      "unmanaged_resources",
			Help:      "Number of unmanaged Vault resources found during discovery",
		},
		[]string{"connection", "type"},
	)

	// DiscoveryScanTotal counts discovery scan operations.
	DiscoveryScanTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "vault_access_operator",
			Subsystem: "discovery",
			Name:      "scans_total",
			Help:      "Total number of discovery scan operations",
		},
		[]string{"connection", "result"},
	)
)

func init() {
	// Register all metrics with the controller-runtime metrics registry
	metrics.Registry.MustRegister(
		ConnectionHealthGauge,
		ConnectionHealthCheckTotal,
		ConnectionConsecutiveFailsGauge,
		PolicyReconcileTotal,
		RoleReconcileTotal,
		OrphanedResourcesGauge,
		DriftDetectedGauge,
		CleanupQueueSizeGauge,
		CleanupRetriesTotal,
		DriftCorrectedTotal,
		DestructiveBlockedTotal,
		AdoptionTotal,
		DiscoveredResourcesGauge,
		DiscoveryScanTotal,
	)
}

// SetConnectionHealth sets the health status for a connection.
func SetConnectionHealth(connection string, healthy bool) {
	val := 0.0
	if healthy {
		val = 1.0
	}
	ConnectionHealthGauge.WithLabelValues(connection).Set(val)
}

// IncrementHealthCheck increments the health check counter.
func IncrementHealthCheck(connection string, success bool) {
	result := ResultFailure
	if success {
		result = ResultSuccess
	}
	ConnectionHealthCheckTotal.WithLabelValues(connection, result).Inc()
}

// SetConsecutiveFails sets the consecutive failure count for a connection.
func SetConsecutiveFails(connection string, count int) {
	ConnectionConsecutiveFailsGauge.WithLabelValues(connection).Set(float64(count))
}

// IncrementPolicyReconcile increments the policy reconcile counter.
func IncrementPolicyReconcile(kind, namespace string, success bool) {
	result := ResultFailure
	if success {
		result = ResultSuccess
	}
	PolicyReconcileTotal.WithLabelValues(kind, namespace, result).Inc()
}

// IncrementRoleReconcile increments the role reconcile counter.
func IncrementRoleReconcile(kind, namespace string, success bool) {
	result := ResultFailure
	if success {
		result = ResultSuccess
	}
	RoleReconcileTotal.WithLabelValues(kind, namespace, result).Inc()
}

// SetOrphanedResources sets the orphaned resource count.
func SetOrphanedResources(connection, resourceType string, count int) {
	OrphanedResourcesGauge.WithLabelValues(connection, resourceType).Set(float64(count))
}

// SetDriftDetected sets the drift detection status for a resource.
func SetDriftDetected(kind, namespace, name string, detected bool) {
	val := 0.0
	if detected {
		val = 1.0
	}
	DriftDetectedGauge.WithLabelValues(kind, namespace, name).Set(val)
}

// SetCleanupQueueSize sets the cleanup queue size.
func SetCleanupQueueSize(size int) {
	CleanupQueueSizeGauge.Set(float64(size))
}

// IncrementCleanupRetry increments the cleanup retry counter.
func IncrementCleanupRetry(resourceType string, success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	CleanupRetriesTotal.WithLabelValues(resourceType, result).Inc()
}

// IncrementDriftCorrected increments the drift correction counter.
func IncrementDriftCorrected(kind, namespace string) {
	DriftCorrectedTotal.WithLabelValues(kind, namespace).Inc()
}

// IncrementDestructiveBlocked increments the blocked destructive operations counter.
func IncrementDestructiveBlocked(kind, namespace string) {
	DestructiveBlockedTotal.WithLabelValues(kind, namespace).Inc()
}

// IncrementAdoption increments the adoption counter.
func IncrementAdoption(kind, namespace string, success bool) {
	result := ResultFailure
	if success {
		result = ResultSuccess
	}
	AdoptionTotal.WithLabelValues(kind, namespace, result).Inc()
}

// SetDiscoveredResources sets the discovered unmanaged resource count.
func SetDiscoveredResources(connection, resourceType string, count int) {
	DiscoveredResourcesGauge.WithLabelValues(connection, resourceType).Set(float64(count))
}

// IncrementDiscoveryScan increments the discovery scan counter.
func IncrementDiscoveryScan(connection string, success bool) {
	result := ResultFailure
	if success {
		result = ResultSuccess
	}
	DiscoveryScanTotal.WithLabelValues(connection, result).Inc()
}
