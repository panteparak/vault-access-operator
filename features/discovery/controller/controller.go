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

// Package controller provides the discovery controller implementation.
package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

const (
	// DefaultScanInterval is the default interval between discovery scans
	DefaultScanInterval = time.Hour
)

// MinScanInterval is the minimum allowed scan interval.
// It can be overridden via the OPERATOR_MIN_SCAN_INTERVAL environment variable.
var MinScanInterval = time.Minute * 5

func init() {
	if v := os.Getenv("OPERATOR_MIN_SCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			MinScanInterval = d
		}
	}
}

// Reconciler reconciles VaultConnection resources for discovery
type Reconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
	Log         logr.Logger
	Recorder    record.EventRecorder
}

// ReconcilerConfig holds configuration for creating a Reconciler
type ReconcilerConfig struct {
	Client      client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
	Log         logr.Logger
	Recorder    record.EventRecorder
}

// NewReconciler creates a new discovery Reconciler
func NewReconciler(cfg ReconcilerConfig) *Reconciler {
	return &Reconciler{
		Client:      cfg.Client,
		Scheme:      cfg.Scheme,
		ClientCache: cfg.ClientCache,
		Log:         cfg.Log.WithName("discovery-controller"),
		Recorder:    cfg.Recorder,
	}
}

// Reconcile handles discovery for a VaultConnection
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("vaultconnection", req.Name)

	// Fetch the VaultConnection
	var conn vaultv1alpha1.VaultConnection
	if err := r.Get(ctx, req.NamespacedName, &conn); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if discovery is enabled
	if conn.Spec.Discovery == nil || !conn.Spec.Discovery.Enabled {
		log.V(2).Info("discovery not enabled for connection")
		return ctrl.Result{}, nil
	}

	// Check if it's time to scan
	scanInterval := ParseInterval(conn.Spec.Discovery.Interval)
	if scanInterval < MinScanInterval {
		scanInterval = MinScanInterval
	}

	if conn.Status.DiscoveryStatus != nil && conn.Status.DiscoveryStatus.LastScanAt != nil {
		timeSinceLastScan := time.Since(conn.Status.DiscoveryStatus.LastScanAt.Time)
		if timeSinceLastScan < scanInterval {
			// Schedule next scan
			nextScan := scanInterval - timeSinceLastScan
			log.V(2).Info("skipping scan, not yet due", "nextScanIn", nextScan)
			return ctrl.Result{RequeueAfter: nextScan}, nil
		}
	}

	// Get Vault client
	vaultClient, err := r.ClientCache.Get(conn.Name)
	if err != nil {
		log.Error(err, "failed to get Vault client")
		return ctrl.Result{RequeueAfter: scanInterval}, nil
	}

	log.Info("starting discovery scan")

	// Create scanner and run
	scanner := NewScanner(vaultClient, conn.Spec.Discovery, log)
	result := scanner.Scan(ctx)

	// Update metrics
	scanner.UpdateMetrics(conn.Name, result)

	// Update status with retry to handle concurrent modifications
	now := metav1.Now()
	if err := r.updateDiscoveryStatus(ctx, req.Name, now, result); err != nil {
		log.Error(err, "failed to update VaultConnection status")
		return ctrl.Result{RequeueAfter: time.Minute}, nil // Don't return error to avoid double requeue
	}

	// Emit event
	if len(result.DiscoveredResources) > 0 {
		r.Recorder.Eventf(&conn, corev1.EventTypeNormal, "DiscoveryScanComplete",
			"Found %d unmanaged policies and %d unmanaged roles",
			len(result.UnmanagedPolicies), len(result.UnmanagedRoles))
	}

	// Handle auto-create if configured
	if conn.Spec.Discovery.AutoCreateCRs && len(result.DiscoveredResources) > 0 {
		if err := r.autoCreateCRs(ctx, &conn, result); err != nil {
			log.Error(err, "failed to auto-create CRs")
			r.Recorder.Eventf(&conn, corev1.EventTypeWarning, "AutoCreateFailed",
				"Failed to auto-create CRs: %v", err)
		}
	}

	log.Info("discovery scan completed",
		"unmanagedPolicies", len(result.UnmanagedPolicies),
		"unmanagedRoles", len(result.UnmanagedRoles))

	return ctrl.Result{RequeueAfter: scanInterval}, nil
}

// autoCreateCRs creates K8s resources for discovered Vault resources
func (r *Reconciler) autoCreateCRs(ctx context.Context, conn *vaultv1alpha1.VaultConnection, result *ScanResult) error {
	if conn.Spec.Discovery.TargetNamespace == "" {
		return fmt.Errorf("targetNamespace is required when autoCreateCRs is enabled")
	}

	targetNS := conn.Spec.Discovery.TargetNamespace
	log := r.Log.WithValues("targetNamespace", targetNS)

	for _, discovered := range result.DiscoveredResources {
		switch discovered.Type {
		case "policy":
			if err := r.createPolicyCR(ctx, conn, targetNS, discovered); err != nil {
				log.Error(err, "failed to create VaultPolicy", "name", discovered.Name)
				continue
			}
			log.Info("created VaultPolicy for discovered resource", "name", discovered.Name)

		case "role":
			if err := r.createRoleCR(ctx, conn, targetNS, discovered); err != nil {
				log.Error(err, "failed to create VaultRole", "name", discovered.Name)
				continue
			}
			log.Info("created VaultRole for discovered resource", "name", discovered.Name)
		}
	}

	return nil
}

// createPolicyCR creates a VaultPolicy CR for a discovered policy
func (r *Reconciler) createPolicyCR(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
	namespace string,
	discovered vaultv1alpha1.DiscoveredResource,
) error {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      discovered.SuggestedCRName,
			Namespace: namespace,
			Annotations: map[string]string{
				vaultv1alpha1.AnnotationAdopt:       "true",
				vaultv1alpha1.AnnotationDiscovered:  discovered.DiscoveredAt.Format(time.RFC3339),
				"vault.platform.io/discovered-from": conn.Name,
			},
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef:  conn.Name,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			DriftMode:      vaultv1alpha1.DriftModeDetect,
			// Rules will be populated during adoption when the policy is synced
			Rules: []vaultv1alpha1.PolicyRule{},
		},
	}

	if err := r.Create(ctx, policy); err != nil {
		return fmt.Errorf("failed to create VaultPolicy: %w", err)
	}

	return nil
}

// createRoleCR creates a VaultRole CR for a discovered role
func (r *Reconciler) createRoleCR(
	ctx context.Context,
	conn *vaultv1alpha1.VaultConnection,
	namespace string,
	discovered vaultv1alpha1.DiscoveredResource,
) error {
	role := &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      discovered.SuggestedCRName,
			Namespace: namespace,
			Annotations: map[string]string{
				vaultv1alpha1.AnnotationAdopt:       "true",
				vaultv1alpha1.AnnotationDiscovered:  discovered.DiscoveredAt.Format(time.RFC3339),
				"vault.platform.io/discovered-from": conn.Name,
			},
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:  conn.Name,
			ConflictPolicy: vaultv1alpha1.ConflictPolicyAdopt,
			DriftMode:      vaultv1alpha1.DriftModeDetect,
			// ServiceAccounts will need to be filled in manually
			ServiceAccounts: []string{},
		},
	}

	if err := r.Create(ctx, role); err != nil {
		return fmt.Errorf("failed to create VaultRole: %w", err)
	}

	return nil
}

// updateDiscoveryStatus updates the discovery status with retry on conflict.
// This is necessary because the connection controller also updates VaultConnection status,
// leading to potential optimistic lock conflicts.
func (r *Reconciler) updateDiscoveryStatus(
	ctx context.Context,
	connectionName string,
	scanTime metav1.Time,
	result *ScanResult,
) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Re-fetch the VaultConnection to get the latest version
		var conn vaultv1alpha1.VaultConnection
		if err := r.Get(ctx, types.NamespacedName{Name: connectionName}, &conn); err != nil {
			if apierrors.IsNotFound(err) {
				return nil // Connection was deleted, nothing to update
			}
			return err
		}

		// Initialize discovery status if needed
		if conn.Status.DiscoveryStatus == nil {
			conn.Status.DiscoveryStatus = &vaultv1alpha1.DiscoveryStatus{}
		}

		// Update discovery status fields
		conn.Status.DiscoveryStatus.LastScanAt = &scanTime
		conn.Status.DiscoveryStatus.UnmanagedPolicies = len(result.UnmanagedPolicies)
		conn.Status.DiscoveryStatus.UnmanagedRoles = len(result.UnmanagedRoles)
		conn.Status.DiscoveryStatus.DiscoveredResources = result.DiscoveredResources

		return r.Status().Update(ctx, &conn)
	})
}

// SetupWithManager sets up the controller with the Manager
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConnection{}).
		Named("discovery").
		Complete(r)
}
