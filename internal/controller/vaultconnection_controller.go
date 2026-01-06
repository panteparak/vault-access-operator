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

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

const (
	defaultHealthCheckInterval = 30 * time.Second
)

// VaultConnectionReconciler reconciles a VaultConnection object
type VaultConnectionReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ClientCache *vault.ClientCache
}

// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.platform.io,resources=vaultconnections/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultConnection", "name", req.Name)

	// Fetch the VaultConnection resource
	conn := &vaultv1alpha1.VaultConnection{}
	if err := r.Get(ctx, req.NamespacedName, conn); err != nil {
		if apierrors.IsNotFound(err) {
			// Resource deleted - remove from cache
			r.ClientCache.Delete(req.Name)
			log.Info("VaultConnection deleted, removed from cache", "name", req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get VaultConnection")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !conn.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, conn)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(conn, vaultv1alpha1.FinalizerName) {
		controllerutil.AddFinalizer(conn, vaultv1alpha1.FinalizerName)
		if err := r.Update(ctx, conn); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Set phase to Syncing
	if conn.Status.Phase != vaultv1alpha1.PhaseSyncing && conn.Status.Phase != vaultv1alpha1.PhaseActive {
		conn.Status.Phase = vaultv1alpha1.PhaseSyncing
		if err := r.Status().Update(ctx, conn); err != nil {
			log.Error(err, "Failed to update status to Syncing")
			return ctrl.Result{}, err
		}
	}

	// Build and authenticate Vault client
	vaultClient, err := r.buildAndAuthenticateClient(ctx, conn)
	if err != nil {
		log.Error(err, "Failed to build/authenticate Vault client")
		return r.updateStatusError(ctx, conn, err)
	}

	// Store client in cache
	r.ClientCache.Set(conn.Name, vaultClient)

	// Get Vault version
	version, err := vaultClient.GetVersion(ctx)
	if err != nil {
		log.Error(err, "Failed to get Vault version")
		return r.updateStatusError(ctx, conn, err)
	}

	// Update status to Active
	now := metav1.Now()
	conn.Status.Phase = vaultv1alpha1.PhaseActive
	conn.Status.VaultVersion = version
	conn.Status.LastHeartbeat = &now
	conn.Status.Message = ""
	r.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue, vaultv1alpha1.ReasonSucceeded, "Connected to Vault")

	if err := r.Status().Update(ctx, conn); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	log.Info("VaultConnection reconciled successfully", "name", conn.Name, "version", version)

	// Requeue for health check
	healthCheckInterval := r.parseHealthCheckInterval(conn.Spec.HealthCheckInterval)
	return ctrl.Result{RequeueAfter: healthCheckInterval}, nil
}

func (r *VaultConnectionReconciler) reconcileDelete(ctx context.Context, conn *vaultv1alpha1.VaultConnection) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling VaultConnection deletion", "name", conn.Name)

	// Update phase to Deleting
	conn.Status.Phase = vaultv1alpha1.PhaseDeleting
	if err := r.Status().Update(ctx, conn); err != nil {
		log.Error(err, "Failed to update status to Deleting")
		return ctrl.Result{}, err
	}

	// Remove from cache
	r.ClientCache.Delete(conn.Name)

	// Remove finalizer
	controllerutil.RemoveFinalizer(conn, vaultv1alpha1.FinalizerName)
	if err := r.Update(ctx, conn); err != nil {
		log.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	log.Info("VaultConnection finalizer removed", "name", conn.Name)
	return ctrl.Result{}, nil
}

func (r *VaultConnectionReconciler) buildAndAuthenticateClient(ctx context.Context, conn *vaultv1alpha1.VaultConnection) (*vault.Client, error) {
	// Build TLS config
	var tlsConfig *vault.TLSConfig
	if conn.Spec.TLS != nil {
		tlsConfig = &vault.TLSConfig{
			SkipVerify: conn.Spec.TLS.SkipVerify,
		}
		if conn.Spec.TLS.CASecretRef != nil {
			caCert, err := r.getSecretData(ctx, conn.Spec.TLS.CASecretRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get CA certificate: %w", err)
			}
			tlsConfig.CACert = caCert
		}
	}

	// Create client
	vaultClient, err := vault.NewClient(vault.ClientConfig{
		Address:   conn.Spec.Address,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Authenticate
	if err := r.authenticate(ctx, vaultClient, conn); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return vaultClient, nil
}

func (r *VaultConnectionReconciler) authenticate(ctx context.Context, vaultClient *vault.Client, conn *vaultv1alpha1.VaultConnection) error {
	auth := conn.Spec.Auth

	// Kubernetes auth
	if auth.Kubernetes != nil {
		mountPath := auth.Kubernetes.MountPath
		if mountPath == "" {
			mountPath = "kubernetes"
		}
		tokenPath := auth.Kubernetes.ServiceAccountTokenPath
		if tokenPath == "" {
			tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
		return vaultClient.AuthenticateKubernetes(ctx, auth.Kubernetes.Role, mountPath, tokenPath)
	}

	// Token auth
	if auth.Token != nil {
		token, err := r.getSecretData(ctx, &auth.Token.SecretRef)
		if err != nil {
			return fmt.Errorf("failed to get token from secret: %w", err)
		}
		return vaultClient.AuthenticateToken(token)
	}

	// AppRole auth
	if auth.AppRole != nil {
		secretID, err := r.getSecretData(ctx, &auth.AppRole.SecretIDRef)
		if err != nil {
			return fmt.Errorf("failed to get secret ID from secret: %w", err)
		}
		mountPath := auth.AppRole.MountPath
		if mountPath == "" {
			mountPath = "approle"
		}
		return vaultClient.AuthenticateAppRole(ctx, auth.AppRole.RoleID, secretID, mountPath)
	}

	return fmt.Errorf("no authentication method configured")
}

func (r *VaultConnectionReconciler) getSecretData(ctx context.Context, ref *vaultv1alpha1.SecretKeySelector) (string, error) {
	secret := &corev1.Secret{}
	namespace := ref.Namespace
	if namespace == "" {
		// For cluster-scoped resources, we need a default namespace or the secret must specify one
		namespace = "default"
	}

	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}

	return string(data), nil
}

func (r *VaultConnectionReconciler) updateStatusError(ctx context.Context, conn *vaultv1alpha1.VaultConnection, err error) (ctrl.Result, error) {
	conn.Status.Phase = vaultv1alpha1.PhaseError
	conn.Status.Message = err.Error()
	r.setCondition(conn, vaultv1alpha1.ConditionTypeReady, metav1.ConditionFalse, vaultv1alpha1.ReasonFailed, err.Error())

	if updateErr := r.Status().Update(ctx, conn); updateErr != nil {
		return ctrl.Result{}, updateErr
	}

	// Retry with backoff
	retryConfig := DefaultRetryConfig()
	retryResult := ShouldRetry(NewTransientError("vault connection failed", err), 0, retryConfig)
	return ctrl.Result{RequeueAfter: retryResult.RequeueAfter}, nil
}

func (r *VaultConnectionReconciler) setCondition(conn *vaultv1alpha1.VaultConnection, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := vaultv1alpha1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: conn.Generation,
	}

	// Find and update existing condition or append new one
	found := false
	for i, c := range conn.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				conn.Status.Conditions[i] = condition
			} else {
				// Only update message and reason if status hasn't changed
				conn.Status.Conditions[i].Reason = reason
				conn.Status.Conditions[i].Message = message
				conn.Status.Conditions[i].ObservedGeneration = conn.Generation
			}
			found = true
			break
		}
	}

	if !found {
		conn.Status.Conditions = append(conn.Status.Conditions, condition)
	}
}

func (r *VaultConnectionReconciler) parseHealthCheckInterval(interval string) time.Duration {
	if interval == "" {
		return defaultHealthCheckInterval
	}
	d, err := time.ParseDuration(interval)
	if err != nil {
		return defaultHealthCheckInterval
	}
	return d
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConnection{}).
		Named("vaultconnection").
		Complete(r)
}
