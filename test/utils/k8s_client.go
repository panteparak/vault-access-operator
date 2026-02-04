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

// Package utils provides test utilities including a Kubernetes client
// for faster E2E tests. Using client-go instead of kubectl subprocess
// reduces per-call overhead from ~500ms to <10ms.
package utils

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

var (
	// k8sClient is a singleton client for E2E tests
	k8sClient     client.Client
	k8sClientOnce sync.Once
	k8sClientErr  error

	// k8sRestConfig is the REST config used to create the client.
	// Stored so that other clients (e.g. kubernetes.Clientset for TokenRequest)
	// can be created from the same config.
	k8sRestConfig *rest.Config

	// scheme for the k8s client
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vaultv1alpha1.AddToScheme(scheme))
}

// GetK8sClient returns a singleton Kubernetes client for E2E tests.
// Using this client instead of kubectl calls reduces overhead significantly.
// The client is lazily initialized on first call.
func GetK8sClient() (client.Client, error) {
	k8sClientOnce.Do(func() {
		k8sRestConfig, k8sClientErr = config.GetConfig()
		if k8sClientErr != nil {
			k8sClientErr = fmt.Errorf("failed to get kubeconfig: %w", k8sClientErr)
			return
		}

		k8sClient, k8sClientErr = client.New(k8sRestConfig, client.Options{Scheme: scheme})
		if k8sClientErr != nil {
			k8sClientErr = fmt.Errorf("failed to create k8s client: %w", k8sClientErr)
		}
	})
	return k8sClient, k8sClientErr
}

// GetK8sRestConfig returns the REST config used by the K8s client.
// Must be called after GetK8sClient() or MustGetK8sClient().
func GetK8sRestConfig() *rest.Config {
	return k8sRestConfig
}

// MustGetK8sClient returns the K8s client or panics if unavailable.
// Use this in BeforeSuite where failure should stop the test.
func MustGetK8sClient() client.Client {
	c, err := GetK8sClient()
	if err != nil {
		panic(fmt.Sprintf("failed to get k8s client: %v", err))
	}
	return c
}

// =============================================================================
// VaultConnection helpers
// =============================================================================

// GetVaultConnectionStatus returns the status phase of a VaultConnection.
func GetVaultConnectionStatus(ctx context.Context, name, namespace string) (string, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	conn := &vaultv1alpha1.VaultConnection{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, conn); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return string(conn.Status.Phase), nil
}

// GetVaultConnection returns a VaultConnection resource.
func GetVaultConnection(ctx context.Context, name, namespace string) (*vaultv1alpha1.VaultConnection, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	conn := &vaultv1alpha1.VaultConnection{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, conn); err != nil {
		return nil, err
	}

	return conn, nil
}

// =============================================================================
// VaultPolicy helpers
// =============================================================================

// GetVaultPolicyStatus returns the status phase of a VaultPolicy.
func GetVaultPolicyStatus(ctx context.Context, name, namespace string) (string, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	policy := &vaultv1alpha1.VaultPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, policy); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return string(policy.Status.Phase), nil
}

// GetVaultPolicy returns a VaultPolicy resource.
func GetVaultPolicy(ctx context.Context, name, namespace string) (*vaultv1alpha1.VaultPolicy, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	policy := &vaultv1alpha1.VaultPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// VaultPolicyCRExists checks if a VaultPolicy CR exists in Kubernetes.
// Note: This is different from VaultPolicyExists which checks Vault directly.
func VaultPolicyCRExists(ctx context.Context, name, namespace string) (bool, error) {
	_, err := GetVaultPolicy(ctx, name, namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// =============================================================================
// VaultClusterPolicy helpers
// =============================================================================

// GetVaultClusterPolicyStatus returns the status phase of a VaultClusterPolicy.
func GetVaultClusterPolicyStatus(ctx context.Context, name string) (string, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	policy := &vaultv1alpha1.VaultClusterPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, policy); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return string(policy.Status.Phase), nil
}

// GetVaultClusterPolicy returns a VaultClusterPolicy resource.
func GetVaultClusterPolicy(ctx context.Context, name string) (*vaultv1alpha1.VaultClusterPolicy, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	policy := &vaultv1alpha1.VaultClusterPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// =============================================================================
// VaultRole helpers
// =============================================================================

// GetVaultRoleStatus returns the status phase of a VaultRole.
func GetVaultRoleStatus(ctx context.Context, name, namespace string) (string, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	role := &vaultv1alpha1.VaultRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, role); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return string(role.Status.Phase), nil
}

// GetVaultRole returns a VaultRole resource.
func GetVaultRole(ctx context.Context, name, namespace string) (*vaultv1alpha1.VaultRole, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	role := &vaultv1alpha1.VaultRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, role); err != nil {
		return nil, err
	}

	return role, nil
}

// =============================================================================
// VaultClusterRole helpers
// =============================================================================

// GetVaultClusterRoleStatus returns the status phase of a VaultClusterRole.
func GetVaultClusterRoleStatus(ctx context.Context, name string) (string, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	role := &vaultv1alpha1.VaultClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, role); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	return string(role.Status.Phase), nil
}

// GetVaultClusterRole returns a VaultClusterRole resource.
func GetVaultClusterRole(ctx context.Context, name string) (*vaultv1alpha1.VaultClusterRole, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	role := &vaultv1alpha1.VaultClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, role); err != nil {
		return nil, err
	}

	return role, nil
}

// =============================================================================
// Generic helpers
// =============================================================================

// ResourceExists checks if any namespaced resource exists.
func ResourceExists(ctx context.Context, obj client.Object, name, namespace string) (bool, error) {
	c, err := GetK8sClient()
	if err != nil {
		return false, err
	}

	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ClusterResourceExists checks if any cluster-scoped resource exists.
func ClusterResourceExists(ctx context.Context, obj client.Object, name string) (bool, error) {
	c, err := GetK8sClient()
	if err != nil {
		return false, err
	}

	if err := c.Get(ctx, types.NamespacedName{Name: name}, obj); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetPodPhase returns the phase of a pod.
func GetPodPhase(ctx context.Context, name, namespace string) (corev1.PodPhase, error) {
	c, err := GetK8sClient()
	if err != nil {
		return "", err
	}

	pod := &corev1.Pod{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, pod); err != nil {
		return "", err
	}

	return pod.Status.Phase, nil
}

// GetPodsByLabel returns pods matching a label selector in a namespace.
func GetPodsByLabel(ctx context.Context, namespace, labelKey, labelValue string) (*corev1.PodList, error) {
	c, err := GetK8sClient()
	if err != nil {
		return nil, err
	}

	pods := &corev1.PodList{}
	if err := c.List(ctx, pods,
		client.InNamespace(namespace),
		client.MatchingLabels{labelKey: labelValue}); err != nil {
		return nil, err
	}

	return pods, nil
}

// CreateNamespace creates a namespace if it doesn't exist.
func CreateNamespace(ctx context.Context, name string) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	if err := c.Create(ctx, ns); err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// DeleteNamespace deletes a namespace.
func DeleteNamespace(ctx context.Context, name string) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	if err := c.Delete(ctx, ns); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// CreateSecret creates a secret.
func CreateSecret(ctx context.Context, namespace, name string, data map[string][]byte) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}

	if err := c.Create(ctx, secret); err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// DeleteSecret deletes a secret.
func DeleteSecret(ctx context.Context, namespace, name string) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	if err := c.Delete(ctx, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// =============================================================================
// Generic CRUD helpers
// =============================================================================

// CreateObject creates any Kubernetes object. Returns nil if it already exists.
func CreateObject(ctx context.Context, obj client.Object) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	if err := c.Create(ctx, obj); err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create %T %s/%s: %w",
			obj, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

// DeleteObject deletes any Kubernetes object. Returns nil if not found.
func DeleteObject(ctx context.Context, obj client.Object) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	if err := c.Delete(ctx, obj); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete %T %s/%s: %w",
			obj, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

// UpdateObject updates any Kubernetes object.
func UpdateObject(ctx context.Context, obj client.Object) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	if err := c.Update(ctx, obj); err != nil {
		return fmt.Errorf("failed to update %T %s/%s: %w",
			obj, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

// PatchObject applies a merge-patch to any Kubernetes object.
func PatchObject(ctx context.Context, obj client.Object, patch client.Patch) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	if err := c.Patch(ctx, obj, patch); err != nil {
		return fmt.Errorf("failed to patch %T %s/%s: %w",
			obj, obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

// =============================================================================
// CRD Create helpers (typed convenience wrappers)
// =============================================================================

// CreateVaultConnectionCR creates a VaultConnection CRD in Kubernetes.
func CreateVaultConnectionCR(ctx context.Context, obj *vaultv1alpha1.VaultConnection) error {
	return CreateObject(ctx, obj)
}

// CreateVaultPolicyCR creates a VaultPolicy CRD in Kubernetes.
func CreateVaultPolicyCR(ctx context.Context, obj *vaultv1alpha1.VaultPolicy) error {
	return CreateObject(ctx, obj)
}

// CreateVaultRoleCR creates a VaultRole CRD in Kubernetes.
func CreateVaultRoleCR(ctx context.Context, obj *vaultv1alpha1.VaultRole) error {
	return CreateObject(ctx, obj)
}

// CreateVaultClusterPolicyCR creates a VaultClusterPolicy CRD in Kubernetes.
func CreateVaultClusterPolicyCR(ctx context.Context, obj *vaultv1alpha1.VaultClusterPolicy) error {
	return CreateObject(ctx, obj)
}

// CreateVaultClusterRoleCR creates a VaultClusterRole CRD in Kubernetes.
func CreateVaultClusterRoleCR(ctx context.Context, obj *vaultv1alpha1.VaultClusterRole) error {
	return CreateObject(ctx, obj)
}

// =============================================================================
// CRD Update helpers
// =============================================================================

// UpdateVaultPolicyCR fetches the latest version of a VaultPolicy, applies the
// mutate function, and writes it back. This handles the resourceVersion conflict
// that occurs when updating a stale object.
func UpdateVaultPolicyCR(ctx context.Context, name, namespace string, mutate func(*vaultv1alpha1.VaultPolicy)) error {
	policy, err := GetVaultPolicy(ctx, name, namespace)
	if err != nil {
		return fmt.Errorf("failed to get VaultPolicy for update: %w", err)
	}
	mutate(policy)
	return UpdateObject(ctx, policy)
}

// UpdateVaultRoleCR fetches the latest VaultRole, applies the mutate function,
// and writes it back.
func UpdateVaultRoleCR(ctx context.Context, name, namespace string, mutate func(*vaultv1alpha1.VaultRole)) error {
	role, err := GetVaultRole(ctx, name, namespace)
	if err != nil {
		return fmt.Errorf("failed to get VaultRole for update: %w", err)
	}
	mutate(role)
	return UpdateObject(ctx, role)
}

// UpdateVaultClusterPolicyCR fetches the latest VaultClusterPolicy, applies the
// mutate function, and writes it back.
func UpdateVaultClusterPolicyCR(
	ctx context.Context, name string, mutate func(*vaultv1alpha1.VaultClusterPolicy),
) error {
	policy, err := GetVaultClusterPolicy(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get VaultClusterPolicy for update: %w", err)
	}
	mutate(policy)
	return UpdateObject(ctx, policy)
}

// UpdateVaultClusterRoleCR fetches the latest VaultClusterRole, applies the
// mutate function, and writes it back.
func UpdateVaultClusterRoleCR(ctx context.Context, name string, mutate func(*vaultv1alpha1.VaultClusterRole)) error {
	role, err := GetVaultClusterRole(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get VaultClusterRole for update: %w", err)
	}
	mutate(role)
	return UpdateObject(ctx, role)
}

// =============================================================================
// CRD Delete helpers (by name, idempotent)
// =============================================================================

// DeleteVaultConnectionCR deletes a VaultConnection CRD by name.
// Returns nil if the resource does not exist.
func DeleteVaultConnectionCR(ctx context.Context, name string) error {
	return DeleteObject(ctx, &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

// DeleteVaultPolicyCR deletes a VaultPolicy CRD by name and namespace.
// Returns nil if the resource does not exist.
// Note: This deletes the K8s CR, not the policy in Vault. For Vault-level
// deletion, use DeleteVaultPolicy() from utils.go.
func DeleteVaultPolicyCR(ctx context.Context, name, namespace string) error {
	return DeleteObject(ctx, &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	})
}

// DeleteVaultRoleCR deletes a VaultRole CRD by name and namespace.
// Returns nil if the resource does not exist.
// Note: This deletes the K8s CR, not the role in Vault. For Vault-level
// deletion, use DeleteVaultRole() from utils.go.
func DeleteVaultRoleCR(ctx context.Context, name, namespace string) error {
	return DeleteObject(ctx, &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	})
}

// DeleteVaultClusterPolicyCR deletes a VaultClusterPolicy CRD by name.
// Returns nil if the resource does not exist.
func DeleteVaultClusterPolicyCR(ctx context.Context, name string) error {
	return DeleteObject(ctx, &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

// DeleteVaultClusterRoleCR deletes a VaultClusterRole CRD by name.
// Returns nil if the resource does not exist.
func DeleteVaultClusterRoleCR(ctx context.Context, name string) error {
	return DeleteObject(ctx, &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

// =============================================================================
// ServiceAccount helpers
// =============================================================================

// CreateServiceAccount creates a ServiceAccount. Returns nil if it already exists.
func CreateServiceAccount(ctx context.Context, namespace, name string) error {
	return CreateObject(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	})
}

// DeleteServiceAccount deletes a ServiceAccount. Returns nil if not found.
func DeleteServiceAccount(ctx context.Context, namespace, name string) error {
	return DeleteObject(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	})
}

// CreateServiceAccountTokenClientGo creates a token for a ServiceAccount using
// the client-go TokenRequest API. This replaces `kubectl create token <sa>`.
func CreateServiceAccountTokenClientGo(
	ctx context.Context, namespace, saName string,
) (string, error) {
	cfg := GetK8sRestConfig()
	if cfg == nil {
		return "", fmt.Errorf("k8s rest config not initialized; call GetK8sClient() first")
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	tokenReq := &authenticationv1.TokenRequest{}
	result, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx, saName, tokenReq, metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token for SA %s/%s: %w", namespace, saName, err)
	}

	return result.Status.Token, nil
}

// CreateServiceAccountTokenWithOpts creates a token for a
// ServiceAccount with custom audiences and/or expiration.
// This replaces `kubectl create token <sa> --audience <aud>
// --duration <dur>`.
func CreateServiceAccountTokenWithOpts(
	ctx context.Context,
	namespace, saName string,
	audiences []string,
	expirationSeconds *int64,
) (string, error) {
	cfg := GetK8sRestConfig()
	if cfg == nil {
		return "", fmt.Errorf(
			"k8s rest config not initialized; " +
				"call GetK8sClient() first",
		)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf(
			"failed to create kubernetes clientset: %w", err,
		)
	}

	tokenReq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: expirationSeconds,
		},
	}
	result, err := clientset.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(ctx, saName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf(
			"failed to create token for SA %s/%s: %w",
			namespace, saName, err,
		)
	}

	return result.Status.Token, nil
}

// =============================================================================
// Namespace helpers
// =============================================================================

// LabelNamespace adds labels to an existing namespace.
func LabelNamespace(ctx context.Context, name string, labels map[string]string) error {
	c, err := GetK8sClient()
	if err != nil {
		return err
	}

	ns := &corev1.Namespace{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, ns); err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", name, err)
	}

	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	for k, v := range labels {
		ns.Labels[k] = v
	}

	return c.Update(ctx, ns)
}

// =============================================================================
// Wait / polling helpers
// =============================================================================

// PhaseGetter is a function that returns the current phase of a resource.
type PhaseGetter func(ctx context.Context) (string, error)

// WaitForPhase polls a PhaseGetter until the resource reaches the expected phase
// or the timeout expires. This replaces the common pattern of:
//
//	Eventually(func(g Gomega) {
//	    cmd := exec.Command("kubectl", "get", "vaultpolicy", name, "-n", ns, "-o", "jsonpath={.status.phase}")
//	    output, err := utils.Run(cmd)
//	    g.Expect(err).NotTo(HaveOccurred())
//	    g.Expect(output).To(Equal("Active"))
//	}).Should(Succeed())
func WaitForPhase(
	ctx context.Context, getter PhaseGetter, expectedPhase string,
	timeout, interval time.Duration,
) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		phase, err := getter(ctx)
		if err != nil {
			// Transient errors during polling are expected (e.g., resource not yet created)
			return false, nil //nolint:nilerr
		}
		return phase == expectedPhase, nil
	})
}

// WaitForVaultPolicyPhase waits for a VaultPolicy to reach the expected phase.
func WaitForVaultPolicyPhase(
	ctx context.Context, name, namespace, phase string,
	timeout, interval time.Duration,
) error {
	return WaitForPhase(ctx, func(ctx context.Context) (string, error) {
		return GetVaultPolicyStatus(ctx, name, namespace)
	}, phase, timeout, interval)
}

// WaitForVaultConnectionPhase waits for a VaultConnection to reach the expected phase.
func WaitForVaultConnectionPhase(ctx context.Context, name, phase string, timeout, interval time.Duration) error {
	return WaitForPhase(ctx, func(ctx context.Context) (string, error) {
		return GetVaultConnectionStatus(ctx, name, "")
	}, phase, timeout, interval)
}

// WaitForVaultRolePhase waits for a VaultRole to reach the expected phase.
func WaitForVaultRolePhase(ctx context.Context, name, namespace, phase string, timeout, interval time.Duration) error {
	return WaitForPhase(ctx, func(ctx context.Context) (string, error) {
		return GetVaultRoleStatus(ctx, name, namespace)
	}, phase, timeout, interval)
}

// WaitForVaultClusterPolicyPhase waits for a VaultClusterPolicy to reach the expected phase.
func WaitForVaultClusterPolicyPhase(ctx context.Context, name, phase string, timeout, interval time.Duration) error {
	return WaitForPhase(ctx, func(ctx context.Context) (string, error) {
		return GetVaultClusterPolicyStatus(ctx, name)
	}, phase, timeout, interval)
}

// WaitForVaultClusterRolePhase waits for a VaultClusterRole to reach the expected phase.
func WaitForVaultClusterRolePhase(ctx context.Context, name, phase string, timeout, interval time.Duration) error {
	return WaitForPhase(ctx, func(ctx context.Context) (string, error) {
		return GetVaultClusterRoleStatus(ctx, name)
	}, phase, timeout, interval)
}

// WaitForDeletion polls until the given resource no longer exists.
func WaitForDeletion(
	ctx context.Context, obj client.Object, name, namespace string,
	timeout, interval time.Duration,
) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		exists, err := ResourceExists(ctx, obj, name, namespace)
		if err != nil {
			return false, nil //nolint:nilerr
		}
		return !exists, nil
	})
}

// WaitForClusterDeletion polls until the given cluster-scoped resource no longer exists.
func WaitForClusterDeletion(
	ctx context.Context, obj client.Object, name string,
	timeout, interval time.Duration,
) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		exists, err := ClusterResourceExists(ctx, obj, name)
		if err != nil {
			return false, nil //nolint:nilerr
		}
		return !exists, nil
	})
}

// =============================================================================
// Kubernetes API helpers
// =============================================================================

// NamespaceExists checks if a namespace exists.
func NamespaceExists(ctx context.Context, name string) (bool, error) {
	return ClusterResourceExists(ctx, &corev1.Namespace{}, name)
}

// GetKubernetesCA returns the Kubernetes cluster CA certificate PEM.
// It reads from the rest config's TLS settings (CAData or CAFile).
func GetKubernetesCA() (string, error) {
	cfg := GetK8sRestConfig()
	if cfg == nil {
		return "", fmt.Errorf(
			"k8s rest config not initialized; call GetK8sClient() first",
		)
	}

	if len(cfg.CAData) > 0 {
		return string(cfg.CAData), nil
	}

	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return "", fmt.Errorf("failed to read CA file %q: %w",
				cfg.CAFile, err)
		}
		return string(data), nil
	}

	return "", fmt.Errorf("no CA cert found in kubeconfig")
}

// GetK8sRawEndpoint calls a raw Kubernetes API endpoint (equivalent to
// kubectl get --raw <path>). Useful for OIDC discovery, JWKS, etc.
func GetK8sRawEndpoint(
	ctx context.Context, path string,
) ([]byte, error) {
	cfg := GetK8sRestConfig()
	if cfg == nil {
		return nil, fmt.Errorf(
			"k8s rest config not initialized; call GetK8sClient() first",
		)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	result, err := clientset.Discovery().
		RESTClient().
		Get().
		AbsPath(path).
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get raw endpoint %q: %w", path, err,
		)
	}
	return result, nil
}
