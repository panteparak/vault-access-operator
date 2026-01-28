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
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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
		var cfg *rest.Config
		cfg, k8sClientErr = config.GetConfig()
		if k8sClientErr != nil {
			k8sClientErr = fmt.Errorf("failed to get kubeconfig: %w", k8sClientErr)
			return
		}

		k8sClient, k8sClientErr = client.New(cfg, client.Options{Scheme: scheme})
		if k8sClientErr != nil {
			k8sClientErr = fmt.Errorf("failed to create k8s client: %w", k8sClientErr)
		}
	})
	return k8sClient, k8sClientErr
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
