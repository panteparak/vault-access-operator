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

package cleanup

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewQueue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")

	if q == nil {
		t.Fatal("NewQueue returned nil")
	}
	if q.namespace != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got %s", q.namespace)
	}
}

func TestQueue_EnqueueAndList(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		Attempts:       1,
		LastError:      "connection refused",
	}

	// Enqueue item
	err := q.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// List items
	items, err := q.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(items))
	}

	if items[0].VaultName != "test-policy" {
		t.Errorf("Expected VaultName 'test-policy', got %s", items[0].VaultName)
	}
	if items[0].ID == "" {
		t.Error("Expected ID to be generated")
	}
}

func TestQueue_EnqueueUpdatesExisting(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		Attempts:       1,
		LastError:      "error 1",
	}

	// Enqueue item first time
	err := q.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("First Enqueue failed: %v", err)
	}

	// Update and enqueue again with same ID
	item.Attempts = 2
	item.LastError = "error 2"
	err = q.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Second Enqueue failed: %v", err)
	}

	// Should still have only 1 item
	items, err := q.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 item after update, got %d", len(items))
	}

	if items[0].Attempts != 2 {
		t.Errorf("Expected Attempts 2, got %d", items[0].Attempts)
	}
	if items[0].LastError != "error 2" {
		t.Errorf("Expected LastError 'error 2', got %s", items[0].LastError)
	}
}

func TestQueue_Dequeue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		Attempts:       1,
		LastError:      "error",
	}

	// Enqueue item
	err := q.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Get the item's ID
	items, _ := q.List(ctx)
	id := items[0].ID

	// Dequeue
	err = q.Dequeue(ctx, id)
	if err != nil {
		t.Fatalf("Dequeue failed: %v", err)
	}

	// Should be empty
	items, err = q.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("Expected 0 items after dequeue, got %d", len(items))
	}
}

func TestQueue_DequeueNonExistent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	// First enqueue something so the ConfigMap exists
	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		Attempts:       1,
		LastError:      "error",
	}
	_ = q.Enqueue(ctx, item)

	// Dequeue non-existent ID - should not error
	err := q.Dequeue(ctx, "non-existent-id")
	if err != nil {
		t.Errorf("Dequeue of non-existent item should not error: %v", err)
	}

	// Original item should still be there
	items, _ := q.List(ctx)
	if len(items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(items))
	}
}

func TestQueue_DequeueFromNonExistentQueue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	// Dequeue when ConfigMap doesn't exist - should not error
	err := q.Dequeue(ctx, "any-id")
	if err != nil {
		t.Errorf("Dequeue from non-existent queue should not error: %v", err)
	}
}

func TestQueue_ListEmpty(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	// List when ConfigMap doesn't exist
	items, err := q.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("Expected 0 items, got %d", len(items))
	}
}

func TestQueue_Size(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	// Empty queue
	size, err := q.Size(ctx)
	if err != nil {
		t.Fatalf("Size failed: %v", err)
	}
	if size != 0 {
		t.Errorf("Expected size 0, got %d", size)
	}

	// Add items
	for i := 0; i < 3; i++ {
		item := Item{
			ResourceType:   ResourceTypePolicy,
			VaultName:      "test-policy",
			ConnectionName: "vault-connection",
			K8sNamespace:   "default",
			K8sName:        "policy-" + string(rune('a'+i)),
			FailedAt:       time.Now(),
			Attempts:       1,
			LastError:      "error",
		}
		_ = q.Enqueue(ctx, item)
	}

	size, err = q.Size(ctx)
	if err != nil {
		t.Fatalf("Size failed: %v", err)
	}
	if size != 3 {
		t.Errorf("Expected size 3, got %d", size)
	}
}

func TestQueue_ConfigMapCreation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	item := Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      "test-policy",
		ConnectionName: "vault-connection",
		K8sNamespace:   "default",
		K8sName:        "my-policy",
		FailedAt:       time.Now(),
		Attempts:       1,
		LastError:      "error",
	}

	// Enqueue should create ConfigMap
	err := q.Enqueue(ctx, item)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Verify ConfigMap exists with correct labels
	cm := &corev1.ConfigMap{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: ConfigMapName, Namespace: "test-namespace"}, cm)
	if err != nil {
		t.Fatalf("Failed to get ConfigMap: %v", err)
	}

	if cm.Labels["app.kubernetes.io/name"] != "vault-access-operator" {
		t.Errorf("Expected label 'vault-access-operator', got %s", cm.Labels["app.kubernetes.io/name"])
	}
	if cm.Labels["app.kubernetes.io/component"] != "cleanup-queue" {
		t.Errorf("Expected label 'cleanup-queue', got %s", cm.Labels["app.kubernetes.io/component"])
	}
}

func TestQueue_ExistingConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Create ConfigMap with existing data
	existingJSON := `[{"id":"existing-id","resourceType":"policy",` +
		`"vaultName":"existing-policy","connectionName":"conn",` +
		`"k8sName":"existing","failedAt":"2024-01-01T00:00:00Z",` +
		`"attempts":5,"lastError":"old error"}]`
	existingCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConfigMapName,
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			QueueDataKey: existingJSON,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingCM).Build()

	q := NewQueue(fakeClient, "test-namespace")
	ctx := context.Background()

	// List should return existing item
	items, err := q.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("Expected 1 existing item, got %d", len(items))
	}

	if items[0].VaultName != "existing-policy" {
		t.Errorf("Expected VaultName 'existing-policy', got %s", items[0].VaultName)
	}
	if items[0].Attempts != 5 {
		t.Errorf("Expected Attempts 5, got %d", items[0].Attempts)
	}
}

func TestGenerateItemID(t *testing.T) {
	tests := []struct {
		name     string
		item     Item
		expected string
	}{
		{
			name: "namespaced policy",
			item: Item{
				ResourceType:   ResourceTypePolicy,
				ConnectionName: "conn",
				K8sNamespace:   "default",
				K8sName:        "my-policy",
			},
			expected: "policy/conn/default/my-policy",
		},
		{
			name: "cluster-scoped policy",
			item: Item{
				ResourceType:   ResourceTypePolicy,
				ConnectionName: "conn",
				K8sNamespace:   "",
				K8sName:        "cluster-policy",
			},
			expected: "policy/conn/cluster-policy",
		},
		{
			name: "namespaced role",
			item: Item{
				ResourceType:   ResourceTypeRole,
				ConnectionName: "conn",
				K8sNamespace:   "kube-system",
				K8sName:        "my-role",
			},
			expected: "role/conn/kube-system/my-role",
		},
		{
			name: "cluster-scoped role",
			item: Item{
				ResourceType:   ResourceTypeRole,
				ConnectionName: "conn",
				K8sNamespace:   "",
				K8sName:        "cluster-role",
			},
			expected: "role/conn/cluster-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := generateItemID(tt.item)
			if id != tt.expected {
				t.Errorf("Expected ID '%s', got '%s'", tt.expected, id)
			}
		})
	}
}

func TestNewPolicyCleanupItem(t *testing.T) {
	item := NewPolicyCleanupItem("vault-name", "conn", "ns", "name", "error msg")

	if item.ResourceType != ResourceTypePolicy {
		t.Errorf("Expected ResourceType 'policy', got %s", item.ResourceType)
	}
	if item.VaultName != "vault-name" {
		t.Errorf("Expected VaultName 'vault-name', got %s", item.VaultName)
	}
	if item.ConnectionName != "conn" {
		t.Errorf("Expected ConnectionName 'conn', got %s", item.ConnectionName)
	}
	if item.K8sNamespace != "ns" {
		t.Errorf("Expected K8sNamespace 'ns', got %s", item.K8sNamespace)
	}
	if item.K8sName != "name" {
		t.Errorf("Expected K8sName 'name', got %s", item.K8sName)
	}
	if item.LastError != "error msg" {
		t.Errorf("Expected LastError 'error msg', got %s", item.LastError)
	}
	if item.Attempts != 1 {
		t.Errorf("Expected Attempts 1, got %d", item.Attempts)
	}
	if item.FailedAt.IsZero() {
		t.Error("Expected FailedAt to be set")
	}
	if item.AuthPath != "" {
		t.Errorf("Expected empty AuthPath for policy, got %s", item.AuthPath)
	}
}

func TestNewRoleCleanupItem(t *testing.T) {
	item := NewRoleCleanupItem("vault-name", "conn", "kubernetes", "ns", "name", "error msg")

	if item.ResourceType != ResourceTypeRole {
		t.Errorf("Expected ResourceType 'role', got %s", item.ResourceType)
	}
	if item.VaultName != "vault-name" {
		t.Errorf("Expected VaultName 'vault-name', got %s", item.VaultName)
	}
	if item.ConnectionName != "conn" {
		t.Errorf("Expected ConnectionName 'conn', got %s", item.ConnectionName)
	}
	if item.AuthPath != "kubernetes" {
		t.Errorf("Expected AuthPath 'kubernetes', got %s", item.AuthPath)
	}
	if item.K8sNamespace != "ns" {
		t.Errorf("Expected K8sNamespace 'ns', got %s", item.K8sNamespace)
	}
	if item.K8sName != "name" {
		t.Errorf("Expected K8sName 'name', got %s", item.K8sName)
	}
	if item.LastError != "error msg" {
		t.Errorf("Expected LastError 'error msg', got %s", item.LastError)
	}
	if item.Attempts != 1 {
		t.Errorf("Expected Attempts 1, got %d", item.Attempts)
	}
}

func TestParseQueueData(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		expectItems int
		expectErr   bool
	}{
		{
			name:        "empty string",
			data:        "",
			expectItems: 0,
			expectErr:   false,
		},
		{
			name:        "empty array",
			data:        "[]",
			expectItems: 0,
			expectErr:   false,
		},
		{
			name: "valid data",
			data: `[{"id":"id1","resourceType":"policy","vaultName":"p1",` +
				`"connectionName":"c","k8sName":"n",` +
				`"failedAt":"2024-01-01T00:00:00Z","attempts":1,"lastError":"e"}]`,
			expectItems: 1,
			expectErr:   false,
		},
		{
			name:        "invalid json",
			data:        "not json",
			expectItems: 0,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, err := parseQueueData(tt.data)
			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(items) != tt.expectItems {
				t.Errorf("Expected %d items, got %d", tt.expectItems, len(items))
			}
		})
	}
}
