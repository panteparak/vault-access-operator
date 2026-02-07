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

// Package cleanup provides a persistent cleanup queue for failed Vault resource deletions.
package cleanup

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResourceType represents the type of Vault resource.
type ResourceType string

const (
	// ResourceTypePolicy represents a Vault policy.
	ResourceTypePolicy ResourceType = "policy"
	// ResourceTypeRole represents a Vault role.
	ResourceTypeRole ResourceType = "role"
)

const (
	// ConfigMapName is the name of the ConfigMap used to store the cleanup queue.
	ConfigMapName = "vault-cleanup-queue"
	// QueueDataKey is the key in the ConfigMap data where queue items are stored.
	QueueDataKey = "queue"
)

// Item represents a failed cleanup operation that needs to be retried.
type Item struct {
	// ID is a unique identifier for this item (used for deduplication).
	ID string `json:"id"`
	// ResourceType is the type of Vault resource ("policy" or "role").
	ResourceType ResourceType `json:"resourceType"`
	// VaultName is the name of the resource in Vault.
	VaultName string `json:"vaultName"`
	// ConnectionName is the name of the VaultConnection to use.
	ConnectionName string `json:"connectionName"`
	// AuthPath is the Vault auth path (for roles only).
	AuthPath string `json:"authPath,omitempty"`
	// K8sNamespace is the namespace of the K8s resource (empty for cluster-scoped).
	K8sNamespace string `json:"k8sNamespace,omitempty"`
	// K8sName is the name of the K8s resource.
	K8sName string `json:"k8sName"`
	// FailedAt is when the cleanup first failed.
	FailedAt time.Time `json:"failedAt"`
	// LastAttemptAt is when the last retry was attempted.
	LastAttemptAt time.Time `json:"lastAttemptAt,omitempty"`
	// Attempts is the number of retry attempts made.
	Attempts int `json:"attempts"`
	// LastError is the error message from the last failed attempt.
	LastError string `json:"lastError"`
}

// Queue provides a persistent cleanup queue backed by a Kubernetes ConfigMap.
// Items are stored in the ConfigMap to survive operator restarts.
type Queue struct {
	client    client.Client
	namespace string // namespace where the ConfigMap is stored
	mu        sync.RWMutex
}

// NewQueue creates a new cleanup queue.
func NewQueue(k8sClient client.Client, namespace string) *Queue {
	return &Queue{
		client:    k8sClient,
		namespace: namespace,
	}
}

// Enqueue adds a failed cleanup item to the queue.
// If an item with the same ID already exists, it updates the existing item.
func (q *Queue) Enqueue(ctx context.Context, item Item) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Generate ID if not set
	if item.ID == "" {
		item.ID = generateItemID(item)
	}

	// Get or create the ConfigMap
	cm, err := q.getOrCreateConfigMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cleanup queue configmap: %w", err)
	}

	// Parse existing queue
	items, err := parseQueueData(cm.Data[QueueDataKey])
	if err != nil {
		return fmt.Errorf("failed to parse queue data: %w", err)
	}

	// Check if item already exists
	found := false
	for i, existing := range items {
		if existing.ID == item.ID {
			// Update existing item
			items[i].Attempts = item.Attempts
			items[i].LastAttemptAt = item.LastAttemptAt
			items[i].LastError = item.LastError
			found = true
			break
		}
	}

	if !found {
		items = append(items, item)
	}

	// Serialize and update ConfigMap
	data, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("failed to serialize queue: %w", err)
	}

	cm.Data[QueueDataKey] = string(data)
	if err := q.client.Update(ctx, cm); err != nil {
		return fmt.Errorf("failed to update cleanup queue configmap: %w", err)
	}

	return nil
}

// Dequeue removes an item from the queue by ID.
func (q *Queue) Dequeue(ctx context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	cm, err := q.getConfigMap(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Queue doesn't exist, nothing to dequeue
			return nil
		}
		return fmt.Errorf("failed to get cleanup queue configmap: %w", err)
	}

	items, err := parseQueueData(cm.Data[QueueDataKey])
	if err != nil {
		return fmt.Errorf("failed to parse queue data: %w", err)
	}

	// Find and remove the item
	newItems := make([]Item, 0, len(items))
	for _, item := range items {
		if item.ID != id {
			newItems = append(newItems, item)
		}
	}

	// Serialize and update ConfigMap
	data, err := json.Marshal(newItems)
	if err != nil {
		return fmt.Errorf("failed to serialize queue: %w", err)
	}

	cm.Data[QueueDataKey] = string(data)
	if err := q.client.Update(ctx, cm); err != nil {
		return fmt.Errorf("failed to update cleanup queue configmap: %w", err)
	}

	return nil
}

// List returns all items in the queue.
func (q *Queue) List(ctx context.Context) ([]Item, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	cm, err := q.getConfigMap(ctx)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return []Item{}, nil
		}
		return nil, fmt.Errorf("failed to get cleanup queue configmap: %w", err)
	}

	items, err := parseQueueData(cm.Data[QueueDataKey])
	if err != nil {
		return nil, fmt.Errorf("failed to parse queue data: %w", err)
	}

	return items, nil
}

// Size returns the number of items in the queue.
func (q *Queue) Size(ctx context.Context) (int, error) {
	items, err := q.List(ctx)
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

// getConfigMap retrieves the ConfigMap from the cluster.
func (q *Queue) getConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: ConfigMapName, Namespace: q.namespace}
	if err := q.client.Get(ctx, key, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

// getOrCreateConfigMap retrieves or creates the ConfigMap.
func (q *Queue) getOrCreateConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	cm, err := q.getConfigMap(ctx)
	if err == nil {
		return cm, nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	// Create new ConfigMap
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConfigMapName,
			Namespace: q.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "vault-access-operator",
				"app.kubernetes.io/component": "cleanup-queue",
			},
		},
		Data: map[string]string{},
	}

	if err := q.client.Create(ctx, cm); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Race condition: another goroutine created it
			return q.getConfigMap(ctx)
		}
		return nil, fmt.Errorf("failed to create cleanup queue configmap: %w", err)
	}

	return cm, nil
}

// parseQueueData parses the queue data from a JSON string.
func parseQueueData(data string) ([]Item, error) {
	if data == "" {
		return []Item{}, nil
	}

	var items []Item
	if err := json.Unmarshal([]byte(data), &items); err != nil {
		return nil, err
	}

	return items, nil
}

// generateItemID generates a unique ID for a cleanup item.
func generateItemID(item Item) string {
	if item.K8sNamespace != "" {
		return fmt.Sprintf("%s/%s/%s/%s", item.ResourceType, item.ConnectionName, item.K8sNamespace, item.K8sName)
	}
	return fmt.Sprintf("%s/%s/%s", item.ResourceType, item.ConnectionName, item.K8sName)
}

// NewPolicyCleanupItem creates a cleanup item for a failed policy deletion.
func NewPolicyCleanupItem(vaultName, connectionName, namespace, name, errMsg string) Item {
	now := time.Now()
	return Item{
		ResourceType:   ResourceTypePolicy,
		VaultName:      vaultName,
		ConnectionName: connectionName,
		K8sNamespace:   namespace,
		K8sName:        name,
		FailedAt:       now,
		LastAttemptAt:  now,
		Attempts:       1,
		LastError:      errMsg,
	}
}

// NewRoleCleanupItem creates a cleanup item for a failed role deletion.
func NewRoleCleanupItem(vaultName, connectionName, authPath, namespace, name, errMsg string) Item {
	now := time.Now()
	return Item{
		ResourceType:   ResourceTypeRole,
		VaultName:      vaultName,
		ConnectionName: connectionName,
		AuthPath:       authPath,
		K8sNamespace:   namespace,
		K8sName:        name,
		FailedAt:       now,
		LastAttemptAt:  now,
		Attempts:       1,
		LastError:      errMsg,
	}
}
