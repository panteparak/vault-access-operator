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
	"encoding/json"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// AC2 (#18): every replayed delete re-checks ownership against the owner the
// item was queued with, and skips an object that now belongs to someone else.

func newGateController(t *testing.T, vc *mockVaultClient) (*Controller, *Queue) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	q := NewQueue(fake.NewClientBuilder().WithScheme(scheme).Build(), "test-namespace")
	return &Controller{
		queue:       q,
		clientCache: &mockClientCache{client: vc},
		maxAttempts: 10,
		log:         newTestLogger(),
	}, q
}

func record(mount, resource string) *vault.Ownership {
	return &vault.Ownership{ManagedBy: vault.KVManagedByValue, AuthMount: mount, K8sResource: resource}
}

func aliasRecord(mount, resource string) map[string]interface{} {
	return map[string]interface{}{vault.RoleAliasMetadataKey: map[string]interface{}{
		vault.KVManagedByKey:        vault.KVManagedByValue,
		vault.OwnershipAuthMountKey: mount,
		vault.KVK8sResourceKey:      resource,
	}}
}

func TestReplayGate_Policy(t *testing.T) {
	owner := &vault.Owner{AuthMount: "cluster-a", K8sResource: "x"}
	cases := []struct {
		name       string
		live       *vault.Ownership
		itemOwner  *vault.Owner
		wantDelete bool
	}{
		{"ours: deleted", record("cluster-a", "x"), owner, true},
		{"header-less: deleted", nil, owner, true},
		{"same CR coords, other cluster's mount: skipped", record("cluster-b", "x"), owner, false},
		{"other CR: skipped", record("cluster-a", "y"), owner, false},
		// Items queued by v0.12.0 carry no owner: the replay expects the
		// connection's current identity for the CR named on the item.
		{"legacy item, ours: deleted", record("cluster-a", "x"), nil, true},
		{"legacy item, foreign: skipped", record("cluster-b", "x"), nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vc := &mockVaultClient{
				authMount:    "cluster-a",
				policyOwners: map[string]*vault.Ownership{"vao.proj._.x": tc.live},
			}
			c, _ := newGateController(t, vc)
			item := Item{ID: "p", ResourceType: ResourceTypePolicy, VaultName: "vao.proj._.x",
				ConnectionName: "conn", K8sName: "x", Owner: tc.itemOwner}
			if _, err := c.processItem(context.Background(), item); err != nil {
				t.Fatalf("processItem: %v", err)
			}
			if got := len(vc.deletedPolicies) == 1; got != tc.wantDelete {
				t.Errorf("deleted = %v, want %v", got, tc.wantDelete)
			}
		})
	}
}

func TestReplayGate_Role(t *testing.T) {
	owner := &vault.Owner{AuthMount: "cluster-a", K8sResource: "ns/x"}
	for _, tc := range []struct {
		name       string
		live       map[string]interface{}
		wantDelete bool
	}{
		{"ours: deleted", aliasRecord("cluster-a", "ns/x"), true},
		{"record-less: deleted", map[string]interface{}{"policies": []interface{}{"p"}}, true},
		{"foreign: skipped", aliasRecord("cluster-b", "ns/x"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vc := &mockVaultClient{roleData: map[string]map[string]interface{}{"github/vao.proj.ns.x": tc.live}}
			c, _ := newGateController(t, vc)
			item := Item{ID: "r", ResourceType: ResourceTypeRole, VaultName: "vao.proj.ns.x",
				ConnectionName: "conn", AuthPath: "github", K8sNamespace: "ns", K8sName: "x", Owner: owner}
			if _, err := c.processItem(context.Background(), item); err != nil {
				t.Fatalf("processItem: %v", err)
			}
			if got := len(vc.deletedRoles) == 1; got != tc.wantDelete {
				t.Errorf("deleted = %v, want %v", got, tc.wantDelete)
			}
		})
	}
}

// A read error is never permission to delete: the item stays queued with
// one more attempt, and nothing is deleted.
func TestReplayGate_ReadErrorRetriesWithoutDeleting(t *testing.T) {
	vc := &mockVaultClient{readErr: errors.New("vault 500")}
	c, q := newGateController(t, vc)
	ctx := context.Background()
	for _, item := range []Item{
		{ID: "p", ResourceType: ResourceTypePolicy, VaultName: "vao.proj._.x", ConnectionName: "conn", K8sName: "x"},
		{ID: "r", ResourceType: ResourceTypeRole, VaultName: "vao.proj._.x", ConnectionName: "conn",
			AuthPath: "github", K8sName: "x"},
	} {
		if err := q.Enqueue(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	c.processQueue(ctx)
	if len(vc.deletedPolicies)+len(vc.deletedRoles) != 0 {
		t.Fatalf("deleted on a read error: policies=%v roles=%v", vc.deletedPolicies, vc.deletedRoles)
	}
	items, _ := q.List(ctx)
	if len(items) != 2 {
		t.Fatalf("items after failed replay = %d, want 2 (retried later)", len(items))
	}
	for _, it := range items {
		if it.Attempts != 1 {
			t.Errorf("%s attempts = %d, want 1", it.ID, it.Attempts)
		}
	}
}

// A foreign object is done, not retried: the item leaves the queue.
func TestReplayGate_ForeignDequeued(t *testing.T) {
	vc := &mockVaultClient{policyOwners: map[string]*vault.Ownership{"vao.proj._.x": record("cluster-b", "x")}}
	c, q := newGateController(t, vc)
	ctx := context.Background()
	_ = q.Enqueue(ctx, Item{ID: "p", ResourceType: ResourceTypePolicy, VaultName: "vao.proj._.x",
		ConnectionName: "conn", K8sName: "x", Owner: &vault.Owner{AuthMount: "cluster-a", K8sResource: "x"}})
	successes := metrics.CleanupRetriesTotal.WithLabelValues(string(ResourceTypePolicy), "success")
	before := testutil.ToFloat64(successes)
	c.processQueue(ctx)
	if len(vc.deletedPolicies) != 0 {
		t.Fatalf("foreign policy deleted: %v", vc.deletedPolicies)
	}
	if n, _ := q.Size(ctx); n != 0 {
		t.Errorf("queue size = %d, want 0", n)
	}
	// A skipped delete is not a successful cleanup (#18 review nit).
	if got := testutil.ToFloat64(successes) - before; got != 0 {
		t.Errorf("skipped foreign item counted as %v successful cleanup retries, want 0", got)
	}
}

// The owner survives the ConfigMap round trip, and items written by v0.12.0
// (no owner key) still parse.
func TestItemOwner_JSON(t *testing.T) {
	in := Item{ID: "p", Owner: &vault.Owner{AuthMount: "m", K8sResource: "ns/x"}}
	b, _ := json.Marshal(in)
	var out Item
	if err := json.Unmarshal(b, &out); err != nil || out.Owner == nil || *out.Owner != *in.Owner {
		t.Fatalf("round trip = %+v, %v", out.Owner, err)
	}
	var legacy []Item
	if err := json.Unmarshal([]byte(`[{"id":"p","resourceType":"policy","vaultName":"n","k8sName":"x"}]`),
		&legacy); err != nil || legacy[0].Owner != nil {
		t.Fatalf("legacy item = %+v, %v", legacy, err)
	}
}
