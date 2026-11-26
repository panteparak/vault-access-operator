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
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/policy/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// AC1 (#18): an ownership-read error on delete is returned (so the caller
// queues a retry) and nothing is deleted.
func TestPolicyOps_DeleteFromVault_OwnershipReadErrorFailsClosed(t *testing.T) {
	m := newMockVaultClient()
	m.ownershipErr = errors.New("vault 500")
	ops := NewPolicyOps(domain.NewVaultPolicyAdapter(newTestVaultPolicy()), &Handler{})

	if err := ops.DeleteFromVault(context.Background(), m, "vao._.test-ns.app-read"); err == nil {
		t.Fatal("ownership read error must be returned, got nil")
	}
	if len(m.deletePolicyCalls) != 0 {
		t.Errorf("deleted on a read error: %v", m.deletePolicyCalls)
	}
}

// AC4 (#18): normalizeHCL strips the ownership header, so a same-content
// write by another owner used to pass readback. With checks on, readback
// fails unless the record read back is the one just written.
func TestPolicyOps_ReadbackVerify_OwnershipRecord(t *testing.T) {
	const name = "vao.cluster-a.test-ns.app-read"
	run := func(t *testing.T, markersOn bool, rewrite func(hcl string) string) error {
		t.Helper()
		if markersOn {
			enableMarkersForTest(t)
		}
		state := newPolicyMockState()
		server := newPolicyMockServer(policyMockConfig{state: state})
		t.Cleanup(server.Close)
		vc := newPolicyTestVaultClient(t, server.URL)
		vc.SetAuthMount("cluster-a")

		ops := NewPolicyOps(domain.NewVaultPolicyAdapter(newTestVaultPolicy()), &Handler{})
		ops.vaultName = name
		if _, err := ops.PrepareContent(context.Background(), vc); err != nil {
			t.Fatal(err)
		}
		state.policies[name] = rewrite(ops.hcl)
		return ops.ReadbackVerify(context.Background(), vc)
	}
	foreign := func(hcl string) string {
		return strings.Replace(hcl, "# auth-mount: cluster-a", "# auth-mount: cluster-b", 1)
	}

	t.Run("own record: ok", func(t *testing.T) {
		if err := run(t, true, func(h string) string { return h }); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
	t.Run("foreign record, identical rules: conflict", func(t *testing.T) {
		if err := run(t, true, foreign); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
	// #18 AC7: checks always run, markers on or off.
	t.Run("markers off: still checked", func(t *testing.T) {
		if err := run(t, false, foreign); !infraerrors.IsConflictError(err) {
			t.Errorf("want ConflictError, got %v", err)
		}
	})
}

func newPolicyTestVaultClient(t *testing.T, url string) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.ClientConfig{Address: url})
	if err != nil {
		t.Fatal(err)
	}
	c.SetAuthenticated(true)
	c.SetToken("s.test")
	return c
}

// Review finding 2 (#18): Adopt must never take over a policy whose
// ownership could not be read. The read error used to take an "adopting
// policy (ownership unknown)" branch, so a transient GET failure let a CR
// with conflictPolicy: Adopt overwrite another cluster's policy. It is now
// a TransientError whatever the adoption setting, as on the role path.
func TestSyncPolicy_AdoptOnOwnershipReadErrorIsTransient(t *testing.T) {
	state := newPolicyMockState()
	name := naming.VaultName("my-cluster", policyTestNamespace, policyTestName)
	foreign := vault.OwnershipHeader(vault.Ownership{ManagedBy: vault.KVManagedByValue,
		AuthMount: "other-cluster", K8sResource: policyTestNamespace + "/" + policyTestName,
		K8sKind: "VaultPolicy"}) + "\npath \"secret/data/other/*\" { capabilities = [\"read\"] }\n"
	state.policies[name] = foreign
	server := newPolicyMockServer(policyMockConfig{state: state, readPolicyErr: true})
	t.Cleanup(server.Close)

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	policy.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt
	k8sClient := fake.NewClientBuilder().WithScheme(newPolicyTestScheme()).
		WithObjects(conn, policy).WithStatusSubresource(conn, policy).Build()
	cache := vault.NewClientCache()
	vc := newPolicyCachedVaultClient(t, server.URL)
	vc.SetAuthMount("my-cluster")
	cache.Set(conn.Name, vc)
	h := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	err := h.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(policy))
	if !infraerrors.IsTransientError(err) {
		t.Errorf("want TransientError for an unreadable owner, got %v", err)
	}
	state.mu.Lock()
	live := state.policies[name]
	state.mu.Unlock()
	if live != foreign {
		own, _ := vault.ParseOwnership(live)
		t.Fatalf("foreign-owned policy %s was overwritten; owner now %s", name, own.String())
	}
}

// Review finding 5 (#18): Vault lowercases ACL policy names. PolicyExists
// compared the bound name byte-for-byte against LIST, so a bound name with
// capitals (login mount "K8s-East", or a --cluster-name with capitals)
// never "existed": the ownership check was skipped and the write replaced
// another owner's policy. The comparison is now case-insensitive.
func TestSyncPolicy_MixedCaseNameStillChecksOwnership(t *testing.T) {
	state := newPolicyMockState()
	lower := "vao.k8s-east.test-ns.app-read"
	foreign := vault.OwnershipHeader(vault.Ownership{ManagedBy: vault.KVManagedByValue,
		AuthMount: "k8s-east-other", K8sResource: policyTestNamespace + "/" + policyTestName,
		K8sKind: "VaultPolicy"}) + "\npath \"secret/data/other/*\" { capabilities = [\"read\"] }\n"
	state.policies[lower] = foreign
	server := newPolicyMockServer(policyMockConfig{state: state, lowercaseNames: true})
	t.Cleanup(server.Close)

	conn := newPolicyTestConnection()
	policy := newTestVaultPolicy()
	k8sClient := fake.NewClientBuilder().WithScheme(newPolicyTestScheme()).
		WithObjects(conn, policy).WithStatusSubresource(conn, policy).Build()
	cache := vault.NewClientCache()
	vc := newPolicyCachedVaultClient(t, server.URL)
	vc.SetAuthMount("K8s-East") // the identity segment keeps the capitals
	cache.Set(conn.Name, vc)
	h := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard())
	ctx := logr.NewContext(context.Background(), logr.Discard())

	err := h.SyncPolicy(ctx, domain.NewVaultPolicyAdapter(policy))
	if !infraerrors.IsConflictError(err) {
		t.Errorf("want ConflictError for another owner's policy, got %v", err)
	}
	state.mu.Lock()
	live := state.policies[lower]
	state.mu.Unlock()
	if live != foreign {
		t.Fatalf("policy %s owned by another login mount was overwritten without a conflict check", lower)
	}
}
