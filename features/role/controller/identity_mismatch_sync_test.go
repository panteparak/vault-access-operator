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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/events"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// TestSyncRole_PolicyIdentityMismatchWarning pins #18 AC10 through a full
// SyncRole (review finding 8): a role written under identity "_" that
// references a policy recorded under identity "cluster-a" gets one
// PolicyIdentityMismatch Warning, and the sync still succeeds.
func TestSyncRole_PolicyIdentityMismatchWarning(t *testing.T) {
	conn := newTestVaultConnection()
	role := newTestVaultRole()
	otherName := naming.VaultName("cluster-a", testNamespace, "app-read")
	refPolicy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "app-read", Namespace: testNamespace},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: testConnName},
		Status:     vaultv1alpha1.VaultPolicyStatus{VaultName: otherName},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(newTestScheme()).
		WithObjects(conn, role, refPolicy).
		WithStatusSubresource(conn, role, refPolicy).
		Build()

	server := newMockVaultServer(mockVaultServerConfig{state: newMockVaultState()})
	defer server.Close()
	cache := vault.NewClientCache()
	cache.Set(conn.Name, newTestCachedVaultClient(t, server.URL))
	recorder := record.NewFakeRecorder(50)
	handler := NewHandler(k8sClient, cache, events.NewEventBus(logr.Discard()), logr.Discard(), recorder)

	ctx := logr.NewContext(context.Background(), logr.Discard())
	if err := handler.SyncRole(ctx, domain.NewVaultRoleAdapter(role)); err != nil {
		t.Fatalf("SyncRole: %v (the mismatch must not block the sync)", err)
	}

	close(recorder.Events)
	var mismatches []string
	for e := range recorder.Events {
		if strings.Contains(e, eventReasonPolicyIdentityMismatch) {
			mismatches = append(mismatches, e)
		}
	}
	if len(mismatches) != 1 || !strings.HasPrefix(mismatches[0], "Warning ") ||
		!strings.Contains(mismatches[0], `"cluster-a"`) || !strings.Contains(mismatches[0], otherName) {
		t.Fatalf("PolicyIdentityMismatch events = %v, want one Warning naming %q under identity cluster-a",
			mismatches, otherName)
	}
}
