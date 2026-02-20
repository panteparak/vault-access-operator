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

package watches

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(s)
	return s
}

func TestPolicyRequestsForConnection(t *testing.T) {
	scheme := newTestScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-conn"},
	}

	// Two policies reference vault-conn, one references other-conn
	policies := []vaultv1alpha1.VaultPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns1"},
			Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "vault-conn"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns2"},
			Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "vault-conn"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: "ns1"},
			Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "other-conn"},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range policies {
		builder = builder.WithObjects(&policies[i])
	}
	k8sClient := builder.Build()

	mapFunc := PolicyRequestsForConnection(k8sClient)
	requests := mapFunc(context.Background(), conn)

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}

	names := map[string]bool{}
	for _, r := range requests {
		names[r.Namespace+"/"+r.Name] = true
	}
	if !names["ns1/p1"] {
		t.Error("expected request for ns1/p1")
	}
	if !names["ns2/p2"] {
		t.Error("expected request for ns2/p2")
	}
}

func TestClusterPolicyRequestsForConnection(t *testing.T) {
	scheme := newTestScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-conn"},
	}

	policies := []vaultv1alpha1.VaultClusterPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cp1"},
			Spec:       vaultv1alpha1.VaultClusterPolicySpec{ConnectionRef: "vault-conn"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cp2"},
			Spec:       vaultv1alpha1.VaultClusterPolicySpec{ConnectionRef: "other-conn"},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range policies {
		builder = builder.WithObjects(&policies[i])
	}
	k8sClient := builder.Build()

	mapFunc := ClusterPolicyRequestsForConnection(k8sClient)
	requests := mapFunc(context.Background(), conn)

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if requests[0].Name != "cp1" {
		t.Errorf("expected request for cp1, got %s", requests[0].Name)
	}
}

func TestRoleRequestsForConnection(t *testing.T) {
	scheme := newTestScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-conn"},
	}

	roles := []vaultv1alpha1.VaultRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "ns1"},
			Spec:       vaultv1alpha1.VaultRoleSpec{ConnectionRef: "vault-conn"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "ns1"},
			Spec:       vaultv1alpha1.VaultRoleSpec{ConnectionRef: "other-conn"},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range roles {
		builder = builder.WithObjects(&roles[i])
	}
	k8sClient := builder.Build()

	mapFunc := RoleRequestsForConnection(k8sClient)
	requests := mapFunc(context.Background(), conn)

	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if requests[0].Name != "r1" {
		t.Errorf("expected request for r1, got %s", requests[0].Name)
	}
}

func TestClusterRoleRequestsForConnection(t *testing.T) {
	scheme := newTestScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-conn"},
	}

	roles := []vaultv1alpha1.VaultClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cr1"},
			Spec:       vaultv1alpha1.VaultClusterRoleSpec{ConnectionRef: "vault-conn"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cr2"},
			Spec:       vaultv1alpha1.VaultClusterRoleSpec{ConnectionRef: "vault-conn"},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for i := range roles {
		builder = builder.WithObjects(&roles[i])
	}
	k8sClient := builder.Build()

	mapFunc := ClusterRoleRequestsForConnection(k8sClient)
	requests := mapFunc(context.Background(), conn)

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
}

func TestPolicyRequestsForConnection_NoMatches(t *testing.T) {
	scheme := newTestScheme()
	conn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "unused-conn"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mapFunc := PolicyRequestsForConnection(k8sClient)
	requests := mapFunc(context.Background(), conn)

	if len(requests) != 0 {
		t.Fatalf("expected 0 requests for unused connection, got %d", len(requests))
	}
}
