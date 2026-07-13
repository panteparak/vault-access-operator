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
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/role/domain"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/controller/conditions"
	"github.com/panteparak/vault-access-operator/shared/controller/drift"
	"github.com/panteparak/vault-access-operator/shared/controller/syncerror"
	"github.com/panteparak/vault-access-operator/shared/controller/vaultclient"
	"github.com/panteparak/vault-access-operator/shared/events"
	infraerrors "github.com/panteparak/vault-access-operator/shared/infrastructure/errors"
)

// setConditionHelper calls conditions.Set directly, replacing the removed handler.setCondition.
//
//nolint:unparam // general-purpose test helper; status/reason vary by caller intent
func setConditionHelper(
	adapter domain.RoleAdapter,
	condType string,
	status metav1.ConditionStatus,
	reason, message string,
) {
	adapter.SetConditions(conditions.Set(
		adapter.GetConditions(), adapter.GetGeneration(),
		condType, status, reason, message,
	))
}

// Helper functions for creating test objects
func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = vaultv1alpha1.AddToScheme(scheme)
	return scheme
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&vaultv1alpha1.VaultRole{}, &vaultv1alpha1.VaultClusterRole{}).
		Build()
}

// syncedPolicy seeds a VaultPolicy CR whose status carries a recorded Vault
// name — the lookup source for role binding resolution (ADR 0010).
func syncedPolicy(name, namespace, vaultName string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       vaultv1alpha1.VaultPolicySpec{ConnectionRef: "test-connection"},
		Status:     vaultv1alpha1.VaultPolicyStatus{VaultName: vaultName},
	}
}

// syncedClusterPolicy is the cluster-scoped twin of syncedPolicy.
func syncedClusterPolicy(name, vaultName string) *vaultv1alpha1.VaultClusterPolicy {
	return &vaultv1alpha1.VaultClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       vaultv1alpha1.VaultClusterPolicySpec{ConnectionRef: "test-connection"},
		Status:     vaultv1alpha1.VaultClusterPolicyStatus{VaultName: vaultName},
	}
}

func newVaultRole(name, namespace string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   "test-connection",
			ServiceAccounts: []string{"default", "app"},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "read-secrets"},
				{Kind: "VaultClusterPolicy", Name: "global-policy"},
			},
			TokenTTL:    "1h",
			TokenMaxTTL: "24h",
		},
	}
}

func newVaultClusterRole(name string) *vaultv1alpha1.VaultClusterRole {
	return &vaultv1alpha1.VaultClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultClusterRoleSpec{
			ConnectionRef: "test-connection",
			ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
				{Name: "default", Namespace: "ns1"},
				{Name: "app", Namespace: "ns2"},
			},
			Policies: []vaultv1alpha1.PolicyReference{
				{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "production"},
				{Kind: "VaultClusterPolicy", Name: "global-policy"},
			},
		},
	}
}

const (
	testConnectionName = "test-connection"
	testVaultRoleName  = "default-test-role"
)

func newActiveVaultConnection() *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testConnectionName,
			Generation: 1,
		},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
			// Kubernetes login → RoleMount resolves auth/kubernetes, the
			// mount these tests always targeted.
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "operator"},
			},
		},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
			Conditions: []vaultv1alpha1.Condition{
				{
					Type:               vaultv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}
}

// Tests for NewHandler
func TestNewHandler(t *testing.T) {
	fakeClient := newFakeClient()
	cache := vault.NewClientCache()
	eventBus := events.NewEventBus(logr.Discard())
	logger := logr.Discard()

	handler := NewHandler(fakeClient, cache, eventBus, logger)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return
	}
	if handler.client == nil {
		t.Error("expected client to be set")
	}
	if handler.clientCache == nil {
		t.Error("expected clientCache to be set")
	}
	if handler.eventBus == nil {
		t.Error("expected eventBus to be set")
	}
}

func TestNewHandler_WithNilEventBus(t *testing.T) {
	fakeClient := newFakeClient()
	cache := vault.NewClientCache()
	logger := logr.Discard()

	handler := NewHandler(fakeClient, cache, nil, logger)

	if handler == nil {
		t.Fatal("expected handler to be non-nil")
		return
	}
	if handler.eventBus != nil {
		t.Error("expected eventBus to be nil")
	}
}

// Tests for resolvePolicyNames
func TestResolvePolicyNames_VaultPolicy(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets"},
		{Kind: "VaultPolicy", Name: "write-data", Namespace: "production"},
	}

	fakeClient := newFakeClient(role,
		syncedPolicy("read-secrets", "default", "vao._.default.read-secrets"),
		syncedPolicy("write-data", "production", "vao._.production.write-data"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The resolved names are the policies' RECORDED status names, not
	// re-derivations (ADR 0010).
	expected := []string{"vao._.default.read-secrets", "vao._.production.write-data"}
	if len(resolution) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(resolution))
	}
	for i, exp := range expected {
		if !resolution[i].Resolved || resolution[i].VaultName != exp {
			t.Errorf("policy[%d]: expected resolved %q, got %+v", i, exp, resolution[i])
		}
	}
}

func TestResolvePolicyNames_VaultClusterPolicy(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultClusterPolicy", Name: "admin-policy"},
		{Kind: "VaultClusterPolicy", Name: "readonly-policy"},
	}

	fakeClient := newFakeClient(role,
		syncedClusterPolicy("admin-policy", "vao._._.admin-policy"),
		syncedClusterPolicy("readonly-policy", "vao._._.readonly-policy"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"vao._._.admin-policy", "vao._._.readonly-policy"}
	if len(resolution) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(resolution))
	}
	for i, exp := range expected {
		if !resolution[i].Resolved || resolution[i].VaultName != exp {
			t.Errorf("policy[%d]: expected resolved %q, got %+v", i, exp, resolution[i])
		}
	}
}

func TestResolvePolicyNames_MixedPolicies(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "myns")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "ns-policy"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
		{Kind: "VaultPolicy", Name: "other-policy", Namespace: "other"},
	}

	fakeClient := newFakeClient(role,
		syncedPolicy("ns-policy", "myns", "vao._.myns.ns-policy"),
		syncedClusterPolicy("cluster-policy", "vao._._.cluster-policy"),
		syncedPolicy("other-policy", "other", "vao._.other.other-policy"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"vao._.myns.ns-policy", "vao._._.cluster-policy", "vao._.other.other-policy"}
	if len(resolution) != len(expected) {
		t.Fatalf("expected %d policies, got %d", len(expected), len(resolution))
	}
	for i, exp := range expected {
		if !resolution[i].Resolved || resolution[i].VaultName != exp {
			t.Errorf("policy[%d]: expected resolved %q, got %+v", i, exp, resolution[i])
		}
	}
}

func TestResolvePolicyNames_InvalidKind(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "InvalidKind", Name: "policy"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := handler.resolvePolicyNames(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for invalid policy kind")
	}
	if !infraerrors.IsValidationError(err) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestResolvePolicyNames_ClusterRoleMissingNamespace(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	clusterRole.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy-without-namespace"},
	}

	fakeClient := newFakeClient(clusterRole)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	_, err := handler.resolvePolicyNames(ctx, adapter)
	if err == nil {
		t.Fatal("expected error for missing namespace in cluster-scoped role")
	}
	if !infraerrors.IsValidationError(err) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestResolvePolicyNames_EmptyPolicies(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resolution) != 0 {
		t.Errorf("expected 0 policies, got %d", len(resolution))
	}
}

// Tests for buildRoleData
func TestBuildRoleData_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	policyNames := []string{"default-policy", "global-policy"}
	serviceAccountBindings := adapter.GetServiceAccountBindings()

	roleData, err := handler.buildRoleData(adapter, vault.AuthBackendKubernetes, policyNames, serviceAccountBindings, nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	// Check policies
	policies, ok := roleData["policies"].([]string)
	if !ok {
		t.Fatal("expected policies to be []string")
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// Check bound service account names
	saNames, ok := roleData["bound_service_account_names"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_names to be []string")
	}
	if len(saNames) != 2 {
		t.Errorf("expected 2 service account names, got %d", len(saNames))
	}
	expectedNames := []string{"app", "default"} // sorted for deterministic hashing
	for i, expected := range expectedNames {
		if saNames[i] != expected {
			t.Errorf("sa name[%d]: expected %q, got %q", i, expected, saNames[i])
		}
	}

	// Check bound service account namespaces
	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	if len(saNamespaces) != 1 {
		t.Errorf("expected 1 namespace, got %d", len(saNamespaces))
	}
	if saNamespaces[0] != "default" {
		t.Errorf("expected namespace 'default', got %q", saNamespaces[0])
	}

	// Check TTL settings
	if roleData["token_ttl"] != "1h" {
		t.Errorf("expected token_ttl '1h', got %v", roleData["token_ttl"])
	}
	if roleData["token_max_ttl"] != "24h" {
		t.Errorf("expected token_max_ttl '24h', got %v", roleData["token_max_ttl"])
	}
}

func TestBuildRoleData_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	fakeClient := newFakeClient(clusterRole)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	policyNames := []string{"cluster-policy"}
	serviceAccountBindings := adapter.GetServiceAccountBindings()

	roleData, err := handler.buildRoleData(adapter, vault.AuthBackendKubernetes, policyNames, serviceAccountBindings, nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	// Check bound service account namespaces (should have 2 different namespaces)
	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	if len(saNamespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(saNamespaces))
	}
}

func TestBuildRoleData_NoTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenTTL = ""
	role.Spec.TokenMaxTTL = ""

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(adapter, vault.AuthBackendKubernetes, []string{}, []string{"default/app"}, nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	if _, exists := roleData["token_ttl"]; exists {
		t.Error("expected token_ttl to not be set")
	}
	if _, exists := roleData["token_max_ttl"]; exists {
		t.Error("expected token_max_ttl to not be set")
	}
}

func TestBuildRoleData_MultipleNamespaces(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	bindings := []string{"ns1/sa1", "ns2/sa2", "ns1/sa3", "ns3/sa4"}
	roleData, err := handler.buildRoleData(adapter, vault.AuthBackendKubernetes, []string{"policy"}, bindings, nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	saNamespaces, ok := roleData["bound_service_account_namespaces"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_namespaces to be []string")
	}
	// Should deduplicate namespaces
	if len(saNamespaces) != 3 {
		t.Errorf("expected 3 unique namespaces, got %d: %v", len(saNamespaces), saNamespaces)
	}
}

func TestBuildRoleData_EmptyBindings(t *testing.T) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(adapter, vault.AuthBackendKubernetes, []string{"policy"}, []string{}, nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	saNames, ok := roleData["bound_service_account_names"].([]string)
	if !ok {
		t.Fatal("expected bound_service_account_names to be []string")
	}
	if len(saNames) != 0 {
		t.Errorf("expected 0 service account names, got %d", len(saNames))
	}
}

// --- JWT role payload tests ---

func newJWTConnection(name string, audiences []string) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
			Auth: vaultv1alpha1.AuthConfig{
				JWT: &vaultv1alpha1.JWTAuth{
					Role:      "operator",
					Audiences: audiences,
				},
			},
		},
	}
}

func TestBuildRoleData_JWT_DerivesBoundSubjectFromServiceAccount(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}

	conn := newJWTConnection("vault-jwt", []string{"aud-a", "aud-b"})
	handler := NewHandler(newFakeClient(role, conn), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"eso-reader"}, adapter.GetServiceAccountBindings(), conn)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}

	if roleData["role_type"] != "jwt" {
		t.Errorf("expected role_type=jwt, got %v", roleData["role_type"])
	}
	if roleData["user_claim"] != "sub" {
		t.Errorf("expected user_claim=sub, got %v", roleData["user_claim"])
	}
	if roleData["bound_subject"] != "system:serviceaccount:bar:foo-sa" {
		t.Errorf("expected bound_subject=system:serviceaccount:bar:foo-sa, got %v", roleData["bound_subject"])
	}
	auds, ok := roleData["bound_audiences"].([]string)
	if !ok {
		t.Fatalf("expected bound_audiences []string, got %T", roleData["bound_audiences"])
	}
	if len(auds) != 2 || auds[0] != "aud-a" || auds[1] != "aud-b" {
		t.Errorf("expected bound_audiences from connection, got %v", auds)
	}
	// k8s-auth-specific keys should not appear
	if _, has := roleData["bound_service_account_names"]; has {
		t.Error("JWT payload should not include bound_service_account_names")
	}
}

func TestBuildRoleData_JWT_UserClaimOverride(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{UserClaim: "email"}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if roleData["user_claim"] != "email" {
		t.Errorf("expected user_claim=email, got %v", roleData["user_claim"])
	}
}

func TestBuildRoleData_JWT_BoundSubjectOverride(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{BoundSubject: "custom-subject"}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if roleData["bound_subject"] != "custom-subject" {
		t.Errorf("expected overridden bound_subject, got %v", roleData["bound_subject"])
	}
}

func TestBuildRoleData_JWT_BoundClaimsReplacesSubject(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa", "bar-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{
		BoundClaims: map[string]string{"groups": "eso-writers"},
	}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if _, has := roleData["bound_subject"]; has {
		t.Error("bound_subject should be absent when bound_claims is set")
	}
	claims, ok := roleData["bound_claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bound_claims map, got %T", roleData["bound_claims"])
	}
	// Scalars from BoundClaims are wrapped as single-element []interface{} so
	// the round-trip shape from Vault matches and the drift comparator stays
	// stable. Vault treats scalar and single-element list values equivalently.
	groups, ok := claims["groups"].([]interface{})
	if !ok || len(groups) != 1 || groups[0] != "eso-writers" {
		t.Errorf("expected bound_claims.groups=[eso-writers], got %v (%T)", claims["groups"], claims["groups"])
	}
	// bound_claims_type defaults to "string" whenever any bound_claims is set.
	if roleData["bound_claims_type"] != "string" {
		t.Errorf("expected bound_claims_type=string default, got %v", roleData["bound_claims_type"])
	}
}

// Claims-only role: no serviceAccounts at all (CI OIDC tokens carry no k8s SA
// identity) — the payload binds on claims and derives no bound_subject.
func TestBuildRoleData_JWT_BoundClaimsOnly_NoServiceAccounts(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = nil
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{
		BoundClaimsList: map[string][]string{
			"repository": {"org/repo"},
			"ref_type":   {"branch"},
		},
	}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if _, has := roleData["bound_subject"]; has {
		t.Error("bound_subject should be absent for a claims-only role")
	}
	claims, ok := roleData["bound_claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bound_claims map, got %T", roleData["bound_claims"])
	}
	repo, ok := claims["repository"].([]interface{})
	if !ok || len(repo) != 1 || repo[0] != "org/repo" {
		t.Errorf("expected bound_claims.repository=[org/repo], got %v", claims["repository"])
	}
	if _, has := roleData["bound_service_account_names"]; has {
		t.Error("JWT payload should not include bound_service_account_names")
	}
}

func TestBuildRoleData_JWT_BoundClaimsList_ScalarsAndLists(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{
		BoundClaimsList: map[string][]string{
			"project_id": {"111"},             // scalar via single-element list
			"ref":        {"main", "develop"}, // multi-value
		},
	}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	claims, ok := roleData["bound_claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bound_claims map, got %T", roleData["bound_claims"])
	}
	projectID, ok := claims["project_id"].([]interface{})
	if !ok || len(projectID) != 1 || projectID[0] != "111" {
		t.Errorf("expected project_id=[111], got %v", claims["project_id"])
	}
	refs, ok := claims["ref"].([]interface{})
	if !ok || len(refs) != 2 || refs[0] != "main" || refs[1] != "develop" {
		t.Errorf("expected ref=[main develop], got %v", claims["ref"])
	}
}

func TestBuildRoleData_JWT_BoundClaimsType_Glob(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{
		BoundClaimsList: map[string][]string{"ref": {"feat/*"}},
		BoundClaimsType: "glob",
	}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if roleData["bound_claims_type"] != "glob" {
		t.Errorf("expected bound_claims_type=glob, got %v", roleData["bound_claims_type"])
	}
}

func TestBuildRoleData_JWT_BoundClaimsList_OverridesBoundClaims(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	role.Spec.JWT = &vaultv1alpha1.VaultRoleJWTSpec{
		BoundClaims:     map[string]string{"ref": "stale"},
		BoundClaimsList: map[string][]string{"ref": {"main", "develop"}},
	}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	claims, ok := roleData["bound_claims"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected bound_claims map, got %T", roleData["bound_claims"])
	}
	refs, ok := claims["ref"].([]interface{})
	if !ok || len(refs) != 2 || refs[0] != "main" || refs[1] != "develop" {
		t.Errorf("expected ref=[main develop] (list wins), got %v", claims["ref"])
	}
}

func TestBuildRoleData_JWT_NoClaimsType_WhenNoClaims(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}
	// No BoundClaims / BoundClaimsList set — falls back to bound_subject path.

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	if _, has := roleData["bound_claims_type"]; has {
		t.Errorf("bound_claims_type should be absent when no bound_claims are set, got %v", roleData["bound_claims_type"])
	}
	if _, has := roleData["bound_subject"]; !has {
		t.Error("expected bound_subject when no bound_claims are set")
	}
}

func TestBuildRoleData_JWT_FallbackAudienceWhenConnectionNotJWT(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"foo-sa"}

	// Connection uses k8s auth, no JWT audiences.
	k8sConn := &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-k8s"},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: "https://vault.example.com:8200",
			Auth: vaultv1alpha1.AuthConfig{
				Kubernetes: &vaultv1alpha1.KubernetesAuth{Role: "operator"},
			},
		},
	}

	handler := NewHandler(newFakeClient(role, k8sConn), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	roleData, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), k8sConn)
	if err != nil {
		t.Fatalf("buildRoleData returned error: %v", err)
	}
	auds, ok := roleData["bound_audiences"].([]string)
	if !ok || len(auds) != 1 || auds[0] != "https://kubernetes.default.svc.cluster.local" {
		t.Errorf("expected cluster-default bound_audiences, got %v", auds)
	}
}

func TestBuildRoleData_JWT_MultipleServiceAccountsRejected(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	role.Spec.ServiceAccounts = []string{"sa1", "sa2"}

	handler := NewHandler(newFakeClient(role), vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	if _, err := handler.buildRoleData(
		adapter, vault.AuthBackendJWT, []string{"p"}, adapter.GetServiceAccountBindings(), nil); err == nil {
		t.Fatal("expected error for multiple service accounts without boundSubject/boundClaims")
	}
}

func TestResolveJWTBoundSubject_ServiceAccountBindingMalformed(t *testing.T) {
	role := newVaultRole("test-role", "bar")
	adapter := domain.NewVaultRoleAdapter(role)
	// Binding missing the slash — adapters normally guarantee namespace/name form.
	if _, err := resolveJWTBoundSubject(adapter, &vaultv1alpha1.VaultRoleJWTSpec{}, []string{"badformat"}); err == nil {
		t.Fatal("expected error for malformed binding")
	}
}

func TestCompareJWTRoleFields(t *testing.T) {
	t.Run("no drift when audiences match regardless of order", func(t *testing.T) {
		expected := map[string]interface{}{
			"policies":        []string{"p1", "p2"},
			"bound_audiences": []string{"aud-a", "aud-b"},
			"role_type":       "jwt",
			"user_claim":      "sub",
			"bound_subject":   "system:serviceaccount:ns:sa",
		}
		current := map[string]interface{}{
			"policies":        []interface{}{"p2", "p1"}, // order reversed, Vault returns interface slice
			"bound_audiences": []interface{}{"aud-b", "aud-a"},
			"role_type":       "jwt",
			"user_claim":      "sub",
			"bound_subject":   "system:serviceaccount:ns:sa",
			// Vault may add extra fields that should be ignored
			"token_num_uses": float64(0),
		}
		c := drift.NewComparator()
		compareJWTRoleFields(c, expected, current)
		if c.Result().HasDrift {
			t.Errorf("expected no drift, got: %s", c.Result().Summary)
		}
	})

	t.Run("drift when bound_subject differs", func(t *testing.T) {
		expected := map[string]interface{}{
			"policies":        []string{"p1"},
			"bound_audiences": []string{"aud"},
			"role_type":       "jwt",
			"user_claim":      "sub",
			"bound_subject":   "system:serviceaccount:ns:sa",
		}
		current := map[string]interface{}{
			"policies":        []interface{}{"p1"},
			"bound_audiences": []interface{}{"aud"},
			"role_type":       "jwt",
			"user_claim":      "sub",
			"bound_subject":   "system:serviceaccount:ns:other",
		}
		c := drift.NewComparator()
		compareJWTRoleFields(c, expected, current)
		if !c.Result().HasDrift {
			t.Error("expected drift for bound_subject mismatch")
		}
	})

	t.Run("falls back to token_policies when policies is absent", func(t *testing.T) {
		expected := map[string]interface{}{
			"policies":        []string{"p1"},
			"bound_audiences": []string{"aud"},
		}
		current := map[string]interface{}{
			// Vault returned only token_policies, not policies
			"token_policies":  []interface{}{"p1"},
			"bound_audiences": []interface{}{"aud"},
		}
		c := drift.NewComparator()
		compareJWTRoleFields(c, expected, current)
		if c.Result().HasDrift {
			t.Errorf("expected no drift when token_policies matches, got: %s", c.Result().Summary)
		}
	})

	t.Run("no drift on bound_claims round-trip with []interface{} values", func(t *testing.T) {
		// Mirrors what buildJWTRoleData produces (lists of []interface{})
		// against what Vault returns when reading the role back.
		expected := map[string]interface{}{
			"policies":        []string{"p"},
			"bound_audiences": []string{"aud"},
			"bound_claims": map[string]interface{}{
				"project_id": []interface{}{"111"},
				"ref":        []interface{}{"main", "develop"},
			},
			"bound_claims_type": "string",
		}
		current := map[string]interface{}{
			"policies":        []interface{}{"p"},
			"bound_audiences": []interface{}{"aud"},
			"bound_claims": map[string]interface{}{
				"project_id": []interface{}{"111"},
				"ref":        []interface{}{"main", "develop"},
			},
			"bound_claims_type": "string",
		}
		c := drift.NewComparator()
		compareJWTRoleFields(c, expected, current)
		if c.Result().HasDrift {
			t.Errorf("expected no drift on round-trip, got: %s", c.Result().Summary)
		}
	})

	t.Run("drift detected when bound_claims_type changes", func(t *testing.T) {
		expected := map[string]interface{}{
			"policies":          []string{"p"},
			"bound_audiences":   []string{"aud"},
			"bound_claims":      map[string]interface{}{"ref": []interface{}{"feat/*"}},
			"bound_claims_type": "glob",
		}
		current := map[string]interface{}{
			"policies":          []interface{}{"p"},
			"bound_audiences":   []interface{}{"aud"},
			"bound_claims":      map[string]interface{}{"ref": []interface{}{"feat/*"}},
			"bound_claims_type": "string",
		}
		c := drift.NewComparator()
		compareJWTRoleFields(c, expected, current)
		if !c.Result().HasDrift {
			t.Error("expected drift when bound_claims_type differs")
		}
	})
}

// Tests for handleSyncError (now delegates to syncerror.Handle)
func TestHandleSyncError_ConflictError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	conflictErr := infraerrors.NewConflictError("role", "test-role", "already managed by other")

	err := syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, conflictErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseConflict {
		t.Errorf("expected phase Conflict, got %s", adapter.GetPhase())
	}

	// Check condition was set
	conds := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conds[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Status != metav1.ConditionFalse {
		t.Errorf("expected Ready condition status False, got %s", readyCondition.Status)
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonConflict {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonConflict, readyCondition.Reason)
	}
}

func TestHandleSyncError_DependencyError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	depErr := infraerrors.NewDependencyError("role", "VaultConnection", "test-conn", "not ready")

	err := syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, depErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conds := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conds[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonConnectionNotReady {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonConnectionNotReady, readyCondition.Reason)
	}
}

func TestHandleSyncError_ValidationError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	validationErr := infraerrors.NewValidationError("policies", "invalid", "invalid policy kind")

	err := syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, validationErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conds := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conds[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonValidationFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonValidationFailed, readyCondition.Reason)
	}
}

func TestHandleSyncError_GenericError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	genericErr := errors.New("some generic error")

	err := syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, genericErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conds := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conds[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	if readyCondition.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCondition.Reason)
	}
}

func TestHandleSyncError_SetsMessage(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	testErr := errors.New("test error message")

	_ = syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, testErr)

	// Message should be set from error
	// The adapter's message is set internally
	conds := adapter.GetConditions()
	var syncedCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeSynced {
			syncedCondition = &conds[i]
			break
		}
	}
	if syncedCondition == nil {
		t.Fatal("expected Synced condition to be set")
		return
	}
	if syncedCondition.Status != metav1.ConditionFalse {
		t.Errorf("expected Synced condition status False, got %s", syncedCondition.Status)
	}
}

func TestHandleSyncError_TransientError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	transientErr := infraerrors.NewTransientError("write role", errors.New("network error"))

	err := syncerror.Handle(ctx, fakeClient, logr.Discard(), adapter, transientErr)
	if err == nil {
		t.Fatal("expected error to be returned")
	}

	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected phase Error, got %s", adapter.GetPhase())
	}

	conds := adapter.GetConditions()
	var readyCondition *vaultv1alpha1.Condition
	for i := range conds {
		if conds[i].Type == vaultv1alpha1.ConditionTypeReady {
			readyCondition = &conds[i]
			break
		}
	}
	if readyCondition == nil {
		t.Fatal("expected Ready condition to be set")
		return
	}
	// Transient errors should get ReasonFailed (not a specific reason for transient)
	if readyCondition.Reason != vaultv1alpha1.ReasonFailed {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonFailed, readyCondition.Reason)
	}
}

// Tests for setCondition
func TestSetCondition_NewCondition(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "test message")

	conds := adapter.GetConditions()
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}

	cond := conds[0]
	if cond.Type != vaultv1alpha1.ConditionTypeReady {
		t.Errorf("expected type %s, got %s", vaultv1alpha1.ConditionTypeReady, cond.Type)
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", cond.Status)
	}
	if cond.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonSucceeded, cond.Reason)
	}
	if cond.Message != "test message" {
		t.Errorf("expected message 'test message', got %s", cond.Message)
	}
}

func TestSetCondition_UpdateExisting(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Status.Conditions = []vaultv1alpha1.Condition{
		{
			Type:    vaultv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  vaultv1alpha1.ReasonFailed,
			Message: "old message",
		},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "new message")

	conds := adapter.GetConditions()
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conds))
	}

	cond := conds[0]
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", cond.Status)
	}
	if cond.Reason != vaultv1alpha1.ReasonSucceeded {
		t.Errorf("expected reason %s, got %s", vaultv1alpha1.ReasonSucceeded, cond.Reason)
	}
	if cond.Message != "new message" {
		t.Errorf("expected message 'new message', got %s", cond.Message)
	}
}

func TestSetCondition_UpdateSameStatus(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Status.Conditions = []vaultv1alpha1.Condition{
		{
			Type:               vaultv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             vaultv1alpha1.ReasonSucceeded,
			Message:            "old message",
			LastTransitionTime: metav1.Now(),
		},
	}
	adapter := domain.NewVaultRoleAdapter(role)

	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "new message")

	conds := adapter.GetConditions()
	cond := conds[0]
	// When status doesn't change, reason and message are updated
	if cond.Message != "new message" {
		t.Errorf("expected message 'new message', got %s", cond.Message)
	}
}

func TestSetCondition_MultipleConditions(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "ready")
	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeSynced, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "synced")

	conds := adapter.GetConditions()
	if len(conds) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conds))
	}
}

func TestSetCondition_ObservedGeneration(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Generation = 5
	adapter := domain.NewVaultRoleAdapter(role)

	setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		vaultv1alpha1.ReasonSucceeded, "test")

	conds := adapter.GetConditions()
	if conds[0].ObservedGeneration != 5 {
		t.Errorf("expected ObservedGeneration 5, got %d", conds[0].ObservedGeneration)
	}
}

// Tests for getVaultClient (now delegates to vaultclient.Resolve)
func TestGetVaultClient_ConnectionNotFound(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role) // No connection
	clientCache := vault.NewClientCache()
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := vaultclient.Resolve(
		ctx, fakeClient, clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier(),
	)
	if err == nil {
		t.Fatal("expected error for missing connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ConnectionNotActive(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()
	conn.Status.Phase = vaultv1alpha1.PhasePending // Not active

	fakeClient := newFakeClient(role, conn)
	clientCache := vault.NewClientCache()
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := vaultclient.Resolve(
		ctx, fakeClient, clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier(),
	)
	if err == nil {
		t.Fatal("expected error for non-active connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ClientNotInCache(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	clientCache := vault.NewClientCache() // Empty cache
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := vaultclient.Resolve(
		ctx, fakeClient, clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier(),
	)
	if err == nil {
		t.Fatal("expected error for client not in cache")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

func TestGetVaultClient_ConnectionPhaseError(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	conn := newActiveVaultConnection()
	conn.Status.Phase = vaultv1alpha1.PhaseError

	fakeClient := newFakeClient(role, conn)
	clientCache := vault.NewClientCache()
	adapter := domain.NewVaultRoleAdapter(role)

	_, err := vaultclient.Resolve(
		ctx, fakeClient, clientCache,
		adapter.GetConnectionRef(), adapter.GetK8sResourceIdentifier(),
	)
	if err == nil {
		t.Fatal("expected error for error phase connection")
	}
	if !infraerrors.IsDependencyError(err) {
		t.Errorf("expected DependencyError, got %T", err)
	}
}

// Tests for CleanupRole
func TestCleanupRole_PublishesRoleDeletedEvent(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	eventCh := make(chan events.RoleDeleted, 1)
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		eventCh <- e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	// Wait for async event delivery
	select {
	case receivedEvent := <-eventCh:
		if receivedEvent.RoleName != testVaultRoleName {
			t.Errorf("expected role name 'testVaultRoleName', got %q", receivedEvent.RoleName)
		}
		if receivedEvent.Resource.Name != "test-role" {
			t.Errorf("expected resource name 'test-role', got %q", receivedEvent.Resource.Name)
		}
		if receivedEvent.Resource.Namespace != "default" {
			t.Errorf("expected namespace 'default', got %q", receivedEvent.Resource.Namespace)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RoleDeleted event")
	}
}

func TestCleanupRole_NoEventBus(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, nil, logr.Discard()) // nil event bus
	adapter := domain.NewVaultRoleAdapter(role)

	// Should not panic with nil event bus
	err := handler.CleanupRole(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanupRole_SetsPhaseToDeleting(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	if adapter.GetPhase() != vaultv1alpha1.PhaseDeleting {
		t.Errorf("expected phase Deleting, got %s", adapter.GetPhase())
	}
}

func TestCleanupRole_DefaultAuthPath(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	eventCh := make(chan events.RoleDeleted, 1)
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		eventCh <- e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	select {
	case receivedEvent := <-eventCh:
		if receivedEvent.AuthPath != vault.DefaultKubernetesAuthPath {
			t.Errorf("expected auth path %q, got %q", vault.DefaultKubernetesAuthPath, receivedEvent.AuthPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RoleDeleted event")
	}
}

func TestCleanupRole_CustomAuthPath(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	// The custom mount is pinned by the binding recorded at last sync —
	// cleanup is binding-first, so it wins over the connection's mount.
	role.Status.Binding = vaultv1alpha1.VaultResourceBinding{AuthMount: "custom-k8s"}
	role.Status.VaultRoleName = testVaultRoleName
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(role, conn)
	eventBus := events.NewEventBus(logr.Discard())

	eventCh := make(chan events.RoleDeleted, 1)
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		eventCh <- e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	_ = handler.CleanupRole(ctx, adapter)

	select {
	case receivedEvent := <-eventCh:
		if receivedEvent.AuthPath != "auth/custom-k8s" {
			t.Errorf("expected auth path 'auth/custom-k8s', got %q", receivedEvent.AuthPath)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RoleDeleted event")
	}
}

func TestCleanupRole_ClusterRole(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	clusterRole.Status.VaultRoleName = "test-cluster-role"
	conn := newActiveVaultConnection()

	fakeClient := newFakeClient(clusterRole, conn)
	eventBus := events.NewEventBus(logr.Discard())

	eventCh := make(chan events.RoleDeleted, 1)
	events.Subscribe[events.RoleDeleted](eventBus, func(_ context.Context, e events.RoleDeleted) error {
		eventCh <- e
		return nil
	})

	cache := vault.NewClientCache()
	handler := NewHandler(fakeClient, cache, eventBus, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	_ = handler.CleanupRole(ctx, adapter)

	select {
	case receivedEvent := <-eventCh:
		if receivedEvent.Resource.ClusterScoped != true {
			t.Error("expected ClusterScoped to be true for VaultClusterRole")
		}
		if receivedEvent.Resource.Namespace != "" {
			t.Errorf("expected empty namespace for cluster role, got %q", receivedEvent.Resource.Namespace)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RoleDeleted event")
	}
}

// Test service account binding extraction
func TestGetServiceAccountBindings_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	bindings := adapter.GetServiceAccountBindings()

	expected := []string{"default/default", "default/app"}
	if len(bindings) != len(expected) {
		t.Fatalf("expected %d bindings, got %d", len(expected), len(bindings))
	}
	for i, exp := range expected {
		if bindings[i] != exp {
			t.Errorf("binding[%d]: expected %q, got %q", i, exp, bindings[i])
		}
	}
}

func TestGetServiceAccountBindings_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	bindings := adapter.GetServiceAccountBindings()

	expected := []string{"ns1/default", "ns2/app"}
	if len(bindings) != len(expected) {
		t.Fatalf("expected %d bindings, got %d", len(expected), len(bindings))
	}
	for i, exp := range expected {
		if bindings[i] != exp {
			t.Errorf("binding[%d]: expected %q, got %q", i, exp, bindings[i])
		}
	}
}

// Test K8s resource identifier
func TestK8sResourceIdentifier_VaultRole(t *testing.T) {
	role := newVaultRole("my-role", "production")
	adapter := domain.NewVaultRoleAdapter(role)

	identifier := adapter.GetK8sResourceIdentifier()
	if identifier != "production/my-role" {
		t.Errorf("expected 'production/my-role', got %q", identifier)
	}
}

func TestK8sResourceIdentifier_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("global-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	identifier := adapter.GetK8sResourceIdentifier()
	if identifier != "global-role" {
		t.Errorf("expected 'global-role', got %q", identifier)
	}
}

// Test IsNamespaced
func TestIsNamespaced_VaultRole(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	if !adapter.IsNamespaced() {
		t.Error("expected VaultRole to be namespaced")
	}
}

func TestIsNamespaced_VaultClusterRole(t *testing.T) {
	clusterRole := newVaultClusterRole("test-cluster-role")
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	if adapter.IsNamespaced() {
		t.Error("expected VaultClusterRole to NOT be namespaced")
	}
}

// Test conflict policy accessor
func TestGetConflictPolicy_Default(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = "" // Empty to test default behavior
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != "" {
		t.Errorf("expected empty conflict policy, got %q", policy)
	}
}

func TestGetConflictPolicy_Fail(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyFail
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != vaultv1alpha1.ConflictPolicyFail {
		t.Errorf("expected ConflictPolicyFail, got %q", policy)
	}
}

func TestGetConflictPolicy_Adopt(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetConflictPolicy()
	if policy != vaultv1alpha1.ConflictPolicyAdopt {
		t.Errorf("expected ConflictPolicyAdopt, got %q", policy)
	}
}

// Test deletion policy accessor
func TestGetDeletionPolicy_Default(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = "" // Empty
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != "" {
		t.Errorf("expected empty deletion policy, got %q", policy)
	}
}

func TestGetDeletionPolicy_Delete(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyDelete
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != vaultv1alpha1.DeletionPolicyDelete {
		t.Errorf("expected DeletionPolicyDelete, got %q", policy)
	}
}

func TestGetDeletionPolicy_Retain(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	adapter := domain.NewVaultRoleAdapter(role)

	policy := adapter.GetDeletionPolicy()
	if policy != vaultv1alpha1.DeletionPolicyRetain {
		t.Errorf("expected DeletionPolicyRetain, got %q", policy)
	}
}

// Test TTL accessors
func TestGetTokenTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenTTL = "2h"
	adapter := domain.NewVaultRoleAdapter(role)

	ttl := adapter.GetTokenTTL()
	if ttl != "2h" {
		t.Errorf("expected '2h', got %q", ttl)
	}
}

func TestGetTokenMaxTTL(t *testing.T) {
	role := newVaultRole("test-role", "default")
	role.Spec.TokenMaxTTL = "48h"
	adapter := domain.NewVaultRoleAdapter(role)

	maxTTL := adapter.GetTokenMaxTTL()
	if maxTTL != "48h" {
		t.Errorf("expected '48h', got %q", maxTTL)
	}
}

// Test status mutators
func TestSetPhase(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	if adapter.GetPhase() != vaultv1alpha1.PhaseActive {
		t.Errorf("expected PhaseActive, got %s", adapter.GetPhase())
	}

	adapter.SetPhase(vaultv1alpha1.PhaseError)
	if adapter.GetPhase() != vaultv1alpha1.PhaseError {
		t.Errorf("expected PhaseError, got %s", adapter.GetPhase())
	}
}

func TestSetVaultRoleName(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetVaultRoleName(testVaultRoleName)
	if role.Status.VaultRoleName != testVaultRoleName {
		t.Errorf("expected 'testVaultRoleName', got %q", role.Status.VaultRoleName)
	}
}

func TestSetManaged(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetManaged(true)
	if !role.Status.Managed {
		t.Error("expected Managed to be true")
	}

	adapter.SetManaged(false)
	if role.Status.Managed {
		t.Error("expected Managed to be false")
	}
}

func TestSetBoundServiceAccounts(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	accounts := []string{"default/sa1", "default/sa2"}
	adapter.SetBoundServiceAccounts(accounts)

	if len(role.Status.BoundServiceAccounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(role.Status.BoundServiceAccounts))
	}
	if role.Status.BoundServiceAccounts[0] != "default/sa1" {
		t.Errorf("expected 'default/sa1', got %q", role.Status.BoundServiceAccounts[0])
	}
}

func TestSetResolvedPolicies(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	policies := []string{"policy1", "policy2"}
	adapter.SetResolvedPolicies(policies)

	if len(role.Status.ResolvedPolicies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(role.Status.ResolvedPolicies))
	}
	if role.Status.ResolvedPolicies[0] != "policy1" {
		t.Errorf("expected 'policy1', got %q", role.Status.ResolvedPolicies[0])
	}
}

func TestSetLastSyncedAt(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	now := metav1.Now()
	adapter.SetLastSyncedAt(&now)

	if role.Status.LastSyncedAt == nil {
		t.Fatal("expected LastSyncedAt to be set")
	}
	if !role.Status.LastSyncedAt.Equal(&now) {
		t.Error("expected LastSyncedAt to match")
	}
}

func TestSetRetryCount(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetRetryCount(5)
	if adapter.GetRetryCount() != 5 {
		t.Errorf("expected retry count 5, got %d", adapter.GetRetryCount())
	}
}

func TestSetMessage(t *testing.T) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetMessage("test message")
	if role.Status.Message != "test message" {
		t.Errorf("expected 'test message', got %q", role.Status.Message)
	}
}

// Benchmark tests
func BenchmarkResolvePolicyNames(b *testing.B) {
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "policy1"},
		{Kind: "VaultPolicy", Name: "policy2"},
		{Kind: "VaultClusterPolicy", Name: "cluster-policy"},
	}
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.resolvePolicyNames(ctx, adapter)
	}
}

func BenchmarkBuildRoleData(b *testing.B) {
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)
	policyNames := []string{"policy1", "policy2"}
	bindings := []string{"default/sa1", "default/sa2", "other/sa3"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.buildRoleData(adapter, vault.AuthBackendKubernetes, policyNames, bindings, nil)
	}
}

func BenchmarkSetCondition(b *testing.B) {
	role := newVaultRole("test-role", "default")
	adapter := domain.NewVaultRoleAdapter(role)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		setConditionHelper(adapter, vaultv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
			vaultv1alpha1.ReasonSucceeded, "test message")
	}
}

// Tests for status updates (previously updateStatusWithRetry, now direct status updates)
func TestStatusUpdate_Success_VaultRole(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	// Set status fields directly on the adapter
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetMessage("sync completed")

	// Update via the K8s client
	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the status was updated in the API server
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.Message != "sync completed" {
		t.Errorf("expected message 'sync completed', got %q", updatedRole.Status.Message)
	}
}

func TestStatusUpdate_Success_VaultClusterRole(t *testing.T) {
	ctx := context.Background()
	clusterRole := newVaultClusterRole("test-cluster-role")
	fakeClient := newFakeClient(clusterRole)
	adapter := domain.NewVaultClusterRoleAdapter(clusterRole)

	// Set status fields directly on the adapter
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetVaultRoleName("test-cluster-role")

	// Update via the K8s client
	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the status was updated in the API server
	var updatedRole vaultv1alpha1.VaultClusterRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(clusterRole), &updatedRole); err != nil {
		t.Fatalf("failed to get updated cluster role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.VaultRoleName != "test-cluster-role" {
		t.Errorf("expected vault role name 'test-cluster-role', got %q", updatedRole.Status.VaultRoleName)
	}
}

func TestStatusUpdate_UpdatesLatestVersion(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	// First update
	adapter.SetPhase(vaultv1alpha1.PhaseSyncing)
	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("first update failed: %v", err)
	}

	// Second update
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetMessage("second update")
	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("second update failed: %v", err)
	}

	// Verify final status
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.Message != "second update" {
		t.Errorf("expected message 'second update', got %q", updatedRole.Status.Message)
	}
}

func TestStatusUpdate_PreservesExistingStatus(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Status.VaultRoleName = "existing-vault-role"
	role.Status.Managed = true
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	// Update only the phase, keeping other fields
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify existing status is preserved
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.VaultRoleName != "existing-vault-role" {
		t.Errorf("expected vault role name 'existing-vault-role', got %q", updatedRole.Status.VaultRoleName)
	}
	if !updatedRole.Status.Managed {
		t.Error("expected Managed to remain true")
	}
}

func TestStatusUpdate_NotFound(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("non-existent-role", "default")
	fakeClient := newFakeClient() // Empty client, role doesn't exist
	adapter := domain.NewVaultRoleAdapter(role)

	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	err := fakeClient.Status().Update(ctx, adapter.GetObject())

	if err == nil {
		t.Fatal("expected error for non-existent role")
	}
}

func TestStatusUpdate_MultipleFields(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	fakeClient := newFakeClient(role)
	adapter := domain.NewVaultRoleAdapter(role)

	now := metav1.Now()
	adapter.SetPhase(vaultv1alpha1.PhaseActive)
	adapter.SetVaultRoleName("default-test-role")
	adapter.SetManaged(true)
	adapter.SetResolvedPolicies([]string{"policy1", "policy2"})
	adapter.SetBoundServiceAccounts([]string{"default/sa1", "default/sa2"})
	adapter.SetLastSyncedAt(&now)
	adapter.SetMessage("all fields updated")

	if err := fakeClient.Status().Update(ctx, adapter.GetObject()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields
	var updatedRole vaultv1alpha1.VaultRole
	if err := fakeClient.Get(ctx, client.ObjectKeyFromObject(role), &updatedRole); err != nil {
		t.Fatalf("failed to get updated role: %v", err)
	}

	if updatedRole.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", updatedRole.Status.Phase)
	}
	if updatedRole.Status.VaultRoleName != "default-test-role" {
		t.Errorf("expected vault role name 'default-test-role', got %q", updatedRole.Status.VaultRoleName)
	}
	if !updatedRole.Status.Managed {
		t.Error("expected Managed to be true")
	}
	if len(updatedRole.Status.ResolvedPolicies) != 2 {
		t.Errorf("expected 2 resolved policies, got %d", len(updatedRole.Status.ResolvedPolicies))
	}
	if len(updatedRole.Status.BoundServiceAccounts) != 2 {
		t.Errorf("expected 2 bound service accounts, got %d", len(updatedRole.Status.BoundServiceAccounts))
	}
	if updatedRole.Status.LastSyncedAt == nil {
		t.Error("expected LastSyncedAt to be set")
	}
	if updatedRole.Status.Message != "all fields updated" {
		t.Errorf("expected message 'all fields updated', got %q", updatedRole.Status.Message)
	}
}

// --- Cross-namespace binding validation tests (Gap 5) ---

func TestResolvePolicyNames_DuplicatePolicyRefs(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets"},
		{Kind: "VaultPolicy", Name: "read-secrets"}, // duplicate
		{Kind: "VaultClusterPolicy", Name: "global"},
	}

	fakeClient := newFakeClient(role,
		syncedPolicy("read-secrets", "default", "vao._.default.read-secrets"),
		syncedClusterPolicy("global", "vao._._.global"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Current implementation doesn't deduplicate — document this behavior.
	// Both read-secrets references resolve to the same recorded name.
	if len(resolution) != 3 {
		t.Errorf("expected 3 entries (duplicates not deduped), got %d: %v", len(resolution), resolution)
	}
}

func TestResolvePolicyNames_EmptyPolicyName(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: ""},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// An empty ref name can never match a CR — it stays unresolved instead
	// of erroring, documenting the behavior (the webhook rejects it anyway).
	if len(resolution) != 1 || resolution[0].Resolved {
		t.Errorf("expected 1 unresolved entry, got %+v", resolution)
	}
}

func TestResolvePolicyNames_ClusterRoleWithNamespacedPolicyExplicitNamespace(t *testing.T) {
	ctx := context.Background()
	role := newVaultClusterRole("cluster-role")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "production"},
	}

	fakeClient := newFakeClient(role,
		syncedPolicy("read-secrets", "production", "vao._.production.read-secrets"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultClusterRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resolution) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(resolution))
	}
	if !resolution[0].Resolved || resolution[0].VaultName != "vao._.production.read-secrets" {
		t.Errorf("expected resolved 'vao._.production.read-secrets', got %+v", resolution[0])
	}
}

func TestResolvePolicyNames_NamespacedRoleCrossNamespace(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "read-secrets", Namespace: "other-ns"},
	}

	fakeClient := newFakeClient(role,
		syncedPolicy("read-secrets", "other-ns", "vao._.other-ns.read-secrets"),
	)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Namespaced role can reference policies in other namespaces
	if len(resolution) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(resolution))
	}
	if !resolution[0].Resolved || resolution[0].VaultName != "vao._.other-ns.read-secrets" {
		t.Errorf("expected resolved 'vao._.other-ns.read-secrets', got %+v", resolution[0])
	}
}

func TestNormalizeTTLToSeconds(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{"30s → 30", "30s", 30},
		{"5m → 300", "5m", 300},
		{"1h → 3600", "1h", 3600},
		{"24h → 86400", "24h", 86400},
		{"1h30m → 5400", "1h30m", 5400},
		{"nil unchanged", nil, nil},
		{"int unchanged", 3600, 3600},
		{"non-duration string unchanged", "not-a-duration", "not-a-duration"},
		{"empty string unchanged", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeTTLToSeconds(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTTLToSeconds(%v) = %v (%T), want %v (%T)",
					tt.input, result, result, tt.expected, tt.expected)
			}
		})
	}
}

// TestResolvePolicyNames_MissingPolicyCR pins the pending-binding case: a
// reference to a policy CR that doesn't exist yields an UNRESOLVED entry
// (not an error) — the watch machinery requeues the role when it appears.
func TestResolvePolicyNames_MissingPolicyCR(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "not-created-yet"},
	}

	fakeClient := newFakeClient(role)
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolution) != 1 || resolution[0].Resolved || resolution[0].VaultName != "" {
		t.Errorf("expected 1 unresolved entry with empty VaultName, got %+v", resolution)
	}
}

// TestResolvePolicyNames_PolicyNotYetSynced pins the second pending case:
// the policy CR exists but hasn't synced (empty status.vaultName) — the
// binding stays unresolved until the policy's recorded name lands.
func TestResolvePolicyNames_PolicyNotYetSynced(t *testing.T) {
	ctx := context.Background()
	role := newVaultRole("test-role", "default")
	role.Spec.Policies = []vaultv1alpha1.PolicyReference{
		{Kind: "VaultPolicy", Name: "pending-policy"},
	}

	fakeClient := newFakeClient(role, syncedPolicy("pending-policy", "default", ""))
	handler := NewHandler(fakeClient, vault.NewClientCache(), nil, logr.Discard())
	adapter := domain.NewVaultRoleAdapter(role)

	resolution, err := handler.resolvePolicyNames(ctx, adapter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolution) != 1 || resolution[0].Resolved {
		t.Errorf("expected 1 unresolved entry (policy not yet synced), got %+v", resolution)
	}
}
