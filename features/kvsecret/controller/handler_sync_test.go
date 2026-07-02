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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

const (
	kvTestConn = "vault"
	kvTestNS   = "team-a"
	kvTestName = "myapp-config"
	kvTestPath = "secret/data/apps/myapp/config"
)

// --- Sync tests --------------------------------------------------------------

func TestSyncKVSecret_SeedWhenAbsent(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	kvs := newKVSecret(nil)

	if err := h.Sync(context.Background(), kvs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !kvs.Status.Seeded || kvs.Status.SeededVersion != 1 {
		t.Errorf("expected seeded=true version=1, got seeded=%v version=%d", kvs.Status.Seeded, kvs.Status.SeededVersion)
	}
	if kvs.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", kvs.Status.Phase)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("expected the path to be created in Vault")
	}
	if !mock.ownedByOperator("apps/myapp/config") {
		t.Errorf("expected operator ownership stamp, got %v", mock.customMeta("apps/myapp/config"))
	}
}

func TestSyncKVSecret_SeedWithPlaceholderKeys(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	kvs := newKVSecret(map[string]string{"username": "", "password": ""})

	if err := h.Sync(context.Background(), kvs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !kvs.Status.Seeded {
		t.Error("expected seeded=true")
	}
	if mock.dataWrites() != 1 {
		t.Errorf("expected exactly 1 data write, got %d", mock.dataWrites())
	}
}

func TestSyncKVSecret_SkipWhenPresent(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	// Pre-existing secret written by someone else (version 2, foreign owner).
	mock.seed("apps/myapp/config", 2, map[string]interface{}{vault.KVManagedByKey: "external-secrets"})
	kvs := newKVSecret(map[string]string{"username": ""})

	if err := h.Sync(context.Background(), kvs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if kvs.Status.Seeded {
		t.Error("must NOT report seeded for a pre-existing path")
	}
	if mock.dataWrites() != 0 {
		t.Errorf("must NOT overwrite an existing path, got %d data writes", mock.dataWrites())
	}
	if mock.version("apps/myapp/config") != 2 {
		t.Errorf("existing version must be untouched, got %d", mock.version("apps/myapp/config"))
	}
	if kvs.Status.Phase != vaultv1alpha1.PhaseActive {
		t.Errorf("expected phase Active, got %s", kvs.Status.Phase)
	}
}

func TestSyncKVSecret_DryRun_NoWrite(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	kvs := newKVSecret(nil)
	kvs.Annotations = map[string]string{vaultv1alpha1.AnnotationDryRun: vaultv1alpha1.AnnotationValueTrue}

	if err := h.Sync(context.Background(), kvs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if mock.dataWrites() != 0 {
		t.Errorf("dry-run must not write, got %d data writes", mock.dataWrites())
	}
	if mock.exists("apps/myapp/config") {
		t.Error("dry-run must not create the path")
	}
	if c := findCond(kvs, vaultv1alpha1.ConditionTypeDryRun); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("expected DryRun condition True, got %+v", c)
	}
}

func TestSyncKVSecret_ConnectionNotReady(t *testing.T) {
	conn := activeConn(kvTestConn)
	conn.Status.Phase = vaultv1alpha1.PhasePending // not Active
	h, _ := setupKVTest(t, conn)
	kvs := newKVSecret(nil)

	if err := h.Sync(context.Background(), kvs); err == nil {
		t.Fatal("expected error when connection is not Active")
	}
}

func TestSyncKVSecret_InvalidPath(t *testing.T) {
	h, _ := setupKVTest(t, activeConn(kvTestConn))
	kvs := newKVSecret(nil)
	kvs.Spec.Path = "secret/not-a-data-path" // no /data/ segment

	if err := h.Sync(context.Background(), kvs); err == nil {
		t.Fatal("expected validation error for a non KV-v2-data path")
	}
}

// --- Cleanup tests -----------------------------------------------------------

func TestCleanupKVSecret_DeleteWhenUntouched(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	mock.seed("apps/myapp/config", 1, map[string]interface{}{
		vault.KVManagedByKey:   vault.KVManagedByValue,
		vault.KVK8sResourceKey: kvTestNS + "/" + kvTestName,
	})
	kvs := newKVSecret(nil)
	kvs.Status.Seeded = true
	kvs.Status.SeededVersion = 1

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if mock.exists("apps/myapp/config") {
		t.Error("expected untouched seeded secret to be deleted")
	}
}

func TestCleanupKVSecret_RetainWhenModified(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	// Ours, but written to since seeding (version advanced 1 -> 4).
	mock.seed("apps/myapp/config", 4, map[string]interface{}{
		vault.KVManagedByKey:   vault.KVManagedByValue,
		vault.KVK8sResourceKey: kvTestNS + "/" + kvTestName,
	})
	kvs := newKVSecret(nil)
	kvs.Status.Seeded = true
	kvs.Status.SeededVersion = 1

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("expected a modified secret to be retained, not deleted")
	}
}

func TestCleanupKVSecret_RetainWhenNotOurs(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	mock.seed("apps/myapp/config", 1, map[string]interface{}{vault.KVManagedByKey: "external-secrets"})
	kvs := newKVSecret(nil)
	kvs.Status.Seeded = true
	kvs.Status.SeededVersion = 1

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("expected a foreign-owned secret to be retained")
	}
}

// TestCleanupKVSecret_RetainWhenForeignOwner pins the identity-aware check
// (ADR 0008): the operator sentinel alone is not ownership — a colliding path
// seeded by another CR (or another cluster's operator) is never deleted.
func TestCleanupKVSecret_RetainWhenForeignOwner(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	mock.seed("apps/myapp/config", 1, map[string]interface{}{
		vault.KVManagedByKey:        vault.KVManagedByValue,
		vault.KVK8sResourceKey:      kvTestNS + "/" + kvTestName,
		vault.OwnershipAuthMountKey: "k8s-other-cluster", // foreign operator identity
	})
	kvs := newKVSecret(nil)
	kvs.Status.Seeded = true
	kvs.Status.SeededVersion = 1

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("expected a foreign-operator-owned secret to be retained")
	}
}

func TestCleanupKVSecret_RetainPolicy(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	mock.seed("apps/myapp/config", 1, map[string]interface{}{vault.KVManagedByKey: vault.KVManagedByValue})
	kvs := newKVSecret(nil)
	kvs.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
	kvs.Status.Seeded = true
	kvs.Status.SeededVersion = 1

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("DeletionPolicy=Retain must never delete")
	}
}

func TestCleanupKVSecret_NotSeeded_NoOp(t *testing.T) {
	h, mock := setupKVTest(t, activeConn(kvTestConn))
	mock.seed("apps/myapp/config", 1, map[string]interface{}{vault.KVManagedByKey: vault.KVManagedByValue})
	kvs := newKVSecret(nil)
	kvs.Status.Seeded = false // operator never created it

	if err := h.Cleanup(context.Background(), kvs); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !mock.exists("apps/myapp/config") {
		t.Error("a secret we never seeded must not be deleted")
	}
}

// --- helpers -----------------------------------------------------------------

func newKVSecret(data map[string]string) *vaultv1alpha1.VaultKVSecret {
	return &vaultv1alpha1.VaultKVSecret{
		ObjectMeta: metav1.ObjectMeta{Name: kvTestName, Namespace: kvTestNS, Generation: 1},
		Spec: vaultv1alpha1.VaultKVSecretSpec{
			ConnectionRef:  kvTestConn,
			Path:           kvTestPath,
			Data:           data,
			DeletionPolicy: vaultv1alpha1.DeletionPolicyDelete,
		},
	}
}

func activeConn(name string) *vaultv1alpha1.VaultConnection { //nolint:unparam
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: vaultv1alpha1.VaultConnectionStatus{
			Phase:   vaultv1alpha1.PhaseActive,
			Healthy: true,
		},
	}
}

func findCond(kvs *vaultv1alpha1.VaultKVSecret, t string) *vaultv1alpha1.Condition {
	for i := range kvs.Status.Conditions {
		if kvs.Status.Conditions[i].Type == t {
			return &kvs.Status.Conditions[i]
		}
	}
	return nil
}

func setupKVTest(t *testing.T, conn *vaultv1alpha1.VaultConnection) (*Handler, *kvMock) {
	t.Helper()
	mock := newKVMock(t)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(conn).
		WithStatusSubresource(&vaultv1alpha1.VaultKVSecret{}).
		Build()

	cache := vault.NewClientCache()
	vc, err := vault.NewClient(vault.ClientConfig{Address: mock.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	vc.SetAuthenticated(true)
	vc.SetToken("s.test-token")
	cache.Set(conn.Name, vc)

	return NewHandler(k8s, cache, logr.Discard(), nil), mock
}

// --- KV v2 mock --------------------------------------------------------------

const kvKindMetadata = "metadata"

type kvMock struct {
	mu      sync.Mutex
	secrets map[string]*kvMockEntry
	server  *httptest.Server
	puts    int
}

type kvMockEntry struct {
	version int
	cm      map[string]interface{}
}

func newKVMock(t *testing.T) *kvMock {
	t.Helper()
	m := &kvMock{secrets: map[string]*kvMockEntry{}}
	const prefix = "/v1/secret/"
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		kind, key, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()

		switch {
		case kind == kvKindMetadata && r.Method == http.MethodGet:
			e := m.secrets[key]
			if e == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]interface{}{"data": map[string]interface{}{
				"current_version": e.version,
				"custom_metadata": e.cm,
				"versions":        map[string]interface{}{},
			}})
		case kind == kvKindMetadata && r.Method == http.MethodPatch:
			e := m.secrets[key]
			if e == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			var body struct {
				CustomMetadata map[string]interface{} `json:"custom_metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if e.cm == nil {
				e.cm = map[string]interface{}{}
			}
			for k, v := range body.CustomMetadata {
				e.cm[k] = v
			}
			w.WriteHeader(http.StatusNoContent)
		case kind == kvKindMetadata && r.Method == http.MethodDelete:
			delete(m.secrets, key)
			w.WriteHeader(http.StatusNoContent)
		case kind == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			var body struct {
				Options struct {
					Cas *int `json:"cas"`
				} `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			e := m.secrets[key]
			if body.Options.Cas != nil && *body.Options.Cas == 0 && e != nil {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]interface{}{
					"errors": []string{"check-and-set parameter did not match the current version"},
				})
				return
			}
			if e == nil {
				e = &kvMockEntry{}
				m.secrets[key] = e
			}
			e.version++
			m.puts++
			writeJSON(w, map[string]interface{}{"data": map[string]interface{}{
				"version": e.version, "created_time": "2026-01-01T00:00:00Z", "deletion_time": "", "destroyed": false,
			}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *kvMock) seed(key string, version int, cm map[string]interface{}) { //nolint:unparam
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[key] = &kvMockEntry{version: version, cm: cm}
}

func (m *kvMock) exists(key string) bool { //nolint:unparam
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secrets[key] != nil
}

func (m *kvMock) version(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.secrets[key]; e != nil {
		return e.version
	}
	return 0
}

func (m *kvMock) customMeta(key string) map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.secrets[key]; e != nil {
		return e.cm
	}
	return nil
}

func (m *kvMock) ownedByOperator(key string) bool {
	cm := m.customMeta(key)
	v, _ := cm[vault.KVManagedByKey].(string)
	return v == vault.KVManagedByValue
}

func (m *kvMock) dataWrites() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
