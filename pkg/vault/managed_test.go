package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/panteparak/vault-access-operator/shared/naming"
)

// markerMock is a path-aware in-memory KV v2 *metadata* store. Markers live
// exclusively in custom_metadata (never a data version), so this mock only
// models the metadata tree — a write to any `secret/data/...` path is recorded
// separately so tests can assert NO data write ever happens.
//
// Endpoints (matching the Vault Go SDK KVv2 metadata calls):
//   - POST   /v1/secret/metadata/<path>        PutMetadata (body: custom_metadata)
//   - GET    /v1/secret/metadata/<path>        GetMetadata → data.custom_metadata
//   - DELETE /v1/secret/metadata/<path>        DeleteMetadata
//   - GET    /v1/secret/metadata/<path>?list=true  LIST → data.keys (child segments)
type markerMock struct {
	mu         sync.Mutex
	meta       map[string]map[string]interface{} // rel path -> custom_metadata
	dataWrites int                               // any POST/PUT to secret/data/*
	failList   bool                              // when true, LIST returns 500
	server     *httptest.Server
}

const markerMetaPrefix = "/v1/secret/metadata/"

func newMarkerMock(t *testing.T) *markerMock {
	t.Helper()
	m := &markerMock{meta: map[string]map[string]interface{}{}}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *markerMock) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{Address: m.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (m *markerMock) handle(w http.ResponseWriter, r *http.Request) {
	// Any write to the data endpoint is a violation of the "metadata-only"
	// contract; record it so tests can assert it never happens.
	if strings.HasPrefix(r.URL.Path, "/v1/secret/data/") {
		m.mu.Lock()
		m.dataWrites++
		m.mu.Unlock()
		writeJSONResp(w, map[string]interface{}{"data": map[string]interface{}{"version": 1}})
		return
	}
	if !strings.HasPrefix(r.URL.Path, markerMetaPrefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, markerMetaPrefix)

	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Query().Get("list") == "true":
		if m.failList {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSONResp(w, map[string]interface{}{"errors": []string{"permission denied"}})
			return
		}
		keys := m.childKeys(rel)
		if keys == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSONResp(w, map[string]interface{}{"data": map[string]interface{}{"keys": keys}})
	case r.Method == http.MethodGet:
		cm, ok := m.meta[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSONResp(w, map[string]interface{}{"data": map[string]interface{}{
			"custom_metadata": cm,
			"current_version": 0,
			"versions":        map[string]interface{}{},
		}})
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		var body struct {
			CustomMetadata map[string]interface{} `json:"custom_metadata"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.meta[rel] = body.CustomMetadata
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		delete(m.meta, rel)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

// childKeys returns the immediate child segments under a LIST path, mirroring
// Vault: intermediate segments get a trailing "/", leaf keys do not. Returns nil
// when the prefix has no descendants (→ 404, matching Vault's empty LIST).
func (m *markerMock) childKeys(prefix string) []interface{} {
	prefix = strings.TrimSuffix(prefix, "/")
	seen := map[string]bool{}
	for full := range m.meta {
		if full == prefix || !strings.HasPrefix(full, prefix+"/") {
			continue
		}
		rest := strings.TrimPrefix(full, prefix+"/")
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			seen[rest[:i]+"/"] = true // intermediate node
		} else {
			seen[rest] = true // leaf marker
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	keys := make([]interface{}, len(out))
	for i, k := range out {
		keys[i] = k
	}
	return keys
}

func (m *markerMock) get(rel string) map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.meta[rel]
}

func (m *markerMock) seed(rel string, cm map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.meta[rel] = cm
}

func (m *markerMock) dataWriteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dataWrites
}

func ownerCM(k8sResource, managedAt, lastUpdated string) map[string]interface{} {
	return map[string]interface{}{
		KVManagedByKey:       KVManagedByValue,
		KVK8sResourceKey:     k8sResource,
		markerManagedAtKey:   managedAt,
		markerLastUpdatedKey: lastUpdated,
	}
}

// --- MarkManaged -------------------------------------------------------------

// TestMarkManaged_WritesCustomMetadataOnly verifies a policy marker lands at the
// correct hierarchical metadata path as custom_metadata, and that NO secret data
// version is ever written (markers are metadata-only).
func TestMarkManaged_WritesCustomMetadataOnly(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	id := MarkerID{Kind: MarkerPolicy, Namespace: "team-a", Name: "reader"}
	if err := c.MarkManaged(context.Background(), id, "team-a/reader"); err != nil {
		t.Fatalf("MarkManaged: %v", err)
	}

	want := "vault-access-operator/managed/policies/team-a/reader"
	cm := m.get(want)
	if cm == nil {
		t.Fatalf("expected marker at %q; store keys: %v", want, keysOf(m))
	}
	if cm[KVManagedByKey] != KVManagedByValue {
		t.Errorf("managed-by = %v, want %q", cm[KVManagedByKey], KVManagedByValue)
	}
	if cm[KVK8sResourceKey] != "team-a/reader" {
		t.Errorf("k8s-resource = %v, want team-a/reader", cm[KVK8sResourceKey])
	}
	if cm[markerManagedAtKey] == "" || cm[markerLastUpdatedKey] == "" {
		t.Errorf("managed-at/last-updated must be set, got %v / %v",
			cm[markerManagedAtKey], cm[markerLastUpdatedKey])
	}
	if n := m.dataWriteCount(); n != 0 {
		t.Errorf("markers must never write secret data; got %d data writes", n)
	}
}

// TestMarkManaged_RolePathMountQualified verifies the role marker path includes
// the auth mount segment.
func TestMarkManaged_RolePathMountQualified(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	id := MarkerID{Kind: MarkerRole, Mount: "kubernetes", Namespace: "team-a", Name: "deployer"}
	if err := c.MarkManaged(context.Background(), id, "team-a/deployer"); err != nil {
		t.Fatalf("MarkManaged: %v", err)
	}
	want := "vault-access-operator/managed/roles/kubernetes/team-a/deployer"
	if m.get(want) == nil {
		t.Fatalf("expected role marker at %q; store keys: %v", want, keysOf(m))
	}
}

// TestMarkManaged_ClusterScopedSentinel verifies a cluster-scoped MarkerID
// (Namespace=="") uses the literal `_cluster` path segment.
func TestMarkManaged_ClusterScopedSentinel(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	id := MarkerID{Kind: MarkerPolicy, Name: "global-reader"} // Namespace empty
	if err := c.MarkManaged(context.Background(), id, "global-reader"); err != nil {
		t.Fatalf("MarkManaged: %v", err)
	}
	want := "vault-access-operator/managed/policies/_cluster/global-reader"
	if m.get(want) == nil {
		t.Fatalf("expected cluster-scoped marker at %q; store keys: %v", want, keysOf(m))
	}
}

// TestMarkManaged_ClusterPrefixOnlyWhenSet verifies the {cluster} path segment
// is present iff naming.SetCluster was configured.
func TestMarkManaged_ClusterPrefixOnlyWhenSet(t *testing.T) {
	naming.SetCluster("prod")
	t.Cleanup(func() { naming.SetCluster("") })

	m := newMarkerMock(t)
	c := m.client(t)

	id := MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "p"}
	if err := c.MarkManaged(context.Background(), id, "ns/p"); err != nil {
		t.Fatalf("MarkManaged: %v", err)
	}
	want := "vault-access-operator/managed/prod/policies/ns/p"
	if m.get(want) == nil {
		t.Fatalf("expected cluster-prefixed marker at %q; store keys: %v", want, keysOf(m))
	}
}

// relPolicyNsP is the reused marker path (relative to the KV mount) for the
// policy ns/p fixture.
const relPolicyNsP = "vault-access-operator/managed/policies/ns/p"

// TestMarkManaged_PreservesManagedAt verifies re-marking keeps the original
// managed-at while bumping last-updated.
func TestMarkManaged_PreservesManagedAt(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	rel := relPolicyNsP
	firstManagedAt := "2024-01-01T00:00:00Z"
	m.seed(rel, ownerCM("ns/p", firstManagedAt, firstManagedAt))

	id := MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "p"}
	if err := c.MarkManaged(context.Background(), id, "ns/p"); err != nil {
		t.Fatalf("MarkManaged: %v", err)
	}

	cm := m.get(rel)
	if cm[markerManagedAtKey] != firstManagedAt {
		t.Errorf("managed-at should be preserved as %q, got %v", firstManagedAt, cm[markerManagedAtKey])
	}
	if cm[markerLastUpdatedKey] == firstManagedAt {
		t.Error("last-updated should have advanced, not stayed at original managed-at")
	}
}

// --- GetManagedBy ------------------------------------------------------------

func TestGetManagedBy_ReturnsOwner(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	rel := relPolicyNsP
	m.seed(rel, ownerCM("ns/p", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"))

	got, err := c.GetManagedBy(context.Background(), MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "p"})
	if err != nil {
		t.Fatalf("GetManagedBy: %v", err)
	}
	if got != "ns/p" {
		t.Errorf("GetManagedBy = %q, want ns/p", got)
	}
}

func TestGetManagedBy_AbsentReturnsEmpty(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	got, err := c.GetManagedBy(context.Background(), MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "missing"})
	if err != nil {
		t.Fatalf("GetManagedBy: %v", err)
	}
	if got != "" {
		t.Errorf("absent marker: GetManagedBy = %q, want empty", got)
	}
}

func TestGetManagedBy_ForeignReturnsEmpty(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	rel := relPolicyNsP
	m.seed(rel, map[string]interface{}{KVManagedByKey: "some-other-operator", KVK8sResourceKey: "ns/p"})

	got, err := c.GetManagedBy(context.Background(), MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "p"})
	if err != nil {
		t.Fatalf("GetManagedBy: %v", err)
	}
	if got != "" {
		t.Errorf("foreign-owned marker: GetManagedBy = %q, want empty (not ours)", got)
	}
}

// --- RemoveManaged -----------------------------------------------------------

func TestRemoveManaged_DeletesMarker(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	rel := "vault-access-operator/managed/roles/kubernetes/ns/r"
	m.seed(rel, ownerCM("ns/r", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"))

	id := MarkerID{Kind: MarkerRole, Mount: "kubernetes", Namespace: "ns", Name: "r"}
	if err := c.RemoveManaged(context.Background(), id); err != nil {
		t.Fatalf("RemoveManaged: %v", err)
	}
	if m.get(rel) != nil {
		t.Error("marker should be gone after RemoveManaged")
	}
}

func TestRemoveManaged_Idempotent(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	// Deleting an absent marker must be a no-op, not an error.
	id := MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "gone"}
	if err := c.RemoveManaged(context.Background(), id); err != nil {
		t.Errorf("RemoveManaged on absent marker should be nil, got %v", err)
	}
}

// --- ListManaged -------------------------------------------------------------

// TestListManaged_Policies verifies the recursive walk returns policy markers
// keyed by vault name with a populated ManagedResource.ID.
func TestListManaged_Policies(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	c.mustMark(t, MarkerID{Kind: MarkerPolicy, Namespace: "team-a", Name: "reader"}, "team-a/reader")
	c.mustMark(t, MarkerID{Kind: MarkerPolicy, Name: "global"}, "global") // cluster-scoped

	got, err := c.ListManaged(context.Background(), MarkerPolicy)
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 policy markers, got %d: %v", len(got), got)
	}
	// Namespaced: key = naming.Vault("team-a-reader"); cluster-scoped: key = naming.Vault("global").
	nsKey := naming.Vault("team-a-reader")
	if mr, ok := got[nsKey]; !ok {
		t.Errorf("missing namespaced key %q; got keys %v", nsKey, keysOfMap(got))
	} else {
		if mr.ID.Namespace != "team-a" || mr.ID.Name != "reader" || mr.ID.Kind != MarkerPolicy {
			t.Errorf("namespaced ID not populated: %+v", mr.ID)
		}
		if mr.K8sResource != "team-a/reader" {
			t.Errorf("K8sResource = %q, want team-a/reader", mr.K8sResource)
		}
	}
	clKey := naming.Vault("global")
	if mr, ok := got[clKey]; !ok {
		t.Errorf("missing cluster-scoped key %q; got keys %v", clKey, keysOfMap(got))
	} else if mr.ID.Namespace != "" {
		t.Errorf("cluster-scoped marker should have empty Namespace, got %q", mr.ID.Namespace)
	}
}

// TestListManaged_RolesMountQualified verifies role list keys are
// mount-qualified so same-name roles on different auth mounts stay distinct.
func TestListManaged_RolesMountQualified(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	c.mustMark(t, MarkerID{Kind: MarkerRole, Mount: "kubernetes", Namespace: "ns", Name: "app"}, "ns/app")
	c.mustMark(t, MarkerID{Kind: MarkerRole, Mount: "jwt", Namespace: "ns", Name: "app"}, "ns/app")

	got, err := c.ListManaged(context.Background(), MarkerRole)
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct role markers (mount-qualified), got %d: %v", len(got), keysOfMap(got))
	}
	k8sKey := "kubernetes/" + naming.Vault("ns-app")
	jwtKey := "jwt/" + naming.Vault("ns-app")
	if _, ok := got[k8sKey]; !ok {
		t.Errorf("missing key %q; got %v", k8sKey, keysOfMap(got))
	}
	if mr, ok := got[jwtKey]; !ok {
		t.Errorf("missing key %q; got %v", jwtKey, keysOfMap(got))
	} else if mr.ID.Mount != "jwt" {
		t.Errorf("jwt marker ID.Mount = %q, want jwt", mr.ID.Mount)
	}
}

// TestListManaged_Empty verifies an empty subtree lists cleanly (no markers, no
// error) rather than erroring on the 404 LIST.
func TestListManaged_Empty(t *testing.T) {
	c := newMarkerMock(t).client(t)

	got, err := c.ListManaged(context.Background(), MarkerPolicy)
	if err != nil {
		t.Fatalf("ListManaged on empty store: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

// TestListManaged_ListErrorSurfaced verifies a LIST failure (e.g. 403) is
// returned, not swallowed.
func TestListManaged_ListErrorSurfaced(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)
	c.mustMark(t, MarkerID{Kind: MarkerPolicy, Namespace: "ns", Name: "p"}, "ns/p")

	m.mu.Lock()
	m.failList = true
	m.mu.Unlock()

	if _, err := c.ListManaged(context.Background(), MarkerPolicy); err == nil {
		t.Error("expected ListManaged to surface a LIST error, got nil")
	}
}

// --- AuthMountName -----------------------------------------------------------

func TestAuthMountName(t *testing.T) {
	cases := map[string]string{
		"auth/kubernetes": "kubernetes",
		"kubernetes":      "kubernetes",
		"":                "kubernetes", // "" defaults to kubernetes
		"auth/jwt":        "jwt",
		"jwt":             "jwt",
	}
	for in, want := range cases {
		if got := AuthMountName(in); got != want {
			t.Errorf("AuthMountName(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- PreflightMarkers --------------------------------------------------------

func TestPreflightMarkers_HappyPath(t *testing.T) {
	m := newMarkerMock(t)
	c := m.client(t)

	if err := c.PreflightMarkers(context.Background()); err != nil {
		t.Fatalf("PreflightMarkers happy path: %v", err)
	}
	// Best-effort delete should leave the probe removed.
	if m.get("vault-access-operator/managed/_preflight") != nil {
		t.Error("preflight probe should be cleaned up after a successful run")
	}
}

func TestPreflightMarkers_WriteErrorSurfaced(t *testing.T) {
	// A server that 403s every metadata write simulates a missing grant; the
	// preflight must surface it (fail fast) rather than swallow.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			w.WriteHeader(http.StatusForbidden)
			writeJSONResp(w, map[string]interface{}{"errors": []string{"permission denied"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(ClientConfig{Address: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.PreflightMarkers(context.Background()); err == nil {
		t.Error("expected PreflightMarkers to surface the write error, got nil")
	}
}

// --- helpers -----------------------------------------------------------------

func (c *Client) mustMark(t *testing.T, id MarkerID, k8sResource string) {
	t.Helper()
	if err := c.MarkManaged(context.Background(), id, k8sResource); err != nil {
		t.Fatalf("MarkManaged(%+v): %v", id, err)
	}
}

func keysOf(m *markerMock) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.meta))
	for k := range m.meta {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOfMap(mm map[string]ManagedResource) []string {
	out := make([]string, 0, len(mm))
	for k := range mm {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
