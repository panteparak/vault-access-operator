package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestSplitKVv2Path(t *testing.T) {
	cases := []struct {
		in         string
		mount, rel string
		ok         bool
	}{
		{"secret/data/apps/foo", "secret", "apps/foo", true},
		{"secret/data/foo", "secret", "foo", true},
		{"kv/data/team/app", "kv", "team/app", true},
		{"secret/metadata/foo", "", "", false}, // not a data path
		{"secret/data/", "", "", false},        // empty relative path
		{"/data/foo", "", "", false},           // empty mount
		{"nodatapath", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		mount, rel, ok := SplitKVv2Path(tc.in)
		if ok != tc.ok || mount != tc.mount || rel != tc.rel {
			t.Errorf("SplitKVv2Path(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, mount, rel, ok, tc.mount, tc.rel, tc.ok)
		}
	}
}

func TestIsOwnedBy(t *testing.T) {
	if IsOwnedBy(nil) {
		t.Error("nil metadata should not be owned")
	}
	if IsOwnedBy(kvMetaForTest(nil)) {
		t.Error("nil custom_metadata should not be owned")
	}
	if IsOwnedBy(kvMetaForTest(map[string]interface{}{KVManagedByKey: "someone-else"})) {
		t.Error("foreign managed-by should not be owned")
	}
	if !IsOwnedBy(kvMetaForTest(map[string]interface{}{KVManagedByKey: KVManagedByValue})) {
		t.Error("operator managed-by should be owned")
	}
}

func TestCreateKVSecretIfAbsent_AbsentCreates(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	c := m.client(t)

	created, version, err := c.CreateKVSecretIfAbsent(
		context.Background(), "secret", "apps/foo", map[string]string{"username": ""})
	if err != nil {
		t.Fatalf("CreateKVSecretIfAbsent: %v", err)
	}
	if !created {
		t.Error("expected created=true for absent path")
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}
	if m.dataWrites() != 1 {
		t.Errorf("expected exactly 1 data write, got %d", m.dataWrites())
	}
}

func TestCreateKVSecretIfAbsent_EmptyDataCreates(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	c := m.client(t)

	// Default {} seed — nil data map must still create version 1.
	created, version, err := c.CreateKVSecretIfAbsent(context.Background(), "secret", "apps/empty", nil)
	if err != nil {
		t.Fatalf("CreateKVSecretIfAbsent: %v", err)
	}
	if !created || version != 1 {
		t.Errorf("expected created=true version=1, got created=%v version=%d", created, version)
	}
}

func TestCreateKVSecretIfAbsent_PresentSkips(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	m.seed("apps/foo", 3, map[string]interface{}{"filled": "by-eso"})
	c := m.client(t)

	created, version, err := c.CreateKVSecretIfAbsent(
		context.Background(), "secret", "apps/foo", map[string]string{"username": ""})
	if err != nil {
		t.Fatalf("CreateKVSecretIfAbsent: %v", err)
	}
	if created {
		t.Error("expected created=false for existing path")
	}
	if version != 3 {
		t.Errorf("expected reported version 3, got %d", version)
	}
	if m.dataWrites() != 0 {
		t.Errorf("must NOT write data when path present, got %d writes", m.dataWrites())
	}
}

func TestCreateKVSecretIfAbsent_CASRaceLost(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	m.forceCASConflict = true // simulate a concurrent create between read and write
	c := m.client(t)

	created, _, err := c.CreateKVSecretIfAbsent(
		context.Background(), "secret", "apps/foo", map[string]string{"k": ""})
	if err != nil {
		t.Fatalf("cas race must not be an error, got: %v", err)
	}
	if created {
		t.Error("expected created=false when cas guard fires (race lost)")
	}
}

func TestKVSecretExists(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	c := m.client(t)

	exists, err := c.KVSecretExists(context.Background(), "secret", "apps/foo")
	if err != nil || exists {
		t.Fatalf("absent path: exists=%v err=%v", exists, err)
	}

	m.seed("apps/foo", 1, nil)
	exists, err = c.KVSecretExists(context.Background(), "secret", "apps/foo")
	if err != nil || !exists {
		t.Fatalf("present path: exists=%v err=%v", exists, err)
	}
}

func TestStampKVOwnership_AndReadback(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	c := m.client(t)

	if _, _, err := c.CreateKVSecretIfAbsent(context.Background(), "secret", "apps/foo", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.StampKVOwnership(context.Background(), "secret", "apps/foo", KVOwnership{
		K8sResource: "team-a/myapp",
	}); err != nil {
		t.Fatalf("StampKVOwnership: %v", err)
	}

	md, err := c.ReadKVMetadata(context.Background(), "secret", "apps/foo")
	if err != nil {
		t.Fatalf("ReadKVMetadata: %v", err)
	}
	if md == nil {
		t.Fatal("expected metadata after stamping")
	}
	if !IsOwnedBy(md) {
		t.Errorf("expected operator ownership stamp, got custom_metadata=%v", md.CustomMetadata)
	}
	if got, _ := md.CustomMetadata[KVK8sResourceKey].(string); got != "team-a/myapp" {
		t.Errorf("k8s-resource = %q, want team-a/myapp", got)
	}
}

func TestDeleteKVSecret(t *testing.T) {
	m := newKVV2Mock(t, "secret")
	m.seed("apps/foo", 1, map[string]interface{}{KVManagedByKey: KVManagedByValue})
	c := m.client(t)

	if err := c.DeleteKVSecret(context.Background(), "secret", "apps/foo"); err != nil {
		t.Fatalf("DeleteKVSecret: %v", err)
	}
	exists, err := c.KVSecretExists(context.Background(), "secret", "apps/foo")
	if err != nil || exists {
		t.Fatalf("expected gone after delete: exists=%v err=%v", exists, err)
	}

	// Idempotent: deleting a missing path is not an error.
	if err := c.DeleteKVSecret(context.Background(), "secret", "apps/missing"); err != nil {
		t.Errorf("delete of missing path should be nil, got %v", err)
	}
}

// --- stateful KV v2 mock -----------------------------------------------------

// kvMetaForTest builds an *api.KVMetadata for IsOwnedBy tests without reaching
// through the SDK.
func kvMetaForTest(cm map[string]interface{}) *api.KVMetadata {
	return &api.KVMetadata{CustomMetadata: cm}
}

const kvKindMetadata = "metadata"

type kvV2Mock struct {
	mu               sync.Mutex
	mount            string
	secrets          map[string]*kvEntry
	server           *httptest.Server
	puts             int
	forceCASConflict bool
}

type kvEntry struct {
	version        int
	customMetadata map[string]interface{}
}

func newKVV2Mock(t *testing.T, mount string) *kvV2Mock { //nolint:unparam
	t.Helper()
	m := &kvV2Mock{mount: mount, secrets: map[string]*kvEntry{}}
	prefix := "/v1/" + mount + "/"
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		kind, key, found := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if !found {
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
			writeJSONResp(w, map[string]interface{}{"data": map[string]interface{}{
				"current_version": e.version,
				"custom_metadata": e.customMetadata,
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
			if e.customMetadata == nil {
				e.customMetadata = map[string]interface{}{}
			}
			for k, v := range body.CustomMetadata {
				e.customMetadata[k] = v
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
			casZero := body.Options.Cas != nil && *body.Options.Cas == 0
			if casZero && (m.forceCASConflict || e != nil) {
				w.WriteHeader(http.StatusBadRequest)
				writeJSONResp(w, map[string]interface{}{
					"errors": []string{"check-and-set parameter did not match the current version"},
				})
				return
			}
			if e == nil {
				e = &kvEntry{}
				m.secrets[key] = e
			}
			e.version++
			m.puts++
			writeJSONResp(w, map[string]interface{}{"data": map[string]interface{}{
				"version":       e.version,
				"created_time":  "2026-01-01T00:00:00Z",
				"deletion_time": "",
				"destroyed":     false,
			}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *kvV2Mock) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{Address: m.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (m *kvV2Mock) seed(key string, version int, cm map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[key] = &kvEntry{version: version, customMetadata: cm}
}

func (m *kvV2Mock) dataWrites() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts
}

func writeJSONResp(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
