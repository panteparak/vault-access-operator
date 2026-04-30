package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestManagedResource_RuleDescriptionsRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	original := ManagedResource{
		K8sResource: "default/my-policy",
		ManagedAt:   now,
		LastUpdated: now,
		RuleDescriptions: map[string]string{
			"secret/data/default/app/*": "Read access to app secrets",
			"secret/metadata/default/*": "List metadata",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ManagedResource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.K8sResource != original.K8sResource {
		t.Errorf("K8sResource = %q, want %q", decoded.K8sResource, original.K8sResource)
	}
	if len(decoded.RuleDescriptions) != 2 {
		t.Fatalf("expected 2 rule descriptions, got %d", len(decoded.RuleDescriptions))
	}
	if decoded.RuleDescriptions["secret/data/default/app/*"] != "Read access to app secrets" {
		t.Errorf("unexpected description: %q", decoded.RuleDescriptions["secret/data/default/app/*"])
	}
	if decoded.RuleDescriptions["secret/metadata/default/*"] != "List metadata" {
		t.Errorf("unexpected description: %q", decoded.RuleDescriptions["secret/metadata/default/*"])
	}
}

func TestManagedResource_BackwardCompat_NoDescriptions(t *testing.T) {
	// Simulate a managed marker written before RuleDescriptions was added
	legacyJSON := `{"k8sResource":"default/old-policy",` +
		`"managedAt":"2025-01-01T00:00:00Z","lastUpdated":"2025-01-01T00:00:00Z"}`

	var decoded ManagedResource
	if err := json.Unmarshal([]byte(legacyJSON), &decoded); err != nil {
		t.Fatalf("failed to unmarshal legacy JSON: %v", err)
	}

	if decoded.K8sResource != "default/old-policy" {
		t.Errorf("K8sResource = %q, want %q", decoded.K8sResource, "default/old-policy")
	}
	if decoded.RuleDescriptions != nil {
		t.Errorf("expected nil RuleDescriptions for legacy marker, got %v", decoded.RuleDescriptions)
	}
}

func TestManagedResource_NilDescriptions_OmittedInJSON(t *testing.T) {
	m := ManagedResource{
		K8sResource: "test/policy",
		ManagedAt:   time.Now(),
		LastUpdated: time.Now(),
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	jsonStr := string(data)
	if json.Valid(data) && contains(jsonStr, "ruleDescriptions") {
		t.Errorf("expected ruleDescriptions to be omitted when nil, got: %s", jsonStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && jsonContains(s, substr)
}

func jsonContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// markManagedHarness tracks reads + the last write payload so tests can
// assert what markManaged actually sent to Vault. Used for the
// description-preservation tests below — re-uses the KV v2 wire shape
// described in pkg/orphan/detect_orphans_test.go.
type markManagedHarness struct {
	mu       sync.Mutex
	existing *ManagedResource // optional: pre-existing marker on the path
	lastSent *ManagedResource // the marker the most recent PUT delivered
	server   *httptest.Server
}

func newMarkManagedHarness(t *testing.T, existing *ManagedResource) *markManagedHarness {
	t.Helper()
	h := &markManagedHarness{existing: existing}
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.mu.Lock()
			cur := h.existing
			h.mu.Unlock()
			if cur == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			payload, _ := json.Marshal(cur)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"metadata": string(payload),
					},
					"metadata": map[string]interface{}{},
				},
			})
		case http.MethodPost, http.MethodPut:
			// Decode the request body to extract the marker payload.
			var body struct {
				Data struct {
					Metadata string `json:"metadata"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var sent ManagedResource
			_ = json.Unmarshal([]byte(body.Data.Metadata), &sent)
			h.mu.Lock()
			h.lastSent = &sent
			// Update existing so a re-read returns the new state (matches Vault).
			h.existing = &sent
			h.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(h.server.Close)
	return h
}

// TestMarkManaged_NilDescriptionsPreservesExisting pins the bug-fix in
// markManaged: when the caller passes nil descriptions and a marker
// already exists with descriptions, we MUST preserve those descriptions
// (not wipe them). The §G restore-managed-markers flow exercises this
// exact path — the connection handler doesn't have access to the
// rules→descriptions map and passes nil; without preservation, restore
// would wipe valid descriptions written by previous reconciles.
func TestMarkManaged_NilDescriptionsPreservesExisting(t *testing.T) {
	existing := &ManagedResource{
		K8sResource: "ns/policy",
		RuleDescriptions: map[string]string{
			"secret/data/ns/foo": "read app secrets",
			"secret/data/ns/bar": "read shared config",
		},
	}
	h := newMarkManagedHarness(t, existing)
	c, err := NewClient(ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.MarkPolicyManaged(
		context.Background(), "ns-policy", "ns/policy", nil,
	); err != nil {
		t.Fatalf("MarkPolicyManaged: %v", err)
	}

	h.mu.Lock()
	got := h.lastSent
	h.mu.Unlock()
	if got == nil {
		t.Fatal("no write was made")
	}
	if len(got.RuleDescriptions) != 2 {
		t.Errorf("expected descriptions preserved (2 entries), got %d: %+v",
			len(got.RuleDescriptions), got.RuleDescriptions)
	}
	if got.RuleDescriptions["secret/data/ns/foo"] != "read app secrets" {
		t.Errorf("first description not preserved: %q", got.RuleDescriptions["secret/data/ns/foo"])
	}
}

// TestMarkManaged_EmptyMapClearsDescriptions pins the OTHER side of
// the contract: an explicit empty map (not nil) means "clear existing
// descriptions, this resource has none". The policy reconciler uses
// this when a user removes all `description:` fields from a policy
// spec — the markers must reflect the new empty state.
func TestMarkManaged_EmptyMapClearsDescriptions(t *testing.T) {
	existing := &ManagedResource{
		K8sResource: "ns/policy",
		RuleDescriptions: map[string]string{
			"old-path": "stale description",
		},
	}
	h := newMarkManagedHarness(t, existing)
	c, err := NewClient(ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Explicit empty map = "clear".
	if err := c.MarkPolicyManaged(
		context.Background(), "ns-policy", "ns/policy", map[string]string{},
	); err != nil {
		t.Fatalf("MarkPolicyManaged: %v", err)
	}

	h.mu.Lock()
	got := h.lastSent
	h.mu.Unlock()
	if got == nil {
		t.Fatal("no write was made")
	}
	if len(got.RuleDescriptions) != 0 {
		t.Errorf("expected empty descriptions (cleared), got %d entries: %+v",
			len(got.RuleDescriptions), got.RuleDescriptions)
	}
}

// TestMarkManaged_NilDescriptionsOnFreshMarker pins the no-existing
// case: nil + no existing marker just means "no descriptions" on the
// new marker. Preservation logic only kicks in when there's something
// to preserve.
func TestMarkManaged_NilDescriptionsOnFreshMarker(t *testing.T) {
	h := newMarkManagedHarness(t, nil) // no existing
	c, err := NewClient(ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.MarkPolicyManaged(
		context.Background(), "ns-new", "ns/new-policy", nil,
	); err != nil {
		t.Fatalf("MarkPolicyManaged: %v", err)
	}

	h.mu.Lock()
	got := h.lastSent
	h.mu.Unlock()
	if got == nil {
		t.Fatal("no write was made")
	}
	if len(got.RuleDescriptions) != 0 {
		t.Errorf("expected no descriptions on fresh marker, got %d", len(got.RuleDescriptions))
	}
}

// TestMarkManaged_NewDescriptionsOverwriteExisting pins the
// happy-path policy reconcile: a non-nil non-empty map replaces the
// previous descriptions wholesale (matches the new spec).
func TestMarkManaged_NewDescriptionsOverwriteExisting(t *testing.T) {
	existing := &ManagedResource{
		K8sResource: "ns/policy",
		RuleDescriptions: map[string]string{
			"old-path": "stale description",
		},
	}
	h := newMarkManagedHarness(t, existing)
	c, err := NewClient(ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	newDescs := map[string]string{
		"new-path": "current description",
	}
	if err := c.MarkPolicyManaged(
		context.Background(), "ns-policy", "ns/policy", newDescs,
	); err != nil {
		t.Fatalf("MarkPolicyManaged: %v", err)
	}

	h.mu.Lock()
	got := h.lastSent
	h.mu.Unlock()
	if got == nil {
		t.Fatal("no write was made")
	}
	if len(got.RuleDescriptions) != 1 {
		t.Errorf("expected exactly 1 description, got %+v", got.RuleDescriptions)
	}
	if got.RuleDescriptions["new-path"] != "current description" {
		t.Errorf("new description not present: %+v", got.RuleDescriptions)
	}
	if _, present := got.RuleDescriptions["old-path"]; present {
		t.Error("old description should have been overwritten, not merged")
	}
}

// TestMarkManaged_PreservesManagedAt pins the existing contract that
// re-marking a resource keeps the original ManagedAt timestamp (only
// LastUpdated bumps). This was already guarded but worth pinning
// alongside the new RuleDescriptions preservation logic.
func TestMarkManaged_PreservesManagedAt(t *testing.T) {
	originalManagedAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	existing := &ManagedResource{
		K8sResource: "ns/policy",
		ManagedAt:   originalManagedAt,
		LastUpdated: originalManagedAt,
	}
	h := newMarkManagedHarness(t, existing)
	c, err := NewClient(ClientConfig{Address: h.server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.MarkPolicyManaged(
		context.Background(), "ns-policy", "ns/policy", nil,
	); err != nil {
		t.Fatalf("MarkPolicyManaged: %v", err)
	}

	h.mu.Lock()
	got := h.lastSent
	h.mu.Unlock()
	if !got.ManagedAt.Equal(originalManagedAt) {
		t.Errorf("ManagedAt should be preserved as %v, got %v",
			originalManagedAt, got.ManagedAt)
	}
	if got.LastUpdated.Equal(originalManagedAt) {
		t.Error("LastUpdated should have advanced, not stayed at original ManagedAt")
	}
}
