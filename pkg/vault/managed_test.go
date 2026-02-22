package vault

import (
	"encoding/json"
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
