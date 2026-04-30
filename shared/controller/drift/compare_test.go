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

package drift

import (
	"strings"
	"testing"
)

func TestComparator_CompareStringSlices_Equal(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"a", "b", "c"})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for equal slices")
	}
}

func TestComparator_CompareStringSlices_DifferentOrder(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"c", "a", "b"})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for same elements in different order")
	}
}

func TestComparator_CompareStringSlices_Different(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b"}, []string{"a", "c"})

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift for different slices")
	}
	if len(result.Fields) != 1 || result.Fields[0] != "policies" {
		t.Errorf("expected fields [policies], got %v", result.Fields)
	}
}

func TestComparator_CompareStringSlices_DifferentLength(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"a", "b"})

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift for slices of different length")
	}
}

func TestComparator_CompareStringSlices_NilHandling(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", nil, nil)

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for nil vs nil")
	}
}

func TestComparator_CompareStringSlices_NilVsEmpty(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", nil, []string{})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for nil vs empty (both have 0 elements)")
	}
}

func TestComparator_CompareStringSlices_InterfaceSlice(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// Simulate JSON-decoded data where []string becomes []interface{}
	c.CompareStringSlices("policies",
		[]string{"a", "b"},
		[]interface{}{"a", "b"})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for []string vs []interface{} with same content")
	}
}

func TestComparator_CompareValues_Equal(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareValues("token_ttl", "1h", "1h")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for equal values")
	}
}

func TestComparator_CompareValues_Different(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareValues("token_ttl", "1h", "2h")

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift for different values")
	}
}

func TestComparator_CompareValues_NumericTypes(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// Vault may return numbers as different types (int vs float64)
	c.CompareValues("token_ttl", 3600, 3600.0)

	result := c.Result()
	// Note: This comparison uses fmt.Sprintf which may differ
	// (3600 vs 3600) - should be equal
	if result.HasDrift {
		t.Error("expected no drift for numeric values with same magnitude")
	}
}

func TestComparator_CompareValuesIfExpected_NilExpected(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareValuesIfExpected("token_ttl", nil, "1h")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift when expected is nil")
	}
}

func TestComparator_CompareValuesIfExpected_SetExpected(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareValuesIfExpected("token_ttl", "1h", "2h")

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift when expected is set and differs")
	}
}

func TestComparator_MultipleFields(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a"}, []string{"b"})
	c.CompareStringSlices("namespaces", []string{"default"}, []string{"default"})
	c.CompareValues("token_ttl", "1h", "2h")

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift")
	}
	if len(result.Fields) != 2 {
		t.Errorf("expected 2 differing fields, got %d: %v", len(result.Fields), result.Fields)
	}
	if result.Summary != "fields differ: policies, token_ttl" {
		t.Errorf("unexpected summary: %s", result.Summary)
	}
}

func TestComparator_Reset(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareValues("field1", "a", "b")

	result1 := c.Result()
	if !result1.HasDrift {
		t.Error("expected drift before reset")
	}

	c.Reset()
	c.CompareValues("field2", "x", "x")

	result2 := c.Result()
	if result2.HasDrift {
		t.Error("expected no drift after reset")
	}
}

func TestCompareMapFields(t *testing.T) {
	t.Parallel()
	expected := map[string]interface{}{
		"policies":  []string{"read", "write"},
		"token_ttl": "1h",
	}
	actual := map[string]interface{}{
		"policies":  []string{"read", "write"},
		"token_ttl": "2h",
	}

	result := CompareMapFields(expected, actual, []string{"policies", "token_ttl"})
	if !result.HasDrift {
		t.Error("expected drift")
	}
	// Note: CompareMapFields uses CompareValues, not CompareStringSlices
	// so policies comparison may differ if treated as strings
}

func TestCompareStringSliceFields(t *testing.T) {
	t.Parallel()
	expected := map[string]interface{}{
		"policies":   []string{"read", "write"},
		"namespaces": []string{"default"},
	}
	actual := map[string]interface{}{
		"policies":   []string{"write", "read"},
		"namespaces": []string{"kube-system"},
	}

	result := CompareStringSliceFields(expected, actual, []string{"policies", "namespaces"})
	if !result.HasDrift {
		t.Error("expected drift for namespaces")
	}
	if len(result.Fields) != 1 || result.Fields[0] != "namespaces" {
		t.Errorf("expected only namespaces to differ, got: %v", result.Fields)
	}
}

func TestToStringSlice_EmptyInterfaceSlice(t *testing.T) {
	t.Parallel()
	result := toStringSlice([]interface{}{})
	if result == nil || len(result) != 0 {
		t.Errorf("expected empty slice, got: %v", result)
	}
}

func TestToStringSlice_MixedInterfaceSlice(t *testing.T) {
	t.Parallel()
	// Non-string elements are skipped
	result := toStringSlice([]interface{}{"a", 123, "b", true})
	if len(result) != 2 {
		t.Errorf("expected 2 string elements, got: %v", result)
	}
}

func TestValuesEqual_BothNil(t *testing.T) {
	t.Parallel()
	if !valuesEqual(nil, nil) {
		t.Error("nil == nil should be true")
	}
}

func TestValuesEqual_OneNil(t *testing.T) {
	t.Parallel()
	if valuesEqual(nil, "value") {
		t.Error("nil != 'value' should be false")
	}
	if valuesEqual("value", nil) {
		t.Error("'value' != nil should be false")
	}
}

// --- Drift comparator edge cases (Gap 10) ---

func TestCompareStringSlices_EmptyVsSingleEmpty(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// An empty slice and a slice with one empty string differ
	c.CompareStringSlices("field", []string{}, []string{""})

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift: []string{} vs []string{''} have different lengths")
	}
}

func TestCompareValues_IntVsString(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// fmt.Sprintf produces "3600" for both int and string "3600"
	c.CompareValues("token_ttl", 3600, "3600")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift: int 3600 and string '3600' should match via Sprintf")
	}
}

func TestCompareValues_BoolVsString(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// fmt.Sprintf produces "true" for both bool and string
	c.CompareValues("enabled", true, "true")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift: bool true and string 'true' should match via Sprintf")
	}
}

func TestCompareStringSlices_NilInInterfaceSlice(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// nil elements in []interface{} are skipped by toStringSlice
	c.CompareStringSlices("field",
		[]string{"a", "b"},
		[]interface{}{"a", nil, "b"})

	result := c.Result()
	// []interface{}{"a", nil, "b"} → toStringSlice produces ["a", "b"] (nil skipped)
	// but the lengths differ (2 vs 2 after conversion) so this should work
	if result.HasDrift {
		t.Error("expected no drift: nil elements in []interface{} are skipped")
	}
}

func TestCompareValues_NestedMap(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	// Nested maps compared via Sprintf — order matters for maps in Sprintf
	expected := map[string]interface{}{"key": "value"}
	actual := map[string]interface{}{"key": "value"}
	c.CompareValues("config", expected, actual)

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for identical nested maps")
	}
}

func TestComparator_ReuseSafety(t *testing.T) {
	t.Parallel()
	c := NewComparator()

	// First comparison with drift
	c.CompareValues("field1", "a", "b")
	r1 := c.Result()
	if !r1.HasDrift {
		t.Error("expected drift in first comparison")
	}

	// Reset and do second comparison without drift
	c.Reset()
	c.CompareValues("field2", "same", "same")
	r2 := c.Result()
	if r2.HasDrift {
		t.Error("expected no drift after Reset")
	}

	// Verify first result fields don't leak into second
	if len(r2.Fields) != 0 {
		t.Errorf("expected no fields after reset, got: %v", r2.Fields)
	}

	// Reset and do third comparison with drift
	c.Reset()
	c.CompareStrings("field3", "x", "y")
	r3 := c.Result()
	if !r3.HasDrift {
		t.Error("expected drift in third comparison")
	}
	if len(r3.Fields) != 1 || r3.Fields[0] != "field3" {
		t.Errorf("expected fields [field3], got %v", r3.Fields)
	}
}

// TestComparator_CompareMultilineText_Identical pins that equal text produces
// no drift — this is the common case on every reconcile when the policy is
// already in sync.
func TestComparator_CompareMultilineText_Identical(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareMultilineText("rules", "path \"foo\" {}\n", "path \"foo\" {}\n")

	r := c.Result()
	if r.HasDrift {
		t.Errorf("expected no drift for identical text, got summary=%q", r.Summary)
	}
}

// TestComparator_CompareMultilineText_AddedLine simulates a Vault admin
// manually adding a capability line the operator doesn't know about — the
// preview must surface the unexpected line with `- ` marker.
func TestComparator_CompareMultilineText_AddedLine(t *testing.T) {
	t.Parallel()
	expected := "path \"foo\" {\ncapabilities = [\"read\"]\n}"
	actual := "path \"foo\" {\ncapabilities = [\"read\", \"list\"]\n}"
	c := NewComparator()
	c.CompareMultilineText("rules", expected, actual)

	r := c.Result()
	if !r.HasDrift {
		t.Fatalf("expected drift for changed capabilities")
	}
	if !strings.Contains(r.Summary, "- capabilities = [\"read\", \"list\"]") {
		t.Errorf("summary missing `- ` marker for Vault-side change:\n%s", r.Summary)
	}
	if !strings.Contains(r.Summary, "+ capabilities = [\"read\"]") {
		t.Errorf("summary missing `+ ` marker for expected line:\n%s", r.Summary)
	}
	if !strings.Contains(r.Summary, "rules:") {
		t.Errorf("summary missing field label `rules:`:\n%s", r.Summary)
	}
}

// TestComparator_CompareMultilineText_CapsPreview pins that a wildly divergent
// blob doesn't flood the summary — only `multilineDiffMaxLines` preview lines
// are emitted, with overflow summarized as `... (N more)`.
func TestComparator_CompareMultilineText_CapsPreview(t *testing.T) {
	t.Parallel()
	var expectedB, actualB strings.Builder
	for i := 0; i < 20; i++ {
		expectedB.WriteString("expected-line-")
		expectedB.WriteString(strings.Repeat("x", i))
		expectedB.WriteString("\n")
		actualB.WriteString("actual-line-")
		actualB.WriteString(strings.Repeat("y", i))
		actualB.WriteString("\n")
	}
	c := NewComparator()
	c.CompareMultilineText("rules", expectedB.String(), actualB.String())

	r := c.Result()
	if !r.HasDrift {
		t.Fatal("expected drift")
	}
	if !strings.Contains(r.Summary, "more)") {
		t.Errorf("summary should cap preview and include `... (N more)`, got:\n%s", r.Summary)
	}
	// The cap is 6 lines total; verify we haven't emitted all 40.
	numMarker := strings.Count(r.Summary, "\n    - ") + strings.Count(r.Summary, "\n    + ")
	if numMarker > multilineDiffMaxLines {
		t.Errorf("emitted %d preview lines, want <=%d", numMarker, multilineDiffMaxLines)
	}
}

// TestComparator_CompareMultilineText_CombinesWithOtherFields verifies that a
// multiline diff doesn't crowd out structured field diffs — the Summary lists
// *all* diverging fields, then per-field details for those that have them.
func TestComparator_CompareMultilineText_CombinesWithOtherFields(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareStrings("name", "role-a", "role-b")
	c.CompareMultilineText("rules", "alpha\n", "beta\n")

	r := c.Result()
	if !r.HasDrift {
		t.Fatal("expected drift")
	}
	if len(r.Fields) != 2 {
		t.Errorf("expected 2 fields, got %v", r.Fields)
	}
	if !strings.HasPrefix(r.Summary, "fields differ: name, rules") {
		t.Errorf("summary should start with combined field list, got:\n%s", r.Summary)
	}
	// `name` has no preview; `rules` should appear with its marker.
	if strings.Contains(r.Summary, "name:\n") {
		t.Errorf("summary should not have a preview for `name`, got:\n%s", r.Summary)
	}
	if !strings.Contains(r.Summary, "rules:\n") {
		t.Errorf("summary should have a preview for `rules`, got:\n%s", r.Summary)
	}
}

// TestComparator_CompareMultilineText_ResetClearsDetails pins that Reset()
// clears the details map so a re-used comparator doesn't leak previews from
// a previous comparison.
func TestComparator_CompareMultilineText_ResetClearsDetails(t *testing.T) {
	t.Parallel()
	c := NewComparator()
	c.CompareMultilineText("rules", "a\n", "b\n")
	_ = c.Result()

	c.Reset()
	c.CompareMultilineText("rules", "x\n", "x\n")
	r := c.Result()
	if r.HasDrift {
		t.Errorf("Reset should have cleared state; got summary=%q", r.Summary)
	}
}
