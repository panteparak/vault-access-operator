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
	"testing"
)

func TestComparator_CompareStringSlices_Equal(t *testing.T) {
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"a", "b", "c"})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for equal slices")
	}
}

func TestComparator_CompareStringSlices_DifferentOrder(t *testing.T) {
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"c", "a", "b"})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for same elements in different order")
	}
}

func TestComparator_CompareStringSlices_Different(t *testing.T) {
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
	c := NewComparator()
	c.CompareStringSlices("policies", []string{"a", "b", "c"}, []string{"a", "b"})

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift for slices of different length")
	}
}

func TestComparator_CompareStringSlices_NilHandling(t *testing.T) {
	c := NewComparator()
	c.CompareStringSlices("policies", nil, nil)

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for nil vs nil")
	}
}

func TestComparator_CompareStringSlices_NilVsEmpty(t *testing.T) {
	c := NewComparator()
	c.CompareStringSlices("policies", nil, []string{})

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for nil vs empty (both have 0 elements)")
	}
}

func TestComparator_CompareStringSlices_InterfaceSlice(t *testing.T) {
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
	c := NewComparator()
	c.CompareValues("token_ttl", "1h", "1h")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift for equal values")
	}
}

func TestComparator_CompareValues_Different(t *testing.T) {
	c := NewComparator()
	c.CompareValues("token_ttl", "1h", "2h")

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift for different values")
	}
}

func TestComparator_CompareValues_NumericTypes(t *testing.T) {
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
	c := NewComparator()
	c.CompareValuesIfExpected("token_ttl", nil, "1h")

	result := c.Result()
	if result.HasDrift {
		t.Error("expected no drift when expected is nil")
	}
}

func TestComparator_CompareValuesIfExpected_SetExpected(t *testing.T) {
	c := NewComparator()
	c.CompareValuesIfExpected("token_ttl", "1h", "2h")

	result := c.Result()
	if !result.HasDrift {
		t.Error("expected drift when expected is set and differs")
	}
}

func TestComparator_MultipleFields(t *testing.T) {
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
	result := toStringSlice([]interface{}{})
	if result == nil || len(result) != 0 {
		t.Errorf("expected empty slice, got: %v", result)
	}
}

func TestToStringSlice_MixedInterfaceSlice(t *testing.T) {
	// Non-string elements are skipped
	result := toStringSlice([]interface{}{"a", 123, "b", true})
	if len(result) != 2 {
		t.Errorf("expected 2 string elements, got: %v", result)
	}
}

func TestValuesEqual_BothNil(t *testing.T) {
	if !valuesEqual(nil, nil) {
		t.Error("nil == nil should be true")
	}
}

func TestValuesEqual_OneNil(t *testing.T) {
	if valuesEqual(nil, "value") {
		t.Error("nil != 'value' should be false")
	}
	if valuesEqual("value", nil) {
		t.Error("'value' != nil should be false")
	}
}
