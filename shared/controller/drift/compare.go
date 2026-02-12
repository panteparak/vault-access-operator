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

// Package drift provides utilities for comparing expected vs actual state
// to detect configuration drift between Kubernetes resources and Vault.
package drift

import (
	"fmt"
	"sort"
	"strings"
)

// Result represents the outcome of a drift comparison.
type Result struct {
	// HasDrift indicates whether drift was detected.
	HasDrift bool

	// Fields lists the names of fields that differ.
	Fields []string

	// Summary provides a human-readable description of the drift.
	Summary string
}

// Comparator provides methods for comparing expected vs actual state.
type Comparator struct {
	diffs []string
}

// NewComparator creates a new drift comparator.
func NewComparator() *Comparator {
	return &Comparator{
		diffs: make([]string, 0),
	}
}

// CompareStringSlices compares two values as string slices.
// Both values are converted to []string before comparison.
// The comparison is order-independent (sorted before comparing).
func (c *Comparator) CompareStringSlices(fieldName string, expected, actual interface{}) {
	expectedSlice := toStringSlice(expected)
	actualSlice := toStringSlice(actual)

	if !stringSlicesEqual(expectedSlice, actualSlice) {
		c.diffs = append(c.diffs, fieldName)
	}
}

// CompareValues compares two values using string representation.
// This is suitable for scalar values like strings, numbers, booleans.
func (c *Comparator) CompareValues(fieldName string, expected, actual interface{}) {
	if !valuesEqual(expected, actual) {
		c.diffs = append(c.diffs, fieldName)
	}
}

// CompareValuesIfExpected compares values only if expected is set (non-nil).
// Use this for optional fields that should only be checked if specified.
func (c *Comparator) CompareValuesIfExpected(fieldName string, expected, actual interface{}) {
	if expected == nil {
		return
	}
	c.CompareValues(fieldName, expected, actual)
}

// CompareStrings compares two string values directly.
func (c *Comparator) CompareStrings(fieldName string, expected, actual string) {
	if expected != actual {
		c.diffs = append(c.diffs, fieldName)
	}
}

// Result returns the comparison result.
func (c *Comparator) Result() Result {
	if len(c.diffs) == 0 {
		return Result{
			HasDrift: false,
			Fields:   nil,
			Summary:  "",
		}
	}

	return Result{
		HasDrift: true,
		Fields:   c.diffs,
		Summary:  "fields differ: " + strings.Join(c.diffs, ", "),
	}
}

// Reset clears the comparator state for reuse.
func (c *Comparator) Reset() {
	c.diffs = c.diffs[:0]
}

// stringSlicesEqual compares two string slices for equality (order-independent).
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Make copies to avoid modifying the originals
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)

	sort.Strings(aCopy)
	sort.Strings(bCopy)

	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

// toStringSlice converts an interface{} to []string.
// Handles []string, []interface{}, and nil.
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// valuesEqual compares two interface{} values.
// Handles nil values and uses string representation for comparison.
func valuesEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// CompareMapFields is a convenience function that creates a Comparator,
// compares the specified fields between two maps, and returns the result.
func CompareMapFields(expected, actual map[string]interface{}, fields []string) Result {
	c := NewComparator()
	for _, field := range fields {
		c.CompareValues(field, expected[field], actual[field])
	}
	return c.Result()
}

// CompareStringSliceFields is a convenience function that creates a Comparator,
// compares the specified string slice fields, and returns the result.
func CompareStringSliceFields(expected, actual map[string]interface{}, fields []string) Result {
	c := NewComparator()
	for _, field := range fields {
		c.CompareStringSlices(field, expected[field], actual[field])
	}
	return c.Result()
}
