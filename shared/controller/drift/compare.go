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
	diffs   []string
	details map[string]string // fieldName → human-readable diff hint (e.g. HCL preview)
}

// NewComparator creates a new drift comparator.
func NewComparator() *Comparator {
	return &Comparator{
		diffs:   make([]string, 0),
		details: make(map[string]string),
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

// CompareMultilineText compares two multiline text blobs (e.g. policy HCL,
// YAML, JSON). When they differ, the comparator records the field name and
// a compact line-level diff preview in Result.Summary.
//
// The preview uses unified-diff markers: lines prefixed with "- " are
// present in actual but missing from expected (Vault-side additions we
// don't know about); lines prefixed with "+ " are present in expected but
// missing from actual (content we'd write that Vault is missing).
//
// Up to multilineDiffMaxLines unique differences are shown; anything beyond
// is summarized as `... (N more)`. Callers should pass already-normalized
// text (e.g. post-`normalizeHCL`) so cosmetic whitespace differences don't
// leak into the preview.
//
// Introduced for IMPROVEMENTS §11 (drift comparator duplication) so policy
// drift surfaces a structured hint instead of a generic "content differs"
// message.
func (c *Comparator) CompareMultilineText(fieldName, expected, actual string) {
	if expected == actual {
		return
	}
	c.diffs = append(c.diffs, fieldName)
	c.details[fieldName] = multilineDiffPreview(expected, actual, multilineDiffMaxLines)
}

// multilineDiffMaxLines caps the number of preview lines surfaced for a
// single field so a wildly divergent blob doesn't flood status conditions.
const multilineDiffMaxLines = 6

// Result returns the comparison result.
func (c *Comparator) Result() Result {
	if len(c.diffs) == 0 {
		return Result{
			HasDrift: false,
			Fields:   nil,
			Summary:  "",
		}
	}

	// Copy the diffs slice to prevent Reset() from corrupting previously returned results.
	fields := make([]string, len(c.diffs))
	copy(fields, c.diffs)

	summary := "fields differ: " + strings.Join(fields, ", ")
	// Append per-field previews in the same order fields were recorded so the
	// message is deterministic across runs.
	for _, f := range fields {
		if preview, ok := c.details[f]; ok && preview != "" {
			summary += "\n  " + f + ":\n" + preview
		}
	}

	return Result{
		HasDrift: true,
		Fields:   fields,
		Summary:  summary,
	}
}

// Reset clears the comparator state for reuse.
func (c *Comparator) Reset() {
	c.diffs = c.diffs[:0]
	for k := range c.details {
		delete(c.details, k)
	}
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

// multilineDiffPreview produces a compact line-level diff preview between
// expected and actual. Lines present only in actual are prefixed `- `
// (unexpected content), lines present only in expected are prefixed `+ `
// (missing content). Up to `max` lines are emitted; anything beyond is
// summarized as `  ... (N more)`.
//
// This is intentionally simple: it's a set-difference on unique lines, not
// a true LCS-based diff. For operator-generated HCL (which is deterministic
// line-by-line) this is sufficient to make the drift cause obvious to an
// operator reading the condition.
func multilineDiffPreview(expected, actual string, maxPreviewLines int) string {
	expectedLines := splitLines(expected)
	actualLines := splitLines(actual)
	expectedSet := make(map[string]struct{}, len(expectedLines))
	for _, l := range expectedLines {
		expectedSet[l] = struct{}{}
	}
	actualSet := make(map[string]struct{}, len(actualLines))
	for _, l := range actualLines {
		actualSet[l] = struct{}{}
	}

	// Preserve original line order when listing diffs; de-dup within each side.
	var previewBuilder strings.Builder
	emitted := 0
	skipped := 0
	seenActual := make(map[string]struct{})
	for _, l := range actualLines {
		if _, ok := expectedSet[l]; ok {
			continue
		}
		if _, dup := seenActual[l]; dup {
			continue
		}
		seenActual[l] = struct{}{}
		if emitted < maxPreviewLines {
			previewBuilder.WriteString("    - ")
			previewBuilder.WriteString(l)
			previewBuilder.WriteString("\n")
			emitted++
		} else {
			skipped++
		}
	}
	seenExpected := make(map[string]struct{})
	for _, l := range expectedLines {
		if _, ok := actualSet[l]; ok {
			continue
		}
		if _, dup := seenExpected[l]; dup {
			continue
		}
		seenExpected[l] = struct{}{}
		if emitted < maxPreviewLines {
			previewBuilder.WriteString("    + ")
			previewBuilder.WriteString(l)
			previewBuilder.WriteString("\n")
			emitted++
		} else {
			skipped++
		}
	}
	if skipped > 0 {
		fmt.Fprintf(&previewBuilder, "    ... (%d more)\n", skipped)
	}
	// Trim the trailing newline for a tidy single-line append in Summary.
	return strings.TrimRight(previewBuilder.String(), "\n")
}

// splitLines is strings.Split(s, "\n") but drops a trailing empty line
// produced when the input ends in a newline.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
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
