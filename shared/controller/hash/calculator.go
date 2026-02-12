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

// Package hash provides utilities for calculating content hashes for change detection.
// These hashes are used to detect when Kubernetes specs change vs external drift.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// FromString calculates a SHA256 hash from a string.
// Used for hashing HCL policy content.
func FromString(content string) string {
	if content == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// FromBytes calculates a SHA256 hash from bytes.
func FromBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// FromMap calculates a SHA256 hash from a map by JSON-marshaling it.
// Used for hashing role data maps.
// Returns empty string if marshaling fails.
func FromMap(data map[string]interface{}) string {
	if data == nil {
		return ""
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return FromBytes(jsonBytes)
}

// FromMapDeterministic calculates a deterministic SHA256 hash from a map.
// Keys are sorted before marshaling to ensure consistent ordering.
// Use this when you need the hash to be stable across different Go versions
// or when the map is built from different code paths.
func FromMapDeterministic(data map[string]interface{}) string {
	if data == nil {
		return ""
	}

	// Sort keys for deterministic ordering
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build ordered representation
	ordered := make([]struct {
		Key   string
		Value interface{}
	}, len(keys))
	for i, k := range keys {
		ordered[i].Key = k
		ordered[i].Value = data[k]
	}

	jsonBytes, err := json.Marshal(ordered)
	if err != nil {
		return ""
	}
	return FromBytes(jsonBytes)
}

// FromJSON calculates a SHA256 hash from a JSON-serializable value.
// Returns empty string if marshaling fails.
func FromJSON(v interface{}) string {
	if v == nil {
		return ""
	}
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return FromBytes(jsonBytes)
}

// Equals compares two hash strings for equality.
// Handles empty strings gracefully.
func Equals(a, b string) bool {
	return a == b && a != ""
}

// Changed returns true if the two hashes differ.
// An empty expected hash is considered "no previous hash" and returns true.
func Changed(expected, actual string) bool {
	if expected == "" {
		return true // No previous hash, consider it changed
	}
	return expected != actual
}
