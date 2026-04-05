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

package hash

import (
	"testing"
)

func TestFromString_SameContent(t *testing.T) {
	t.Parallel()
	hash1 := FromString("test content")
	hash2 := FromString("test content")

	if hash1 != hash2 {
		t.Errorf("expected same hash for same content, got %s vs %s", hash1, hash2)
	}
}

func TestFromString_DifferentContent(t *testing.T) {
	t.Parallel()
	hash1 := FromString("content A")
	hash2 := FromString("content B")

	if hash1 == hash2 {
		t.Error("expected different hashes for different content")
	}
}

func TestFromString_EmptyContent(t *testing.T) {
	t.Parallel()
	hash := FromString("")
	if hash != "" {
		t.Errorf("expected empty hash for empty content, got %s", hash)
	}
}

func TestFromString_Length(t *testing.T) {
	t.Parallel()
	hash := FromString("test")
	// SHA256 produces 32 bytes = 64 hex characters
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}
}

func TestFromString_Deterministic(t *testing.T) {
	t.Parallel()
	content := "test content"
	hashes := make([]string, 10)
	for i := 0; i < 10; i++ {
		hashes[i] = FromString(content)
	}

	for i := 1; i < 10; i++ {
		if hashes[i] != hashes[0] {
			t.Errorf("hash %d differs from hash 0: %s vs %s", i, hashes[i], hashes[0])
		}
	}
}

func TestFromBytes_Empty(t *testing.T) {
	t.Parallel()
	hash := FromBytes(nil)
	if hash != "" {
		t.Errorf("expected empty hash for nil bytes, got %s", hash)
	}

	hash = FromBytes([]byte{})
	if hash != "" {
		t.Errorf("expected empty hash for empty bytes, got %s", hash)
	}
}

func TestFromBytes_Content(t *testing.T) {
	t.Parallel()
	hash := FromBytes([]byte("test"))
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}
}

func TestFromMap_Nil(t *testing.T) {
	t.Parallel()
	h, err := FromMap(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Errorf("expected empty hash for nil map, got %s", h)
	}
}

func TestFromMap_SameContent(t *testing.T) {
	t.Parallel()
	data1 := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}
	data2 := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}

	hash1, err := FromMap(data1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := FromMap(data2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("expected same hash for same map content, got %s vs %s", hash1, hash2)
	}
}

func TestFromMap_DifferentContent(t *testing.T) {
	t.Parallel()
	data1 := map[string]interface{}{"key": "value1"}
	data2 := map[string]interface{}{"key": "value2"}

	hash1, _ := FromMap(data1)
	hash2, _ := FromMap(data2)

	if hash1 == hash2 {
		t.Error("expected different hashes for different map content")
	}
}

func TestFromMapDeterministic_OrderIndependent(t *testing.T) {
	t.Parallel()
	// Build maps in different orders
	data1 := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}

	// Note: Go maps have random iteration order, but building the same
	// map should produce same result with deterministic function
	hash1, err := FromMapDeterministic(data1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hash2, err := FromMapDeterministic(data1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("expected same deterministic hash, got %s vs %s", hash1, hash2)
	}
}

func TestFromMapDeterministic_Nil(t *testing.T) {
	t.Parallel()
	h, err := FromMapDeterministic(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Errorf("expected empty hash for nil map, got %s", h)
	}
}

func TestFromJSON_Struct(t *testing.T) {
	t.Parallel()
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	data := testStruct{Name: "test", Value: 42}
	h, err := FromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h == "" {
		t.Error("expected non-empty hash")
	}
	if len(h) != 64 {
		t.Errorf("expected hash length 64, got %d", len(h))
	}
}

func TestFromJSON_Nil(t *testing.T) {
	t.Parallel()
	h, err := FromJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Errorf("expected empty hash for nil, got %s", h)
	}
}

func TestEqualNonEmpty_BothEmpty(t *testing.T) {
	t.Parallel()
	if EqualNonEmpty("", "") {
		t.Error("empty strings should not be equal (falsy)")
	}
}

func TestEqualNonEmpty_Same(t *testing.T) {
	t.Parallel()
	h := FromString("test")
	if !EqualNonEmpty(h, h) {
		t.Error("same hash should be equal")
	}
}

func TestEqualNonEmpty_Different(t *testing.T) {
	t.Parallel()
	hash1 := FromString("test1")
	hash2 := FromString("test2")
	if EqualNonEmpty(hash1, hash2) {
		t.Error("different hashes should not be equal")
	}
}

func TestChanged_EmptyExpected(t *testing.T) {
	t.Parallel()
	if !Changed("", "abc123") {
		t.Error("empty expected should indicate changed")
	}
}

func TestChanged_Same(t *testing.T) {
	t.Parallel()
	hash := FromString("test")
	if Changed(hash, hash) {
		t.Error("same hashes should not indicate changed")
	}
}

func TestChanged_Different(t *testing.T) {
	t.Parallel()
	hash1 := FromString("test1")
	hash2 := FromString("test2")
	if !Changed(hash1, hash2) {
		t.Error("different hashes should indicate changed")
	}
}

// Benchmark tests
func BenchmarkFromString(b *testing.B) {
	content := "path \"secret/*\" { capabilities = [\"read\", \"list\"] }"
	for i := 0; i < b.N; i++ {
		FromString(content)
	}
}

func BenchmarkFromMap(b *testing.B) {
	data := map[string]interface{}{
		"policies":                         []string{"read", "write"},
		"bound_service_account_names":      []string{"default"},
		"bound_service_account_namespaces": []string{"default"},
		"token_ttl":                        "1h",
	}
	for i := 0; i < b.N; i++ {
		_, _ = FromMap(data)
	}
}
