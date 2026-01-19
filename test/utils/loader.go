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

package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// FixtureLoader provides utilities for loading and templating test fixtures.
type FixtureLoader struct {
	basePath string
	cache    map[string]string
}

// NewFixtureLoader creates a new FixtureLoader with the given base path.
// If basePath is empty, it defaults to "test/e2e/fixtures".
func NewFixtureLoader(basePath string) *FixtureLoader {
	if basePath == "" {
		basePath = "test/e2e/fixtures"
	}
	return &FixtureLoader{
		basePath: basePath,
		cache:    make(map[string]string),
	}
}

// LoadPolicy loads an HCL policy file from the policies directory.
// The filename should not include the .hcl extension.
func (l *FixtureLoader) LoadPolicy(name string) (string, error) {
	return l.loadFile(filepath.Join("policies", name+".hcl"))
}

// LoadPolicyWithData loads an HCL policy and applies template substitutions.
// Template variables use Go's text/template syntax (e.g., {{.Namespace}}).
func (l *FixtureLoader) LoadPolicyWithData(name string, data any) (string, error) {
	content, err := l.LoadPolicy(name)
	if err != nil {
		return "", err
	}
	return l.applyTemplate(name, content, data)
}

// LoadCRD loads a CRD YAML file from the crds directory.
// The path should be relative to the crds directory (e.g., "vaultpolicy/basic.yaml").
func (l *FixtureLoader) LoadCRD(relPath string) (string, error) {
	return l.loadFile(filepath.Join("crds", relPath))
}

// LoadCRDWithData loads a CRD YAML and applies template substitutions.
func (l *FixtureLoader) LoadCRDWithData(relPath string, data any) (string, error) {
	content, err := l.LoadCRD(relPath)
	if err != nil {
		return "", err
	}
	return l.applyTemplate(relPath, content, data)
}

// LoadExpected loads an expected output file from the expected directory.
func (l *FixtureLoader) LoadExpected(name string) (string, error) {
	return l.loadFile(filepath.Join("expected", name))
}

// LoadRaw loads a file directly from the fixtures directory.
func (l *FixtureLoader) LoadRaw(relPath string) (string, error) {
	return l.loadFile(relPath)
}

// loadFile reads a file and caches its content.
func (l *FixtureLoader) loadFile(relPath string) (string, error) {
	fullPath := filepath.Join(l.basePath, relPath)

	// Check cache first
	if content, ok := l.cache[fullPath]; ok {
		return content, nil
	}

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to load fixture %s: %w", relPath, err)
	}

	content := string(data)
	l.cache[fullPath] = content
	return content, nil
}

// applyTemplate applies Go template substitutions to content.
func (l *FixtureLoader) applyTemplate(name string, content string, data any) (string, error) {
	tmpl, err := template.New(name).Parse(content)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}

	return buf.String(), nil
}

// ClearCache clears the fixture cache.
func (l *FixtureLoader) ClearCache() {
	l.cache = make(map[string]string)
}

// PolicyData holds common template data for policy fixtures.
type PolicyData struct {
	Namespace string
	Path      string
	Name      string
}

// CRDData holds common template data for CRD fixtures.
type CRDData struct {
	Name            string
	Namespace       string
	ConnectionRef   string
	VaultNamespace  string
	ServiceAccount  string
	PolicyName      string
	PolicyNamespace string
	TokenTTL        string
	TokenMaxTTL     string
	AuthPath        string
	Rules           []RuleData
	TestID          string // Unique identifier for test isolation
}

// RuleData holds data for a single policy rule.
type RuleData struct {
	Path         string
	Capabilities []string
	Description  string
}

// Global fixture loader instance (initialized lazily).
var defaultLoader *FixtureLoader

// GetFixtureLoader returns the default fixture loader.
// It auto-detects the fixtures path based on common locations.
func GetFixtureLoader() *FixtureLoader {
	if defaultLoader == nil {
		basePath := findFixturesPath()
		defaultLoader = NewFixtureLoader(basePath)
	}
	return defaultLoader
}

// findFixturesPath attempts to locate the fixtures directory.
func findFixturesPath() string {
	// Try common paths
	paths := []string{
		"test/e2e/fixtures",
		"../e2e/fixtures",
		"../../test/e2e/fixtures",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Default fallback
	return "test/e2e/fixtures"
}

// LoadPolicy is a convenience function using the default loader.
func LoadPolicy(name string) (string, error) {
	return GetFixtureLoader().LoadPolicy(name)
}

// LoadPolicyWithData is a convenience function using the default loader.
func LoadPolicyWithData(name string, data any) (string, error) {
	return GetFixtureLoader().LoadPolicyWithData(name, data)
}

// LoadCRD is a convenience function using the default loader.
func LoadCRD(relPath string) (string, error) {
	return GetFixtureLoader().LoadCRD(relPath)
}

// LoadCRDWithData is a convenience function using the default loader.
func LoadCRDWithData(relPath string, data any) (string, error) {
	return GetFixtureLoader().LoadCRDWithData(relPath, data)
}

// GenerateTestID generates a unique test identifier for resource isolation.
// Format: {prefix}-{random8chars}
func GenerateTestID(prefix string) string {
	// Use a simple timestamp-based approach for uniqueness
	// In production tests, this provides enough isolation
	timestamp := fmt.Sprintf("%d", os.Getpid())
	if len(timestamp) > 8 {
		timestamp = timestamp[len(timestamp)-8:]
	}
	return fmt.Sprintf("%s-%s", prefix, timestamp)
}

// SanitizeResourceName ensures a string is valid for K8s resource names.
// - Converts to lowercase
// - Replaces underscores with hyphens
// - Truncates to 63 characters (K8s limit)
func SanitizeResourceName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, " ", "-")

	// Remove any characters that aren't alphanumeric or hyphens
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}

	name = result.String()

	// Ensure it doesn't start or end with a hyphen
	name = strings.Trim(name, "-")

	// Truncate to 63 characters
	if len(name) > 63 {
		name = name[:63]
		// Ensure truncation doesn't leave a trailing hyphen
		name = strings.TrimRight(name, "-")
	}

	return name
}
