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

// Package controller provides the discovery controller implementation.
package controller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/metrics"
	"github.com/panteparak/vault-access-operator/pkg/vault"
)

// SystemPolicies are Vault's built-in policies that should typically be excluded
var SystemPolicies = map[string]bool{
	"root":              true,
	"default":           true,
	"response-wrapping": true,
}

// ScanResult contains the results of a discovery scan
type ScanResult struct {
	// UnmanagedPolicies are policies in Vault not managed by any K8s resource
	UnmanagedPolicies []string

	// UnmanagedRoles are roles in Vault not managed by any K8s resource
	UnmanagedRoles []string

	// DiscoveredResources contains detailed info about discovered resources
	DiscoveredResources []vaultv1alpha1.DiscoveredResource

	// Error if the scan failed
	Error error
}

// Scanner scans Vault for unmanaged resources
type Scanner struct {
	vaultClient *vault.Client
	config      *vaultv1alpha1.DiscoveryConfig
	authPath    string // Kubernetes auth mount path for role discovery
	// managedRoles is the set of Vault role names the cluster's role CRs
	// derive to (computed by the reconciler from VaultRole/VaultClusterRole
	// lists). Roles carry no in-band ownership record (ADR 0008), so the CR
	// set IS the ownership source for role discovery.
	managedRoles map[string]struct{}
	log          logr.Logger
}

// NewScanner creates a new Scanner.
// authPath is the Kubernetes auth mount path (defaults to "auth/kubernetes" if empty).
// managedRoles is the CR-derived set of owned Vault role names (may be nil).
func NewScanner(
	vaultClient *vault.Client, config *vaultv1alpha1.DiscoveryConfig,
	authPath string, managedRoles map[string]struct{}, log logr.Logger,
) *Scanner {
	if authPath == "" {
		authPath = vault.DefaultKubernetesAuthPath
	}
	return &Scanner{
		vaultClient:  vaultClient,
		config:       config,
		authPath:     authPath,
		managedRoles: managedRoles,
		log:          log.WithName("scanner"),
	}
}

// Scan performs a discovery scan against Vault.
// Each phase (policies, roles) runs independently — a failure in one phase
// does not prevent the other from executing.
func (s *Scanner) Scan(ctx context.Context) *ScanResult {
	result := &ScanResult{
		UnmanagedPolicies:   make([]string, 0),
		UnmanagedRoles:      make([]string, 0),
		DiscoveredResources: make([]vaultv1alpha1.DiscoveredResource, 0),
	}

	s.log.V(1).Info("starting discovery scan")

	var errs []error

	// Scan policies
	if err := s.scanPolicies(ctx, result); err != nil {
		s.log.Error(err, "failed to scan policies (continuing with roles)")
		errs = append(errs, fmt.Errorf("policies: %w", err))
	}

	// Scan roles
	if err := s.scanRoles(ctx, result); err != nil {
		s.log.Error(err, "failed to scan roles (continuing)")
		errs = append(errs, fmt.Errorf("roles: %w", err))
	}

	if len(errs) > 0 {
		result.Error = errors.Join(errs...)
	}

	s.log.Info("discovery scan completed",
		"unmanagedPolicies", len(result.UnmanagedPolicies),
		"unmanagedRoles", len(result.UnmanagedRoles))

	return result
}

// scanPolicies scans for unmanaged policies. Ownership is read in-band from
// each candidate policy's comment header (ADR 0008) — filters run FIRST so
// only candidates that could actually be surfaced cost a policy read. Any
// operator-managed policy is skipped, whether owned by this operator or a
// foreign one (a foreign owner's policy must never become an adoption
// candidate on a shared Vault).
func (s *Scanner) scanPolicies(ctx context.Context, result *ScanResult) error {
	// List all policies in Vault
	allPolicies, err := s.vaultClient.ListPolicies(ctx)
	if err != nil {
		return err
	}

	now := metav1.Now()
	for _, policyName := range allPolicies {
		// Skip system policies if configured
		if s.shouldExcludeSystemPolicy(policyName) {
			continue
		}

		// Check against pattern filters
		if !s.matchesPolicyPatterns(policyName) {
			continue
		}

		// Skip if operator-managed (ours or foreign). A read failure skips
		// the candidate conservatively — better to miss a discovery than to
		// offer a possibly-owned policy for adoption.
		own, err := s.vaultClient.GetPolicyOwnership(ctx, policyName)
		if err != nil {
			s.log.V(1).Info("failed to read policy ownership; skipping candidate",
				"policy", policyName, "error", err.Error())
			continue
		}
		if own != nil {
			if own.AuthMount != s.vaultClient.AuthMount() {
				s.log.V(1).Info("policy managed by a foreign operator; excluded from discovery",
					"policy", policyName, "owner", own.String())
			}
			continue
		}

		result.UnmanagedPolicies = append(result.UnmanagedPolicies, policyName)
		result.DiscoveredResources = append(result.DiscoveredResources, vaultv1alpha1.DiscoveredResource{
			Type:            "policy",
			Name:            policyName,
			DiscoveredAt:    now,
			SuggestedCRName: suggestCRName(policyName),
			AdoptionStatus:  "discovered",
		})
	}

	return nil
}

// scanRoles scans for unmanaged Kubernetes auth roles. Roles carry no
// in-band ownership record (ADR 0008): the managed set is derived from the
// cluster's role CRs by the reconciler and injected at construction. The
// scan only ever targets this connection's own mount — under the
// one-cluster-per-mount invariant, everything here is legitimately in scope.
func (s *Scanner) scanRoles(ctx context.Context, result *ScanResult) error {
	authPath := s.authPath

	// List all roles in Vault
	allRoles, err := s.vaultClient.ListKubernetesAuthRoles(ctx, authPath)
	if err != nil {
		return err
	}
	if allRoles == nil {
		return nil
	}

	now := metav1.Now()
	for _, roleName := range allRoles {
		// Skip if a role CR already derives to this Vault role name
		if _, managed := s.managedRoles[roleName]; managed {
			continue
		}

		// Check against pattern filters
		if !s.matchesRolePatterns(roleName) {
			continue
		}

		result.UnmanagedRoles = append(result.UnmanagedRoles, roleName)
		result.DiscoveredResources = append(result.DiscoveredResources, vaultv1alpha1.DiscoveredResource{
			Type:            "role",
			Name:            roleName,
			DiscoveredAt:    now,
			SuggestedCRName: suggestCRName(roleName),
			AdoptionStatus:  "discovered",
		})
	}

	return nil
}

// shouldExcludeSystemPolicy returns true if the policy should be excluded
func (s *Scanner) shouldExcludeSystemPolicy(policyName string) bool {
	// Check the config - if explicitly disabled, don't exclude any
	if s.config.ExcludeSystemPolicies != nil && !*s.config.ExcludeSystemPolicies {
		return false
	}

	// Check built-in system policies
	if SystemPolicies[policyName] {
		return true
	}

	// Check custom system policies (user-defined)
	for _, customPolicy := range s.config.CustomSystemPolicies {
		if customPolicy == policyName {
			return true
		}
	}

	return false
}

// matchesPolicyPatterns checks if a policy name matches the configured patterns.
// filepath.Match errors are logged at Error level instead of silently dropped —
// the webhook validates patterns at admission, so an error here means either
// (a) the CR was applied with the webhook unavailable (failurePolicy=Ignore),
// or (b) a bug in ValidatePatterns. Either way the operator should know.
func (s *Scanner) matchesPolicyPatterns(policyName string) bool {
	if len(s.config.PolicyPatterns) == 0 {
		return true // No patterns means match all
	}

	for _, pattern := range s.config.PolicyPatterns {
		matched, err := filepath.Match(pattern, policyName)
		if err != nil {
			s.log.Error(err, "invalid glob pattern in policyPatterns (bypassing webhook validation?)",
				"pattern", pattern, "policyName", policyName)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// matchesRolePatterns checks if a role name matches the configured patterns.
// Same logging contract as matchesPolicyPatterns.
func (s *Scanner) matchesRolePatterns(roleName string) bool {
	if len(s.config.RolePatterns) == 0 {
		return true // No patterns means match all
	}

	for _, pattern := range s.config.RolePatterns {
		matched, err := filepath.Match(pattern, roleName)
		if err != nil {
			s.log.Error(err, "invalid glob pattern in rolePatterns (bypassing webhook validation?)",
				"pattern", pattern, "roleName", roleName)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// invalidK8sChars matches characters that are not valid in Kubernetes names.
var invalidK8sChars = regexp.MustCompile(`[^a-z0-9-]`)

// suggestCRName generates a suggested Kubernetes resource name from a Vault resource name.
// The result is RFC 1123 compliant:
//   - Lowercase only
//   - Only alphanumeric characters and hyphens
//   - Must start and end with alphanumeric character
//   - Maximum 253 characters
func suggestCRName(vaultName string) string {
	if vaultName == "" {
		return "vault-resource"
	}

	// Convert to lowercase
	name := strings.ToLower(vaultName)

	// Replace invalid characters with hyphens
	name = invalidK8sChars.ReplaceAllString(name, "-")

	// Collapse multiple consecutive hyphens into one
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// Trim leading and trailing hyphens
	name = strings.Trim(name, "-")

	// Truncate to 253 characters (Kubernetes resource name limit)
	if len(name) > 253 {
		name = name[:253]
		// Ensure we don't end with a hyphen after truncation
		name = strings.TrimRight(name, "-")
	}

	// If empty after sanitization, use a fallback
	if name == "" {
		return "vault-resource"
	}

	return name
}

// ValidatePatterns validates glob patterns for correctness.
// Returns an error for each invalid pattern, indexed by position.
func ValidatePatterns(patterns []string) map[int]error {
	errs := make(map[int]error)
	for i, pattern := range patterns {
		// filepath.Match returns an error only for malformed patterns
		_, err := filepath.Match(pattern, "test")
		if err != nil {
			errs[i] = err
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// UpdateMetrics updates Prometheus metrics based on scan results
func (s *Scanner) UpdateMetrics(connectionName string, result *ScanResult) {
	metrics.SetDiscoveredResources(connectionName, "policy", len(result.UnmanagedPolicies))
	metrics.SetDiscoveredResources(connectionName, "role", len(result.UnmanagedRoles))
	metrics.IncrementDiscoveryScan(connectionName, result.Error == nil)
}

// ParseInterval parses the interval string to a duration, with a default
func ParseInterval(interval string) time.Duration {
	if interval == "" {
		return time.Hour // Default to 1 hour
	}

	d, err := time.ParseDuration(interval)
	if err != nil {
		return time.Hour // Default on parse error
	}
	return d
}
