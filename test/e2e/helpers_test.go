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

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test Resource Builders
// ─────────────────────────────────────────────────────────────────────────────

// uniqueName generates a unique resource name to avoid conflicts between tests.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%100000)
}

// BuildTestPolicy creates a VaultPolicy with sensible defaults for testing.
func BuildTestPolicy(name string) *vaultv1alpha1.VaultPolicy {
	return &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: sharedVaultConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{
				{
					Path: "secret/data/test/*",
					Capabilities: []vaultv1alpha1.Capability{
						vaultv1alpha1.CapabilityRead,
					},
				},
			},
		},
	}
}

// BuildPolicyWithPath creates a VaultPolicy with a specific path and optional namespace enforcement.
func BuildPolicyWithPath(name, path string, enforceNS bool) *vaultv1alpha1.VaultPolicy {
	p := BuildTestPolicy(name)
	p.Spec.Rules[0].Path = path
	p.Spec.EnforceNamespaceBoundary = &enforceNS
	return p
}

// BuildPolicyWithCapabilities creates a VaultPolicy with specific capabilities.
func BuildPolicyWithCapabilities(name string, caps []vaultv1alpha1.Capability) *vaultv1alpha1.VaultPolicy {
	p := BuildTestPolicy(name)
	p.Spec.Rules[0].Capabilities = caps
	return p
}

// BuildPolicyWithRules creates a VaultPolicy with a specified number of rules.
func BuildPolicyWithRules(name string, ruleCount int) *vaultv1alpha1.VaultPolicy {
	p := BuildTestPolicy(name)
	p.Spec.Rules = make([]vaultv1alpha1.PolicyRule, ruleCount)
	for i := 0; i < ruleCount; i++ {
		p.Spec.Rules[i] = vaultv1alpha1.PolicyRule{
			Path:         fmt.Sprintf("secret/data/rule-%d/*", i),
			Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
		}
	}
	return p
}

// BuildTestRole creates a VaultRole with sensible defaults for testing.
func BuildTestRole(name, serviceAccount, policyName string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   sharedVaultConnectionName,
			ServiceAccounts: []string{serviceAccount},
			Policies: []vaultv1alpha1.PolicyReference{
				{
					Kind:      "VaultPolicy",
					Name:      policyName,
					Namespace: testNamespace,
				},
			},
			TokenTTL: "30m",
		},
	}
}

// BuildRoleWithTTL creates a VaultRole with a specific TTL.
func BuildRoleWithTTL(name, serviceAccount, policyName, ttl string) *vaultv1alpha1.VaultRole {
	r := BuildTestRole(name, serviceAccount, policyName)
	r.Spec.TokenTTL = ttl
	return r
}

// BuildRoleWithMultipleSAs creates a VaultRole with multiple service accounts.
func BuildRoleWithMultipleSAs(name string, serviceAccounts []string, policyName string) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   sharedVaultConnectionName,
			ServiceAccounts: serviceAccounts,
			Policies: []vaultv1alpha1.PolicyReference{
				{
					Kind:      "VaultPolicy",
					Name:      policyName,
					Namespace: testNamespace,
				},
			},
			TokenTTL: "30m",
		},
	}
}

// BuildRoleWithMultiplePolicies creates a VaultRole with multiple policy references.
func BuildRoleWithMultiplePolicies(
	name, serviceAccount string,
	policies []vaultv1alpha1.PolicyReference,
) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   sharedVaultConnectionName,
			ServiceAccounts: []string{serviceAccount},
			Policies:        policies,
			TokenTTL:        "30m",
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Helpers
// ─────────────────────────────────────────────────────────────────────────────

// AllCRUDCapabilities returns all standard CRUD + list capabilities.
func AllCRUDCapabilities() []vaultv1alpha1.Capability {
	return []vaultv1alpha1.Capability{
		vaultv1alpha1.CapabilityCreate,
		vaultv1alpha1.CapabilityRead,
		vaultv1alpha1.CapabilityUpdate,
		vaultv1alpha1.CapabilityDelete,
		vaultv1alpha1.CapabilityList,
	}
}

// AllCapabilities returns all available capabilities including sudo.
func AllCapabilities() []vaultv1alpha1.Capability {
	return []vaultv1alpha1.Capability{
		vaultv1alpha1.CapabilityCreate,
		vaultv1alpha1.CapabilityRead,
		vaultv1alpha1.CapabilityUpdate,
		vaultv1alpha1.CapabilityDelete,
		vaultv1alpha1.CapabilityList,
		vaultv1alpha1.CapabilitySudo,
	}
}

// ReadOnlyCapabilities returns read and list capabilities.
func ReadOnlyCapabilities() []vaultv1alpha1.Capability {
	return []vaultv1alpha1.Capability{
		vaultv1alpha1.CapabilityRead,
		vaultv1alpha1.CapabilityList,
	}
}

// CapabilitiesToStrings converts capability slice to string slice for comparisons.
func CapabilitiesToStrings(caps []vaultv1alpha1.Capability) []string {
	result := make([]string, len(caps))
	for i, c := range caps {
		result[i] = string(c)
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase & Status Assertions
// ─────────────────────────────────────────────────────────────────────────────

// WaitForPolicyPhase waits for a VaultPolicy to reach the expected phase.
// Uses Gomega Eventually which fails the test automatically if not satisfied.
func WaitForPolicyPhase(ctx context.Context, name, namespace string, expectedPhase string, timeout time.Duration) {
	Eventually(func(g Gomega) {
		status, err := utils.GetVaultPolicyStatus(ctx, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal(expectedPhase))
	}, timeout, 2*time.Second).Should(Succeed())
}

// WaitForRolePhase waits for a VaultRole to reach the expected phase.
// Uses Gomega Eventually which fails the test automatically if not satisfied.
func WaitForRolePhase(ctx context.Context, name, namespace string, expectedPhase string, timeout time.Duration) {
	Eventually(func(g Gomega) {
		status, err := utils.GetVaultRoleStatus(ctx, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal(expectedPhase))
	}, timeout, 2*time.Second).Should(Succeed())
}

// ExpectPolicyActive waits for a VaultPolicy to become Active.
func ExpectPolicyActive(ctx context.Context, name string) {
	Eventually(func(g Gomega) {
		status, err := utils.GetVaultPolicyStatus(ctx, name, testNamespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal("Active"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// ExpectRoleActive waits for a VaultRole to become Active.
func ExpectRoleActive(ctx context.Context, name string) {
	Eventually(func(g Gomega) {
		status, err := utils.GetVaultRoleStatus(ctx, name, testNamespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal("Active"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// ExpectPhaseNotActive waits for a resource to be in a non-Active phase.
func ExpectPhaseNotActive(ctx context.Context, statusFunc func() (string, error)) {
	Eventually(func(g Gomega) {
		status, err := statusFunc()
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).NotTo(Equal("Active"))
		g.Expect(status).To(Or(
			Equal("Error"),
			Equal("Pending"),
			Equal("Syncing"),
		))
	}, 30*time.Second, 2*time.Second).Should(Succeed())
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault Verification Helpers
// ─────────────────────────────────────────────────────────────────────────────

// ExpectPolicyInVault verifies that a policy exists in Vault with expected name.
func ExpectPolicyInVault(ctx context.Context, vaultPolicyName string) {
	vaultClient, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	Eventually(func(g Gomega) {
		exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(exists).To(BeTrue())
	}, 30*time.Second, 2*time.Second).Should(Succeed())
}

// ExpectPolicyNotInVault verifies that a policy does NOT exist in Vault.
func ExpectPolicyNotInVault(ctx context.Context, vaultPolicyName string) {
	vaultClient, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	Eventually(func(g Gomega) {
		exists, err := vaultClient.PolicyExists(ctx, vaultPolicyName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(exists).To(BeFalse())
	}, 30*time.Second, 2*time.Second).Should(Succeed())
}

// ExpectRoleInVault verifies that a role exists in Vault.
func ExpectRoleInVault(ctx context.Context, authPath, vaultRoleName string) {
	vaultClient, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	Eventually(func(g Gomega) {
		exists, err := vaultClient.RoleExists(ctx, authPath, vaultRoleName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(exists).To(BeTrue())
	}, 30*time.Second, 2*time.Second).Should(Succeed())
}

// ExpectRoleNotInVault verifies that a role does NOT exist in Vault.
func ExpectRoleNotInVault(ctx context.Context, authPath, vaultRoleName string) {
	vaultClient, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	Eventually(func(g Gomega) {
		exists, err := vaultClient.RoleExists(ctx, authPath, vaultRoleName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(exists).To(BeFalse())
	}, 30*time.Second, 2*time.Second).Should(Succeed())
}

// GetVaultPolicyContent reads policy content from Vault.
func GetVaultPolicyContent(ctx context.Context, vaultPolicyName string) (string, error) {
	vaultClient, err := utils.GetTestVaultClient()
	if err != nil {
		return "", err
	}
	return vaultClient.ReadPolicy(ctx, vaultPolicyName)
}

// ─────────────────────────────────────────────────────────────────────────────
// Cleanup Helpers
// ─────────────────────────────────────────────────────────────────────────────

// CleanupPolicy deletes a VaultPolicy and waits for cleanup.
func CleanupPolicy(ctx context.Context, name string) {
	_ = utils.DeleteVaultPolicyCR(ctx, name, testNamespace)
	_ = utils.WaitForDeletion(
		ctx, &vaultv1alpha1.VaultPolicy{},
		name, testNamespace,
		30*time.Second, 2*time.Second,
	)
}

// CleanupRole deletes a VaultRole and waits for cleanup.
func CleanupRole(ctx context.Context, name string) {
	_ = utils.DeleteVaultRoleCR(ctx, name, testNamespace)
	_ = utils.WaitForDeletion(
		ctx, &vaultv1alpha1.VaultRole{},
		name, testNamespace,
		30*time.Second, 2*time.Second,
	)
}

// CleanupServiceAccount deletes a ServiceAccount.
func CleanupServiceAccount(ctx context.Context, name string) {
	_ = utils.DeleteServiceAccount(ctx, testNamespace, name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Data Constants
// ─────────────────────────────────────────────────────────────────────────────

// ValidPaths contains paths that should pass validation.
var ValidPaths = []string{
	"secret/data/myapp",
	"secret/data/*",
	"secret/data/{{namespace}}/*",
	"auth/kubernetes/role/*",
	"sys/policies/acl/*",
	"secret/+/data",
	"kv/data/team-a/app-1",
}

// InvalidPathChars contains characters that should be rejected in paths.
var InvalidPathChars = []string{
	";",  // shell injection
	"|",  // pipe
	"&",  // command chaining
	"$",  // variable expansion
	"`",  // command substitution
	"\\", // escape char
	"'",  // quote
	"\"", // double quote
	"(",  // subshell
	")",  // subshell
	"<",  // redirect
	">",  // redirect
}

// ValidTTLs contains TTL values that should pass validation.
var ValidTTLs = []string{
	"30s",
	"5m",
	"30m",
	"1h",
	"24h",
	"168h", // 1 week
}

// InvalidTTLs contains TTL values that should fail validation.
var InvalidTTLs = []string{
	"invalid-ttl",
	"thirty-minutes",
	"",
	"-1h",
	"abc",
}
