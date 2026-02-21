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
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test Resource Builders
// ─────────────────────────────────────────────────────────────────────────────

// uniqueCounter is an atomic counter that guarantees unique names even when
// called in tight loops (e.g., batch fuzz item generation) where
// time.Now().UnixNano() may return duplicate values.
var uniqueCounter atomic.Int64

// uniqueName generates a unique resource name to avoid conflicts between tests.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, uniqueCounter.Add(1))
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
			TokenTTL: "2m",
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
			TokenTTL: "2m",
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
			TokenTTL:        "2m",
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
// Token Refresh Helpers
// ─────────────────────────────────────────────────────────────────────────────

// RefreshSharedVaultToken creates a fresh operator token and updates the shared
// VaultConnection's token secret. This must be called in BeforeAll of any test
// suite that depends on the shared connection and runs after suites that create
// or delete VaultConnections — connection finalizers revoke tokens, which can
// invalidate the cached Vault client for the shared connection.
func RefreshSharedVaultToken(ctx context.Context) {
	By("refreshing shared VaultConnection token")
	vc, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	operatorToken, err := vc.CreateToken(ctx, []string{operatorPolicyName}, "4h")
	Expect(err).NotTo(HaveOccurred())

	// Delete-and-recreate to guarantee the secret holds a valid token.
	_ = utils.DeleteSecret(ctx, testNamespace, sharedVaultTokenSecretName)
	err = utils.CreateSecret(ctx, testNamespace, sharedVaultTokenSecretName,
		map[string][]byte{"token": []byte(operatorToken)})
	Expect(err).NotTo(HaveOccurred())

	// Wait for the operator to pick up the new token and re-sync the connection.
	Eventually(func(g Gomega) {
		conn, err := utils.GetVaultConnection(ctx, sharedVaultConnectionName, "")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(string(conn.Status.Phase)).To(Equal("Active"))
	}, 30*time.Second, 2*time.Second).Should(Succeed())
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

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz Batch Runner
// ─────────────────────────────────────────────────────────────────────────────

// FuzzBatchItem holds a single fuzz-generated resource for batch processing.
type FuzzBatchItem struct {
	Name string      // K8s resource name (for cleanup)
	Data interface{} // Test-specific payload (ruleCount, caps, etc.)
}

// RunFuzzBatch replaces rapid.Check for E2E fuzz tests. It creates N
// resources in batches of batchSize, waiting once per batch for reconciliation
// instead of once per item. This reduces total fuzz time from ~7min/test to
// ~1min/test by amortizing the reconciliation wait across the batch.
//
// The RNG is seeded from GinkgoRandomSeed() so failures are reproducible
// via --seed.
//
// Named RunFuzzBatch (not FuzzBatchRunner) to avoid Go's "Fuzz" prefix
// convention which expects func FuzzXxx(f *testing.F).
func RunFuzzBatch(
	ctx context.Context,
	generate func(rng *rand.Rand, idx int) FuzzBatchItem,
	create func(ctx context.Context, item FuzzBatchItem) error,
	verify func(ctx context.Context, item FuzzBatchItem),
	cleanup func(ctx context.Context, item FuzzBatchItem),
) {
	total := fuzzIterations
	batchSz := fuzzBatchSize
	rng := rand.New(rand.NewPCG(uint64(GinkgoRandomSeed()), 0xCAFE))

	for batchStart := 0; batchStart < total; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > total {
			batchEnd = total
		}
		batchLen := batchEnd - batchStart

		// 1. Generate all items for this batch
		items := make([]FuzzBatchItem, batchLen)
		for i := range items {
			items[i] = generate(rng, batchStart+i)
		}

		// 2. Create all CRs, tracking which succeeded
		created := make([]bool, batchLen)
		for i, item := range items {
			if err := create(ctx, item); err == nil {
				created[i] = true
			}
		}

		// 3. Wait once for reconciliation: max(3s, len(created) * 200ms)
		createdCount := 0
		for _, ok := range created {
			if ok {
				createdCount++
			}
		}
		wait := time.Duration(createdCount) * 200 * time.Millisecond
		if wait < 3*time.Second {
			wait = 3 * time.Second
		}
		time.Sleep(wait)

		// 4. Verify all successfully created items
		for i, item := range items {
			if created[i] {
				verify(ctx, item)
			}
		}

		// 5. Cleanup all items in parallel (including failed creates, for safety)
		var wg sync.WaitGroup
		for _, item := range items {
			wg.Add(1)
			go func(it FuzzBatchItem) {
				defer wg.Done()
				cleanup(ctx, it)
			}(item)
		}
		wg.Wait()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Random Generators (replace rapid.StringMatching for batch fuzz)
// ─────────────────────────────────────────────────────────────────────────────

const (
	charsetAlphaNum      = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetAlphaNumUpper = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetPath          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_*+-"
)

// randStringFromCharset generates a random string of length [minLen, maxLen]
// from the given character set.
func randStringFromCharset(rng *rand.Rand, charset string, minLen, maxLen int) string {
	n := minLen + rng.IntN(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rng.IntN(len(charset))]
	}
	return string(b)
}

// randPath generates a random valid CRD path (matches `[a-zA-Z0-9/_*+-]{1,50}`).
func randPath(rng *rand.Rand) string {
	return randStringFromCharset(rng, charsetPath, 1, 50)
}

// randSegment generates a lowercase alphanumeric segment (matches `[a-z0-9]{1,10}`).
func randSegment(rng *rand.Rand) string {
	return randStringFromCharset(rng, charsetAlphaNum, 1, 10)
}

// randDNSName generates a DNS-1123 compliant name (starts/ends with alphanumeric,
// middle may contain hyphens). Length 1–20.
func randDNSName(rng *rand.Rand) string {
	const dnsChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
	n := 1 + rng.IntN(20)
	if n == 1 {
		return string(charsetAlphaNum[rng.IntN(len(charsetAlphaNum))])
	}
	var b strings.Builder
	b.WriteByte(charsetAlphaNum[rng.IntN(len(charsetAlphaNum))])
	for i := 1; i < n-1; i++ {
		b.WriteByte(dnsChars[rng.IntN(len(dnsChars))])
	}
	b.WriteByte(charsetAlphaNum[rng.IntN(len(charsetAlphaNum))])
	return b.String()
}

// randTTL generates a random TTL-like string: one of valid Go durations,
// compound durations, pure numbers, random text, or empty string.
func randTTL(rng *rand.Rand) string {
	switch rng.IntN(5) {
	case 0: // Valid Go duration: [0-9]{1,3}[smh]
		units := []byte{'s', 'm', 'h'}
		n := 1 + rng.IntN(999)
		return fmt.Sprintf("%d%c", n, units[rng.IntN(len(units))])
	case 1: // Compound duration: [0-9]{1,2}h[0-9]{1,2}m
		h := 1 + rng.IntN(99)
		m := 1 + rng.IntN(99)
		return fmt.Sprintf("%dh%dm", h, m)
	case 2: // Pure number (should be invalid)
		return fmt.Sprintf("%d", rng.IntN(99999))
	case 3: // Random text
		return randStringFromCharset(rng, "abcdefghijklmnopqrstuvwxyz", 1, 10)
	default: // Empty
		return ""
	}
}

// randCapSubset returns a random subset (size 0..len(caps)) of the given
// capability slice.
func randCapSubset(rng *rand.Rand, caps []vaultv1alpha1.Capability) []vaultv1alpha1.Capability {
	count := rng.IntN(len(caps) + 1)
	selected := make([]vaultv1alpha1.Capability, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, caps[rng.IntN(len(caps))])
	}
	return selected
}
