/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// TC-AU08 exercises the multi-value bound_claims and bound_claims_type
// fields added to VaultRoleJWTSpec. Tests run against the e2e Dex instance
// at a dedicated JWT mount auth/jwt-gitlab.
//
// Dex doesn't natively emit GitLab-shaped claim names (project_id, ref, etc.)
// — it emits standard OIDC claims (email, name, sub). The wire format the
// operator writes is issuer-agnostic, so binding on `email` exercises the
// same code path GitLab CI's `project_path`/`ref` would.
//
// See docs/auth-methods/jwt-gitlab.md for the user-facing runbook and
// jwt_bound_claims_helpers_test.go for the fixture / assertion helpers.
var _ = Describe("JWT BoundClaims Tests", Label("auth"), Ordered, func() {
	ctx := context.Background()

	BeforeAll(func() {
		RefreshSharedVaultToken(ctx)
		skipIfDexUnreachable()

		By("enabling auth/jwt-gitlab mount in Vault")
		ensureJWTGitlabMount(ctx)

		By("configuring auth/jwt-gitlab with Dex OIDC discovery + bound_issuer")
		configureJWTGitlabAuthWithDex(ctx)

		By("creating the dedicated VaultConnection that pins roles to auth/jwt-gitlab")
		createJWTGitlabConnection(ctx)

		By("creating placeholder ServiceAccount for the JWT VaultRole spec")
		_ = utils.CreateServiceAccount(ctx, testNamespace, jwtGitlabSA)

		By("creating shared VaultPolicy for TC-AU08")
		createTCAU08Policy(ctx)
	})

	AfterAll(func() {
		By("cleaning up TC-AU08 suite-level resources")
		cleanupTCAU08Suite(ctx)
		// auth/jwt-gitlab mount intentionally left enabled — idempotent across runs.
	})

	// TC-AU08-01: multi-value bound_claims via boundClaimsList lets a token's
	// claim value match ANY of the listed allowed values.
	Context("TC-AU08-01: boundClaimsList multi-value match",
		Ordered, func() {
			const crName = "tc-au08-01-multi"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should write list-valued bound_claims and accept "+
				"a matching token", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					BoundClaimsList: map[string][]string{
						"email": {dexTestEmail, "someone-else@example.com"},
					},
					BoundClaimsType: "string",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				By("reading the role back from Vault and asserting the payload")
				data := readJWTGitlabRoleData(ctx, vaultRoleName)
				assertBoundClaimsListEqual(data, "email",
					[]string{dexTestEmail, "someone-else@example.com"})
				assertBoundClaimsType(data, "string")
				assertHasPolicy(data, expectedPolicyName)

				By("authenticating with the matching admin@example.com token")
				secret := mustLoginWithDex(ctx, vaultRoleName)
				Expect(secret.Auth.Policies).To(ContainElement(expectedPolicyName))
			})
		})

	// TC-AU08-02: a token whose claim value isn't in the bound list is
	// rejected by Vault even if all other fields are valid.
	Context("TC-AU08-02: boundClaimsList rejects non-matching token",
		Ordered, func() {
			const crName = "tc-au08-02-reject"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should reject a token whose email is not in the list", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					BoundClaimsList: map[string][]string{
						// Deliberately exclude dexTestEmail so the Dex token's
						// email claim won't match.
						"email": {"someone-else@example.com"},
					},
					BoundClaimsType: "string",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				By("expecting login to fail because email is not in bound list")
				_, err := tryLoginWithDex(ctx, vaultRoleName)
				Expect(err).To(HaveOccurred(),
					"login with non-matching email should be rejected by Vault")
			})
		})

	// TC-AU08-03: boundClaimsType=glob causes Vault to treat the claim values
	// as shell-style globs. The Dex email "admin@example.com" matches "admin@*".
	Context("TC-AU08-03: boundClaimsType=glob match",
		Ordered, func() {
			const crName = "tc-au08-03-glob"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should emit bound_claims_type=glob and accept "+
				"a token via glob match", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					BoundClaimsList: map[string][]string{
						"email": {"admin@*"},
					},
					BoundClaimsType: "glob",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				By("asserting bound_claims_type=glob in Vault")
				data := readJWTGitlabRoleData(ctx, vaultRoleName)
				assertBoundClaimsType(data, "glob")

				By("authenticating via the admin@* glob match")
				_ = mustLoginWithDex(ctx, vaultRoleName)
			})
		})

	// TC-AU08-04: boundClaimsType=glob rejects when the glob doesn't match.
	Context("TC-AU08-04: boundClaimsType=glob rejects non-matching token",
		Ordered, func() {
			const crName = "tc-au08-04-glob-reject"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should reject a token whose email doesn't match the glob", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					BoundClaimsList: map[string][]string{
						// admin@example.com does NOT match other@*
						"email": {"other@*"},
					},
					BoundClaimsType: "glob",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				_, err := tryLoginWithDex(ctx, vaultRoleName)
				Expect(err).To(HaveOccurred(),
					"login should fail when token email doesn't match the glob")
			})
		})

	// TC-AU08-05: when the same key is set in BOTH BoundClaims (deprecated
	// scalars) AND BoundClaimsList (lists), the list value wins.
	Context("TC-AU08-05: BoundClaimsList overrides BoundClaims on key collision",
		Ordered, func() {
			const crName = "tc-au08-05-merge"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should let the list value win on collision and accept "+
				"the matching token", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					// Both fields set the same key — the list wins, so the
					// real bound_claims.email becomes the admin email and
					// the dummy scalar is ignored.
					BoundClaims: map[string]string{
						"email": "this-would-be-wrong@example.com",
					},
					BoundClaimsList: map[string][]string{
						"email": {dexTestEmail},
					},
					BoundClaimsType: "string",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				By("verifying Vault stored the list value, not the scalar")
				data := readJWTGitlabRoleData(ctx, vaultRoleName)
				assertBoundClaimsListEqual(data, "email", []string{dexTestEmail})

				By("authenticating with the admin token — list wins")
				_ = mustLoginWithDex(ctx, vaultRoleName)
			})
		})

	// TC-AU08-06: round-trip drift safety. After the role is Active, a full
	// reconcile cycle must NOT produce drift even though Vault returns
	// bound_claims values as []interface{} while the operator's spec stores
	// []string. The fix is in mergeBoundClaims, which emits []interface{} at
	// write time so the shapes match on round-trip.
	Context("TC-AU08-06: no false drift on round-trip",
		Ordered, func() {
			const crName = "tc-au08-06-drift"
			vaultRoleName := vaultRoleNameOf(crName)

			AfterAll(func() { cleanupJWTGitlabRole(ctx, crName, vaultRoleName) })

			It("should remain Active with Drifted=False after reconcile", func() {
				role := buildJWTGitlabRole(crName, &vaultv1alpha1.VaultRoleJWTSpec{
					UserClaim:      "email",
					BoundAudiences: []string{dexClientID},
					BoundClaimsList: map[string][]string{
						"email": {dexTestEmail, "second@example.com"},
					},
					BoundClaimsType: "string",
				})
				Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
				waitForRoleActive(ctx, crName)

				By("waiting through one full reconcile cycle to expose drift if any")
				time.Sleep(driftObservationWindow)

				By("verifying the role stayed Active (no false drift)")
				status, err := utils.GetVaultRoleStatus(ctx, crName, testNamespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(status).To(Equal("Active"),
					"role should remain Active — false drift would push it to Syncing")

				By("verifying the Drifted condition is False")
				current, err := utils.GetVaultRole(ctx, crName, testNamespace)
				Expect(err).NotTo(HaveOccurred())
				assertDriftedFalse(current)
			})
		})
})

// skipIfDexUnreachable shorts out the suite when Dex isn't listening.
// Lives in the spec file rather than helpers so the Skip() reason
// references the discovery URL directly — easier to spot in CI output.
func skipIfDexUnreachable() {
	resp, err := http.Get(dexDiscoveryURL) //nolint:gosec
	if err != nil {
		Skip(fmt.Sprintf(
			"Dex not reachable at %s: %v — skipping TC-AU08",
			dexDiscoveryURL, err,
		))
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		Skip(fmt.Sprintf(
			"Dex discovery returned status %d — skipping TC-AU08",
			resp.StatusCode,
		))
	}
}
