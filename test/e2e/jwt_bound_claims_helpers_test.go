/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Helpers for the TC-AU08 "JWT BoundClaims" e2e suite. Split out of
// tc_auth_jwt_bound_claims_test.go so each test case in the spec file reads
// as a sequence of intent-revealing calls rather than 50 lines of HTTP and
// CRUD boilerplate.
//
// Responsibility breakdown:
//   - Constants — single source of truth for the mount path, auth path,
//     policy name, and SA used by every TC-AU08 case.
//   - Suite lifecycle (ensureJWTGitlabMount, configureJWTGitlabAuthWithDex,
//     createTCAU08Policy, cleanupTCAU08Suite) — called from BeforeAll/AfterAll.
//   - Per-case role lifecycle (waitForRoleActive, cleanupJWTGitlabRole) —
//     called from each It block.
//   - Builders (buildJWTGitlabRole) — VaultRole construction.
//   - Actions (tryLoginWithDex, mustLoginWithDex, readJWTGitlabRoleData) —
//     I/O against Vault, separated from assertions so callers can choose
//     "expect success" vs "expect failure" semantics.
//   - Assertions (assertBoundClaimsListEqual, assertBoundClaimsType,
//     assertHasPolicy, assertDriftedFalse) — Gomega-driven invariant checks.

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// jwtGitlabMount is the bare Vault auth mount name. Used with the Vault
	// SDK's auth-method calls like EnableAuth, DeleteAuthRole — they take
	// the mount without the "auth/" prefix.
	jwtGitlabMount = "jwt-gitlab"

	// jwtGitlabAuthPath is the full Vault auth path including the "auth/"
	// prefix. Used in VaultRole CRs (`spec.authPath`) and HTTP login URLs.
	jwtGitlabAuthPath = "auth/jwt-gitlab"

	// jwtGitlabPolicy is the VaultPolicy CR name attached to every TC-AU08 role.
	jwtGitlabPolicy = "tc-au08-policy"

	// jwtGitlabSA is the service-account placeholder. JWT roles don't actually
	// authenticate by SA, but the VaultRole schema currently requires at least
	// one entry — fixed in the JWT plan; until then this is the workaround.
	jwtGitlabSA = "tc-au08-sa"

	// expectedPolicyName is the Vault-side name the operator generates from
	// the (namespace, policyName) pair. Used to assert the role payload
	// references the right policy.
	expectedPolicyName = "e2e-test-tc-au08-policy"

	// roleActiveTimeout / pollInterval are the budget for waiting on
	// reconciliation. 2 minutes covers cold-start operator latency.
	roleActiveTimeout    = 2 * time.Minute
	roleActivePollPeriod = 5 * time.Second

	// driftObservationWindow gives the reconciler one full requeue cycle
	// (default 30s) plus headroom — long enough to catch a false-drift
	// trigger but short enough to keep the test suite responsive.
	driftObservationWindow = 45 * time.Second
)

// ─────────────────────────────────────────────────────────────────────────────
// Suite lifecycle — called from BeforeAll / AfterAll
// ─────────────────────────────────────────────────────────────────────────────

// ensureJWTGitlabMount enables auth/jwt-gitlab if it isn't already.
// Idempotent: re-runs against an already-enabled mount return without error.
func ensureJWTGitlabMount(ctx context.Context) {
	vc, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	err = vc.EnableAuth(ctx, jwtGitlabMount, "jwt")
	if err != nil && !isAlreadyEnabledErr(err) {
		Fail(fmt.Sprintf("failed to enable %s: %v", jwtGitlabAuthPath, err))
	}
}

// configureJWTGitlabAuthWithDex points the mount at Dex's OIDC discovery
// URL and pins `bound_issuer` to the same. Pinning bound_issuer is the
// load-bearing security control — without it, any OIDC issuer Vault can
// reach could mint a token that satisfies role bindings.
func configureJWTGitlabAuthWithDex(ctx context.Context) {
	vc, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())

	err = vc.WriteAuthConfig(
		ctx, fmt.Sprintf("%s/config", jwtGitlabAuthPath),
		map[string]interface{}{
			"oidc_discovery_url": dexIssuer,
			"bound_issuer":       dexIssuer,
		},
	)
	Expect(err).NotTo(HaveOccurred())
}

// createTCAU08Policy creates the shared VaultPolicy CR every TC-AU08 role
// attaches to. Waits for the operator to reconcile it to Active before
// returning so role tests can immediately bind without races.
func createTCAU08Policy(ctx context.Context) {
	policy := &vaultv1alpha1.VaultPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jwtGitlabPolicy,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultPolicySpec{
			ConnectionRef: sharedVaultConnectionName,
			Rules: []vaultv1alpha1.PolicyRule{{
				Path:         "secret/data/tc-au08/*",
				Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
			}},
		},
	}
	Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())

	Eventually(func(g Gomega) {
		status, err := utils.GetVaultPolicyStatus(ctx, jwtGitlabPolicy, testNamespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal("Active"))
	}, roleActiveTimeout, roleActivePollPeriod).Should(Succeed())
}

// cleanupTCAU08Suite releases the policy and the placeholder SA. The
// auth/jwt-gitlab mount is intentionally left enabled — subsequent test
// runs reuse it via ensureJWTGitlabMount's idempotency.
func cleanupTCAU08Suite(ctx context.Context) {
	_ = utils.DeleteVaultPolicyCR(ctx, jwtGitlabPolicy, testNamespace)
	_ = utils.DeleteServiceAccount(ctx, testNamespace, jwtGitlabSA)
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-case role lifecycle
// ─────────────────────────────────────────────────────────────────────────────

// waitForRoleActive blocks until the named VaultRole reaches Phase=Active or
// the budget runs out. Fails the spec via Gomega if it doesn't.
func waitForRoleActive(ctx context.Context, roleName string) {
	Eventually(func(g Gomega) {
		status, err := utils.GetVaultRoleStatus(ctx, roleName, testNamespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(status).To(Equal("Active"))
	}, roleActiveTimeout, roleActivePollPeriod).Should(Succeed())
}

// cleanupJWTGitlabRole deletes a TC-AU08 role from both Kubernetes (CR) and
// Vault. Errors are intentionally swallowed: cleanup runs in AfterAll where
// surfacing transient failures would mask the actual test outcome.
func cleanupJWTGitlabRole(ctx context.Context, roleName, vaultRoleName string) {
	_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)

	vc, err := utils.GetTestVaultClient()
	if err != nil || vc == nil {
		return
	}
	_ = vc.DeleteAuthRole(ctx, jwtGitlabMount, vaultRoleName)
}

// ─────────────────────────────────────────────────────────────────────────────
// Builders
// ─────────────────────────────────────────────────────────────────────────────

// buildJWTGitlabRole constructs a VaultRole CR pointed at the auth/jwt-gitlab
// mount with the given JWT sub-spec. Centralising the boilerplate (ConnectionRef,
// AuthPath, ServiceAccounts, Policies, TokenTTL) keeps each test focused on
// the JWT spec under test.
func buildJWTGitlabRole(
	name string, jwtSpec *vaultv1alpha1.VaultRoleJWTSpec,
) *vaultv1alpha1.VaultRole {
	return &vaultv1alpha1.VaultRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: vaultv1alpha1.VaultRoleSpec{
			ConnectionRef:   sharedVaultConnectionName,
			AuthPath:        jwtGitlabAuthPath,
			ServiceAccounts: []string{jwtGitlabSA},
			Policies: []vaultv1alpha1.PolicyReference{{
				Kind:      "VaultPolicy",
				Name:      jwtGitlabPolicy,
				Namespace: testNamespace,
			}},
			TokenTTL: "5m",
			JWT:      jwtSpec,
		},
	}
}

// vaultRoleNameOf maps a CR name to the Vault-side role name the operator
// generates: "{namespace}-{crName}". Avoids fmt.Sprintf duplication.
func vaultRoleNameOf(crName string) string {
	return fmt.Sprintf("%s-%s", testNamespace, crName)
}

// ─────────────────────────────────────────────────────────────────────────────
// Actions — separate "try" (returns error) from "must" (expects success).
// Tests that exercise the rejection path want the error; tests that expect
// success want a Secret back without manual error plumbing.
// ─────────────────────────────────────────────────────────────────────────────

// tryLoginWithDex mints a Dex id_token and POSTs it to the JWT mount's
// login endpoint as the given Vault role. Returns the raw Vault response
// plus any error from Vault. Callers expecting failure use this directly.
func tryLoginWithDex(
	ctx context.Context, vaultRoleName string,
) (*vaultapi.Secret, error) {
	dexToken, err := getDexToken(dexClientID, dexClientSecret)
	if err != nil {
		return nil, fmt.Errorf("mint dex token: %w", err)
	}

	vc, err := utils.GetTestVaultClient()
	if err != nil {
		return nil, fmt.Errorf("get vault client: %w", err)
	}
	return vc.Write(ctx, fmt.Sprintf("%s/login", jwtGitlabAuthPath),
		map[string]interface{}{
			"role": vaultRoleName,
			"jwt":  dexToken,
		},
	)
}

// mustLoginWithDex is tryLoginWithDex with success expectations baked in:
// fails the spec if the login errors or returns no client token. Returns
// the Vault Secret so callers can assert on the attached policies.
func mustLoginWithDex(
	ctx context.Context, vaultRoleName string,
) *vaultapi.Secret {
	secret, err := tryLoginWithDex(ctx, vaultRoleName)
	Expect(err).NotTo(HaveOccurred(),
		"login with Dex token should succeed for role %q", vaultRoleName)
	Expect(secret).NotTo(BeNil())
	Expect(secret.Auth).NotTo(BeNil())
	Expect(secret.Auth.ClientToken).NotTo(BeEmpty(),
		"Vault should issue a client token on successful JWT login")
	return secret
}

// readJWTGitlabRoleData reads the Vault role payload for assertions about
// the operator's write shape (bound_claims, bound_claims_type, policies).
func readJWTGitlabRoleData(
	ctx context.Context, vaultRoleName string,
) map[string]interface{} {
	vc, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())
	data, err := vc.ReadAuthRole(ctx, jwtGitlabMount, vaultRoleName)
	Expect(err).NotTo(HaveOccurred())
	Expect(data).NotTo(BeNil(),
		"role %q should exist in Vault after VaultRole reconcile", vaultRoleName)
	return data
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions
// ─────────────────────────────────────────────────────────────────────────────

// assertBoundClaimsListEqual asserts that data["bound_claims"][key] is a list
// containing exactly the expected values (order-insensitive). Vault returns
// list values as []interface{} regardless of how they were written, which is
// why the wrapping in mergeBoundClaims matters for drift stability.
func assertBoundClaimsListEqual(
	data map[string]interface{}, key string, expected []string,
) {
	claims, ok := data["bound_claims"].(map[string]interface{})
	Expect(ok).To(BeTrue(),
		"bound_claims should be a map, got %T", data["bound_claims"])

	got, ok := claims[key].([]interface{})
	Expect(ok).To(BeTrue(),
		"bound_claims[%q] should be a list, got %T", key, claims[key])

	gotStrings := make([]string, 0, len(got))
	for _, v := range got {
		s, ok := v.(string)
		Expect(ok).To(BeTrue(),
			"bound_claims[%q] list item should be a string, got %T", key, v)
		gotStrings = append(gotStrings, s)
	}
	Expect(gotStrings).To(ConsistOf(expected),
		"bound_claims[%q] should contain %v, got %v", key, expected, gotStrings)
}

// assertBoundClaimsType asserts the explicit bound_claims_type field is
// emitted by the operator. We always write it (defaulting to "string") so
// toggling glob -> unset on the CR isn't a silent no-op in Vault.
func assertBoundClaimsType(data map[string]interface{}, expected string) {
	Expect(data["bound_claims_type"]).To(Equal(expected),
		"bound_claims_type should round-trip as %q", expected)
}

// assertHasPolicy asserts the role payload's policy list (under either
// "policies" or its newer alias "token_policies") contains the expected
// Vault-side policy name.
func assertHasPolicy(data map[string]interface{}, expected string) {
	for _, key := range []string{"policies", "token_policies"} {
		if containsPolicy(data[key], expected) {
			return
		}
	}
	Fail(fmt.Sprintf(
		"policy %q not found in role data (policies=%v, token_policies=%v)",
		expected, data["policies"], data["token_policies"],
	))
}

// assertDriftedFalse asserts that if the role exposes a Drifted condition,
// it is False. Roles with no Drifted condition pass — the drift workflow
// only adds the condition when a drift check actually ran. The point of
// this assertion is to catch FALSE drift on round-trip — see TC-AU08-06.
func assertDriftedFalse(role *vaultv1alpha1.VaultRole) {
	for _, cond := range role.Status.Conditions {
		if cond.Type != "Drifted" {
			continue
		}
		Expect(string(cond.Status)).To(Equal("False"),
			"Drifted should be False; got reason=%q message=%q",
			cond.Reason, cond.Message)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// isAlreadyEnabledErr returns true for Vault's idempotent "mount in use"
// error so ensureJWTGitlabMount can re-run cleanly across spec retries.
func isAlreadyEnabledErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already in use")
}

// containsPolicy checks a "policies" / "token_policies" field for a name
// match across both the []interface{} (Vault JSON) and []string (operator
// write) shapes. Returns false for nil or unexpected types.
func containsPolicy(field interface{}, expected string) bool {
	switch list := field.(type) {
	case []interface{}:
		for _, p := range list {
			if s, ok := p.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, p := range list {
			if p == expected {
				return true
			}
		}
	}
	return false
}
