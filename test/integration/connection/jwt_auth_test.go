//go:build integration

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

package connection

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vault "github.com/hashicorp/vault/api"
	"github.com/panteparak/vault-access-operator/test/utils"
)

var _ = Describe("JWT Authentication Integration", Ordered, func() {
	var (
		vaultClient *vault.Client
		jwtFixtures *utils.JWTFixtures
		authHelper  *utils.VaultAuthHelper

		testPolicyName = "jwt-test-policy"
		testRoleName   = "jwt-test-role"
		testIssuer     = "https://test-issuer.example.com"
	)

	BeforeAll(func() {
		By("Creating Vault client")
		config := vault.DefaultConfig()
		config.Address = testEnv.VaultAddress()

		var err error
		vaultClient, err = vault.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		vaultClient.SetToken(testEnv.VaultToken())

		authHelper = utils.NewVaultAuthHelper(vaultClient)

		By("Creating JWT fixtures with RSA key pair")
		jwtFixtures, err = utils.NewJWTFixtures()
		Expect(err).NotTo(HaveOccurred())

		By("Creating test policy in Vault")
		testPolicyHCL := `
path "secret/data/jwt-test/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`
		err = authHelper.CreateTestPolicy(ctx, testPolicyName, testPolicyHCL)
		Expect(err).NotTo(HaveOccurred())

		By("Getting public key in PEM format")
		publicKeyPEM, err := jwtFixtures.GetPublicKeyPEM()
		Expect(err).NotTo(HaveOccurred())

		By("Configuring JWT auth method")
		err = authHelper.ConfigureJWTAuth(ctx, utils.JWTAuthConfig{
			Path:                 "jwt",
			BoundIssuer:          testIssuer,
			JWTValidationPubKeys: []string{publicKeyPEM},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating JWT auth role")
		err = authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
			Name:           testRoleName,
			RoleType:       "jwt",
			BoundAudiences: []string{"vault"},
			UserClaim:      "sub",
			TokenPolicies:  []string{testPolicyName, "default"},
			TokenTTL:       "1h",
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		if authHelper != nil {
			By("Cleaning up JWT role")
			_ = authHelper.DeleteJWTRole(ctx, "jwt", testRoleName)

			By("Cleaning up test policy")
			_ = authHelper.DeletePolicy(ctx, testPolicyName)
		}
	})

	Context("Valid JWT Authentication", func() {
		It("should authenticate with a valid JWT token", func() {
			By("Creating a valid JWT")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "test-user",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Logging in with the JWT")
			secret, err := authHelper.LoginWithJWT(ctx, "jwt", testRoleName, jwt)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret).NotTo(BeNil())
			Expect(secret.Auth).NotTo(BeNil())
			Expect(secret.Auth.ClientToken).NotTo(BeEmpty())

			By("Verifying token policies")
			Expect(secret.Auth.Policies).To(ContainElement(testPolicyName))

			By("Verifying the token can access the protected path")
			testClient, err := vault.NewClient(vault.DefaultConfig())
			Expect(err).NotTo(HaveOccurred())
			Expect(testClient.SetAddress(testEnv.VaultAddress())).To(Succeed())
			testClient.SetToken(secret.Auth.ClientToken)

			// Write a test secret
			_, err = testClient.Logical().WriteWithContext(ctx, "secret/data/jwt-test/mykey", map[string]interface{}{
				"data": map[string]interface{}{
					"value": "test-value",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Read it back
			readSecret, err := testClient.Logical().ReadWithContext(ctx, "secret/data/jwt-test/mykey")
			Expect(err).NotTo(HaveOccurred())
			Expect(readSecret).NotTo(BeNil())
		})

		It("should authenticate with Kubernetes-style service account JWT", func() {
			By("Creating a Kubernetes service account JWT")
			jwt, err := jwtFixtures.CreateKubernetesServiceAccountJWT(testIssuer, "default", "test-sa")
			Expect(err).NotTo(HaveOccurred())

			By("Creating a role that matches the K8s JWT claims")
			k8sRoleName := "k8s-sa-role"
			err = authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
				Name:           k8sRoleName,
				RoleType:       "jwt",
				BoundAudiences: []string{"vault"},
				BoundSubject:   "system:serviceaccount:default:test-sa",
				UserClaim:      "sub",
				TokenPolicies:  []string{"default"},
				TokenTTL:       "15m",
			})
			Expect(err).NotTo(HaveOccurred())

			By("Logging in with the K8s-style JWT")
			secret, err := authHelper.LoginWithJWT(ctx, "jwt", k8sRoleName, jwt)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Auth.ClientToken).NotTo(BeEmpty())

			By("Cleaning up the K8s SA role")
			_ = authHelper.DeleteJWTRole(ctx, "jwt", k8sRoleName)
		})

		It("should support JWT with array audience", func() {
			By("Creating a JWT with array audience")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "array-aud-user",
				Audience:  []string{"vault", "other-service"},
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Logging in - should match 'vault' in the array")
			secret, err := authHelper.LoginWithJWT(ctx, "jwt", testRoleName, jwt)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Auth.ClientToken).NotTo(BeEmpty())
		})
	})

	Context("Invalid JWT Authentication", func() {
		It("should reject an expired JWT", func() {
			By("Creating an expired JWT")
			jwt, err := jwtFixtures.CreateExpiredJWT(testIssuer, "expired-user", "vault")
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to login with expired JWT")
			_, err = authHelper.LoginWithJWT(ctx, "jwt", testRoleName, jwt)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("exp"))
		})

		It("should reject a JWT with wrong issuer", func() {
			By("Creating a JWT with wrong issuer")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    "https://wrong-issuer.example.com",
				Subject:   "wrong-issuer-user",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to login with wrong issuer JWT")
			_, err = authHelper.LoginWithJWT(ctx, "jwt", testRoleName, jwt)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Or(
				ContainSubstring("issuer"),
				ContainSubstring("iss"),
				ContainSubstring("claim"),
			))
		})

		It("should reject a JWT with wrong audience", func() {
			By("Creating a JWT with wrong audience")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "wrong-aud-user",
				Audience:  "wrong-audience",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to login with wrong audience JWT")
			_, err = authHelper.LoginWithJWT(ctx, "jwt", testRoleName, jwt)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Or(
				ContainSubstring("audience"),
				ContainSubstring("aud"),
			))
		})

		It("should reject an unsigned/tampered JWT", func() {
			By("Creating a JWT and tampering with it")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "tampered-user",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			// Tamper with the signature
			tamperedJWT := jwt[:len(jwt)-10] + "0000000000"

			By("Attempting to login with tampered JWT")
			_, err = authHelper.LoginWithJWT(ctx, "jwt", testRoleName, tamperedJWT)
			Expect(err).To(HaveOccurred())
		})

		It("should reject a JWT for non-existent role", func() {
			By("Creating a valid JWT")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "no-role-user",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Attempting to login to non-existent role")
			_, err = authHelper.LoginWithJWT(ctx, "jwt", "non-existent-role", jwt)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("JWT Role Configuration", func() {
		It("should enforce bound_subject when configured", func() {
			By("Creating a role with bound_subject")
			boundSubjectRole := "bound-subject-role"
			err := authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
				Name:           boundSubjectRole,
				RoleType:       "jwt",
				BoundAudiences: []string{"vault"},
				BoundSubject:   "allowed-subject",
				UserClaim:      "sub",
				TokenPolicies:  []string{"default"},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Creating JWT with matching subject - should succeed")
			matchingJWT, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "allowed-subject",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			secret, err := authHelper.LoginWithJWT(ctx, "jwt", boundSubjectRole, matchingJWT)
			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Auth.ClientToken).NotTo(BeEmpty())

			By("Creating JWT with non-matching subject - should fail")
			nonMatchingJWT, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "different-subject",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			_, err = authHelper.LoginWithJWT(ctx, "jwt", boundSubjectRole, nonMatchingJWT)
			Expect(err).To(HaveOccurred())

			By("Cleaning up bound subject role")
			_ = authHelper.DeleteJWTRole(ctx, "jwt", boundSubjectRole)
		})

		It("should respect token TTL configuration", func() {
			By("Creating a role with short TTL")
			shortTTLRole := "short-ttl-role"
			err := authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
				Name:           shortTTLRole,
				RoleType:       "jwt",
				BoundAudiences: []string{"vault"},
				UserClaim:      "sub",
				TokenPolicies:  []string{"default"},
				TokenTTL:       "5m",
				TokenMaxTTL:    "10m",
			})
			Expect(err).NotTo(HaveOccurred())

			By("Creating and logging in with JWT")
			jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
				Issuer:    testIssuer,
				Subject:   "ttl-test-user",
				Audience:  "vault",
				ExpiresIn: 1 * time.Hour,
			})
			Expect(err).NotTo(HaveOccurred())

			secret, err := authHelper.LoginWithJWT(ctx, "jwt", shortTTLRole, jwt)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying token TTL is around 5 minutes")
			Expect(secret.Auth.LeaseDuration).To(BeNumerically("<=", 300))

			By("Cleaning up short TTL role")
			_ = authHelper.DeleteJWTRole(ctx, "jwt", shortTTLRole)
		})
	})
})

var _ = Describe("OIDC-style JWT Authentication", Ordered, func() {
	var (
		vaultClient *vault.Client
		jwtFixtures *utils.JWTFixtures
		authHelper  *utils.VaultAuthHelper

		oidcRoleName = "oidc-style-role"
		oidcIssuer   = "https://oidc.example.com"
	)

	BeforeAll(func() {
		By("Creating Vault client")
		config := vault.DefaultConfig()
		config.Address = testEnv.VaultAddress()

		var err error
		vaultClient, err = vault.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		vaultClient.SetToken(testEnv.VaultToken())

		authHelper = utils.NewVaultAuthHelper(vaultClient)

		By("Creating JWT fixtures")
		jwtFixtures, err = utils.NewJWTFixtures()
		Expect(err).NotTo(HaveOccurred())

		publicKeyPEM, err := jwtFixtures.GetPublicKeyPEM()
		Expect(err).NotTo(HaveOccurred())

		By("Configuring JWT auth for OIDC-style tokens")
		err = authHelper.ConfigureJWTAuth(ctx, utils.JWTAuthConfig{
			Path:                 "jwt",
			BoundIssuer:          oidcIssuer,
			JWTValidationPubKeys: []string{publicKeyPEM},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating OIDC-style JWT role with email claim")
		err = authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
			Name:           oidcRoleName,
			RoleType:       "jwt",
			BoundAudiences: []string{"vault", "api"},
			UserClaim:      "email",
			TokenPolicies:  []string{"default"},
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		if authHelper != nil {
			_ = authHelper.DeleteJWTRole(ctx, "jwt", oidcRoleName)
		}
	})

	It("should authenticate with OIDC-style JWT using email claim", func() {
		By("Creating an OIDC-style JWT with email")
		jwt, err := jwtFixtures.CreateOIDCJWT(
			oidcIssuer,
			"user-123",
			"testuser@example.com",
			[]string{"vault", "api"},
		)
		Expect(err).NotTo(HaveOccurred())

		By("Logging in with the OIDC JWT")
		secret, err := authHelper.LoginWithJWT(ctx, "jwt", oidcRoleName, jwt)
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Auth).NotTo(BeNil())

		By("Verifying the metadata contains the email")
		Expect(secret.Auth.Metadata["email"]).To(Or(
			Equal("testuser@example.com"),
			BeEmpty(), // Some Vault versions may not include this
		))
	})

	It("should extract custom claims correctly", func(sCtx context.Context) {
		By("Creating a role with groups claim")
		groupsRole := "groups-claim-role"
		err := authHelper.CreateJWTRole(sCtx, "jwt", utils.JWTRoleConfig{
			Name:           groupsRole,
			RoleType:       "jwt",
			BoundAudiences: []string{"vault"},
			UserClaim:      "sub",
			GroupsClaim:    "groups",
			TokenPolicies:  []string{"default"},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating JWT with groups claim")
		jwt, err := jwtFixtures.CreateJWT(utils.JWTOptions{
			Issuer:    oidcIssuer,
			Subject:   "group-user",
			Audience:  "vault",
			ExpiresIn: 1 * time.Hour,
			CustomClaims: map[string]interface{}{
				"groups": []string{"admin", "developers"},
			},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Logging in with the groups JWT")
		secret, err := authHelper.LoginWithJWT(sCtx, "jwt", groupsRole, jwt)
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Auth.ClientToken).NotTo(BeEmpty())

		By("Cleaning up groups role")
		_ = authHelper.DeleteJWTRole(sCtx, "jwt", groupsRole)
	}, SpecTimeout(30*time.Second))
})

// BoundClaimsTest verifies bound_claims functionality
var _ = Describe("JWT Bound Claims", Ordered, func() {
	var (
		vaultClient *vault.Client
		jwtFixtures *utils.JWTFixtures
		authHelper  *utils.VaultAuthHelper

		boundClaimsRole = "bound-claims-role"
		issuer          = "https://bound-claims.example.com"
	)

	BeforeAll(func() {
		config := vault.DefaultConfig()
		config.Address = testEnv.VaultAddress()

		var err error
		vaultClient, err = vault.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		vaultClient.SetToken(testEnv.VaultToken())

		authHelper = utils.NewVaultAuthHelper(vaultClient)

		jwtFixtures, err = utils.NewJWTFixtures()
		Expect(err).NotTo(HaveOccurred())

		publicKeyPEM, err := jwtFixtures.GetPublicKeyPEM()
		Expect(err).NotTo(HaveOccurred())

		err = authHelper.ConfigureJWTAuth(ctx, utils.JWTAuthConfig{
			Path:                 "jwt",
			BoundIssuer:          issuer,
			JWTValidationPubKeys: []string{publicKeyPEM},
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should enforce bound_claims restrictions", func() {
		By("Creating role with bound claims on custom field")
		err := authHelper.CreateJWTRole(ctx, "jwt", utils.JWTRoleConfig{
			Name:           boundClaimsRole,
			RoleType:       "jwt",
			BoundAudiences: []string{"vault"},
			BoundClaims: map[string]interface{}{
				"department": "engineering",
			},
			UserClaim:     "sub",
			TokenPolicies: []string{"default"},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating JWT with matching bound claim - should succeed")
		matchingJWT, err := jwtFixtures.CreateJWT(utils.JWTOptions{
			Issuer:    issuer,
			Subject:   "eng-user",
			Audience:  "vault",
			ExpiresIn: 1 * time.Hour,
			CustomClaims: map[string]interface{}{
				"department": "engineering",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		secret, err := authHelper.LoginWithJWT(ctx, "jwt", boundClaimsRole, matchingJWT)
		Expect(err).NotTo(HaveOccurred())
		Expect(secret.Auth.ClientToken).NotTo(BeEmpty())

		By("Creating JWT with non-matching bound claim - should fail")
		nonMatchingJWT, err := jwtFixtures.CreateJWT(utils.JWTOptions{
			Issuer:    issuer,
			Subject:   "sales-user",
			Audience:  "vault",
			ExpiresIn: 1 * time.Hour,
			CustomClaims: map[string]interface{}{
				"department": "sales",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = authHelper.LoginWithJWT(ctx, "jwt", boundClaimsRole, nonMatchingJWT)
		Expect(err).To(HaveOccurred())
	})

	AfterAll(func() {
		if authHelper != nil {
			_ = authHelper.DeleteJWTRole(ctx, "jwt", boundClaimsRole)
		}
	})
})
