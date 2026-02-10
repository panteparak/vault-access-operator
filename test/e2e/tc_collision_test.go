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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/test/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Naming Collision Detection Tests", Ordered, Label("collision"), func() {
	ctx := context.Background()

	// Shared resources
	var sharedPolicyName, sharedSAName string
	var webhooksDeployed bool

	BeforeAll(func() {
		By("checking if webhooks are deployed")
		var err error
		webhooksDeployed, err = utils.IsWebhookDeployed(ctx)
		if err != nil {
			GinkgoWriter.Printf("Warning: failed to check webhook deployment: %v\n", err)
			webhooksDeployed = false
		}

		if !webhooksDeployed {
			GinkgoWriter.Println("WARNING: Webhooks are not deployed. Collision detection tests will be skipped.")
			GinkgoWriter.Println("To enable collision detection, deploy the operator with webhooks enabled.")
			Skip("Webhooks not deployed - collision detection requires admission webhooks")
		}

		By("creating shared resources for collision tests")
		sharedPolicyName = uniqueName("tc-col-policy")
		sharedSAName = uniqueName("tc-col-sa")

		_ = utils.CreateServiceAccount(ctx, testNamespace, sharedSAName)

		policy := BuildTestPolicy(sharedPolicyName)
		err = utils.CreateVaultPolicyCR(ctx, policy)
		Expect(err).NotTo(HaveOccurred())

		ExpectPolicyActive(ctx, sharedPolicyName)
	})

	AfterAll(func() {
		By("cleaning up shared collision test resources")
		CleanupPolicy(ctx, sharedPolicyName)
		CleanupServiceAccount(ctx, sharedSAName)
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-COLLISION-POLICY: Policy Collision Detection
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-COLLISION-POLICY: Policy Collision Detection", func() {
		It("TC-COLLISION-POLICY01: should reject VaultClusterPolicy colliding with existing VaultPolicy", func() {
			// Create a namespaced VaultPolicy first
			policyName := uniqueName("tc-col-pol01")
			policy := BuildTestPolicy(policyName)

			By("creating a VaultPolicy that will establish the Vault name")
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)

			ExpectPolicyActive(ctx, policyName)

			// The Vault policy name would be: {testNamespace}-{policyName}
			collidingName := fmt.Sprintf("%s-%s", testNamespace, policyName)

			By(fmt.Sprintf("attempting to create VaultClusterPolicy with colliding name %q", collidingName))
			clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: collidingName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/different/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}

			err = utils.CreateVaultClusterPolicyCR(ctx, clusterPolicy)
			defer func() {
				_ = utils.DeleteVaultClusterPolicyCR(ctx, collidingName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterPolicy{},
					collidingName, "", 30*time.Second, 2*time.Second)
			}()

			// Should be rejected by admission webhook
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("naming collision"))
		})

		It("TC-COLLISION-POLICY02: should reject VaultPolicy colliding with existing VaultClusterPolicy", func() {
			// Create a VaultClusterPolicy first
			clusterPolicyName := uniqueName("tc-col-pol02-cluster")

			By(fmt.Sprintf("creating VaultClusterPolicy %q", clusterPolicyName))
			clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterPolicyName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/shared/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}

			err := utils.CreateVaultClusterPolicyCR(ctx, clusterPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = utils.DeleteVaultClusterPolicyCR(ctx, clusterPolicyName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterPolicy{},
					clusterPolicyName, "", 30*time.Second, 2*time.Second)
			}()

			// Wait for cluster policy to be active
			Eventually(func(g Gomega) {
				cp, getErr := utils.GetVaultClusterPolicy(ctx, clusterPolicyName)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(cp.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			// Now try to create a VaultPolicy that would collide
			// Parse the cluster policy name to get namespace and policy name
			// For example: "tc-col-pol02-cluster-12345" -> we need to create VaultPolicy
			// in a namespace where ns-name would equal clusterPolicyName

			// Simple approach: create VaultPolicy in testNamespace where
			// {testNamespace}-{policyName} = clusterPolicyName
			// This requires the cluster policy name to follow the pattern {ns}-{name}

			// Create a simpler test: create cluster policy "default-collision-test"
			// then try to create VaultPolicy "collision-test" in "default" namespace

			By("attempting to create VaultPolicy that would collide")
			// We need a VaultPolicy where {namespace}-{name} = clusterPolicyName
			// If clusterPolicyName is in format "ns-name", we can split it
			// But since we generated a unique name, let's create a different scenario

			// Create a cluster policy with predictable pattern
			predictableClusterName := testNamespace + "-" + uniqueName("col-predict")
			predictableClusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: predictableClusterName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/predict/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}

			err = utils.CreateVaultClusterPolicyCR(ctx, predictableClusterPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = utils.DeleteVaultClusterPolicyCR(ctx, predictableClusterName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterPolicy{},
					predictableClusterName, "", 30*time.Second, 2*time.Second)
			}()

			// Wait for it to be active
			Eventually(func(g Gomega) {
				cp, getErr := utils.GetVaultClusterPolicy(ctx, predictableClusterName)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(cp.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			// Now try to create VaultPolicy in testNamespace with name that would collide
			// The colliding VaultPolicy name would need: testNamespace-{name} = predictableClusterName
			// Since predictableClusterName = testNamespace-col-predict-XXXXX
			// The VaultPolicy name should be: col-predict-XXXXX (extract from predictableClusterName)
			collidingPolicyName := predictableClusterName[len(testNamespace)+1:] // Remove "testNamespace-" prefix

			collidingPolicy := &vaultv1alpha1.VaultPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      collidingPolicyName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/other/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}

			err = utils.CreateVaultPolicyCR(ctx, collidingPolicy)
			defer CleanupPolicy(ctx, collidingPolicyName)

			// Should be rejected by admission webhook
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("naming collision"))
		})

		It("TC-COLLISION-POLICY03: should allow non-colliding policy names", func() {
			// Create VaultPolicy
			policyName := uniqueName("tc-col-pol03-ns")
			policy := BuildTestPolicy(policyName)

			By("creating VaultPolicy")
			err := utils.CreateVaultPolicyCR(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupPolicy(ctx, policyName)

			ExpectPolicyActive(ctx, policyName)

			// Create VaultClusterPolicy with different name (no collision)
			clusterPolicyName := uniqueName("tc-col-pol03-cluster-unique")
			clusterPolicy := &vaultv1alpha1.VaultClusterPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterPolicyName,
				},
				Spec: vaultv1alpha1.VaultClusterPolicySpec{
					ConnectionRef: sharedVaultConnectionName,
					Rules: []vaultv1alpha1.PolicyRule{
						{
							Path:         "secret/data/cluster/*",
							Capabilities: []vaultv1alpha1.Capability{vaultv1alpha1.CapabilityRead},
						},
					},
				},
			}

			By("creating VaultClusterPolicy with non-colliding name")
			err = utils.CreateVaultClusterPolicyCR(ctx, clusterPolicy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = utils.DeleteVaultClusterPolicyCR(ctx, clusterPolicyName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterPolicy{},
					clusterPolicyName, "", 30*time.Second, 2*time.Second)
			}()

			// Should become active
			Eventually(func(g Gomega) {
				cp, getErr := utils.GetVaultClusterPolicy(ctx, clusterPolicyName)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(cp.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})

	// ─────────────────────────────────────────────────────────────────────────
	// TC-COLLISION-ROLE: Role Collision Detection
	// ─────────────────────────────────────────────────────────────────────────

	Context("TC-COLLISION-ROLE: Role Collision Detection", func() {
		It("TC-COLLISION-ROLE01: should reject VaultClusterRole colliding with existing VaultRole", func() {
			// Create a namespaced VaultRole first
			roleName := uniqueName("tc-col-role01")
			role := BuildTestRole(roleName, sharedSAName, sharedPolicyName)

			By("creating a VaultRole that will establish the Vault name")
			err := utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)

			ExpectRoleActive(ctx, roleName)

			// The Vault role name would be: {testNamespace}-{roleName}
			collidingName := fmt.Sprintf("%s-%s", testNamespace, roleName)

			By(fmt.Sprintf("attempting to create VaultClusterRole with colliding name %q", collidingName))
			clusterRole := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: collidingName,
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      sharedSAName,
							Namespace: testNamespace,
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      sharedPolicyName,
							Namespace: testNamespace,
						},
					},
				},
			}

			err = utils.CreateVaultClusterRoleCR(ctx, clusterRole)
			defer func() {
				_ = utils.DeleteVaultClusterRoleCR(ctx, collidingName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterRole{},
					collidingName, "", 30*time.Second, 2*time.Second)
			}()

			// Should be rejected by admission webhook
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("naming collision"))
		})

		It("TC-COLLISION-ROLE02: should reject VaultRole colliding with existing VaultClusterRole", func() {
			// Create a VaultClusterRole with predictable pattern
			predictableClusterName := testNamespace + "-" + uniqueName("col-role-pred")

			By(fmt.Sprintf("creating VaultClusterRole %q", predictableClusterName))
			clusterRole := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: predictableClusterName,
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      sharedSAName,
							Namespace: testNamespace,
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      sharedPolicyName,
							Namespace: testNamespace,
						},
					},
				},
			}

			err := utils.CreateVaultClusterRoleCR(ctx, clusterRole)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = utils.DeleteVaultClusterRoleCR(ctx, predictableClusterName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterRole{},
					predictableClusterName, "", 30*time.Second, 2*time.Second)
			}()

			// Wait for it to be active
			Eventually(func(g Gomega) {
				cr, getErr := utils.GetVaultClusterRole(ctx, predictableClusterName)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(cr.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			// Now try to create VaultRole that would collide
			collidingRoleName := predictableClusterName[len(testNamespace)+1:] // Remove "testNamespace-" prefix

			By(fmt.Sprintf("attempting to create VaultRole %q that would collide", collidingRoleName))
			collidingRole := &vaultv1alpha1.VaultRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:      collidingRoleName,
					Namespace: testNamespace,
				},
				Spec: vaultv1alpha1.VaultRoleSpec{
					ConnectionRef:   sharedVaultConnectionName,
					ServiceAccounts: []string{sharedSAName},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind: "VaultPolicy",
							Name: sharedPolicyName,
						},
					},
					TokenTTL: "2m",
				},
			}

			err = utils.CreateVaultRoleCR(ctx, collidingRole)
			defer CleanupRole(ctx, collidingRoleName)

			// Should be rejected by admission webhook
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("naming collision"))
		})

		It("TC-COLLISION-ROLE03: should allow non-colliding role names", func() {
			// Create VaultRole
			roleName := uniqueName("tc-col-role03-ns")
			role := BuildTestRole(roleName, sharedSAName, sharedPolicyName)

			By("creating VaultRole")
			err := utils.CreateVaultRoleCR(ctx, role)
			Expect(err).NotTo(HaveOccurred())
			defer CleanupRole(ctx, roleName)

			ExpectRoleActive(ctx, roleName)

			// Create VaultClusterRole with different name (no collision)
			clusterRoleName := uniqueName("tc-col-role03-cluster-unique")
			clusterRole := &vaultv1alpha1.VaultClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterRoleName,
				},
				Spec: vaultv1alpha1.VaultClusterRoleSpec{
					ConnectionRef: sharedVaultConnectionName,
					ServiceAccounts: []vaultv1alpha1.ServiceAccountRef{
						{
							Name:      sharedSAName,
							Namespace: testNamespace,
						},
					},
					Policies: []vaultv1alpha1.PolicyReference{
						{
							Kind:      "VaultPolicy",
							Name:      sharedPolicyName,
							Namespace: testNamespace,
						},
					},
				},
			}

			By("creating VaultClusterRole with non-colliding name")
			err = utils.CreateVaultClusterRoleCR(ctx, clusterRole)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = utils.DeleteVaultClusterRoleCR(ctx, clusterRoleName)
				_ = utils.WaitForDeletion(ctx, &vaultv1alpha1.VaultClusterRole{},
					clusterRoleName, "", 30*time.Second, 2*time.Second)
			}()

			// Should become active
			Eventually(func(g Gomega) {
				cr, getErr := utils.GetVaultClusterRole(ctx, clusterRoleName)
				g.Expect(getErr).NotTo(HaveOccurred())
				g.Expect(cr.Status.Phase).To(Equal(vaultv1alpha1.PhaseActive))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})
