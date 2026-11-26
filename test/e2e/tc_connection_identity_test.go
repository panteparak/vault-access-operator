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
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/shared/naming"
	"github.com/panteparak/vault-access-operator/test/utils"
)

// Connection identity tests (#18, ADR 0011). They run against the default
// e2e stack (`make e2e-local-up`, static-token operator connection, so the
// default naming identity is "_"). Run them with
// `make e2e-local-test-connection-identity`.
//
// TC-ID01 upgrades from a previous release image: it swaps the operator
// Deployment's image to E2E_UPGRADE_FROM_IMAGE (imported into k3s by the
// Make target), lets that release write objects, then swaps back. It skips
// when E2E_UPGRADE_FROM_IMAGE is empty. It runs first, before any
// identity-bearing connection exists, because the old release does not know
// spec.identity and would rename those objects: that is the only reason the
// container is Ordered.
//
// ContinueOnFailure, and every spec sets up what it needs itself
// (ensureIdentityConnection, its own policies and roles), so one failing
// spec cannot skip or break the others (#18 review finding 3).
var _ = Describe("Connection Identity", Ordered, ContinueOnFailure, Label("connection-identity"), func() {
	const (
		operatorNS     = "vault-access-operator-system"
		idName         = "tc-id-proj"
		idConnName     = "tc-id-conn"
		idK8sConnName  = "tc-id-k8s-conn"
		collideConn    = "tc-id-collide"
		idPolicy       = "tc-id-policy"
		idRole         = "tc-id-role"
		idSA           = "tc-id-sa"
		foreignPolicy  = "tc-id04-policy"
		restartPolicy  = "tc-id05-policy"
		restartRole    = "tc-id05-role"
		migratePolicy  = "tc-id06-policy"
		k8sLoginMount  = "kubernetes"
		operatorK8sRol = "vault-access-operator"
	)

	ctx := context.Background()

	// ensureIdentityConnection creates the identity-bearing connection unless
	// it already exists, and waits for it to be Active. Each spec that needs
	// it calls this, so none depends on another spec having run or passed.
	ensureIdentityConnection := func() {
		GinkgoHelper()
		if _, err := utils.GetVaultConnection(ctx, idConnName, ""); err != nil {
			Expect(utils.CreateVaultConnectionCR(ctx, identityConnection(idConnName, idName))).To(Succeed())
		}
		Expect(utils.WaitForVaultConnectionPhase(ctx, idConnName, "Active", 2*time.Minute, 5*time.Second)).To(Succeed())
	}

	BeforeAll(func() {
		RefreshSharedVaultToken(ctx)
		_ = utils.CreateServiceAccount(ctx, testNamespace, idSA)
	})

	AfterAll(func() {
		By("cleaning up connection-identity test resources")
		for _, r := range []string{idRole, restartRole} {
			_ = utils.DeleteVaultRoleCR(ctx, r, testNamespace)
		}
		for _, p := range []string{idPolicy, foreignPolicy, restartPolicy, migratePolicy} {
			_ = utils.DeleteVaultPolicyCR(ctx, p, testNamespace)
		}
		for _, c := range []string{idConnName, idK8sConnName, collideConn} {
			_ = utils.DeleteVaultConnectionCR(ctx, c)
		}
		_ = utils.DeleteServiceAccount(ctx, testNamespace, idSA)
		if vc, err := utils.GetTestVaultClient(); err == nil {
			_ = vc.DeletePolicy(ctx, utils.ExpectedVaultName(idName, testNamespace, foreignPolicy))
		}
	})

	It("TC-ID01: objects written by the previous release (markers off and on) stay ours after upgrade", func() {
		fromImage := os.Getenv("E2E_UPGRADE_FROM_IMAGE")
		if fromImage == "" {
			Skip("E2E_UPGRADE_FROM_IMAGE not set: run `make e2e-local-test-connection-identity`")
		}
		deploy := operatorDeployment(operatorNS)
		currentImage := kubectlOut("get", "deployment", deploy, "-n", operatorNS, "-o",
			`jsonpath={.spec.template.spec.containers[?(@.name=="manager")].image}`)
		Expect(currentImage).NotTo(BeEmpty())
		DeferCleanup(func() {
			By("restoring the operator image and MANAGED_MARKERS")
			kubectlOut("set", "image", "deployment/"+deploy, "-n", operatorNS, "manager="+currentImage)
			kubectlOut("set", "env", "deployment/"+deploy, "-n", operatorNS, "-c", "manager", "MANAGED_MARKERS-")
			kubectlOut("rollout", "status", "deployment/"+deploy, "-n", operatorNS, "--timeout=180s")
		})

		for _, markersOn := range []bool{false, true} {
			suffix := map[bool]string{false: "off", true: "on"}[markersOn]
			policyName, roleName := "tc-id01-policy-"+suffix, "tc-id01-role-"+suffix
			DeferCleanup(func() {
				_ = utils.DeleteVaultRoleCR(ctx, roleName, testNamespace)
				_ = utils.DeleteVaultPolicyCR(ctx, policyName, testNamespace)
			})

			By("running the previous release with MANAGED_MARKERS=" + suffix)
			kubectlOut("set", "image", "deployment/"+deploy, "-n", operatorNS, "manager="+fromImage)
			if markersOn {
				kubectlOut("set", "env", "deployment/"+deploy, "-n", operatorNS, "-c", "manager", "MANAGED_MARKERS=true")
			} else {
				kubectlOut("set", "env", "deployment/"+deploy, "-n", operatorNS, "-c", "manager", "MANAGED_MARKERS-")
			}
			kubectlOut("rollout", "status", "deployment/"+deploy, "-n", operatorNS, "--timeout=180s")

			By("letting the previous release write a policy and a role")
			Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(policyName))).To(Succeed())
			ExpectPolicyActive(ctx, policyName)
			Expect(utils.CreateVaultRoleCR(ctx, BuildTestRole(roleName, idSA, policyName))).To(Succeed())
			ExpectRoleActive(ctx, roleName)
			before := snapshotPolicyAndRole(ctx, policyName, roleName)

			By("upgrading back to the operator under test")
			kubectlOut("set", "image", "deployment/"+deploy, "-n", operatorNS, "manager="+currentImage)
			kubectlOut("set", "env", "deployment/"+deploy, "-n", operatorNS, "-c", "manager", "MANAGED_MARKERS-")
			kubectlOut("rollout", "status", "deployment/"+deploy, "-n", operatorNS, "--timeout=180s")

			By("verifying: no conflict, no rewrite (status and Vault content unchanged)")
			Consistently(func(g Gomega) {
				g.Expect(snapshotPolicyAndRole(ctx, policyName, roleName)).To(Equal(before))
			}, 60*time.Second, 5*time.Second).Should(Succeed())
			Expect(conflictEvents(policyName) + conflictEvents(roleName)).To(BeEmpty())
		}
	})

	It("TC-ID02: the CRD refuses a malformed identity; the controller refuses one equal to an auth mount", func() {
		for _, bad := range []string{"_", "Proj", "a.b", strings.Repeat("a", 41)} {
			err := utils.CreateVaultConnectionCR(ctx, identityConnection(collideConn, bad))
			Expect(err).To(HaveOccurred(), "identity %q must be rejected at admission", bad)
			Expect(err.Error()).To(ContainSubstring("spec.identity.name"))
		}

		By("an identity equal to an auth mount on the server is refused (Phase=Error)")
		Expect(utils.CreateVaultConnectionCR(ctx, identityConnection(collideConn, k8sLoginMount))).To(Succeed())
		Eventually(func(g Gomega) {
			conn, err := utils.GetVaultConnection(ctx, collideConn, "")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(conn.Status.Phase).To(Equal(vaultv1alpha1.PhaseError))
			g.Expect(readyReason(conn.Status.Conditions)).To(Equal(vaultv1alpha1.ReasonIdentityCollidesWithAuthMount))
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
		Expect(utils.DeleteVaultConnectionCR(ctx, collideConn)).To(Succeed())
	})

	It("TC-ID03: names, ownership records and status carry the connection identity", func() {
		ensureIdentityConnection()

		conn, err := utils.GetVaultConnection(ctx, idConnName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(conn.Status.Identity).To(Equal(&vaultv1alpha1.IdentityStatus{Name: idName, Source: naming.SourceSpec}))
		shared, err := utils.GetVaultConnection(ctx, sharedVaultConnectionName, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(shared.Status.Identity).NotTo(BeNil())
		Expect(shared.Status.Identity.Name).To(Equal(utils.DefaultIdentity()))

		By("a policy through the identity connection is named and recorded under it")
		policy := BuildTestPolicy(idPolicy)
		policy.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		ExpectPolicyActive(ctx, idPolicy)
		vaultPolicyName := utils.ExpectedVaultName(idName, testNamespace, idPolicy)
		p, err := utils.GetVaultPolicy(ctx, idPolicy, testNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.VaultName).To(Equal(vaultPolicyName))
		Expect(p.Status.Binding.Identity).To(Equal(idName))
		Expect(p.Status.Binding.Connection).To(Equal(idConnName))

		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())
		hcl, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		own, ok := vault.ParseOwnership(hcl)
		Expect(ok).To(BeTrue(), "expected ownership header, got:\n%s", hcl)
		Expect(own.Identity).To(Equal(idName))
		Expect(own.K8sResource).To(Equal(testNamespace + "/" + idPolicy))

		By("a role through the identity connection is named and recorded under it")
		role := BuildTestRole(idRole, idSA, idPolicy)
		role.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
		ExpectRoleActive(ctx, idRole)
		r, err := utils.GetVaultRole(ctx, idRole, testNamespace)
		Expect(err).NotTo(HaveOccurred())
		vaultRoleName := utils.ExpectedVaultName(idName, testNamespace, idRole)
		Expect(r.Status.VaultRoleName).To(Equal(vaultRoleName))
		Expect(r.Status.Binding.Identity).To(Equal(idName))
		data, err := vc.ReadAuthRole(ctx, k8sLoginMount, vaultRoleName)
		Expect(err).NotTo(HaveOccurred())
		roleOwn, ok := vault.ParseAliasMetadata(data)
		Expect(ok).To(BeTrue(), "expected alias_metadata record (Vault >= 1.21.3; e2e pins 1.21.4), got %v", data)
		Expect(roleOwn.Identity).To(Equal(idName))
	})

	It("TC-ID04: a foreign-owned object at the identity name is a Conflict; nothing is written or deleted", func() {
		ensureIdentityConnection()
		vaultPolicyName := utils.ExpectedVaultName(idName, testNamespace, foreignPolicy)
		foreign := vault.OwnershipHeader(vault.Ownership{
			ManagedBy:   vault.KVManagedByValue,
			AuthMount:   "k8s-other-cluster",
			Identity:    idName,
			K8sResource: testNamespace + "/" + foreignPolicy,
			K8sKind:     "VaultPolicy",
		}) + "\npath \"secret/data/foreign/*\" { capabilities = [\"read\"] }"
		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())
		Expect(vc.WritePolicy(ctx, vaultPolicyName, foreign)).To(Succeed())
		written, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())

		policy := BuildTestPolicy(foreignPolicy)
		policy.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		WaitForPolicyPhase(ctx, foreignPolicy, testNamespace, "Conflict", 2*time.Minute)
		Consistently(func(g Gomega) {
			got, readErr := vc.ReadPolicy(ctx, vaultPolicyName)
			g.Expect(readErr).NotTo(HaveOccurred())
			g.Expect(got).To(Equal(written))
		}, 20*time.Second, 5*time.Second).Should(Succeed())

		By("deleting the CR leaves the foreign object in place")
		Expect(utils.DeleteVaultPolicyCR(ctx, foreignPolicy, testNamespace)).To(Succeed())
		Eventually(func() bool {
			_, getErr := utils.GetVaultPolicy(ctx, foreignPolicy, testNamespace)
			return getErr != nil
		}, 2*time.Minute, 5*time.Second).Should(BeTrue(), "CR should be gone")
		got, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(written))
	})

	It("TC-ID05: an operator restart gives no conflict events and no rewrites", func() {
		ensureIdentityConnection()
		policy := BuildTestPolicy(restartPolicy)
		policy.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		ExpectPolicyActive(ctx, restartPolicy)
		role := BuildTestRole(restartRole, idSA, restartPolicy)
		role.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultRoleCR(ctx, role)).To(Succeed())
		ExpectRoleActive(ctx, restartRole)

		before := snapshotPolicyAndRole(ctx, restartPolicy, restartRole)
		deploy := operatorDeployment(operatorNS)
		kubectlOut("rollout", "restart", "deployment/"+deploy, "-n", operatorNS)
		kubectlOut("rollout", "status", "deployment/"+deploy, "-n", operatorNS, "--timeout=180s")
		Consistently(func(g Gomega) {
			g.Expect(snapshotPolicyAndRole(ctx, restartPolicy, restartRole)).To(Equal(before))
		}, 60*time.Second, 5*time.Second).Should(Succeed())
		Expect(conflictEvents(restartPolicy) + conflictEvents(restartRole)).To(BeEmpty())
	})

	It("TC-ID06: moving an identity to another login mount is delete-then-create", func() {
		ensureIdentityConnection()
		vaultPolicyName := utils.ExpectedVaultName(idName, testNamespace, migratePolicy)
		policy := BuildTestPolicy(migratePolicy)
		policy.Spec.ConnectionRef = idConnName
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		ExpectPolicyActive(ctx, migratePolicy)

		By("a second connection with the same identity logs in through the kubernetes mount")
		k8sConn := identityConnection(idK8sConnName, idName)
		k8sConn.Spec.Auth = vaultv1alpha1.AuthConfig{Kubernetes: &vaultv1alpha1.KubernetesAuth{
			Role: operatorK8sRol, AuthPath: k8sLoginMount,
			TokenDuration: metav1.Duration{Duration: time.Hour},
		}}
		Expect(utils.CreateVaultConnectionCR(ctx, k8sConn)).To(Succeed())
		Expect(utils.WaitForVaultConnectionPhase(ctx, idK8sConnName, "Active", 3*time.Minute, 5*time.Second)).To(Succeed())

		By("wrong order: pointing the CR at the new login mount first is a Conflict")
		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())
		written, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.UpdateVaultPolicyCR(ctx, migratePolicy, testNamespace, func(p *vaultv1alpha1.VaultPolicy) {
			p.Spec.ConnectionRef = idK8sConnName
		})).To(Succeed())
		WaitForPolicyPhase(ctx, migratePolicy, testNamespace, "Conflict", 2*time.Minute)
		got, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(written))

		By("right order: delete on the old login mount, then apply on the new one")
		Expect(utils.UpdateVaultPolicyCR(ctx, migratePolicy, testNamespace, func(p *vaultv1alpha1.VaultPolicy) {
			p.Spec.ConnectionRef = idConnName
		})).To(Succeed())
		ExpectPolicyActive(ctx, migratePolicy)
		Expect(utils.DeleteVaultPolicyCR(ctx, migratePolicy, testNamespace)).To(Succeed())
		ExpectPolicyNotInVault(ctx, vaultPolicyName)

		policy = BuildTestPolicy(migratePolicy)
		policy.Spec.ConnectionRef = idK8sConnName
		Expect(utils.CreateVaultPolicyCR(ctx, policy)).To(Succeed())
		ExpectPolicyActive(ctx, migratePolicy)
		hcl, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		own, ok := vault.ParseOwnership(hcl)
		Expect(ok).To(BeTrue())
		Expect(own.AuthMount).To(Equal(k8sLoginMount))
		Expect(own.Identity).To(Equal(idName))
	})

	It("TC-ID07: a new CR targeting an unrecorded existing object is a Conflict until it adopts", func() {
		name := "tc-id07-policy"
		vaultPolicyName := nsVaultName(name)
		vc, err := utils.GetTestVaultClient()
		Expect(err).NotTo(HaveOccurred())
		Expect(vc.WritePolicy(ctx, vaultPolicyName, `path "secret/data/unrecorded/*" { capabilities = ["read"] }`)).
			To(Succeed())
		DeferCleanup(func() { _ = utils.DeleteVaultPolicyCR(ctx, name, testNamespace) })

		Expect(utils.CreateVaultPolicyCR(ctx, BuildTestPolicy(name))).To(Succeed())
		WaitForPolicyPhase(ctx, name, testNamespace, "Conflict", 2*time.Minute)

		Expect(utils.UpdateVaultPolicyCR(ctx, name, testNamespace, func(p *vaultv1alpha1.VaultPolicy) {
			p.Spec.ConflictPolicy = vaultv1alpha1.ConflictPolicyAdopt
		})).To(Succeed())
		ExpectPolicyActive(ctx, name)
		hcl, err := vc.ReadPolicy(ctx, vaultPolicyName)
		Expect(err).NotTo(HaveOccurred())
		own, ok := vault.ParseOwnership(hcl)
		Expect(ok).To(BeTrue())
		Expect(own.K8sResource).To(Equal(testNamespace + "/" + name))
	})
})

// identityConnection builds a static-token connection (the suite's shared
// operator token) that sets spec.identity.
func identityConnection(name, identity string) *vaultv1alpha1.VaultConnection {
	return &vaultv1alpha1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConnectionSpec{
			Address: vaultK8sAddr,
			Auth: vaultv1alpha1.AuthConfig{Token: &vaultv1alpha1.TokenAuth{
				SecretRef: vaultv1alpha1.SecretKeySelector{
					Name: sharedVaultTokenSecretName, Namespace: testNamespace, Key: "token",
				},
			}},
			Defaults:            &vaultv1alpha1.ConnectionDefaults{AuthPath: "kubernetes"},
			HealthCheckInterval: "10s",
			Identity:            &vaultv1alpha1.ConnectionIdentity{Name: identity},
		},
	}
}

// syncSnapshot is what an unchanged reconcile must leave alone: the status a
// write would bump and the Vault content a write would replace.
type syncSnapshot struct {
	PolicyVaultName, PolicyHash, RoleVaultName, RoleHash string
	PolicySyncedAt, RoleSyncedAt                         string
	PolicyPhase, RolePhase                               string
	PolicyHCL                                            string
	RoleData                                             string
}

// snapshotPolicyAndRole snapshots a policy + role; the Vault names come
// from the CRs' recorded status (ADR 0010: status is authoritative).
func snapshotPolicyAndRole(ctx context.Context, policyName, roleName string) syncSnapshot {
	GinkgoHelper()
	p, err := utils.GetVaultPolicy(ctx, policyName, testNamespace)
	Expect(err).NotTo(HaveOccurred())
	r, err := utils.GetVaultRole(ctx, roleName, testNamespace)
	Expect(err).NotTo(HaveOccurred())
	vc, err := utils.GetTestVaultClient()
	Expect(err).NotTo(HaveOccurred())
	hcl, err := vc.ReadPolicy(ctx, p.Status.VaultName)
	Expect(err).NotTo(HaveOccurred())
	data, err := vc.ReadAuthRole(ctx, "kubernetes", r.Status.VaultRoleName)
	Expect(err).NotTo(HaveOccurred())
	return syncSnapshot{
		PolicyVaultName: p.Status.VaultName, PolicyHash: p.Status.LastAppliedHash,
		RoleVaultName: r.Status.VaultRoleName, RoleHash: r.Status.LastAppliedHash,
		PolicySyncedAt: timeString(p.Status.LastSyncedAt), RoleSyncedAt: timeString(r.Status.LastSyncedAt),
		PolicyPhase: string(p.Status.Phase), RolePhase: string(r.Status.Phase),
		PolicyHCL: hcl, RoleData: fmt.Sprint(data), // fmt prints map keys sorted
	}
}

func timeString(t *metav1.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// conflictEvents returns the Warning events on an object in the test
// namespace whose reason or message mentions a conflict.
func conflictEvents(name string) string {
	GinkgoHelper()
	out := kubectlOut("get", "events", "-n", testNamespace,
		"--field-selector", "type=Warning,involvedObject.name="+name,
		"-o", `jsonpath={range .items[*]}{.reason}: {.message}{"\n"}{end}`)
	var hits []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(line), "conflict") {
			hits = append(hits, line)
		}
	}
	return strings.Join(hits, "\n")
}

func readyReason(conds []vaultv1alpha1.Condition) string {
	for _, c := range conds {
		if c.Type == vaultv1alpha1.ConditionTypeReady {
			return c.Reason
		}
	}
	return ""
}

// operatorDeployment is the operator Deployment's name in its namespace.
func operatorDeployment(namespace string) string {
	GinkgoHelper()
	name := kubectlOut("get", "deployment", "-n", namespace, "-l", "control-plane=controller-manager",
		"-o", "jsonpath={.items[0].metadata.name}")
	Expect(name).NotTo(BeEmpty())
	return name
}

func kubectlOut(args ...string) string {
	GinkgoHelper()
	out, err := utils.Run(exec.Command("kubectl", args...)) //nolint:gosec // test-controlled args
	Expect(err).NotTo(HaveOccurred(), "kubectl %v: %s", args, out)
	return strings.TrimSpace(out)
}
