//go:build integration

package kvsecret

import (
	"context"

	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/panteparak/vault-access-operator/pkg/vault"
	"github.com/panteparak/vault-access-operator/test/integration"
)

// These tests exercise the pkg/vault KV v2 seeding surface against a REAL Vault
// container, pinning behavior that the httptest mock cannot guarantee — most
// importantly the create-only ACL decision (INT-KVS07).
var _ = Describe("VaultKVSecret seeding (real Vault)", func() {
	var (
		ctx context.Context
		env *integration.TestEnvironment
		vc  *vault.Client
	)

	BeforeEach(func() {
		ctx = context.Background()
		env = integration.GetTestEnv()
		Expect(env).NotTo(BeNil())
		vc = env.VaultClient
		Expect(vc).NotTo(BeNil())
	})

	It("seeds an absent path [INT-KVS01]", func() {
		created, version, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs01/config",
			map[string]string{"username": ""})
		Expect(err).NotTo(HaveOccurred())
		Expect(created).To(BeTrue())
		Expect(version).To(Equal(1))

		md, err := vc.ReadKVMetadata(ctx, "secret", "int-kvs01/config")
		Expect(err).NotTo(HaveOccurred())
		Expect(md).NotTo(BeNil())
		Expect(md.CurrentVersion).To(Equal(1))
	})

	It("never overwrites an existing path [INT-KVS02]", func() {
		_, _, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs02/config",
			map[string]string{"a": "first"})
		Expect(err).NotTo(HaveOccurred())

		created, version, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs02/config",
			map[string]string{"a": "second"})
		Expect(err).NotTo(HaveOccurred())
		Expect(created).To(BeFalse())
		Expect(version).To(Equal(1), "existing secret must not be overwritten")
	})

	It("stamps ownership and deletes-if-untouched [INT-KVS03]", func() {
		_, _, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs03/config", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(vc.StampKVOwnership(ctx, "secret", "int-kvs03/config",
			vault.KVOwnership{K8sResource: "ns/app"})).To(Succeed())

		md, err := vc.ReadKVMetadata(ctx, "secret", "int-kvs03/config")
		Expect(err).NotTo(HaveOccurred())
		Expect(vault.IsOwnedBy(md)).To(BeTrue())
		Expect(md.CustomMetadata[vault.KVK8sResourceKey]).To(Equal("ns/app"))

		Expect(vc.DeleteKVSecret(ctx, "secret", "int-kvs03/config")).To(Succeed())
		md, err = vc.ReadKVMetadata(ctx, "secret", "int-kvs03/config")
		Expect(err).NotTo(HaveOccurred())
		Expect(md).To(BeNil(), "secret must be gone after delete")
	})

	It("surfaces a write since seeding as a version bump (retain signal) [INT-KVS04]", func() {
		_, seededVersion, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs04/config", nil)
		Expect(err).NotTo(HaveOccurred())

		// Simulate ESO/user writing real data — this advances the version.
		_, err = vc.KVv2("secret").Put(ctx, "int-kvs04/config", map[string]interface{}{"filled": "by-user"})
		Expect(err).NotTo(HaveOccurred())

		md, err := vc.ReadKVMetadata(ctx, "secret", "int-kvs04/config")
		Expect(err).NotTo(HaveOccurred())
		Expect(md.CurrentVersion).To(BeNumerically(">", seededVersion),
			"cleanup would RETAIN because current version != seeded version")
	})

	It("seeds a truly empty {} secret [INT-KVS05]", func() {
		created, version, err := vc.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs05/empty", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(created).To(BeTrue())
		Expect(version).To(Equal(1))

		md, err := vc.ReadKVMetadata(ctx, "secret", "int-kvs05/empty")
		Expect(err).NotTo(HaveOccurred())
		Expect(md).NotTo(BeNil(), "an empty {} secret must still exist at version 1")
	})

	// INT-KVS07 pins the create-only operator-policy decision against the real
	// Vault image: a create-only data-path token MUST be able to seed a new
	// path, but MUST NOT be able to overwrite or read existing secret values.
	// If the first create fails here, the operator policy must fall back to
	// ["create","update"] on secret/data/* (see the plan/PRD).
	It("works under a create-only data-path policy; denies overwrite and read [INT-KVS07]", func() {
		const policyHCL = `
path "secret/data/*"     { capabilities = ["create"] }
path "secret/metadata/*" { capabilities = ["create", "read", "update", "patch", "delete", "list"] }
`
		Expect(vc.WritePolicy(ctx, "kv-seed-createonly", policyHCL)).To(Succeed())

		tok, err := vc.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{
			Policies: []string{"kv-seed-createonly"},
			TTL:      "10m",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(tok).NotTo(BeNil())

		co, err := vault.NewClient(vault.ClientConfig{Address: env.VaultAddress()})
		Expect(err).NotTo(HaveOccurred())
		Expect(co.AuthenticateToken(tok.Auth.ClientToken)).To(Succeed())

		// (a) create-only allows the first seed.
		created, version, err := co.CreateKVSecretIfAbsent(ctx, "secret", "int-kvs07/a", nil)
		Expect(err).NotTo(HaveOccurred(), "create-only token must be able to CREATE a new secret")
		Expect(created).To(BeTrue())
		Expect(version).To(Equal(1))
		Expect(co.StampKVOwnership(ctx, "secret", "int-kvs07/a",
			vault.KVOwnership{K8sResource: "ns/app"})).To(Succeed())

		// (b) create-only DENIES overwriting an existing secret (update).
		_, err = co.KVv2("secret").Put(ctx, "int-kvs07/a", map[string]interface{}{"x": "y"})
		Expect(err).To(HaveOccurred(), "create-only token must NOT be able to overwrite an existing secret")

		// (c) create-only DENIES reading the data values.
		_, err = co.KVv2("secret").Get(ctx, "int-kvs07/a")
		Expect(err).To(HaveOccurred(), "create-only token must NOT be able to read secret data values")
	})
})
