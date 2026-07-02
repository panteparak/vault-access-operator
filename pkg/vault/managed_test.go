package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testMountA is a sample operator identity (auth mount path) used across tests.
const testMountA = "k8s-a"

// TestOwnership_HeaderRoundTrip verifies that a full ownership record
// survives OwnershipHeader → ParseOwnership unchanged.
func TestOwnership_HeaderRoundTrip(t *testing.T) {
	in := Ownership{
		ManagedBy:   KVManagedByValue,
		AuthMount:   "k8s-prod-eu",
		Cluster:     "prod-eu",
		K8sResource: "team-a/my-policy",
		K8sKind:     "VaultPolicy",
	}
	hcl := OwnershipHeader(in) + "\npath \"secret/data/team-a/*\" {\n  capabilities = [\"read\"]\n}\n"

	out, ok := ParseOwnership(hcl)
	if !ok {
		t.Fatalf("ParseOwnership: ok=false, want true")
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

// TestOwnership_HeaderOmitsEmptyFields verifies empty fields produce no
// header lines (a token-auth operator without --cluster-name emits only
// managed-by + k8s-resource + kind).
func TestOwnership_HeaderOmitsEmptyFields(t *testing.T) {
	h := OwnershipHeader(Ownership{
		ManagedBy:   KVManagedByValue,
		K8sResource: "team-a/p",
		K8sKind:     "VaultPolicy",
	})
	for _, banned := range []string{OwnershipAuthMountKey, OwnershipClusterKey} {
		if strings.Contains(h, banned) {
			t.Errorf("header contains %q line for empty field:\n%s", banned, h)
		}
	}
	if !strings.Contains(h, KVManagedByKey+": "+KVManagedByValue) {
		t.Errorf("header missing managed-by line:\n%s", h)
	}
}

// TestParseOwnership_NotManaged covers documents that must NOT parse as
// operator-owned.
func TestParseOwnership_NotManaged(t *testing.T) {
	cases := map[string]string{
		"no comments":     "path \"secret/*\" {\n  capabilities = [\"read\"]\n}\n",
		"foreign comment": "# managed-by: terraform\npath \"a\" {\n  capabilities = [\"read\"]\n}\n",
		"legacy header": "# Vault policy managed by vault-access-operator\n" +
			"# Kubernetes resource: team-a/p\n\npath \"a\" {\n  capabilities = [\"read\"]\n}\n",
		"header after body": "path \"a\" {\n  capabilities = [\"read\"]\n}\n# managed-by: vault-access-operator\n",
		"empty":             "",
	}
	for name, hcl := range cases {
		if o, ok := ParseOwnership(hcl); ok {
			t.Errorf("%s: parsed as managed (%+v), want unmanaged", name, o)
		}
	}
}

// TestParseOwnership_ToleratesSpacing verifies the parser accepts leading
// blank lines and varied whitespace around the comment marker and colon.
func TestParseOwnership_ToleratesSpacing(t *testing.T) {
	hcl := "\n\n#   managed-by :   vault-access-operator\n#auth-mount:k8s-a\n\npath \"a\" {}\n"
	// "managed-by " with a space before the colon: key is trimmed, so it
	// must still match.
	o, ok := ParseOwnership(hcl)
	if !ok {
		t.Fatalf("ParseOwnership: ok=false, want true")
	}
	if o.AuthMount != testMountA {
		t.Errorf("AuthMount = %q, want k8s-a", o.AuthMount)
	}
}

// TestOwnership_SameOwner covers the identity comparison matrix (ADR 0008):
// ownership requires the sentinel, the same auth mount, AND the same CR.
func TestOwnership_SameOwner(t *testing.T) {
	base := Ownership{ManagedBy: KVManagedByValue, AuthMount: testMountA, K8sResource: "ns/p"}

	if !base.SameOwner(testMountA, "ns/p") {
		t.Error("identical identity+resource: want SameOwner=true")
	}
	if base.SameOwner("k8s-b", "ns/p") {
		t.Error("different auth mount (another cluster's operator): want SameOwner=false")
	}
	if base.SameOwner(testMountA, "ns/other") {
		t.Error("different owning CR: want SameOwner=false")
	}
	foreign := Ownership{ManagedBy: "someone-else", AuthMount: testMountA, K8sResource: "ns/p"}
	if foreign.SameOwner(testMountA, "ns/p") {
		t.Error("foreign managed-by sentinel: want SameOwner=false")
	}
	// Token-auth operator (no mount) matches only records that also carry
	// no mount.
	tokenOwned := Ownership{ManagedBy: KVManagedByValue, K8sResource: "ns/p"}
	if !tokenOwned.SameOwner("", "ns/p") {
		t.Error("both sides mountless: want SameOwner=true")
	}
	if base.SameOwner("", "ns/p") {
		t.Error("record has mount, caller has none: want SameOwner=false")
	}
}

// policyStore is a minimal sys/policies/acl mock for GetPolicyOwnership.
type policyStore struct {
	policies map[string]string
	fail     bool
}

func (p *policyStore) handle(w http.ResponseWriter, r *http.Request) {
	const prefix = "/v1/sys/policies/acl/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if p.fail {
		w.WriteHeader(http.StatusForbidden)
		writeJSONResp(w, map[string]interface{}{"errors": []string{"permission denied"}})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	hcl, ok := p.policies[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSONResp(w, map[string]interface{}{
		"data": map[string]interface{}{"name": name, "policy": hcl},
	})
}

func newPolicyStoreClient(t *testing.T, store *policyStore) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(store.handle))
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{Address: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestGetPolicyOwnership covers the three read outcomes: owned, unmanaged,
// and absent.
func TestGetPolicyOwnership(t *testing.T) {
	owned := OwnershipHeader(Ownership{
		ManagedBy:   KVManagedByValue,
		AuthMount:   testMountA,
		K8sResource: "team-a/p",
		K8sKind:     "VaultPolicy",
	}) + "\npath \"a\" {\n  capabilities = [\"read\"]\n}\n"

	store := &policyStore{policies: map[string]string{
		"team-a-p":  owned,
		"unmanaged": "path \"b\" {\n  capabilities = [\"read\"]\n}\n",
	}}
	c := newPolicyStoreClient(t, store)
	ctx := context.Background()

	own, err := c.GetPolicyOwnership(ctx, "team-a-p")
	if err != nil || own == nil {
		t.Fatalf("owned policy: got (%v, %v), want ownership", own, err)
	}
	if own.AuthMount != testMountA || own.K8sResource != "team-a/p" {
		t.Errorf("ownership = %+v", own)
	}

	own, err = c.GetPolicyOwnership(ctx, "unmanaged")
	if err != nil || own != nil {
		t.Errorf("unmanaged policy: got (%v, %v), want (nil, nil)", own, err)
	}

	own, err = c.GetPolicyOwnership(ctx, "absent")
	if err != nil || own != nil {
		t.Errorf("absent policy: got (%v, %v), want (nil, nil)", own, err)
	}
}

// TestGetPolicyOwnership_ReadError verifies a Vault error is surfaced (the
// caller decides whether to adopt or retry — it must be able to tell "error"
// from "unmanaged").
func TestGetPolicyOwnership_ReadError(t *testing.T) {
	c := newPolicyStoreClient(t, &policyStore{fail: true})
	if _, err := c.GetPolicyOwnership(context.Background(), "x"); err == nil {
		t.Fatal("want error on 403, got nil")
	}
}

// TestSetAuthMount_TrimsSlashes verifies mount normalization on the client.
func TestSetAuthMount_TrimsSlashes(t *testing.T) {
	c := &Client{}
	c.SetAuthMount("k8s-a/")
	if got := c.AuthMount(); got != testMountA {
		t.Errorf("AuthMount = %q, want k8s-a", got)
	}
}
