package vault

import (
	"context"
	"fmt"
	"strings"
)

// In-band ownership records (ADR 0008, supersedes ADR 0007's dedicated KV
// marker subtree). The operator stamps ownership onto the managed Vault
// objects themselves:
//
//   - ACL policies carry a structured comment header inside the policy
//     document (Vault stores HCL verbatim, so comments round-trip).
//   - KV secrets carry custom_metadata on their own path (kvsecret.go).
//   - Auth roles carry the same record in alias_metadata (ADR 0010): both
//     kubernetes and jwt auth roles store it (Vault >= 1.21.3; older Vaults,
//     including 1.21.0-1.21.2, silently drop the parameter) and echo it on read; Vault additionally
//     copies it onto entity aliases at login.
//
// The operator's identity is the auth mount path it logged in through
// (Client.AuthMount): on a shared Vault every cluster authenticates via its
// own mount, so the mount uniquely identifies the owning operator instance.
// A static-token connection has no mount and therefore no identity.
const (
	// OwnershipAuthMountKey records the owning operator's auth mount path.
	OwnershipAuthMountKey = "auth-mount"
	// OwnershipClusterKey records --cluster-name (informational; identity is
	// the auth mount).
	OwnershipClusterKey = "cluster"
	// OwnershipK8sKindKey records the owning CR kind (e.g. "VaultPolicy").
	OwnershipK8sKindKey = "k8s-kind"
	// OwnershipIdentityKey records the connection's spec.identity.name
	// (ADR 0011). Written only when set, so records (and content hashes) of
	// connections without an identity stay byte-identical to v0.12.0.
	OwnershipIdentityKey = "identity"
)

// Ownership is the in-band ownership record attached to a managed Vault
// object. For policies it is rendered as a comment header (OwnershipHeader)
// and read back with ParseOwnership.
type Ownership struct {
	// ManagedBy is the operator sentinel (KVManagedByValue).
	ManagedBy string
	// AuthMount is the owning operator's auth mount path — the operator
	// identity. Empty for static-token connections (identity unavailable).
	AuthMount string
	// Cluster is the owning operator's --cluster-name, empty when unset.
	Cluster string
	// Identity is the writing connection's spec.identity.name, empty when
	// unset (ADR 0011). Informational: SameOwner does not compare it.
	Identity string
	// K8sResource is the owning CR ("namespace/name", or "name" for
	// cluster-scoped CRs).
	K8sResource string
	// K8sKind is the owning CR kind.
	K8sKind string
}

// SameOwner reports whether this record identifies the given operator
// instance and CR: the managed-by sentinel, the same auth-mount identity,
// and the same owning K8s resource.
func (o Ownership) SameOwner(authMount, k8sResource string) bool {
	return o.ManagedBy == KVManagedByValue &&
		o.AuthMount == authMount &&
		o.K8sResource == k8sResource
}

// Owner is the operator instance and CR a sync or delete acts for: what an
// Ownership record must name for the object to count as ours. It is stored
// on cleanup-queue items so a replayed delete re-checks the same owner.
type Owner struct {
	// AuthMount is the login mount of the acting connection ("" for a
	// static token).
	AuthMount string `json:"authMount"`
	// K8sResource is the owning CR ("namespace/name", or "name").
	K8sResource string `json:"k8sResource"`
}

// OwnedBy reports whether this record names owner (SameOwner on its fields).
func (o Ownership) OwnedBy(w Owner) bool {
	return o.SameOwner(w.AuthMount, w.K8sResource)
}

// PolicyOwnershipReader is the read a policy delete gate needs.
type PolicyOwnershipReader interface {
	GetPolicyOwnership(ctx context.Context, name string) (*Ownership, error)
}

// RoleReader is the read a role delete gate needs.
type RoleReader interface {
	ReadKubernetesAuthRole(ctx context.Context, authPath, roleName string) (map[string]interface{}, error)
}

// ForeignPolicyOwner re-reads a policy's in-band record before a destructive
// delete. It returns the record only when it names someone other than owner;
// nil means absent, header-less, or ours. A read error is returned and never
// treated as permission to delete (fail closed): callers queue a retry.
func ForeignPolicyOwner(ctx context.Context, c PolicyOwnershipReader, name string, owner Owner) (*Ownership, error) {
	own, err := c.GetPolicyOwnership(ctx, name)
	if err != nil || own == nil || own.OwnedBy(owner) {
		return nil, err
	}
	return own, nil
}

// ForeignRoleOwner is ForeignPolicyOwner for auth roles (alias_metadata).
func ForeignRoleOwner(ctx context.Context, c RoleReader, authPath, name string, owner Owner) (*Ownership, error) {
	data, err := c.ReadKubernetesAuthRole(ctx, authPath, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read role %s for ownership check: %w", name, err)
	}
	own, ok := ParseAliasMetadata(data)
	if !ok || own.OwnedBy(owner) {
		return nil, nil
	}
	return &own, nil
}

// String renders a compact human-readable owner description for conflict
// messages and events.
func (o Ownership) String() string {
	s := o.K8sResource
	if o.K8sKind != "" {
		s = o.K8sKind + " " + s
	}
	if o.AuthMount != "" {
		s += " (auth-mount " + o.AuthMount + ")"
	}
	return s
}

// OwnershipHeader renders the structured comment header stamped at the top of
// every operator-written policy document. Only stable identity fields — no
// timestamps — so the content hash of an unchanged policy never churns.
// Empty fields are omitted.
func OwnershipHeader(o Ownership) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n", KVManagedByKey, KVManagedByValue)
	if o.AuthMount != "" {
		fmt.Fprintf(&b, "# %s: %s\n", OwnershipAuthMountKey, o.AuthMount)
	}
	if o.Cluster != "" {
		fmt.Fprintf(&b, "# %s: %s\n", OwnershipClusterKey, o.Cluster)
	}
	if o.Identity != "" {
		fmt.Fprintf(&b, "# %s: %s\n", OwnershipIdentityKey, o.Identity)
	}
	if o.K8sResource != "" {
		fmt.Fprintf(&b, "# %s: %s\n", KVK8sResourceKey, o.K8sResource)
	}
	if o.K8sKind != "" {
		fmt.Fprintf(&b, "# %s: %s\n", OwnershipK8sKindKey, o.K8sKind)
	}
	return b.String()
}

// ParseOwnership extracts the ownership header from a policy document.
// It scans only the leading comment block (parsing stops at the first
// non-comment, non-blank line) and returns ok=false when the block carries
// no `managed-by: vault-access-operator` line — i.e. the policy is not
// operator-managed (or was written by a pre-ADR-0008 operator version).
func ParseOwnership(hcl string) (Ownership, bool) {
	var o Ownership
	for _, line := range strings.Split(hcl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break // end of leading comment block
		}
		key, value, found := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case KVManagedByKey:
			o.ManagedBy = value
		case OwnershipAuthMountKey:
			o.AuthMount = value
		case OwnershipClusterKey:
			o.Cluster = value
		case OwnershipIdentityKey:
			o.Identity = value
		case KVK8sResourceKey:
			o.K8sResource = value
		case OwnershipK8sKindKey:
			o.K8sKind = value
		}
	}
	return o, o.ManagedBy == KVManagedByValue
}

// RoleAliasMetadataKey is the auth-role payload field carrying the ownership
// record (ADR 0010, amending ADR 0008's "roles carry nothing"). Supported by
// the kubernetes and jwt auth backends on Vault >= 1.21.3; older Vaults
// (verified on 1.17 and 1.21.0-1.21.2) silently drop the parameter, degrading roles back to
// no in-band ownership.
const RoleAliasMetadataKey = "alias_metadata"

// OwnershipAliasMetadata renders the ownership record as the alias_metadata
// map for role writes — the same vocabulary as the policy comment header.
// Only stable identity fields, so an unchanged spec hashes identically.
func OwnershipAliasMetadata(o Ownership) map[string]string {
	m := map[string]string{KVManagedByKey: KVManagedByValue}
	if o.AuthMount != "" {
		m[OwnershipAuthMountKey] = o.AuthMount
	}
	if o.Cluster != "" {
		m[OwnershipClusterKey] = o.Cluster
	}
	if o.Identity != "" {
		m[OwnershipIdentityKey] = o.Identity
	}
	if o.K8sResource != "" {
		m[KVK8sResourceKey] = o.K8sResource
	}
	if o.K8sKind != "" {
		m[OwnershipK8sKindKey] = o.K8sKind
	}
	return m
}

// ParseAliasMetadata extracts the ownership record from a role's read-back
// data. ok=false when the role carries no operator sentinel (hand-created,
// pre-ADR-0010, or written to a Vault that dropped alias_metadata).
func ParseAliasMetadata(roleData map[string]interface{}) (Ownership, bool) {
	raw, _ := roleData[RoleAliasMetadataKey].(map[string]interface{})
	get := func(k string) string {
		v, _ := raw[k].(string)
		return v
	}
	o := Ownership{
		ManagedBy:   get(KVManagedByKey),
		AuthMount:   get(OwnershipAuthMountKey),
		Cluster:     get(OwnershipClusterKey),
		Identity:    get(OwnershipIdentityKey),
		K8sResource: get(KVK8sResourceKey),
		K8sKind:     get(OwnershipK8sKindKey),
	}
	return o, o.ManagedBy == KVManagedByValue
}

// GetPolicyOwnership reads a policy and parses its ownership header.
// Returns (nil, nil) when the policy does not exist or carries no operator
// ownership header. Requires only the `read` capability on
// `sys/policies/acl/*` that the operator already holds for policy CRUD.
func (c *Client) GetPolicyOwnership(ctx context.Context, name string) (*Ownership, error) {
	hcl, err := c.ReadPolicy(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy %s for ownership check: %w", name, err)
	}
	if hcl == "" {
		return nil, nil
	}
	o, ok := ParseOwnership(hcl)
	if !ok {
		return nil, nil
	}
	return &o, nil
}
