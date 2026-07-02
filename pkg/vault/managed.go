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
//   - Auth roles carry nothing — Vault has no role metadata surface. Role
//     ownership lives in the owning CR's status plus the one-cluster-per-
//     auth-mount deployment invariant.
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
		case KVK8sResourceKey:
			o.K8sResource = value
		case OwnershipK8sKindKey:
			o.K8sKind = value
		}
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
