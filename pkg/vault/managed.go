package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"

	"github.com/panteparak/vault-access-operator/shared/naming"
)

const (
	// markerKVMount is the KV v2 mount that holds managed markers.
	markerKVMount = "secret"

	// markerBaseRel is the marker root relative to the KV mount. Full metadata
	// path: secret/metadata/vault-access-operator/managed/...
	markerBaseRel = "vault-access-operator/managed"

	// markerClusterScopedNS is the sentinel namespace segment used for
	// cluster-scoped CRs (VaultClusterPolicy/VaultClusterRole). It is not a
	// valid DNS-1123 namespace, so it can never collide with a real namespace,
	// and it keeps the path depth uniform for the recursive list walk.
	markerClusterScopedNS = "_cluster"

	// markerPreflightSeg is a probe path (at the kind level, so ListManaged
	// never traverses it) used to fail fast when the flag is on but the grant
	// is missing.
	markerPreflightSeg = "_preflight"

	// custom_metadata keys unique to markers. managed-by / k8s-resource reuse
	// the KV ownership constants (KVManagedByKey / KVK8sResourceKey).
	markerManagedAtKey   = "managed-at"
	markerLastUpdatedKey = "last-updated"
)

// MarkerKind distinguishes the two managed resource families. Its value is also
// the path segment for that kind.
type MarkerKind string

const (
	MarkerPolicy MarkerKind = "policies"
	MarkerRole   MarkerKind = "roles"
)

// MarkerID identifies a managed marker by its structural coordinates. The Vault
// path — and thus per-segment ACL scoping — is derived entirely from these.
type MarkerID struct {
	// Kind is "policies" or "roles".
	Kind MarkerKind
	// Mount is the bare auth-mount name (e.g. "kubernetes"); roles only, "" for policies.
	Mount string
	// Namespace is the owning K8s namespace; "" means cluster-scoped (encoded
	// as the _cluster sentinel in the path).
	Namespace string
	// Name is the CR name.
	Name string
}

// ManagedResource is the ownership record read from a marker's custom_metadata.
type ManagedResource struct {
	// ID are the structural coordinates the marker was found at (lets a caller
	// reconstruct the exact path to read or remove it).
	ID MarkerID
	// K8sResource is the owning Kubernetes resource (namespace/name, or name for cluster-scoped).
	K8sResource string
	// ManagedAt is when this resource was first marked.
	ManagedAt time.Time
	// LastUpdated is when the marker was last written.
	LastUpdated time.Time
}

// markerKindRoot returns the marker path (relative to the KV mount) up to and
// including the kind segment: {base}[/{cluster}]/{kind}. The cluster segment is
// omitted when no cluster prefix is configured. This is the root the recursive
// list walk descends from.
func markerKindRoot(kind MarkerKind) string {
	segs := []string{markerBaseRel}
	if c := naming.Cluster(); c != "" {
		segs = append(segs, c)
	}
	segs = append(segs, string(kind))
	return strings.Join(segs, "/")
}

// markerRelPath returns the full marker path relative to the KV mount:
//
//	roles:    {base}[/{cluster}]/roles/{mount}/{ns|_cluster}/{name}
//	policies: {base}[/{cluster}]/policies/{ns|_cluster}/{name}
func markerRelPath(id MarkerID) string {
	ns := id.Namespace
	if ns == "" {
		ns = markerClusterScopedNS
	}
	root := markerKindRoot(id.Kind)
	if id.Kind == MarkerRole {
		return strings.Join([]string{root, id.Mount, ns, id.Name}, "/")
	}
	return strings.Join([]string{root, ns, id.Name}, "/")
}

// markerVaultName reconstructs the Vault object name a marker corresponds to,
// matching the derivation used to write the policy/role itself:
// naming.Vault("{ns}-{name}") for namespaced CRs, naming.Vault("{name}") for
// cluster-scoped. Used to key ListManaged for comparison against live Vault
// object names.
func markerVaultName(id MarkerID) string {
	if id.Namespace == "" {
		return naming.Vault(id.Name)
	}
	return naming.Vault(id.Namespace + "-" + id.Name)
}

// MarkManaged writes (or refreshes) the ownership marker for id. Storage is KV
// v2 custom_metadata only — never a secret data version. managed-at is
// preserved across re-marks.
func (c *Client) MarkManaged(ctx context.Context, id MarkerID, k8sResource string) error {
	rel := markerRelPath(id)
	now := time.Now().UTC().Format(time.RFC3339)

	managedAt := now
	if md, err := c.ReadKVMetadata(ctx, markerKVMount, rel); err == nil && md != nil {
		if v, ok := md.CustomMetadata[markerManagedAtKey].(string); ok && v != "" {
			managedAt = v
		}
	}

	// PutMetadata (not Patch): creates a metadata-only entry for a path that has
	// zero data versions, and works whether or not the marker already exists.
	err := c.KVv2(markerKVMount).PutMetadata(ctx, rel, api.KVMetadataPutInput{
		CustomMetadata: map[string]interface{}{
			KVManagedByKey:       KVManagedByValue,
			KVK8sResourceKey:     k8sResource,
			markerManagedAtKey:   managedAt,
			markerLastUpdatedKey: now,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to mark %s managed at %s: %w", id.Kind, rel, err)
	}
	return nil
}

// GetManagedBy returns the K8s resource recorded as owning id, or "" when no
// marker exists (or it isn't ours).
func (c *Client) GetManagedBy(ctx context.Context, id MarkerID) (string, error) {
	md, err := c.ReadKVMetadata(ctx, markerKVMount, markerRelPath(id))
	if err != nil {
		return "", err
	}
	if md == nil || !IsOwnedBy(md) {
		return "", nil
	}
	owner, _ := md.CustomMetadata[KVK8sResourceKey].(string)
	return owner, nil
}

// RemoveManaged deletes the ownership marker for id. Idempotent: a missing
// marker is not an error.
func (c *Client) RemoveManaged(ctx context.Context, id MarkerID) error {
	rel := markerRelPath(id)
	if err := c.KVv2(markerKVMount).DeleteMetadata(ctx, rel); err != nil {
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil
		}
		return fmt.Errorf("failed to remove %s managed marker at %s: %w", id.Kind, rel, err)
	}
	return nil
}

// ListManaged returns every managed marker of a kind within this operator's
// cluster subtree, keyed for comparison against live Vault object names:
//
//	roles:    "{mount}/{vaultName}"  (mount-qualified — same-name roles on
//	          different auth mounts stay distinct)
//	policies: "{vaultName}"
//
// where vaultName == markerVaultName(id). LIST is recursive because the path is
// hierarchical; a per-marker read failure is logged and skipped (partial
// results), while a LIST failure (e.g. 403) is surfaced.
func (c *Client) ListManaged(ctx context.Context, kind MarkerKind) (map[string]ManagedResource, error) {
	log := logr.FromContextOrDiscard(ctx)
	root := markerKindRoot(kind)
	result := map[string]ManagedResource{}

	collect := func(id MarkerID, key string) {
		mr, err := c.readMarker(ctx, id)
		if err != nil {
			log.V(1).Info("failed to read managed marker; skipping entry",
				"path", markerRelPath(id), "error", err.Error())
			return
		}
		if mr != nil {
			result[key] = *mr
		}
	}

	if kind == MarkerRole {
		mounts, err := c.listMarkerChildren(ctx, root)
		if err != nil {
			return nil, err
		}
		for _, mount := range mounts {
			nsList, err := c.listMarkerChildren(ctx, root+"/"+mount)
			if err != nil {
				return nil, err
			}
			for _, nsSeg := range nsList {
				names, err := c.listMarkerChildren(ctx, root+"/"+mount+"/"+nsSeg)
				if err != nil {
					return nil, err
				}
				for _, name := range names {
					id := MarkerID{Kind: kind, Mount: mount, Namespace: nsFromSentinel(nsSeg), Name: name}
					collect(id, mount+"/"+markerVaultName(id))
				}
			}
		}
		return result, nil
	}

	nsList, err := c.listMarkerChildren(ctx, root)
	if err != nil {
		return nil, err
	}
	for _, nsSeg := range nsList {
		names, err := c.listMarkerChildren(ctx, root+"/"+nsSeg)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			id := MarkerID{Kind: kind, Namespace: nsFromSentinel(nsSeg), Name: name}
			collect(id, markerVaultName(id))
		}
	}
	return result, nil
}

// PreflightMarkers verifies the operator can write/read/delete under the marker
// root, so an operator that enables --managed-markers without the metadata grant
// fails fast at startup rather than 403-looping per resource. The probe sits at
// the kind level (never traversed by ListManaged); deletion is best-effort.
func (c *Client) PreflightMarkers(ctx context.Context) error {
	segs := []string{markerBaseRel}
	if cl := naming.Cluster(); cl != "" {
		segs = append(segs, cl)
	}
	rel := strings.Join(append(segs, markerPreflightSeg), "/")

	if err := c.KVv2(markerKVMount).PutMetadata(ctx, rel, api.KVMetadataPutInput{
		CustomMetadata: map[string]interface{}{KVManagedByKey: KVManagedByValue},
	}); err != nil {
		return fmt.Errorf(
			"managed-markers preflight failed: cannot write %s/metadata/%s "+
				"(grant secret/metadata/%s/* create,read,update,list,delete, or unset --managed-markers): %w",
			markerKVMount, rel, markerBaseRel, err)
	}
	if _, err := c.ReadKVMetadata(ctx, markerKVMount, rel); err != nil {
		return fmt.Errorf("managed-markers preflight failed: cannot read %s/metadata/%s: %w", markerKVMount, rel, err)
	}
	_ = c.KVv2(markerKVMount).DeleteMetadata(ctx, rel) // best-effort; harmless if it lingers
	return nil
}

// readMarker reads a single marker's ownership record. Returns (nil, nil) when
// the marker is absent or not owned by the operator.
func (c *Client) readMarker(ctx context.Context, id MarkerID) (*ManagedResource, error) {
	md, err := c.ReadKVMetadata(ctx, markerKVMount, markerRelPath(id))
	if err != nil {
		return nil, err
	}
	if md == nil || !IsOwnedBy(md) {
		return nil, nil
	}
	mr := &ManagedResource{ID: id}
	mr.K8sResource, _ = md.CustomMetadata[KVK8sResourceKey].(string)
	if v, ok := md.CustomMetadata[markerManagedAtKey].(string); ok {
		mr.ManagedAt, _ = time.Parse(time.RFC3339, v)
	}
	if v, ok := md.CustomMetadata[markerLastUpdatedKey].(string); ok {
		mr.LastUpdated, _ = time.Parse(time.RFC3339, v)
	}
	return mr, nil
}

// listMarkerChildren lists the direct children of a marker path (relative to the
// KV mount), returning bare segment names (trailing "/" stripped). A missing
// path yields nil (no children); a permission error is surfaced.
func (c *Client) listMarkerChildren(ctx context.Context, rel string) ([]string, error) {
	listPath := markerKVMount + "/metadata/" + rel
	secret, err := c.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list managed markers at %s: %w", listPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		s, ok := k.(string)
		if !ok {
			continue
		}
		out = append(out, strings.TrimSuffix(s, "/"))
	}
	return out, nil
}

// nsFromSentinel maps the _cluster sentinel path segment back to the empty
// namespace used by cluster-scoped MarkerIDs.
func nsFromSentinel(nsSeg string) string {
	if nsSeg == markerClusterScopedNS {
		return ""
	}
	return nsSeg
}
