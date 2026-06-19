package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

// KV v2 ownership markers. The operator stamps these into a seeded secret's
// custom_metadata so it can later tell whether it still owns the path — the
// basis of the delete-if-untouched cleanup. They are intentionally human
// readable: an operator inspecting `vault kv metadata get <path>` sees who
// created the secret.
const (
	// KVManagedByKey is the custom_metadata key marking operator ownership.
	KVManagedByKey = "managed-by"
	// KVManagedByValue is the sentinel value stored under KVManagedByKey.
	KVManagedByValue = "vault-access-operator"
	// KVK8sResourceKey records the owning K8s resource (namespace/name).
	KVK8sResourceKey = "k8s-resource"
)

// KVOwnership is the ownership information stamped into a seeded secret's
// KV v2 custom_metadata.
type KVOwnership struct {
	// ManagedBy defaults to KVManagedByValue when empty.
	ManagedBy string
	// K8sResource is the owning resource identifier (namespace/name).
	K8sResource string
}

// SplitKVv2Path splits a full KV v2 data path such as "secret/data/apps/foo"
// into its mount ("secret") and relative secret path ("apps/foo"). The SDK's
// KV v2 helper (Client.KVv2) operates on mount + relative path, whereas CRD
// specs and Vault policies use the full "<mount>/data/<path>" form. The split
// is on the FIRST "/data/" segment so non-default mounts ("kv/data/x") work.
// Returns ok=false when there is no "/data/" segment or either side is empty.
func SplitKVv2Path(full string) (mount, rel string, ok bool) {
	const sep = "/data/"
	idx := strings.Index(full, sep)
	if idx <= 0 {
		return "", "", false
	}
	mount = full[:idx]
	rel = full[idx+len(sep):]
	if mount == "" || rel == "" {
		return "", "", false
	}
	return mount, rel, true
}

// ReadKVMetadata reads the KV v2 metadata for a secret. Returns (nil, nil) when
// the path does not exist. Requires `read` on `<mount>/metadata/*`. This is the
// only read the seeding feature performs — it never reads secret DATA, so the
// operator needs no `read` capability on `<mount>/data/*`.
func (c *Client) ReadKVMetadata(ctx context.Context, mount, path string) (*api.KVMetadata, error) {
	md, err := c.KVv2(mount).GetMetadata(ctx, path)
	if err != nil {
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read KV metadata for %s/%s: %w", mount, path, err)
	}
	return md, nil
}

// KVSecretExists reports whether a KV v2 secret exists at the path. It probes
// the metadata endpoint (not the data endpoint) so it works under a create-only
// data-path policy where the operator has no `read` on `<mount>/data/*`.
func (c *Client) KVSecretExists(ctx context.Context, mount, path string) (bool, error) {
	md, err := c.ReadKVMetadata(ctx, mount, path)
	if err != nil {
		return false, err
	}
	return md != nil, nil
}

// CreateKVSecretIfAbsent writes data to a KV v2 path ONLY if the path does not
// already exist, returning whether it created the secret and the resulting
// version. It never overwrites: an existing path yields (false, currentVersion,
// nil). The write uses check-and-set (cas=0) as a race backstop, so a create
// that loses a concurrent race is reported as "already present" rather than
// clobbering the winner.
//
// Existence is determined via the metadata endpoint, and the only write is the
// cas=0 create — so this works under a create-only data-path policy.
func (c *Client) CreateKVSecretIfAbsent(
	ctx context.Context, mount, path string, data map[string]string,
) (created bool, version int, err error) {
	md, err := c.ReadKVMetadata(ctx, mount, path)
	if err != nil {
		return false, 0, err
	}
	if md != nil {
		return false, md.CurrentVersion, nil
	}

	payload := make(map[string]interface{}, len(data))
	for k, v := range data {
		payload[k] = v
	}

	sec, err := c.KVv2(mount).Put(ctx, path, payload, api.WithCheckAndSet(0))
	if err != nil {
		// Lost the create race: the path was created between the metadata
		// read above and this write, so cas=0 fails the check-and-set guard.
		// Treat as "already present" — do NOT surface as an error.
		if isKVCASMismatch(err) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("failed to create KV secret %s/%s: %w", mount, path, err)
	}

	version = 1
	if sec != nil && sec.VersionMetadata != nil {
		version = sec.VersionMetadata.Version
	}
	return true, version, nil
}

// StampKVOwnership records operator ownership in the secret's KV v2
// custom_metadata via a non-destructive merge patch. Requires `patch` on
// `<mount>/metadata/*` (Vault >= 1.9). Called immediately after
// CreateKVSecretIfAbsent, when the metadata entry already exists.
//
// PutMetadata (needs `create`/`update`) is an acceptable fallback on older
// Vault versions since we stamp right after create — there is no sibling
// metadata to preserve.
func (c *Client) StampKVOwnership(ctx context.Context, mount, path string, own KVOwnership) error {
	managedBy := own.ManagedBy
	if managedBy == "" {
		managedBy = KVManagedByValue
	}
	err := c.KVv2(mount).PatchMetadata(ctx, path, api.KVMetadataPatchInput{
		CustomMetadata: map[string]interface{}{
			KVManagedByKey:   managedBy,
			KVK8sResourceKey: own.K8sResource,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to stamp KV ownership on %s/%s: %w", mount, path, err)
	}
	return nil
}

// IsOwnedBy reports whether the KV metadata's custom_metadata marks the secret
// as managed by the operator (managed-by == KVManagedByValue). Used by the
// delete-if-untouched check to avoid removing a secret we don't own.
func IsOwnedBy(md *api.KVMetadata) bool {
	if md == nil || md.CustomMetadata == nil {
		return false
	}
	v, _ := md.CustomMetadata[KVManagedByKey].(string)
	return v == KVManagedByValue
}

// DeleteKVSecret permanently removes a KV v2 secret and ALL its versions via the
// metadata endpoint (DeleteMetadata). Requires `delete` on `<mount>/metadata/*`.
// Idempotent: a missing path is not an error.
func (c *Client) DeleteKVSecret(ctx context.Context, mount, path string) error {
	if err := c.KVv2(mount).DeleteMetadata(ctx, path); err != nil {
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil
		}
		return fmt.Errorf("failed to delete KV secret %s/%s: %w", mount, path, err)
	}
	return nil
}

// isKVCASMismatch reports whether err is a KV v2 check-and-set conflict (HTTP
// 400 whose body mentions check-and-set), i.e. the cas=0 create lost a race
// because the path already exists.
func isKVCASMismatch(err error) bool {
	var re *api.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusBadRequest {
		for _, e := range re.Errors {
			if strings.Contains(strings.ToLower(e), "check-and-set") {
				return true
			}
		}
	}
	return false
}
