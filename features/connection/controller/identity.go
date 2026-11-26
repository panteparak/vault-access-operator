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

package controller

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/shared/naming"
)

// identityNameRE mirrors the CRD pattern on spec.identity.name. The CRD
// enforces it at admission; the controller re-checks because CRDs shipped in
// the chart's crds/ directory are not upgraded by `helm upgrade`.
var identityNameRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// identityError is a refusal of spec.identity; reason becomes the Ready
// condition reason (classifyConnectionError).
type identityError struct {
	reason string
	msg    string
}

func (e *identityError) Error() string { return e.msg }

// authMountLister is the one Vault read the identity check needs.
type authMountLister interface {
	AuthMountNames(ctx context.Context) ([]string, error)
}

// specIdentityName is spec.identity.name, or "" when unset.
func specIdentityName(conn *vaultv1alpha1.VaultConnection) string {
	if conn.Spec.Identity == nil {
		return ""
	}
	return conn.Spec.Identity.Name
}

// resolveIdentity validates spec.identity (ADR 0011) and returns the naming
// identity the connection uses and where it came from. Only a connection
// that sets an identity reads sys/auth, and a failed read fails closed: an
// identity equal to a mount-derived identity would let this connection
// write under another cluster's names.
func resolveIdentity(
	ctx context.Context, conn *vaultv1alpha1.VaultConnection, vc authMountLister, loginMount string,
) (vaultv1alpha1.IdentityStatus, error) {
	spec := specIdentityName(conn)
	if spec != "" {
		if err := checkIdentity(ctx, spec, vc); err != nil {
			return vaultv1alpha1.IdentityStatus{}, err
		}
	}
	name, source := naming.Identity(spec, naming.Cluster(), loginMount)
	return vaultv1alpha1.IdentityStatus{Name: name, Source: source}, nil
}

func checkIdentity(ctx context.Context, name string, vc authMountLister) error {
	if name == naming.Placeholder {
		return &identityError{vaultv1alpha1.ReasonIdentityCollidesWithAuthMount,
			`spec.identity.name "_" is reserved: it marks an absent identity`}
	}
	if !identityNameRE.MatchString(name) {
		return &identityError{vaultv1alpha1.ReasonValidationFailed, fmt.Sprintf(
			"spec.identity.name %q must match ^[a-z0-9-]+$ and be at most 40 characters", name)}
	}
	mounts, err := vc.AuthMountNames(ctx)
	if err != nil {
		return fmt.Errorf("cannot check spec.identity.name %q against the server's auth mounts "+
			"(the operator needs read on sys/auth): %w", name, err)
	}
	for _, m := range mounts {
		// EqualFold: Vault lowercases policy names, so "PE" and "pe"
		// identities would name the same policies.
		if strings.EqualFold(naming.SanitizeMount(m), name) {
			return &identityError{vaultv1alpha1.ReasonIdentityCollidesWithAuthMount, fmt.Sprintf(
				"spec.identity.name %q equals the auth mount %q: a connection logging in through that "+
					"mount derives the same identity, so the two would write the same Vault names", name, m)}
		}
	}
	return nil
}
