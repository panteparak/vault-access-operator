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

package v1alpha1

import (
	"fmt"
	"strings"
)

// RoleMount resolves the auth mount that VaultRole / VaultClusterRole
// resources referencing this connection are written to, plus its backend
// family. The connection is the sole declaration point of the mount (the
// role CRDs carry no mount fields): the platform team either sets
// spec.defaults.authPath explicitly, or the mount follows the connection's
// own login method.
//
// Resolution, in order:
//  1. spec.defaults.authPath set → that mount. Family from
//     spec.defaults.authType when set, otherwise inferred from the mount
//     name (`kubernetes`/`jwt` exact or with a `-`/`_` separator);
//     unclassifiable names error.
//  2. Login mount: auth.kubernetes → (its authPath, kubernetes family);
//     auth.jwt / auth.oidc → (its authPath, jwt family — Vault's OIDC
//     method IS the jwt backend).
//  3. Anything else (token / appRole / aws / gcp / bootstrap-only) has no
//     role-capable mount → error naming the method and the fix.
//
// Returns the bare mount name (e.g. "kubernetes", "jwt-gitlab"); callers
// wanting the SDK path form use pkg/vault.NormalizeAuthPath. Defaults that
// the CRD schema declares (kubernetes→"kubernetes", jwt→"jwt", oidc→"oidc")
// are applied here too, so in-memory objects that never passed the API
// server resolve identically. An `auth/` prefix on any path is tolerated.
func (c *VaultConnection) RoleMount() (string, AuthBackendType, error) {
	if d := c.Spec.Defaults; d != nil && d.AuthPath != "" {
		mount := bareMountName(d.AuthPath)
		family := d.AuthType
		if family == "" {
			family = familyForMountName(mount)
		}
		if family == "" {
			return "", "", fmt.Errorf(
				"defaults.authPath %q does not start with a recognizable backend family; set defaults.authType to kubernetes or jwt",
				d.AuthPath)
		}
		return mount, family, nil
	}

	auth := c.Spec.Auth
	switch {
	case auth.Kubernetes != nil:
		return bareMountNameOr(auth.Kubernetes.AuthPath, "kubernetes"), AuthBackendTypeKubernetes, nil
	case auth.JWT != nil:
		return bareMountNameOr(auth.JWT.AuthPath, "jwt"), AuthBackendTypeJWT, nil
	case auth.OIDC != nil:
		return bareMountNameOr(auth.OIDC.AuthPath, "oidc"), AuthBackendTypeJWT, nil
	}

	return "", "", fmt.Errorf(
		"auth method %s has no role-capable mount; roles require a connection using kubernetes, jwt, or oidc auth, or an explicit defaults.authPath",
		c.activeAuthMethodName())
}

// bareMountName strips an optional `auth/` prefix and trailing slashes,
// returning the bare mount segment form used throughout status bindings.
func bareMountName(path string) string {
	p := strings.TrimRight(path, "/")
	return strings.TrimPrefix(p, "auth/")
}

// bareMountNameOr applies the CRD-schema default for a login method whose
// authPath is empty on an in-memory object.
func bareMountNameOr(path, def string) string {
	if m := bareMountName(path); m != "" {
		return m
	}
	return def
}

// familyForMountName infers the backend family from a mount name's first
// segment: `kubernetes`/`jwt` exact, or followed by `-`/`_` (multi-tenant
// submounts like `kubernetes-prod`). Requiring a separator avoids
// false-positives like `kubernetestest` routing role writes through the
// kubernetes code path against a mount that isn't kubernetes auth.
// Returns "" for unclassifiable names.
func familyForMountName(mount string) AuthBackendType {
	seg, _, _ := strings.Cut(mount, "/")
	switch {
	case hasFamilyPrefix(seg, string(AuthBackendTypeKubernetes)):
		return AuthBackendTypeKubernetes
	case hasFamilyPrefix(seg, string(AuthBackendTypeJWT)):
		return AuthBackendTypeJWT
	}
	return ""
}

func hasFamilyPrefix(seg, family string) bool {
	if seg == family {
		return true
	}
	if len(seg) <= len(family) || !strings.HasPrefix(seg, family) {
		return false
	}
	sep := seg[len(family)]
	return sep == '-' || sep == '_'
}

// activeAuthMethodName names the configured login method for error messages.
func (c *VaultConnection) activeAuthMethodName() string {
	auth := c.Spec.Auth
	switch {
	case auth.Token != nil:
		return "token"
	case auth.AppRole != nil:
		return "appRole"
	case auth.AWS != nil:
		return "aws"
	case auth.GCP != nil:
		return "gcp"
	case auth.Bootstrap != nil:
		return "bootstrap"
	}
	return "unconfigured"
}
