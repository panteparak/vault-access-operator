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

package webhook

import (
	"context"
	"fmt"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	scanner "github.com/panteparak/vault-access-operator/features/discovery/controller"
)

// vaultconnectionlog is the logger for this validator.
var vaultconnectionlog = logf.Log.WithName("vaultconnection-webhook")

// VaultConnectionValidator implements admission.Validator for VaultConnection
// (IMPROVEMENTS §8). Before this webhook existed, malformed connection specs
// only surfaced at reconcile time as Phase=Error — users saw the failure
// hours after applying and had to dig through status messages to understand
// why. This validator catches the common mistakes at `kubectl apply` time
// with clear, actionable messages.
type VaultConnectionValidator struct {
	client client.Client
}

var _ admission.Validator[*vaultv1alpha1.VaultConnection] = &VaultConnectionValidator{}

// +kubebuilder:webhook:path=/validate-vault-platform-io-v1alpha1-vaultconnection,mutating=false,failurePolicy=fail,sideEffects=None,groups=vault.platform.io,resources=vaultconnections,verbs=create;update,versions=v1alpha1,name=vvaultconnection.kb.io,admissionReviewVersions=v1

// SetupVaultConnectionWebhookWithManager registers the VaultConnection
// validator with the manager. Call from cmd/main.go alongside the
// policy/role webhook registrations when --enable-webhooks is set.
func SetupVaultConnectionWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &vaultv1alpha1.VaultConnection{}).
		WithValidator(&VaultConnectionValidator{client: mgr.GetClient()}).
		Complete()
}

// ValidateCreate runs the full validation suite on a fresh VaultConnection.
func (v *VaultConnectionValidator) ValidateCreate(_ context.Context, conn *vaultv1alpha1.VaultConnection) (admission.Warnings, error) {
	vaultconnectionlog.Info("validating VaultConnection create", "name", conn.Name)
	return validateVaultConnection(conn)
}

// ValidateUpdate validates spec changes. `address` is immutable — changing
// it would move the operator to a different Vault without migrating any
// of the existing policies/roles, silently orphaning everything.
func (v *VaultConnectionValidator) ValidateUpdate(ctx context.Context, oldConn, newConn *vaultv1alpha1.VaultConnection) (admission.Warnings, error) {
	vaultconnectionlog.Info("validating VaultConnection update", "name", newConn.Name)

	if oldConn.Spec.Address != newConn.Spec.Address {
		return nil, fmt.Errorf(
			"spec.address is immutable (was %q, attempted %q) — create a new VaultConnection instead of moving an existing one to a different Vault instance",
			oldConn.Spec.Address, newConn.Spec.Address)
	}

	warnings, err := validateVaultConnection(newConn)
	if err != nil {
		return warnings, err
	}
	warnings = append(warnings, v.warnOnRoleMountChange(ctx, oldConn, newConn)...)
	return warnings, nil
}

// warnOnRoleMountChange surfaces a mount re-point at admission time. Roles
// carry no mount of their own — they follow the connection — so changing
// the resolved role mount re-targets every dependent role's next sync,
// orphaning the Vault roles already written at the old mount (their
// recorded status bindings still pin deletion to the old mount). Warn, not
// deny: a deliberate mount migration is a legitimate platform-team action.
func (v *VaultConnectionValidator) warnOnRoleMountChange(
	ctx context.Context, oldConn, newConn *vaultv1alpha1.VaultConnection,
) admission.Warnings {
	oldMount, _, oldErr := oldConn.RoleMount()
	newMount, _, newErr := newConn.RoleMount()
	if oldErr != nil || newErr != nil || oldMount == newMount {
		return nil
	}

	dependents := "dependent roles"
	if v.client != nil {
		if n, err := v.countDependentRoles(ctx, newConn.Name); err == nil {
			if n == 0 {
				return nil
			}
			dependents = fmt.Sprintf("%d dependent role(s)", n)
		}
		// Listing failed — still warn, just without the count.
	}

	return admission.Warnings{fmt.Sprintf(
		"changing the resolved role mount from auth/%s to auth/%s re-points %s on their next sync; "+
			"Vault roles already written at auth/%s are orphaned there (recorded bindings still target the old mount for deletion)",
		oldMount, newMount, dependents, oldMount)}
}

// countDependentRoles counts VaultRole + VaultClusterRole CRs referencing
// the connection by name.
func (v *VaultConnectionValidator) countDependentRoles(ctx context.Context, connName string) (int, error) {
	count := 0
	var roles vaultv1alpha1.VaultRoleList
	if err := v.client.List(ctx, &roles); err != nil {
		return 0, err
	}
	for i := range roles.Items {
		if roles.Items[i].Spec.ConnectionRef == connName {
			count++
		}
	}
	var clusterRoles vaultv1alpha1.VaultClusterRoleList
	if err := v.client.List(ctx, &clusterRoles); err != nil {
		return 0, err
	}
	for i := range clusterRoles.Items {
		if clusterRoles.Items[i].Spec.ConnectionRef == connName {
			count++
		}
	}
	return count, nil
}

// ValidateDelete is a no-op. The connection handler's Cleanup already
// enforces the "no dependent policies/roles" rule at deletion time.
func (v *VaultConnectionValidator) ValidateDelete(_ context.Context, _ *vaultv1alpha1.VaultConnection) (admission.Warnings, error) {
	return nil, nil
}

// validateVaultConnection is the shared validation entry point for Create
// and Update. Returns errors on hard validation failures; warnings for
// non-blocking concerns that the user should see but shouldn't block apply.
func validateVaultConnection(conn *vaultv1alpha1.VaultConnection) (admission.Warnings, error) {
	var errs []string
	var warnings admission.Warnings

	if err := validateAuthExactlyOne(&conn.Spec.Auth); err != "" {
		errs = append(errs, err)
	}

	if conn.Spec.Auth.AppRole != nil {
		if conn.Spec.Auth.AppRole.RoleID == "" {
			errs = append(errs, "spec.auth.appRole.roleId is required when AppRole auth is selected")
		}
	}

	if conn.Spec.Auth.OIDC != nil {
		useSAToken := true // the default when UseServiceAccountToken is nil
		if conn.Spec.Auth.OIDC.UseServiceAccountToken != nil {
			useSAToken = *conn.Spec.Auth.OIDC.UseServiceAccountToken
		}
		if !useSAToken && conn.Spec.Auth.OIDC.JWTSecretRef == nil {
			errs = append(errs, "spec.auth.oidc: either useServiceAccountToken must be true OR jwtSecretRef must be set")
		}
		if conn.Spec.Auth.OIDC.ProviderURL == "" {
			warnings = append(warnings,
				"spec.auth.oidc.providerURL is empty — Vault will use the audience from the token as the issuer, which may not match your provider config")
		}
	}

	// defaults.authPath with a name the family heuristic can't classify
	// needs an explicit defaults.authType — the same rule reconcile-time
	// resolution applies (VaultConnection.RoleMount), surfaced at apply time.
	if conn.Spec.Defaults != nil && conn.Spec.Defaults.AuthPath != "" {
		if _, _, err := conn.RoleMount(); err != nil {
			errs = append(errs, fmt.Sprintf("spec.defaults: %v", err))
		}
	}

	if conn.Spec.Discovery != nil && conn.Spec.Discovery.AutoCreateCRs && conn.Spec.Discovery.TargetNamespace == "" {
		errs = append(errs, "spec.discovery.targetNamespace is required when autoCreateCRs=true (otherwise the operator has nowhere to put the adopted CRs)")
	}

	// Validate discovery glob patterns at admission time. Without this,
	// a malformed pattern (e.g., `"[admin*"` — missing closing bracket)
	// causes filepath.Match to return ErrBadPattern inside the scanner,
	// which silently swallowed the error and returned "no match" for
	// every resource. The user saw "0 discovered resources" with no
	// explanation and no way to debug without attaching a logger at V(1).
	if conn.Spec.Discovery != nil {
		if patternErrs := scanner.ValidatePatterns(conn.Spec.Discovery.PolicyPatterns); patternErrs != nil {
			for idx, e := range patternErrs {
				errs = append(errs, fmt.Sprintf(
					"spec.discovery.policyPatterns[%d] %q is invalid: %v",
					idx, conn.Spec.Discovery.PolicyPatterns[idx], e))
			}
		}
		if patternErrs := scanner.ValidatePatterns(conn.Spec.Discovery.RolePatterns); patternErrs != nil {
			for idx, e := range patternErrs {
				errs = append(errs, fmt.Sprintf(
					"spec.discovery.rolePatterns[%d] %q is invalid: %v",
					idx, conn.Spec.Discovery.RolePatterns[idx], e))
			}
		}
	}

	// VaultConnection is cluster-scoped. SecretRef.Namespace must be
	// explicit because there's no implicit namespace to fall back to.
	// The runtime handler also rejects empty namespaces (defense-in-depth)
	// but flagging at admission gives the user immediate feedback instead
	// of "secret not found in default" hours later when the operator tries
	// to read it.
	for _, secretRef := range collectSecretRefs(&conn.Spec) {
		if secretRef.ref.Name != "" && secretRef.ref.Namespace == "" {
			errs = append(errs, fmt.Sprintf(
				"%s.namespace is required (VaultConnection is cluster-scoped — no implicit namespace fallback)",
				secretRef.path))
		}
	}

	if strings.HasPrefix(conn.Spec.Address, "http://") {
		warnings = append(warnings,
			"spec.address uses http:// — credentials traverse the network unencrypted. Use https:// unless you're testing in a trusted local environment.")
	}

	// TLS verification skip is a security-sensitive choice. Surface it
	// as a webhook warning so an operator setting it sees an explicit
	// notice — without this, a user could silently MITM all Vault
	// traffic by setting `tls.skipVerify: true` and the cluster would
	// accept it without any signal.
	if conn.Spec.TLS != nil && conn.Spec.TLS.SkipVerify {
		warnings = append(warnings,
			"spec.tls.skipVerify=true disables Vault TLS certificate verification — "+
				"any network attacker on the path between the operator and Vault can "+
				"intercept Vault tokens and secrets. Use only for local development "+
				"or with a self-signed CA pinned via spec.tls.caSecretRef.")
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("VaultConnection validation failed: %s", strings.Join(errs, "; "))
	}
	return warnings, nil
}

// secretRefWithPath pairs a SecretKeySelector with its dotted path in
// the spec for human-readable error messages.
type secretRefWithPath struct {
	path string
	ref  *vaultv1alpha1.SecretKeySelector
}

// collectSecretRefs returns every SecretKeySelector referenced from the
// spec along with its path. New auth backends with secret refs must
// be added here so the namespace check covers them.
func collectSecretRefs(spec *vaultv1alpha1.VaultConnectionSpec) []secretRefWithPath {
	var refs []secretRefWithPath
	if spec.Auth.Bootstrap != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.bootstrap.secretRef", &spec.Auth.Bootstrap.SecretRef,
		})
	}
	if spec.Auth.Token != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.token.secretRef", &spec.Auth.Token.SecretRef,
		})
	}
	if spec.Auth.AppRole != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.appRole.secretIdRef", &spec.Auth.AppRole.SecretIDRef,
		})
	}
	if spec.Auth.JWT != nil && spec.Auth.JWT.JWTSecretRef != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.jwt.jwtSecretRef", spec.Auth.JWT.JWTSecretRef,
		})
	}
	if spec.Auth.OIDC != nil && spec.Auth.OIDC.JWTSecretRef != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.oidc.jwtSecretRef", spec.Auth.OIDC.JWTSecretRef,
		})
	}
	if spec.Auth.GCP != nil && spec.Auth.GCP.CredentialsSecretRef != nil {
		refs = append(refs, secretRefWithPath{
			"spec.auth.gcp.credentialsSecretRef", spec.Auth.GCP.CredentialsSecretRef,
		})
	}
	if spec.TLS != nil && spec.TLS.CASecretRef != nil {
		refs = append(refs, secretRefWithPath{
			"spec.tls.caSecretRef", spec.TLS.CASecretRef,
		})
	}
	return refs
}

// validateAuthExactlyOne returns a non-empty error message if the AuthConfig
// does not have exactly one non-nil sub-struct. Bootstrap is allowed
// alongside Kubernetes (bootstrap is a one-time setup path that transitions
// to Kubernetes auth) — that's the only legal pair.
func validateAuthExactlyOne(auth *vaultv1alpha1.AuthConfig) string {
	methods := []string{}
	if auth.Bootstrap != nil {
		methods = append(methods, "bootstrap")
	}
	if auth.Kubernetes != nil {
		methods = append(methods, "kubernetes")
	}
	if auth.Token != nil {
		methods = append(methods, "token")
	}
	if auth.AppRole != nil {
		methods = append(methods, "appRole")
	}
	if auth.JWT != nil {
		methods = append(methods, "jwt")
	}
	if auth.OIDC != nil {
		methods = append(methods, "oidc")
	}
	if auth.AWS != nil {
		methods = append(methods, "aws")
	}
	if auth.GCP != nil {
		methods = append(methods, "gcp")
	}

	if len(methods) == 0 {
		return "spec.auth: one auth method must be configured (bootstrap, kubernetes, token, appRole, jwt, oidc, aws, or gcp)"
	}

	// Exception: Bootstrap + Kubernetes is the legal transition pair.
	if len(methods) == 2 && auth.Bootstrap != nil && auth.Kubernetes != nil {
		return ""
	}

	if len(methods) > 1 {
		return fmt.Sprintf(
			"spec.auth: exactly one auth method must be configured (except bootstrap+kubernetes transition pair); found %d: %s",
			len(methods), strings.Join(methods, ", "))
	}

	return ""
}
