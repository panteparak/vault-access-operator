# Changelog

All notable changes to vault-access-operator are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JWT VaultRole support.** `VaultRole` and `VaultClusterRole` now produce a
  Vault JWT-auth role payload when `spec.authPath` targets a JWT mount
  (e.g. `auth/jwt`). Previously the operator always sent a Kubernetes-auth
  payload regardless of `authPath` and Vault rejected JWT mounts with
  `a user claim must be defined on the role`.
  - Defaults are derived from `spec.serviceAccounts` and the referenced
    `VaultConnection`: `role_type=jwt`, `user_claim=sub`,
    `bound_subject=system:serviceaccount:<ns>:<sa>`, and
    `bound_audiences` from the connection's `spec.auth.jwt.audiences`
    (falling back to `["https://kubernetes.default.svc.cluster.local"]`).
  - New optional `spec.jwt` sub-object lets users override `userClaim`,
    `boundAudiences`, `boundSubject`, `boundClaims`, and `roleType`.
  - Admission webhook rejects JWT `VaultRole`s with multiple
    `serviceAccounts` unless `spec.jwt.boundSubject` or
    `spec.jwt.boundClaims` is set explicitly — `bound_subject` accepts a
    single value, so the derivation is ambiguous otherwise.
  - Admission webhook rejects `spec.jwt` on non-JWT auth paths.
  - Drift comparator branches on the auth backend so k8s-auth and JWT
    roles compare only the fields they actually set.
- Exported helper `vault.AuthBackendForPath(path)` that resolves an auth
  path to a backend family (`kubernetes`, `jwt`, or `unknown`).

### Changed

- **VaultPolicy / VaultClusterPolicy `spec.connectionRef` is no longer
  strictly immutable.** The webhook now allows a change when the old and
  new `VaultConnection`s resolve to the same `spec.address`. Different
  addresses are still rejected to prevent silent migrations between Vault
  instances. This unblocks switching a policy between two `VaultConnection`
  CRs that authenticate to the same Vault via different auth methods.
- `VaultRoleSpec.AuthPath` / `VaultClusterRoleSpec.AuthPath` doc comment
  updated to reflect that any `auth/<backend>` mount is supported now
  (was previously documented as Kubernetes-only).

### Backward compatibility

Existing `VaultRole` / `VaultClusterRole` resources that target
`auth/kubernetes` (the default) behave identically. No migration is
required.
