/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// The least-privilege Vault policy the operator uses across the e2e suite.
// Lives in its own file so policy edits (adding a new auth mount, adjusting
// a capability) are an isolated diff that doesn't compete for review
// attention with lifecycle or auth-setup changes.

package e2e

// operatorPolicyHCL defines the minimum permissions required for the
// operator under test. Following Principle of Least Privilege: only the
// capabilities each path actually needs, no `sudo` on auth mounts.
//
// Path groups:
//   - sys/policies/acl/* — policy CRD lifecycle
//   - auth/<backend>/role/* and /config — role + mount configuration
//   - sys/auth/*         — enable/disable mounts during test setup
//   - sys/health, sys/mounts — read-only diagnostics
//   - secret/{data,metadata}/vault-access-operator/managed/* — managed-marker tracking
const operatorPolicyHCL = `
# Policy management - operator needs to create/update/delete policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Kubernetes auth role management
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}

# Kubernetes auth configuration (for initial setup)
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# JWT auth role management (for JWT auth tests)
path "auth/jwt/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/jwt/role" {
  capabilities = ["list"]
}

# JWT auth configuration
path "auth/jwt/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# JWT auth role management on a CI-oriented submount (TC-AU08 multi-value
# bound_claims tests). Uses jwt-gitlab to mirror the GitLab CI runbook —
# the engine type is still jwt, just at a separate mount path so it doesn't
# share Dex's bound_issuer config with the K3S-issuer JWT mount.
path "auth/jwt-gitlab/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/jwt-gitlab/role" {
  capabilities = ["list"]
}
path "auth/jwt-gitlab/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Auth method management (enable/disable auth methods)
path "sys/auth" {
  capabilities = ["read"]
}
path "sys/auth/*" {
  capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}

# AppRole auth management
path "auth/approle/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "auth/approle" {
  capabilities = ["read"]
}

# OIDC (JWT at oidc path) auth management
path "auth/oidc/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "auth/oidc" {
  capabilities = ["read"]
}

# Health checks
path "sys/health" {
  capabilities = ["read"]
}

# Mount listing (used by bootstrap to verify auth methods)
path "sys/mounts" {
  capabilities = ["read"]
}

# KV v2 managed resource metadata (ownership tracking)
# The operator stores metadata about which K8s resource manages each Vault policy/role
# KV v2 requires separate data/ and metadata/ path prefixes
path "secret/data/vault-access-operator/managed/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/vault-access-operator/managed/*" {
  capabilities = ["list", "read", "delete"]
}

# KV v2 secret seeding (VaultKVSecret). CREATE-ONLY on the data path — the
# operator only ever creates new secrets, never overwrites or reads values.
# Existence checks, the ownership custom_metadata stamp, the untouched-check,
# and DeleteMetadata cleanup all run through the metadata path. The more
# specific managed-marker rules above still win for those paths. Mirrors
# test/e2e/fixtures/policies/e2e-operator-bootstrap.hcl.
path "secret/data/*" {
  capabilities = ["create"]
}
path "secret/metadata/*" {
  capabilities = ["read", "patch", "delete"]
}
`
