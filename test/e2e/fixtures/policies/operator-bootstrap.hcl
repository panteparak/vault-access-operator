# Operator bootstrap policy for vault-access-operator
# Usage: Full permissions needed for operator to manage policies and roles
#
# This policy grants the operator permissions to:
# - Manage ACL policies
# - Configure Kubernetes auth method
# - Manage auth roles

# Policy management
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Auth method configuration (Kubernetes)
path "auth/kubernetes/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Auth role management
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Self token introspection (for health checks)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Token renewal (for bootstrap token lifecycle)
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# KV v2 secret seeding (VaultKVSecret) — OPTIONAL, only needed if you use the
# VaultKVSecret CRD to pre-seed paths for External Secrets Operator.
#
# CREATE-ONLY on the data path: the operator only ever CREATES new secrets — it
# never reads or overwrites the values stored there, so Vault enforces the
# never-clobber guarantee. Lifecycle/ownership (custom_metadata stamp,
# untouched-check, DeleteMetadata) runs through the metadata path.
#
# LEAST PRIVILEGE: scope the data prefix to the paths you actually seed, e.g.
# "secret/data/apps/*", instead of the broad "secret/data/*" shown here.
path "secret/data/*" {
  capabilities = ["create"]
}
path "secret/metadata/*" {
  capabilities = ["read", "patch", "delete"]
}
