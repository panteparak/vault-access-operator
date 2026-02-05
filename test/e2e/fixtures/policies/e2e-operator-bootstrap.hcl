# E2E operator bootstrap policy
# Full permissions for vault-access-operator E2E testing
# Covers: policy management, all auth methods, KV v2 secrets, system info

# Policy management
path "sys/policies/acl/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/acl" { capabilities = ["list"] }

# Kubernetes auth
path "auth/kubernetes/role/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/kubernetes/role" { capabilities = ["list"] }
path "auth/kubernetes/config" { capabilities = ["create", "read", "update", "delete"] }

# JWT auth
path "auth/jwt/role/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/jwt/role" { capabilities = ["list"] }
path "auth/jwt/config" { capabilities = ["create", "read", "update", "delete"] }

# AppRole auth
path "auth/approle/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/approle" { capabilities = ["read"] }

# OIDC auth
path "auth/oidc/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/oidc" { capabilities = ["read"] }

# System: auth mounts, mounts, health
path "sys/auth" { capabilities = ["read"] }
path "sys/auth/*" { capabilities = ["sudo", "create", "read", "update", "delete", "list"] }
path "sys/mounts" { capabilities = ["read"] }
path "sys/health" { capabilities = ["read"] }

# KV v2 secrets for operator-managed data
path "secret/data/vault-access-operator/managed/*" { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/vault-access-operator/managed/*" { capabilities = ["list", "read", "delete"] }
