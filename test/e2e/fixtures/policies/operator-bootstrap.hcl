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
