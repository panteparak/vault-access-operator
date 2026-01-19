# Basic secret access policy template
# Usage: Full CRUD access to secrets in a given namespace path
#
# Template variables:
#   {{.Namespace}} - Kubernetes namespace for scoped access

path "secret/data/{{.Namespace}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
