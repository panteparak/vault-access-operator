# Namespace-scoped policy template with full CRUD and metadata access
# Usage: Complete namespace-isolated secret access with metadata listing
#
# Template variables:
#   {{.Namespace}} - Kubernetes namespace for scoped access

path "secret/data/{{.Namespace}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/{{.Namespace}}/*" {
  capabilities = ["list", "read"]
}
