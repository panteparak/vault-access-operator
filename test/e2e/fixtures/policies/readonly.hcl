# Read-only policy template
# Usage: Tests where only read capability is needed
#
# Template variables:
#   {{.Path}} - The secret path to grant read access to

path "secret/data/{{.Path}}/*" {
  capabilities = ["read"]
}
