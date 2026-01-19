# Cluster-shared policy for read-only access to shared secrets
# Usage: VaultClusterPolicy for shared/global secrets

path "secret/data/shared/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/shared/*" {
  capabilities = ["read", "list"]
}
