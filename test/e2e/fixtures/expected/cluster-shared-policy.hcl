# Expected HCL output for cluster-shared policy
# Used by: TC-CP02 to verify policy content in Vault

path "secret/data/shared/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/shared/*" {
  capabilities = ["read", "list"]
}
