# INTENTIONALLY INVALID HCL for negative testing
# This file contains syntax errors to test webhook validation
#
# DO NOT FIX - This is used for TC-EH05: Invalid HCL syntax test

path "secret/data/broken/*" {
  capabilities = ["read", "list"
  # Missing closing bracket - intentional syntax error
}

path "secret/data/another/*"
  capabilities = ["read"]
  # Missing opening brace - intentional syntax error
}
