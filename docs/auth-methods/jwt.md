# JWT Authentication

JWT (JSON Web Token) authentication enables workloads to authenticate to Vault using JWTs from any identity provider. This is the most flexible authentication method for external identity systems.

## Overview

**Best for:** External identity providers, custom identity systems, or when OIDC discovery isn't available.

**How it works:**

1. The operator obtains a JWT (from K8s SA token or external secret)
2. The JWT is sent to Vault's JWT auth endpoint
3. Vault validates the JWT signature against configured keys
4. Vault returns a token with the configured policies

## Prerequisites

### Vault Requirements

- Vault server v1.12 or later
- JWT auth method enabled
- JWKS URI or public keys configured

### Kubernetes Requirements

- Kubernetes v1.25 or later
- ServiceAccount for the operator (if using SA tokens)

## Assumptions

This guide assumes:

- You have access to JWT signing keys or JWKS endpoint
- You have `kubectl` and `vault` CLI access
- You understand your identity provider's JWT format

## Step-by-Step Setup

### Step 1: Enable JWT Auth in Vault

```bash
vault auth enable jwt
```

### Step 2: Configure JWT Validation

=== "Using JWKS URI"
    ```bash
    vault write auth/jwt/config \
        jwks_url="https://your-idp.example.com/.well-known/jwks.json" \
        default_role="vault-access-operator"
    ```

=== "Using OIDC Discovery"
    ```bash
    vault write auth/jwt/config \
        oidc_discovery_url="https://your-idp.example.com" \
        default_role="vault-access-operator"
    ```

=== "Using Public Key"
    ```bash
    vault write auth/jwt/config \
        jwt_validation_pubkeys="-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
    -----END PUBLIC KEY-----" \
        default_role="vault-access-operator"
    ```

### Step 3: Create Vault Policy

```bash
vault policy write vault-access-operator - <<EOF
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "auth/kubernetes/role/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "auth/kubernetes/role" {
  capabilities = ["list"]
}
EOF
```

### Step 4: Create Vault Role

```bash
vault write auth/jwt/role/vault-access-operator \
    role_type="jwt" \
    bound_audiences="vault" \
    bound_subject="system:serviceaccount:vault-access-operator-system:vault-access-operator-controller-manager" \
    user_claim="sub" \
    policies="vault-access-operator" \
    ttl="1h"
```

| Parameter | Description |
|-----------|-------------|
| `role_type` | Always `jwt` for JWT auth |
| `bound_audiences` | Required audience claim(s) |
| `bound_subject` | Required subject claim (optional) |
| `user_claim` | Claim to use as entity alias |
| `policies` | Vault policies to attach |

### Step 5: Create VaultConnection Resource

=== "Using SA Token"
    ```yaml
    apiVersion: vault.platform.io/v1alpha1
    kind: VaultConnection
    metadata:
      name: vault-jwt
    spec:
      address: https://vault.example.com:8200
      auth:
        jwt:
          role: vault-access-operator
          authPath: jwt
          audiences:
            - vault
          tokenDuration: 1h
          # No jwtSecretRef means use SA token
    ```

=== "Using External JWT"
    ```yaml
    apiVersion: vault.platform.io/v1alpha1
    kind: VaultConnection
    metadata:
      name: vault-jwt
    spec:
      address: https://vault.example.com:8200
      auth:
        jwt:
          role: vault-access-operator
          authPath: jwt
          jwtSecretRef:
            name: external-jwt
            namespace: vault-access-operator-system
            key: token
    ```

### Step 6: Verify the Connection

```bash
kubectl get vaultconnection vault-jwt -o yaml
```

## Configuration Reference

### Required Fields

| Field | Description |
|-------|-------------|
| `auth.jwt.role` | The Vault role name to authenticate as |

### Optional Fields

| Field | Default | Description |
|-------|---------|-------------|
| `authPath` | `jwt` | Vault auth mount path |
| `jwtSecretRef` | None | Secret containing external JWT |
| `audiences` | `["vault"]` | Audience claim(s) for SA token |
| `tokenDuration` | `1h` | SA token lifetime |
| `expectedIssuer` | None | Expected issuer claim (for validation) |
| `expectedAudience` | None | Expected audience (for validation) |
| `userClaim` | None | Claim for entity alias |
| `groupsClaim` | None | Claim for group membership |
| `claimsToPass` | None | Claims to include in token metadata |

### Claims Passthrough

Pass JWT claims to Vault for identity templating:

```yaml
auth:
  jwt:
    role: vault-access-operator
    claimsToPass:
      - email
      - groups
      - team
```

This enables policies like:

```hcl
path "secret/data/{{identity.entity.aliases.jwt.metadata.team}}/*" {
  capabilities = ["read"]
}
```

## Troubleshooting

### "signature verification failed" error

**Symptoms:**
```
Error: error validating token: signature verification failed
```

**Solutions:**

1. Verify JWKS URL is accessible from Vault:
   ```bash
   curl -s https://your-idp.example.com/.well-known/jwks.json
   ```

2. Check the JWT is signed with a key known to Vault:
   ```bash
   vault read auth/jwt/config
   ```

### "claim not found" error

**Symptoms:**
```
Error: claim "sub" not found in token
```

**Solutions:**

1. Decode your JWT and verify claims:
   ```bash
   echo "$JWT" | jwt decode -
   ```

2. Ensure the user_claim exists in your tokens

### "audience mismatch" error

**Solutions:**

1. Check bound_audiences in Vault role matches your token's aud claim
2. For SA tokens, ensure audiences field in VaultConnection matches

## Binding `VaultRole`s to JWT claims

The `spec.jwt` sub-object on `VaultRole` / `VaultClusterRole` controls the Vault JWT-auth role payload — `user_claim`, `bound_audiences`, `bound_subject`, `bound_claims`, and `bound_claims_type`.

### Multi-value claim matching

Use `boundClaimsList` to allow any-of matching on a claim:

```yaml
spec:
  jwt:
    boundClaimsList:
      ref: ["main", "develop"]      # token matches if ref ∈ {main, develop}
      project_id: ["111"]           # single-element list = exact scalar match
```

The deprecated `boundClaims` field (scalar `map[string]string`) is still accepted for backwards compatibility; entries are merged into `boundClaimsList` at apply time, with `boundClaimsList` winning on key collision. Prefer `boundClaimsList` for new specs.

### Glob matching

`boundClaimsType` controls how Vault interprets claim values:

```yaml
spec:
  jwt:
    boundClaimsList:
      ref: ["feat/*", "hotfix/*"]
    boundClaimsType: glob
```

The mode is **per-role**, not per-claim — Vault applies it to every key in the map. Values without wildcards still match exactly under `glob` mode. If you need exact matching on some claims and glob on others, split into separate roles.

### CI/CD provider runbooks

- **[GitLab CI](jwt-gitlab.md)** — `id_tokens:` keyword, claim glossary, protected vs unprotected branch flows, security checklist.
- GitHub Actions, Buildkite, CircleCI — the generic `boundClaimsList` + `boundClaimsType` shape works for any OIDC issuer. Apply the same security checklist (audience pinning, ref/branch-protection guards, short TTLs).

## See Also

- [JWT for GitLab CI](jwt-gitlab.md) - Step-by-step GitLab CI integration
- [OIDC Authentication](oidc.md) - When OIDC discovery is available
- [Kubernetes Authentication](kubernetes.md) - Simpler for K8s workloads
- [API Reference](../api-reference.md) - Complete field reference
