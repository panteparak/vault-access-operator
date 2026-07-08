# JWT Authentication: GitLab CI

This runbook walks through wiring **GitLab CI jobs** to authenticate to Vault using GitLab's OIDC ID tokens. Works for both `https://gitlab.com` and self-hosted GitLab — the only difference is the issuer URL.

!!! info "What this guide covers"
    - The `id_tokens:` keyword (GitLab 16.0+) — *not* the legacy `CI_JOB_JWT_V2`.
    - Binding a `VaultRole` to GitLab claims (`project_id`, `project_path`, `ref`, `ref_type`, `ref_protected`).
    - Two reference scenarios: protected-branch secrets and unprotected-branch (feature/dev) secrets.

!!! warning "Operator scope"
    The operator manages **Vault JWT roles** declaratively. It does **not** manage the JWT auth method's *mount config* (`oidc_discovery_url`, `bound_issuer`, `jwks_url`). The mount config is a one-time `vault write auth/<path>/config` step — see Step 2 below.

## Security checklist

Before deploying any GitLab CI VaultRole, confirm each item:

- [ ] **`bound_issuer` is set on the JWT mount** (Step 2). Without this, anyone hosting a GitLab clone at a different URL can mint tokens with identical claims and bypass your role bindings.
- [ ] **`boundAudiences` is set per role** (Step 4). Prevents replay of tokens to a different Vault instance.
- [ ] **`ref_type` is bound** for any role that pins `ref`. Without it, a tag named after a protected branch can satisfy the role.
- [ ] **`ref_protected: ["true"]` is bound** for production-secret roles. Without it, an unprotected branch with the same name as your protected branch satisfies the role.
- [ ] **`tokenTTL` is short** (≤ 15 minutes). Limits blast radius if a token leaks.
- [ ] **The operator's Vault policy uses `["create","read","update","delete"]` on `auth/<your-jwt-mount>/role/*`** — never `sudo`, unless you're also managing the mount config out-of-band.
- [ ] **`pipeline_source` is allowlisted** on unprotected-branch roles. Blocks scheduled/API-triggered exfiltration and fork-MR token misuse.

## Step 1: Enable the JWT auth mount

Use a per-issuer mount path so GitLab tokens don't interfere with other JWT-emitting workloads (in-cluster Dex, GitHub Actions, etc.).

```bash
vault auth enable -path=jwt-gitlab jwt
```

## Step 2: Configure the JWT mount (the manual step)

This step points Vault at GitLab's public keys so it can verify CI token signatures. GitLab publishes a **JWKS** (JSON Web Key Set) — a JSON document listing GitLab's current signing public keys, rotated periodically — at `<GITLAB_URL>/-/jwks`. Vault uses these keys to verify every CI token's signature on login.

Replace `https://gitlab.example.com` with your GitLab base URL (`https://gitlab.com` for SaaS, your self-hosted URL otherwise).

```bash
export GITLAB_URL="https://gitlab.example.com"
```

`bound_issuer` is the load-bearing security control here — Vault rejects any token whose `iss` claim doesn't exactly match. Without it, a self-hosted GitLab impersonation is undefended.

There are three ways to wire Vault to GitLab's JWKS. Pick one:

=== "OIDC discovery (recommended)"

    Easiest: Vault fetches `/.well-known/openid-configuration` from `${GITLAB_URL}` and follows the link to JWKS automatically. Vault re-fetches on a cadence so GitLab key rotation is transparent.

    ```bash
    vault write auth/jwt-gitlab/config \
        oidc_discovery_url="${GITLAB_URL}" \
        bound_issuer="${GITLAB_URL}"
    ```

    Use this for **gitlab.com** and most self-hosted GitLab setups behind a publicly-trusted TLS cert.

=== "Direct `jwks_url` (pinned)"

    Skip OIDC discovery, point Vault directly at GitLab's JWKS endpoint. One fewer indirection, slightly tighter control. Trade-off: you must update this value if GitLab ever changes the JWKS path (rare, but it's happened).

    ```bash
    vault write auth/jwt-gitlab/config \
        jwks_url="${GITLAB_URL}/-/jwks" \
        bound_issuer="${GITLAB_URL}"
    ```

    Use this when you want to avoid the OIDC-discovery call entirely (e.g. air-gapped setups where `/.well-known/openid-configuration` is blocked but `/-/jwks` is allowed), or when you prefer to audit a single pinned URL.

=== "Self-hosted with a custom CA"

    If your self-hosted GitLab uses a TLS cert from an internal CA (not in Vault's system trust store), pass the CA PEM bundle so Vault can verify the TLS handshake when it fetches OIDC discovery or JWKS.

    ```bash
    vault write auth/jwt-gitlab/config \
        oidc_discovery_url="${GITLAB_URL}" \
        oidc_discovery_ca_pem="$(cat /path/to/gitlab-ca.pem)" \
        bound_issuer="${GITLAB_URL}"
    ```

    For the direct-JWKS path, the equivalent field is `jwks_ca_pem`. Both fields take an inline PEM blob — Vault stores it; no on-disk path is referenced at runtime.

### Verify Vault can reach the JWKS

Before creating roles, confirm Vault's view of the JWKS matches what GitLab publishes:

```bash
# 1. What does GitLab publish?
curl -s "${GITLAB_URL}/-/jwks" | jq '.keys[].kid'

# 2. What does Vault see?  (reads back the operator-configured mount)
vault read auth/jwt-gitlab/config

# 3. (optional) Verify TLS reachability from Vault's network
#    For docker Vault: docker exec <vault-container> wget -qO- "${GITLAB_URL}/-/jwks"
```

If `vault read` shows `jwks_url` (or `oidc_discovery_url`) set but logins fail with `error validating token: signature verification failed`, the most likely causes are: Vault can't reach the URL (firewall/network), TLS verification fails (missing `*_ca_pem`), or GitLab rotated keys faster than Vault re-fetched (rare; force a re-fetch by re-running `vault write … config`).

## Step 3: Pick a project claim to bind on

GitLab's ID token carries both `project_id` (numeric, opaque, rename-stable) and `project_path` (slug, matches the URL, breaks on rename/transfer). Pick one:

| Bind on | Pros | Cons |
|---|---|---|
| `project_path` (recommended default) | Human-readable, matches the URL the team already knows | Breaks silently on project rename/transfer |
| `project_id` | Survives renames/transfers | Opaque; you have to look it up once |
| Both | Defense in depth | Doesn't actually help against renames — both would mismatch |

**Looking up the numeric ID** (only needed if you're binding on `project_id`):

1. **GitLab UI**: open the project page; "Project ID: 111" appears as a badge under the project name.
2. **REST API**:
   ```bash
   # Public project
   curl -s "${GITLAB_URL}/api/v4/projects/groupA%2FrepoA" | jq -r .id

   # Private project — needs a read_api PAT
   curl -s -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
        "${GITLAB_URL}/api/v4/projects/groupA%2FrepoA" | jq -r .id
   ```
   Note the URL-encoded `%2F` between group and repo.
3. **Inside any CI job**: echo `$CI_PROJECT_ID`.

The operator deliberately does **not** resolve URL→ID at admission time — that would couple every CRD apply to GitLab's availability, require a GitLab token on the webhook, and lock the operator to a specific issuer.

## Step 4: Create the VaultConnection, VaultPolicy, and VaultRole

The `jwt-gitlab` mount is declared **once**, on a dedicated `VaultConnection`
(platform team). Roles carry no mount fields — they follow their connection,
and the `jwt-gitlab` name resolves to the JWT backend family automatically:

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultConnection
metadata:
  name: vault-gitlab
spec:
  address: https://vault.example.com:8200
  auth:
    kubernetes:
      role: vault-access-operator
  # Roles referencing this connection land on auth/jwt-gitlab
  # (the jwt-* name resolves to the jwt family automatically).
  defaults:
    authPath: jwt-gitlab
```

### Scenario A — protected-branch secrets

Allows the role to be assumed *only* when a job in project `groupA/repoA` runs on the protected `develop` branch.

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultPolicy
metadata:
  name: prod-secret-reader
  namespace: ci-secrets
spec:
  connectionRef: vault-gitlab
  rules: |
    path "secret/data/prod/*" {
      capabilities = ["read"]
    }
---
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: gitlab-groupa-repoa-develop
  namespace: ci-secrets
spec:
  connectionRef: vault-gitlab
  policies:
    - kind: VaultPolicy
      name: prod-secret-reader
  tokenTTL: 10m
  tokenMaxTTL: 15m
  serviceAccounts:
    - gitlab-ci      # placeholder; not used for JWT auth but currently required
  jwt:
    userClaim: project_id
    boundAudiences: ["https://vault.example.com"]
    boundClaimsList:
      project_path:    ["groupA/repoA"]
      ref:             ["develop"]
      ref_type:        ["branch"]
      ref_protected:   ["true"]
    boundClaimsType: string
```

### Scenario B — unprotected-branch (feature) secrets

Allows any feature branch in the same project to assume a **lower-trust** dev secret-reader role. Pair this with a Vault policy scoped to non-production secrets only.

```yaml
apiVersion: vault.platform.io/v1alpha1
kind: VaultRole
metadata:
  name: gitlab-groupa-repoa-feat
  namespace: ci-secrets
spec:
  connectionRef: vault-gitlab
  policies:
    - kind: VaultPolicy
      name: dev-secret-reader   # MUST be a different, lower-trust policy
  tokenTTL: 5m
  serviceAccounts:
    - gitlab-ci
  jwt:
    userClaim: project_id
    boundAudiences: ["https://vault.example.com"]
    boundClaimsList:
      project_path:      ["groupA/repoA"]
      ref:               ["feat/*"]
      ref_type:          ["branch"]
      pipeline_source:   ["push", "merge_request_event"]
    boundClaimsType: glob
```

Key differences vs Scenario A:

- **No `ref_protected` binding** — anyone with push access to the project can assume this role. The attached policy MUST NOT grant production access.
- **`boundClaimsType: glob`** is per-role, not per-claim. `project_path: ["groupA/repoA"]` and `ref_type: ["branch"]` still match exactly (no wildcards), but every claim in the map is evaluated as a glob. If you need mixed semantics, split into two roles.
- **`pipeline_source` allowlist** blocks scheduled pipelines, API-triggered pipelines, and fork-MR token misuse.
- **Shorter `tokenTTL`** — limit blast radius.

### Org-wide bindings

To allow any repo under a namespace, bind on `namespace_path`:

```yaml
spec:
  jwt:
    boundClaimsList:
      namespace_path: ["groupA"]            # exact match: any direct child of groupA
      # OR for subgroup matching:
      # namespace_path: ["groupA/*"]
      # boundClaimsType: glob
```

## Step 5: Configure the GitLab CI job

In `.gitlab-ci.yml`, request an ID token scoped to your Vault's audience and exchange it for a Vault token.

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com    # must match boundAudiences in VaultRole
  script:
    - |
      VAULT_TOKEN=$(curl -s -X POST \
        --data "{\"jwt\":\"${VAULT_ID_TOKEN}\",\"role\":\"ci-secrets-gitlab-groupa-repoa-develop\"}" \
        https://vault.example.com/v1/auth/jwt-gitlab/login | jq -r .auth.client_token)
      export VAULT_TOKEN
      # ... use vault CLI or HTTP API ...
  rules:
    - if: '$CI_COMMIT_REF_NAME == "develop" && $CI_COMMIT_REF_PROTECTED == "true"'
```

The Vault role name in `--data` follows the operator's naming convention: `<namespace>-<vaultrole-name>` for `VaultRole`, or just `<vaultrole-name>` for `VaultClusterRole`. Read it back with `kubectl get vaultrole -n ci-secrets gitlab-groupa-repoa-develop -o jsonpath='{.status.vaultRoleName}'` to confirm.

## What this does not protect against

JWT auth gates the *identity* of the requestor, not the *behavior* of the code running under that identity. JWT auth cannot defend against:

- A malicious `.gitlab-ci.yml` change merged by anyone with push access — they can read the secret and exfiltrate it to artifacts/logs.
- A compromised maintainer who can push to protected branches.
- Secret-exposure through CI variables once the token is exchanged.

Partner controls: **CODEOWNERS**, **required MR review on protected branches**, **branch-protection rules in GitLab**, **short Vault token TTLs**, and **per-environment Vault namespaces**.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `invalid role name`/`role not found` | Vault role name doesn't match what the operator wrote. Check `kubectl get vaultrole -o jsonpath='{.status.vaultRoleName}'`. |
| `audience claim does not match any bound audience` | `aud:` in `id_tokens:` doesn't match `boundAudiences` in the VaultRole. |
| `claim "ref" does not match bound claim` (unprotected branch tries to assume protected role) | Expected — this is the `ref_protected` guard working. |
| `error validating token: oidc: id token issued by a different provider` | `bound_issuer` on the mount doesn't match the GitLab URL. Re-run Step 2. |
| `error validating token: signature verification failed` | Vault has stale/wrong JWKS. Re-run Step 2 to force a JWKS re-fetch; check `vault read auth/jwt-gitlab/config` against `curl ${GITLAB_URL}/-/jwks`. |
| `failed to get OIDC discovery: ...x509: certificate signed by unknown authority` | Self-hosted GitLab using a custom CA. Re-run Step 2 with `oidc_discovery_ca_pem` (or `jwks_ca_pem` for the direct-JWKS path). |
| `failed to get OIDC discovery: dial tcp: connection refused` | Vault can't reach GitLab over the network. Check firewall rules between Vault and `${GITLAB_URL}`; consider the direct-`jwks_url` path if `/.well-known/openid-configuration` is blocked but `/-/jwks` is reachable. |
| Admission webhook warning "binds 'ref' without 'ref_protected'" | You bound `ref` without `ref_protected`. Add the binding or accept the lower security posture. |

## See Also

- [JWT Authentication overview](jwt.md)
- [Security checklist (top of this page)](#security-checklist)
- [GitLab docs: ID tokens for HashiCorp Vault](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) (version-stable URL; pin to the version your runners are on)
- [GitLab JWKS endpoint reference](https://docs.gitlab.com/ee/api/openid_connect_discovery.html) — the `/oauth/discovery/keys` and `/-/jwks` endpoints, key rotation cadence, and supported algorithms
- [HashiCorp Vault `jwt` auth method config reference](https://developer.hashicorp.com/vault/api-docs/auth/jwt#configure) — full list of `jwks_url`, `oidc_discovery_url`, `*_ca_pem`, and tunable timeouts
