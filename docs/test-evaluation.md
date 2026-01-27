# E2E vs Integration Test Evaluation

## Evaluation Criteria

| Criteria | E2E Required | Integration OK |
|----------|--------------|----------------|
| Real K8s networking (Service DNS) | ✅ | ❌ |
| kubectl exec into pods | ✅ | ❌ |
| K8s auth method (TokenReview API) | ✅ | ❌ |
| Operator deployed as real pod | ✅ | ❌ |
| Controller reconciliation logic | ✅ | ✅ |
| Vault API interactions | ✅ | ✅ |
| CRD validation/webhooks | ✅ | ✅ |
| Error handling paths | ✅ | ✅ |
| Simple permission checks | ❌ | ✅ |

---

## Test Case Evaluation

### 1. tc_connection_test.go (2 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-VC01: Create VaultConnection with token auth | **E2E** | Core CRD, needs real operator reconciliation |
| TC-VC02: Verify VaultConnection health check | **E2E** | Tests real health check to Vault service |

**Summary:** Keep ALL in E2E (2 tests) - fundamental functionality

---

### 2. tc_policy_test.go (5 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-VP01: Create and sync VaultPolicy | **E2E** | Core lifecycle, happy path |
| TC-VP02: Substitute {{namespace}} variable | **Integration** | Tests string substitution logic |
| TC-VP03: Update VaultPolicy when spec changes | **E2E** | Tests update reconciliation |
| TC-VP04-DEL: Handle deletion with finalizer | **E2E** | Tests finalizer with real cleanup |
| TC-VP05-RET: Respect deletionPolicy=Retain | **Integration** | Tests flag logic, no cleanup verification needed |

**Summary:** E2E: 3, Integration: 2

---

### 3. tc_cluster_policy_test.go (4 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-CP01: Create and sync cluster policy | **E2E** | Core lifecycle |
| TC-CP02: Verify policy HCL content | **E2E** | Part of lifecycle verification |
| TC-CP03: Handle invalid connection reference | **Integration** | Error handling path |
| TC-CP04: Handle empty rules | **Integration** | Validation error path |

**Summary:** E2E: 2, Integration: 2

---

### 4. tc_role_test.go (3 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-VR01: Create namespaced VaultRole | **E2E** | Core lifecycle |
| TC-VR02: Verify role configuration | **E2E** | Verification of Vault state |
| TC-VR03-DEL: Remove role on deletion | **E2E** | Tests cleanup in Vault |

**Summary:** Keep ALL in E2E (3 tests) - core functionality with Vault state verification

---

### 5. tc_cluster_role_test.go (5 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-CR01: Create VaultClusterRole | **E2E** | Core lifecycle |
| TC-CR02: Verify cluster role config | **E2E** | Vault state verification |
| TC-CR03-DEL: Remove on deletion | **E2E** | Cleanup verification |
| TC-CR04: Handle invalid connection | **Integration** | Error handling |
| TC-CR05: Handle missing policy ref | **Integration** | Error handling |

**Summary:** E2E: 3, Integration: 2

---

### 6. tc_conflict_test.go (3 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-CF01-ADOPT: Adopt existing policy | **E2E** | Tests real Vault state management |
| TC-CF02-FAIL: Fail when policy exists | **E2E** | Tests real conflict detection |
| TC-CF03-NORM: Create normally (no conflict) | **Integration** | Simple happy path, can use testcontainer |

**Summary:** E2E: 2, Integration: 1

---

### 7. tc_error_test.go (6 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-EH01: Invalid connection reference | **Integration** | Simple error path |
| TC-EH02: Missing policy reference | **Integration** | Simple error path |
| TC-EH03: Namespace boundary violation | **E2E** | Needs real RBAC enforcement |
| TC-EH04: VaultConnection unavailable | **E2E** | Tests real connection failure handling |
| TC-EH05: Invalid TTL format | **Integration** | Validation error |
| TC-EH06: Empty policy rules | **Integration** | Validation error |

**Summary:** E2E: 2, Integration: 4

---

### 8. tc_auth_test.go (5 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-AU01-01: Allow bound SA to authenticate | **E2E** | Needs real K8s auth + TokenReview |
| TC-AU01-02: Reject incorrect SA | **E2E** | Needs real K8s auth rejection |
| TC-AU01-03: Reject invalid JWT | **E2E** | Needs real token validation |
| TC-AU01-04: Re-authenticate after expiration | **E2E** | Tests real token lifecycle |
| TC-AU01-05: Multiple SAs same role | **E2E** | Needs real K8s SA tokens |

**Summary:** Keep ALL in E2E (5 tests) - K8s auth method requires real TokenReview API

---

### 9. tc_jwt_auth_test.go (7 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-AU04-01: JWT auth with SA token | **E2E** | Needs real K8s OIDC issuer |
| TC-AU04-02: Reject wrong audience | **Integration** | JWT validation logic |
| TC-AU04-03: Reject wrong subject | **Integration** | JWT validation logic |
| TC-AU05-01: Discover OIDC config | **E2E** | Tests real K8s /.well-known/openid-configuration |
| TC-AU05-02: Auth with OIDC keys | **E2E** | Needs real JWKS endpoint |
| TC-AU05-03: Custom audiences | **E2E** | Needs real TokenRequest API |
| TC-AU06-01: VaultConnection with JWT | **E2E** | Tests full JWT connection flow |

**Summary:** E2E: 5, Integration: 2

---

### 10. token_lifecycle_test.go (13 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| Bootstrap: should bootstrap K8s auth | **E2E** | Core bootstrap flow |
| Bootstrap: complete and transition | **E2E** | Bootstrap verification |
| Bootstrap: K8s auth enabled | **E2E** | Vault state check |
| Bootstrap: operator role created | **E2E** | Vault state check |
| Bootstrap: not re-bootstrap | **E2E** | Idempotency test |
| Bootstrap: token expiration info | **Integration** | Status field check |
| Bootstrap: Vault version in status | **Integration** | Status field check |
| K8s Auth: connect pre-configured | **E2E** | Non-bootstrap flow |
| K8s Auth: NOT bootstrapComplete | **Integration** | Status field check |
| K8s Auth: authMethod set | **Integration** | Status field check |
| K8s Auth: Vault version | **Integration** | Status field check (duplicate) |
| K8s Auth: token expiration | **Integration** | Status field check (duplicate) |
| TC-LC07: Renew token | **E2E** | Real token renewal |

**Summary:** E2E: 6, Integration: 7 (many are status field checks that could be consolidated)

---

### 11. operator_token_test.go (10 tests)

| Test | Verdict | Reason |
|------|---------|--------|
| TC-OP01: create capability on policies | **Integration** | Just Vault permission check |
| TC-OP01: list capability on policies | **Integration** | Just Vault permission check |
| TC-OP02: CRUD on auth/kubernetes/role | **Integration** | Just Vault permission check |
| TC-OP02: list on auth/kubernetes/role | **Integration** | Just Vault permission check |
| TC-OP03: read on sys/health | **Integration** | Just Vault permission check |
| TC-OP04: NOT access secret/* | **Integration** | Vault permission denial check |
| TC-OP04: NOT access sys/seal | **Integration** | Vault permission denial check |
| TC-OP04: NOT access sys/unseal | **Integration** | Vault permission denial check |
| TC-OP04: NOT root capability | **Integration** | Vault permission check |
| TC-OP05: create/read test policy | **Integration** | Functional permission test |

**Summary:** Move ALL to Integration (10 tests) - only needs Vault, no K8s required

---

## Summary Table

| Test File | Current E2E | Keep E2E | Move to Integration |
|-----------|-------------|----------|---------------------|
| tc_connection_test.go | 2 | 2 | 0 |
| tc_policy_test.go | 5 | 3 | 2 |
| tc_cluster_policy_test.go | 4 | 2 | 2 |
| tc_role_test.go | 3 | 3 | 0 |
| tc_cluster_role_test.go | 5 | 3 | 2 |
| tc_conflict_test.go | 3 | 2 | 1 |
| tc_error_test.go | 6 | 2 | 4 |
| tc_auth_test.go | 5 | 5 | 0 |
| tc_jwt_auth_test.go | 7 | 5 | 2 |
| token_lifecycle_test.go | 13 | 6 | 7 |
| operator_token_test.go | 10 | 0 | 10 |
| **TOTAL** | **63** | **33** | **30** |

## Recommended Actions

1. **Move operator_token_test.go entirely** to `test/integration/permissions/`
2. **Create `test/integration/error/`** for error handling tests
3. **Create `test/integration/validation/`** for validation tests
4. **Consolidate token_lifecycle status checks** - many are duplicates
5. **Keep K8s auth tests in E2E** - TokenReview API requires real K8s

## Result

- **E2E tests reduced from 63 to 33** (~48% reduction)
- **CI time should improve significantly**
- **Integration tests provide faster feedback** for error/validation paths
