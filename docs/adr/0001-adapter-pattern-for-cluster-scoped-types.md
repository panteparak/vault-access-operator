# ADR 0001: Adapter pattern for namespaced + cluster-scoped Vault resources

- **Status:** Accepted
- **Date:** 2026-05-27
- **Related:** [`FLOW_POLICY.md`](../internal/FLOW_POLICY.md), [`FLOW_ROLE.md`](../internal/FLOW_ROLE.md), [`CONTEXT.md`](../internal/CONTEXT.md#adapter)

## Context

The operator exposes two CRD pairs that differ only in scope:

- `VaultPolicy` (namespaced) and `VaultClusterPolicy` (cluster-scoped) — both render to Vault HCL policies under `sys/policies/acl/{name}`. Namespaced policies use a `{namespace}-{name}` Vault name to avoid collisions; cluster policies use the bare `{name}`.
- `VaultRole` (namespaced) and `VaultClusterRole` (cluster-scoped) — both produce Vault auth-method roles. Same naming pattern.

The sync logic, drift detection, condition management, finalizer handling, and webhook validation are 95% identical between each pair. The only differences are:
- The Vault resource name format.
- The optional `enforceNamespaceBoundary` validation (only on namespaced kinds).
- The owner reference / scoping (cluster-scoped resources cannot be owned by namespaced ones).

Without abstraction, every change touches both reconcilers — a recurring pain point flagged in [`IMPROVEMENTS.md`](../internal/IMPROVEMENTS.md) and historically the source of subtle regressions where one of the pair was updated and the other lagged.

## Decision

Introduce a domain-level **adapter interface per resource kind**:

- `PolicyAdapter` in [`features/policy/domain/adapter.go`](../../features/policy/domain/adapter.go) — unifies `*VaultPolicy` and `*VaultClusterPolicy`.
- `RoleAdapter` in [`features/role/domain/adapter.go`](../../features/role/domain/adapter.go) — unifies `*VaultRole` and `*VaultClusterRole`.

Each adapter exposes the scope-aware operations the Handler needs:
- `GetVaultPolicyName()` / `GetVaultRoleName()` — returns the correctly-namespaced Vault name
- `GetK8sResourceIdentifier()` — returns `namespace/name` or just `name`
- `IsNamespaced()` — used by webhook for `enforceNamespaceBoundary`
- Plus delegation to `SyncStatusReadWriter` for shared status manipulation

The feature `Handler` operates exclusively on the adapter. Both reconcilers wrap their concrete type into the adapter before invoking the handler.

## Consequences

### Positive

- **Single source of truth for sync logic** — `handler.go` has one `SyncPolicy` / `CleanupPolicy` method, not two.
- **Easier to add a new scope** — if Vault Enterprise's "namespaces" map to a third K8s scope in future, only the adapter needs extending.
- **Tests at the handler level cover both kinds** — table-driven tests parameterize on adapter, doubling coverage per test.

### Negative

- One extra abstraction layer to navigate when tracing code (reconciler → adapter → handler).
- The adapter must stay in lockstep with the underlying types; adding a new field to `VaultPolicy.Spec` requires adapter accessors if the handler needs it.

### Neutral

- The Workflow layer (`shared/controller/workflow`) operates on `vaultv1alpha1.SyncStatusReadWriter`, which the adapter satisfies. So this decision composes cleanly with [ADR 0002](0002-template-method-base-reconciler.md).

## Alternatives considered

### Alternative A: Code generation

Generate the cluster variant from the namespaced variant via a `//go:generate` directive. Rejected because:
- The scope difference is more than syntactic — it changes naming logic, webhook rules, and watch semantics.
- Operator-sdk's existing scaffolding produces distinct files; codegen would diverge from the standard tooling.

### Alternative B: Generics-only (no interface)

Define `Handler[T metav1.Object]` with type constraints. Rejected because:
- Go generics cannot express the scope-aware behavior cleanly (the methods on `*VaultPolicy` vs `*VaultClusterPolicy` differ in signature, not just type).
- An explicit interface documents the contract.

### Alternative C: Inheritance via struct embedding

Embed a common `PolicyCommon` struct in both types. Rejected because:
- K8s code generation and DeepCopy do not handle embedded types cleanly in CRDs.
- Embedding propagates fields into the CRD schema in ways that are hard to control.

## References

- Adapter source: [`features/policy/domain/adapter.go`](../../features/policy/domain/adapter.go), [`features/role/domain/adapter.go`](../../features/role/domain/adapter.go)
- Consumers: [`features/policy/controller/handler.go`](../../features/policy/controller/handler.go), [`features/role/controller/handler.go`](../../features/role/controller/handler.go)
- Related: [ADR 0002 — Template Method BaseReconciler](0002-template-method-base-reconciler.md)
