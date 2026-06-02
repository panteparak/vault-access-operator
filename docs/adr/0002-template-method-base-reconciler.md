# ADR 0002: Template Method base reconciler for feature controllers

- **Status:** Accepted
- **Date:** 2026-05-27
- **Related:** [`FLOW_LIFECYCLE.md`](../internal/FLOW_LIFECYCLE.md), [`FLOW_POLICY.md`](../internal/FLOW_POLICY.md)

## Context

Every feature reconciler in this operator (connection, policy, role, discovery, plus the cluster-scoped variants) needs to perform a near-identical lifecycle:

1. Fetch the CR from the K8s API.
2. Initialize observability (reconcile ID for log correlation).
3. Handle deletion (finalizer + cleanup hook).
4. Add finalizer if missing.
5. Call feature-specific `Sync` logic.
6. Update status + conditions.
7. Decide requeue interval.

In a vanilla kubebuilder layout each reconciler reimplements all 7 steps with subtle variations. This leads to drift between features (e.g., one reconciler logs reconcile ID, another doesn't; one updates status atomically, another races).

## Decision

Introduce a **generic Template Method base reconciler** at [`shared/controller/base/reconciler.go`](../../shared/controller/base/reconciler.go):

```go
type BaseReconciler[T client.Object] struct { ... }
type FeatureHandler[T client.Object] interface {
    Sync(ctx, obj T) error
    Cleanup(ctx, obj T) error
}

func (r *BaseReconciler[T]) Reconcile(ctx, req) (ctrl.Result, error) {
    // 1. fetch, 2. ID, 3. cleanup-if-deleting, 4. add-finalizer,
    // 5. delegate to FeatureHandler.Sync, 6. update status, 7. requeue
}
```

Feature reconcilers register a `FeatureHandler` and call into `BaseReconciler.Reconcile`. The feature-specific code shrinks to just the `Sync` and `Cleanup` methods on the handler.

The base reconciler is generic over the CR type so each feature wires concrete types at compile time.

## Consequences

### Positive

- **Lifecycle bugs fixed once apply everywhere** — when we added reconcile-ID tracking, every feature got it automatically.
- **New features are smaller** — a new CRD's reconciler can be ~50 lines instead of 200.
- **Easier to enforce invariants** — finalizer logic, observed-generation updates, condition consistency all live in one place.

### Negative

- The generic signature is moderately complex (`BaseReconciler[T client.Object]` with type-parameterized predicates). Contributors unfamiliar with Go generics may struggle initially.
- Stack traces are slightly deeper (one extra frame for the base reconciler).
- Customizing the lifecycle (e.g., a feature wants to skip finalizer logic) requires a "hook" parameter rather than just overriding a method.

### Neutral

- Composes with [ADR 0001](0001-adapter-pattern-for-cluster-scoped-types.md) — the adapter unifies cluster+namespaced; the base reconciler unifies the lifecycle. Together they let one Handler serve four reconciler entry points.

## Alternatives considered

### Alternative A: Copy-paste with diligent code review

Accept the duplication and rely on PR review to catch drift. Rejected — drift accumulated even with active review, and the lifecycle code is the part most likely to silently break.

### Alternative B: Helper functions instead of a base type

A package `lifecycle.RunReconcile(ctx, req, handler)` invoked from each feature's `Reconcile`. Rejected — would not centralize state like the cached client, the resource type, or the predicate chain; effectively a thin wrapper that pushes the boilerplate one level up.

### Alternative C: Sigs.k8s.io reconciler-builder

There's no upstream "base reconciler" abstraction in controller-runtime. Adopting a third-party framework (e.g., `operator-utils`) was rejected as additional dependency surface for a problem we can solve in-tree.

## References

- Base reconciler: [`shared/controller/base/reconciler.go`](../../shared/controller/base/reconciler.go)
- Consumers: [`features/*/controller/*_reconciler.go`](../../features/)
- Related: [ADR 0001 — Adapter pattern](0001-adapter-pattern-for-cluster-scoped-types.md)
