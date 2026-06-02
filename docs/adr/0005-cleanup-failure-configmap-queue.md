# ADR 0005: ConfigMap-backed retry queue for cleanup failures

- **Status:** Accepted
- **Date:** 2026-05-27
- **Related:** [`FLOW_DELETION.md`](../internal/FLOW_DELETION.md), [`CONTEXT.md`](../internal/CONTEXT.md#cleanup-queue)

## Context

When a K8s resource (e.g., `VaultPolicy`) is deleted, the operator must also delete the corresponding Vault resource. The finalizer pattern keeps the K8s object alive until the Vault delete succeeds — but what if Vault is unreachable, or returns a transient error?

Naive options:
1. **Block deletion indefinitely** — keep retrying in the reconcile loop until Vault is reachable. Problem: the K8s object stays in `Terminating` state forever, blocking namespace deletion and confusing users.
2. **Give up and remove the finalizer** — accept that Vault has an orphan resource. Problem: silent leak. Vault accumulates managed resources for which no K8s owner exists, exhausting limits or accumulating cost.

Both leak information in different directions.

## Decision

Introduce a **leader-gated cleanup retry queue backed by a ConfigMap**:

1. When `CleanupWorkflow` fails to delete a Vault resource and the K8s object has been in `Terminating` for > `cleanupGracePeriod` (default 5 minutes), the workflow:
   - Records the pending deletion in a ConfigMap (`operator-cleanup-queue` in the operator's namespace) — keyed by `<connection>/<resource-type>/<vault-name>`.
   - Removes the K8s finalizer, allowing the K8s object to finish deleting.
2. A separate controller (`CleanupRetryController`, leader-gated) reconciles the ConfigMap on a periodic interval, retrying each entry against the relevant Vault connection.
3. Successful deletes remove the entry from the ConfigMap. Persistent failures (e.g., Vault permission denied) surface as an event/metric.

## Consequences

### Positive

- **K8s lifecycle is never blocked indefinitely** — namespaces can finish deleting; users aren't stuck.
- **No silent leak** — every failed cleanup is durably tracked.
- **Single leader does the retries** — no thundering herd across replicas.
- **Visible to operators** — `kubectl get cm operator-cleanup-queue -o yaml` shows the backlog.

### Negative

- ConfigMap size limit (1MB) caps how many failures we can track. At ~200 bytes per entry, that's ~5000 backlogged deletes — adequate for most clusters, but a busy operator could overflow.
- Adds a new controller and a new ConfigMap that must be RBACed properly.
- The 5-minute grace period is a tunable that needs documentation.

### Neutral

- The retry queue is a K8s-native artifact (ConfigMap), not an external database. Backup of the operator namespace covers the queue automatically.

## Alternatives considered

### Alternative A: In-memory retry queue

Keep failures in a map in the operator process. Rejected — lost on restart; lost on leader failover.

### Alternative B: A new CRD (`CleanupTask` or similar)

More structured than a ConfigMap. Rejected — adds a CRD migration burden and increases the schema surface for a comparatively simple use case. Reconsider if entry count outgrows the ConfigMap limit.

### Alternative C: Block deletion forever

The simplest option — never remove the finalizer until Vault confirms delete. Rejected — operationally hostile when Vault is genuinely unavailable for hours.

## References

- Workflow: [`shared/controller/workflow/cleanup.go`](../../shared/controller/workflow/)
- Retry controller: [`cmd/main.go`](../../cmd/main.go) (search for `CleanupRetryController` registration)
- Related: [ADR 0001 — Adapter pattern](0001-adapter-pattern-for-cluster-scoped-types.md), [ADR 0002 — BaseReconciler](0002-template-method-base-reconciler.md)
