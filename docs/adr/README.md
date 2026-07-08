# Architecture Decision Records (ADRs)

This directory captures load-bearing design decisions for the Vault Access Operator. Each ADR documents a single decision: the context that called for it, what we decided, and what alternatives were considered.

ADRs are immutable once Accepted. If a decision is reversed or superseded, write a new ADR that references the old one in its `Superseded by` link.

## Index

| # | Title | Status | Date |
|---|-------|--------|------|
| [0001](0001-adapter-pattern-for-cluster-scoped-types.md) | Adapter pattern for namespaced + cluster-scoped Vault resources | Accepted | 2026-05-27 |
| [0002](0002-template-method-base-reconciler.md) | Template Method base reconciler for feature controllers | Accepted | 2026-05-27 |
| [0003](0003-two-level-drift-and-conflict-config.md) | Two-level drift and conflict-policy configuration | Accepted | 2026-05-27 |
| [0004](0004-event-bus-closure-capture.md) | Event bus with closure-captured type dispatch | Accepted | 2026-05-27 |
| [0005](0005-cleanup-failure-configmap-queue.md) | ConfigMap-backed retry queue for cleanup failures | Accepted | 2026-05-27 |
| [0006](0006-cluster-name-prefix.md) | Per-cluster name prefix for Vault resources (CE multi-tenancy) | Superseded by 0010 | 2026-06-29 |
| [0007](0007-hierarchical-metadata-only-managed-markers.md) | Hierarchical, metadata-only managed markers with opt-in flag | Superseded by 0008 | 2026-07-02 |
| [0008](0008-in-band-ownership-markers.md) | In-band ownership markers on the managed Vault objects | Accepted | 2026-07-02 |
| [0009](0009-connection-owned-role-mount.md) | The VaultConnection owns the role auth mount | Accepted | 2026-07-08 |
| [0010](0010-structured-vault-names-and-recorded-name-authority.md) | Structured Vault names and recorded-name authority | Accepted | 2026-07-08 |

## Process

1. **Propose**: copy [`0000-template.md`](0000-template.md) via `/new-adr <slug>`. Mark `Status: Proposed`.
2. **Discuss**: open a PR with the proposed ADR. Iterate based on review.
3. **Decide**: when consensus is reached, change `Status: Accepted` and merge.
4. **Reference**: link the ADR from the relevant `docs/internal/FLOW_*.md` and add a glossary entry in `docs/internal/CONTEXT.md` if it introduces vocabulary.
5. **Update the index**: add a row to the table above.

## Format

We use MADR-lite — five sections (Context, Decision, Consequences, Alternatives, References). Keep each ADR under ~100 lines. Verbose rationale belongs in linked FLOW docs or design discussion threads.
