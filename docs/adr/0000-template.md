# ADR NNNN: Title in Sentence Case

- **Status:** Proposed | Accepted | Deprecated | Superseded by [ADR-NNNN](NNNN-slug.md)
- **Date:** YYYY-MM-DD
- **Deciders:** @name, @name
- **Related:** [`docs/internal/FLOW_X.md`](../internal/FLOW_X.md), [`docs/internal/CONTEXT.md`](../internal/CONTEXT.md)

## Context

What is the situation that calls for a decision? One or two paragraphs. Include the constraint, the problem, and (if known) the trigger that made this decision necessary now.

If a related issue or IMPROVEMENTS.md section motivated this, link it: [`IMPROVEMENTS.md §N`](../internal/IMPROVEMENTS.md#section-n).

## Decision

What did we decide, in one or two sentences? Then enumerate the specifics:

- Specific change 1
- Specific change 2
- Boundary: what this decision does *not* cover

Keep the decision crisp. Rationale belongs in the Consequences section.

## Consequences

### Positive

- Benefit 1 — with concrete why
- Benefit 2

### Negative

- Cost / trade-off 1
- Cost / trade-off 2

### Neutral

- Anything else worth flagging that's not strictly positive or negative.

## Alternatives considered

### Alternative A: <short name>

Brief description and why we did NOT choose this.

### Alternative B: <short name>

Brief description and why we did NOT choose this.

## References

- Source code: link to canonical implementation files
- Related ADRs: cross-link
- External docs: K8s, Vault, controller-runtime references if relevant
