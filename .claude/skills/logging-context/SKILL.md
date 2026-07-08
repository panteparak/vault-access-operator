---
name: logging-context
description: Enforce the context-logger enrichment convention — reconcileID, vaultConnection, and authPath must reach every log line via ctx, never via per-call-site fields. Use when writing or reviewing controller/handler/workflow code that logs, or invoke /logging-context to audit the current diff for violations.
---

# logging-context

Repo-scoped skill for the structured-logging convention in `vault-access-operator`.
Goal: every log line is traceable (`controller → name/namespace → reconcileID → vaultConnection → authPath`)
without any call site hand-adding those fields.

## The convention

1. **In reconcile paths, the logger comes from ctx.** Use `log.FromContext(ctx)` /
   `logr.FromContextOrDiscard(ctx)`. Never a struct-held (`r.Log`, `h.log`) or global logger —
   those bypass the enrichment chain and lose `reconcileID`.
2. **Enrich once at the choke point, not per call site.** When a new identifying fact becomes
   known (connection resolved, auth mount known), fold it in with
   `logr.NewContext(ctx, log.WithValues(...))` and pass that ctx down. Everything downstream
   inherits it. Zap does NOT dedupe keys — re-adding a field at a call site prints it twice.
3. **Field keys come from `pkg/logger` constants** (`KeyReconcileID`, `KeyVaultConnection`,
   `KeyAuthPath`, …). No string literals — that's how `vaultconnection` vs `vaultConnection`
   drift happens.
4. **Single handling rule for errors**: return wrapped errors up; log once where handled.
   `BaseReconciler` logs "sync failed" — handlers must not also `Error`-log the same failure.
   Degrade-and-continue paths (e.g. skipping drift detection) may `Info`-log because no error
   is returned.
5. **Levels**: `Info` = state changes an operator cares about (synced, drift detected, deleted);
   `V(1)` = per-step debug; `Error` = terminal failure of this reconcile attempt.
   Bounded values only; never log tokens or secret payloads.
6. **JSON in production.** `cmd/main.go` uses controller-runtime zap production defaults;
   local/e2e passes `--zap-devel=true` for console output. Don't re-hardcode `Development: true`.

## Choke-point map (where enrichment already happens)

| Fact | Injected at | Fields |
|------|-------------|--------|
| Reconcile identity | `shared/controller/base/reconciler.go` `Reconcile()` | `name`, `namespace`, `reconcileID` (also persisted to CR status via `ReconcileTrackable`) |
| Connection + auth mount (sync) | `shared/controller/workflow/sync.go` `Execute()` → `enrichLogContext()` | `vaultConnection`, `authPath` (empty for policies → omitted) |
| Connection + auth mount (cleanup) | `shared/controller/workflow/cleanup.go` `Execute()` → `enrichLogContext()` | same |
| Discovery scan identity | `features/discovery/controller/controller.go` `Reconcile()` | ctx logger (controller-runtime `reconcileID`) + `vaultConnection`, `authPath` |

Adding a new controller or workflow? Wire it into this chain — take the ctx logger, enrich at
the point the fact is known, pass the enriched ctx down. Do not thread a `logr.Logger`
parameter through new call stacks; the ctx already carries it.

## When invoked (`/logging-context`): audit the current diff

Run `git diff` (or `git diff <base>...` if a base is given) and check ONLY changed/added code for:

- [ ] `r.Log` / struct-held / package-global loggers used inside a `Reconcile`/`Sync`/`Cleanup` path
- [ ] String-literal field keys where a `pkg/logger.Key*` constant exists
- [ ] Call sites re-adding fields the ctx logger already carries (`reconcileID`, `vaultConnection`, `authPath`, `name`, `namespace`)
- [ ] An error both logged AND returned in the same function
- [ ] A new choke-point fact (new resolver, new client type) that is NOT folded into the ctx logger
- [ ] Secrets/tokens/JWTs in log fields
- [ ] New `logr.Logger` function parameters where ctx is already threaded

Report a markdown checklist grouped by severity (Violation / Worth checking / Clean).
**Report-only — do not auto-edit.** Same contract as `/docs-drift`.

## Out of scope

- Watch map-functions and token/bootstrap background goroutines run outside any reconcile —
  no `reconcileID` exists there by definition. They carry `connection`/`path` fields ad-hoc.
- `pkg/vault` client does not log (errors return to callers) — keep it that way.

## Related

- `docs/internal/FLOW_POLICY.md` — canonical 9-step sync sequence (enrichment is pre-step-1)
- `pkg/logger/logger.go` — field-key constants
- `/docs-drift` — sibling report-only audit skill
