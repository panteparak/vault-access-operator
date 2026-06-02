---
description: Run the full pre-push verification chain — codegen, lint, unit tests, template parity
---

You will run the standard pre-push verification for this operator. Execute the following Make targets in sequence, stopping at the first failure and surfacing the error to the user clearly:

1. `make manifests generate helm-update-crds` — regenerate CRDs, deep-copy, and Helm chart CRDs from `api/v1alpha1/*_types.go`
2. `make lint` — golangci-lint with project config
3. `make test` — unit tests (excludes integration + e2e via build tags)
4. `make compare-templates` — verify kustomize and helm template outputs match

For each step:
- Run the command via Bash
- If it fails, stop and report which step failed with the relevant error output
- If it succeeds, print a brief "✅ <step name>" line and continue

After all four steps succeed, run `git status` to show whether codegen produced any uncommitted changes. If so, remind the user to commit them.

Do NOT run integration or e2e tests — those need separate infrastructure. Use `/e2e-test` for e2e.
