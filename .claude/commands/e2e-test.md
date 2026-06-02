---
description: Run E2E tests against the local stack. Optional argument = Ginkgo focus pattern or label filter
argument-hint: [focus pattern or label]
---

Run E2E tests against the locally-running stack (started via `/e2e-up`).

If `$ARGUMENTS` is empty: run all E2E tests via `make e2e-local-test`.

If `$ARGUMENTS` is provided, decide whether it's a focus pattern (literal test name fragment like `TC-DRIFT04`) or a label filter (e.g., `auth`, `drift || discovery`):
- Test-ID pattern (matches `TC-[A-Z]+[0-9]+`): use `-ginkgo.focus="$ARGUMENTS"`
- Otherwise: use `-ginkgo.label-filter="$ARGUMENTS"`

Construct the command roughly as:
```
KUBECONFIG=$PWD/tmp/e2e/kubeconfig.yaml \
VAULT_ADDR=http://localhost:8200 \
E2E_K8S_HOST=https://k3s:6443 \
E2E_SKIP_BUILD=true E2E_SKIP_IMAGE_LOAD=true \
go test ./test/e2e/ -v -ginkgo.v <focus or label flag> -timeout 15m
```

(The `E2E_SKIP_BUILD=true` and `E2E_SKIP_IMAGE_LOAD=true` flags skip re-build/re-import — assumes the stack is already up. If tests fail with "image not found", run `/e2e-up` first.)

Before running: check that the stack is up via `make e2e-local-status`. If it's not, instruct the user to run `/e2e-up` first.
