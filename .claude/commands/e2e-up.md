---
description: Spin up the local E2E stack (k3s + Vault + Dex + operator) via docker-compose
---

Run `make e2e-local-up` to start the full local E2E stack. This brings up:
- k3s (Kubernetes API server)
- Vault (with dev-mode root token `root`)
- Dex (OIDC provider for OIDC auth tests)
- The operator (built locally, imported into k3s containerd)

The stack typically takes 60–90 seconds to be fully ready.

After it's up, run `make e2e-local-status` and show the result so the user can confirm pods are healthy.

The kubeconfig lands at `tmp/e2e/kubeconfig.yaml`. If the user wants to use kubectl directly:
```
export KUBECONFIG=$PWD/tmp/e2e/kubeconfig.yaml
```

To run tests against this stack, use `/e2e-test`. To tear down, use `/e2e-down`.

If you need cert-manager (for webhook TLS tests), suggest running `make e2e-local-up-with-webhooks` instead.
