---
description: Tear down the local E2E stack (k3s + Vault + Dex + operator)
---

Run `make e2e-local-down` to tear down the docker-compose E2E stack and clean up:
- Stops and removes the k3s, Vault, Dex containers
- Removes the kubeconfig at `tmp/e2e/`
- Frees ports

This is a clean teardown — no data is preserved. If you need to keep state across runs, mention that the user should `docker compose -f docker-compose.e2e.yaml stop` instead (containers paused but volumes kept).
