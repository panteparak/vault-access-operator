#!/usr/bin/env bash
# Tears down the local E2E development stack.
# Stops docker-compose services and cleans up the kubeconfig directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Tearing down E2E stack..."

docker compose -f "$PROJECT_ROOT/docker-compose.e2e.yaml" down -v 2>/dev/null || true
rm -rf "$PROJECT_ROOT/tmp/e2e"

echo "E2E stack torn down."
