#!/usr/bin/env bash
# Tears down the local E2E development stack.
# Delegates to 'make e2e-local-down' which handles Helm uninstall + compose down.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Tearing down E2E stack..."

make -C "$PROJECT_ROOT" e2e-local-down

echo "E2E stack torn down."
