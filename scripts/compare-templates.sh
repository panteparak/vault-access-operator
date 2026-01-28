#!/bin/bash
# Compare kustomize and helm rendered templates to ensure equivalence
#
# This script renders both kustomize and helm templates, then uses a Go tool
# to compare them and report differences. Expected differences (helm-specific
# labels, optional features) are handled gracefully.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create temp directory for output files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

KUSTOMIZE_OUTPUT="$TEMP_DIR/kustomize-output.yaml"
HELM_OUTPUT="$TEMP_DIR/helm-output.yaml"

echo "Rendering kustomize templates..."
if ! kustomize build "$PROJECT_ROOT/config/default" > "$KUSTOMIZE_OUTPUT" 2>&1; then
    echo "ERROR: Failed to render kustomize templates"
    cat "$KUSTOMIZE_OUTPUT"
    exit 2
fi

echo "Rendering helm templates..."
if ! helm template vault-access-operator "$PROJECT_ROOT/charts/vault-access-operator" \
    --namespace vault-access-operator-system \
    --set webhook.enabled=false \
    --set networkPolicy.enabled=false \
    --set podDisruptionBudget.enabled=false \
    --set serviceMonitor.enabled=false \
    > "$HELM_OUTPUT" 2>&1; then
    echo "ERROR: Failed to render helm templates"
    cat "$HELM_OUTPUT"
    exit 2
fi

echo ""
echo "Comparing templates..."
echo ""

# Run Go comparison tool
cd "$PROJECT_ROOT"
go run ./test/template-compare \
    --kustomize="$KUSTOMIZE_OUTPUT" \
    --helm="$HELM_OUTPUT"
