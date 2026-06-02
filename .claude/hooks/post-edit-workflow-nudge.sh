#!/usr/bin/env bash
# PostToolUse hook: echoes workflow reminders when load-bearing files change.
# Reads $CLAUDE_HOOK_PAYLOAD (JSON) on stdin or env, extracts tool_input.file_path,
# and prints a nudge line based on which area of the codebase was touched.
#
# Designed to be non-blocking: always exits 0. Worst case, prints nothing.

set -u

payload="${CLAUDE_HOOK_PAYLOAD:-}"
if [ -z "$payload" ] && [ ! -t 0 ]; then
  payload="$(cat)"
fi

path=""
if [ -n "$payload" ] && command -v jq >/dev/null 2>&1; then
  path="$(jq -r '.tool_input.file_path // empty' <<<"$payload" 2>/dev/null || true)"
fi

[ -z "$path" ] && exit 0

case "$path" in
  */api/v1alpha1/*_types.go)
    echo "[workflow] CRD type changed — run 'make manifests generate helm-update-crds', update docs/api-reference.md, add a CHANGELOG entry, and consider invoking /docs-drift before commit."
    ;;
  */features/*/controller/*.go)
    feat="$(printf '%s' "$path" | sed -E 's|.*/features/([^/]+)/controller/.*|\1|')"
    flow_upper="$(printf '%s' "$feat" | tr '[:lower:]' '[:upper:]')"
    echo "[workflow] Controller logic changed in feature '$feat' — update docs/internal/FLOW_${flow_upper}.md if runtime behavior changed; a new shared abstraction → consider /new-adr."
    ;;
  */shared/controller/*/*.go)
    pkg="$(printf '%s' "$path" | sed -E 's|.*/shared/controller/([^/]+)/.*|\1|')"
    echo "[workflow] Cross-cutting shared package '$pkg' changed — consider whether this needs a docs/adr/ entry and a CONTEXT.md update."
    ;;
  */cmd/main.go)
    echo "[workflow] Entry point changed — verify docs/configuration.md reflects any new/removed flag."
    ;;
  */.github/workflows/*.yaml | */.github/workflows/*.yml)
    echo "[workflow] CI workflow changed — run 'actionlint' locally and add a CHANGELOG entry if user-visible."
    ;;
  */internal/webhook/*.go)
    echo "[workflow] Webhook layer changed — consider a STRIDE pass via /security-threat-model and update docs/webhooks.md if user-visible."
    ;;
esac

exit 0
