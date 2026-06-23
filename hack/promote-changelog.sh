#!/usr/bin/env bash
#
# Promote the CHANGELOG.md "[Unreleased]" section into a dated release section.
#
# Usage: hack/promote-changelog.sh <version> [changelog-file]
#
# Inserts a "## [<version>] - <YYYY-MM-DD>" heading immediately after
# "## [Unreleased]", moving the current Unreleased entries under the new version
# and leaving a fresh, empty [Unreleased]. Hand-written prose is preserved
# verbatim (this does NOT regenerate the changelog from commit messages), so it
# composes with the `/changelog-add` workflow that maintains [Unreleased].
#
# Used both for the one-time backlog promotion and by the automated release
# pipeline (.github/workflows/release.yaml) on every version bump.
set -euo pipefail

VERSION="${1:?usage: promote-changelog.sh <version> [changelog-file]}"
FILE="${2:-CHANGELOG.md}"
DATE="$(date -u +%Y-%m-%d)"

if [[ ! -f "$FILE" ]]; then
  echo "error: changelog file not found: $FILE" >&2
  exit 1
fi
if ! grep -q '^## \[Unreleased\]' "$FILE"; then
  echo "error: '## [Unreleased]' heading not found in $FILE" >&2
  exit 1
fi

# Insert the new version heading right after the first "## [Unreleased]" line,
# pushing the existing Unreleased content beneath it.
awk -v ver="$VERSION" -v date="$DATE" '
  /^## \[Unreleased\]/ && !done {
    print
    print ""
    print "## [" ver "] - " date
    done = 1
    next
  }
  { print }
' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"

echo "Promoted [Unreleased] -> [$VERSION] - $DATE in $FILE"
