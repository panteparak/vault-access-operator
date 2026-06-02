---
description: Audit the current branch for documentation drift — code changes without matching doc updates
---

Invoke the project's `docs-drift` skill (defined under `.claude/skills/docs-drift/`).

If the skill is available as `/docs-drift` from the skills catalog, prefer invoking it directly. Otherwise, perform the audit inline using the rules documented in `.claude/skills/docs-drift/SKILL.md`:

1. Determine the merge base: `git merge-base HEAD origin/main` (fallback to `main`).
2. List changed paths: `git diff <base>..HEAD --name-only`.
3. Apply repo-specific rules (see SKILL.md for full set) and produce a checklist of doc files that likely need updates.
4. Print the checklist with file paths; do NOT auto-edit any docs.

This command is the entry-point recommended in CLAUDE.md and WORKFLOWS.md before pushing a branch.
