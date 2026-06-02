---
description: Add an entry to CHANGELOG.md under [Unreleased], following Keep-a-Changelog
argument-hint: [Added|Changed|Fixed|Removed|Deprecated|Security] <one-line summary>
---

Help the user add a CHANGELOG.md entry following the project's Keep-a-Changelog convention.

1. Read the top of `CHANGELOG.md` to locate the `## [Unreleased]` section and its existing subsections (`### Added`, `### Changed`, etc.).

2. If the user provided `$ARGUMENTS`:
   - First token = subsection (Added / Changed / Fixed / Removed / Deprecated / Security). If it doesn't match one of these, ask the user which one applies.
   - Remainder = one-line summary.

3. If no arguments were provided, ask the user:
   - Which category (Added / Changed / Fixed / Removed / Deprecated / Security)?
   - One-line summary (imperative mood, e.g., "Add JWT auth method support")?
   - Optional follow-up bullets (multi-line detail)?

4. Edit `CHANGELOG.md` to add the entry under `## [Unreleased] > ### <Category>`. If the subsection doesn't exist yet under `[Unreleased]`, create it in the canonical order: Added, Changed, Deprecated, Removed, Fixed, Security.

5. Follow the existing entry style (look at a recent release for tone — often 1-line summary + 2-3 bullet sub-items explaining what/why).

6. After writing, show `git diff CHANGELOG.md` so the user can review.

Do NOT bump the version number. Do NOT move entries out of `[Unreleased]` — that happens at release time.
