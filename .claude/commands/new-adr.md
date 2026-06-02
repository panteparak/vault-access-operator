---
description: Create a new Architecture Decision Record from the template at the next sequential number
argument-hint: <kebab-case-slug>
---

Create a new ADR under `docs/adr/`.

1. Require `$ARGUMENTS` to be a non-empty kebab-case slug (e.g., `add-prometheus-scrape-config`). If empty or contains spaces/uppercase, ask the user for a proper slug.

2. List existing ADRs: `ls docs/adr/ | grep -E '^[0-9]{4}-.*\.md$' | sort` to find the highest number.

3. Compute the next number: highest + 1, zero-padded to 4 digits (e.g., `0006`).

4. Copy `docs/adr/0000-template.md` to `docs/adr/<NNNN>-$ARGUMENTS.md`.

5. Pre-fill the template:
   - Title (first heading): `# ADR <NNNN>: <Title Case of slug>` (transform kebab-case → Title Case)
   - Status: `Proposed` (user changes to `Accepted` after review)
   - Date: today's date in `YYYY-MM-DD` format

6. Read the new file back and show its contents to the user so they can start filling in Context / Decision / Consequences / Alternatives.

7. Remind the user to:
   - Update `docs/adr/README.md` (the ADR index table) when accepting the decision
   - Reference the ADR from CONTEXT.md if it introduces new domain vocabulary
   - Add a CHANGELOG entry under `### Changed` if the decision changes user-visible behavior

Do NOT auto-edit the index — let the user add it intentionally after the decision is accepted.
