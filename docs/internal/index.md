# Vault Access Operator — Internal Documentation

This is the contributor-facing documentation site for `vault-access-operator`. It is **not** listed in the main user-facing nav; you reached it via direct URL or a back-link from the main docs.

For the user-facing documentation (install, CRD reference, auth methods, troubleshooting), go back to the [main site](../).

## Where to start

Pick the entry point that matches what you're trying to do:

| You want to… | Read |
|--------------|------|
| Understand what this project is and how the codebase is laid out | [PROJECT_OVERVIEW](PROJECT_OVERVIEW.md) |
| See the static layers, package dependencies, and CRD relationships | [ARCHITECTURE](ARCHITECTURE.md) |
| Read the shared runtime foundations every flow doc builds on | [FLOW_OVERVIEW](FLOW_OVERVIEW.md) |
| Walk through how the operator boots, elects a leader, and shuts down | [FLOW_LIFECYCLE](FLOW_LIFECYCLE.md) |
| Understand the connection / policy / role / discovery / deletion / auth flows | [FLOW_CONNECTION](FLOW_CONNECTION.md), [FLOW_POLICY](FLOW_POLICY.md), [FLOW_ROLE](FLOW_ROLE.md), [FLOW_DISCOVERY](FLOW_DISCOVERY.md), [FLOW_DELETION](FLOW_DELETION.md), [FLOW_AUTH](FLOW_AUTH.md) |
| Understand admission webhooks (rejection rules, TLS, opt-in gate) | [FLOW_WEBHOOK](FLOW_WEBHOOK.md) |
| Understand the in-process event bus (publishers, subscribers, gotchas) | [FLOW_EVENTS](FLOW_EVENTS.md) |
| See every Prometheus metric, where it's emitted, and which are dead | [FLOW_METRICS](FLOW_METRICS.md) |
| Step-by-step contributor procedures (add an auth backend, debug a stuck reconcile, …) | [INSTRUCTIONS](INSTRUCTIONS.md) |
| Catalogue of disconnects, duplicates, gaps, and recommendations | [IMPROVEMENTS](IMPROVEMENTS.md) ⭐ |

## Conventions

- **Source references** are written as `[path/file.go:line](../../path/file.go:line)`. They resolve correctly when reading the docs in-repo on GitHub. They appear as broken on this rendered site (MkDocs can't follow into the source tree); that's expected — click "Edit on GitHub" to jump to the source.
- **Mermaid diagrams** are used throughout for sequence, flowchart, class, and ER diagrams. Render natively in this site.
- **IMPROVEMENTS items are stable-numbered**: §1, §2, …, §36. Other docs cross-reference them by number.

## License

Apache 2.0 — same as the main project.
