# Lupetto

Lupetto is being rebuilt as a local tool for selecting Wolfi APK packages, composing OCI images with apko, and retaining verifiable build evidence. Optional publication and Cosign signing extend the local build workflow.

**Status: CLI bootstrap only.** A standalone Go entry point checks external tools and accepts exact APK request syntax, but image builds, SBOMs, catalog access, publication, and Explorer are not implemented. An accepted build request fails explicitly without creating an image.

The source of the rebuild specification is the operator-documentation request supplied for the lost implementation. The overwritten older checkout is excluded from this project’s evidence and design. No claim about the lost implementation has been verified against its source or executable.

## Check external tools

```bash
go run ./cmd/lupetto doctor
```

The check reports whether `apko` and `docker` (required for the planned default build workflow) and `cosign` (optional for signing) are on `PATH`. It suggests OS-specific installation steps for missing tools. It does not install anything, verify tool versions, or check whether the Docker daemon is running. Exit status is 1 if a required tool is missing, 0 otherwise.

## Documentation map

| Document | Purpose |
| --- | --- |
| [Scope and behavior](docs/scope.md) | What to rebuild, recovered command contracts, and explicit exclusions. |
| [Architecture](docs/architecture.md) | Recommended component boundaries, data flow, and evidence handling. |
| [Decisions](docs/decisions.md) | Distinguish specification constraints, design proposals, and open questions. |
| [Implementation checklist](docs/implementation-plan.md) | Single actionable checklist, with separate CLI and Explorer workstreams and release gates. |
| [Verification](docs/verification.md) | Observable checks required before claiming a feature works. |

Start with scope, then resolve the decisions needed for the next implementation milestone. Update these documents when a decision changes; do not turn proposed behavior into a claim of implemented behavior.

[AGENTS.md](AGENTS.md) defines repository instructions for coding agents, including evidence requirements and the CLI/Explorer boundary.

## Core workflow

```text
Wolfi snapshot → package selection → exact APK version
                                      │
                                      ▼
                              apko resolution/build
                                      │
                         lock + image + validated SPDX
                                      │
                               local Docker load
                                      │ optional
                               registry publication
                                      │
                              immutable image digest
                                      │ optional
                         image signature + SPDX attestation
```

Major selectors remain part of the planned interface. They resolve to an exact package/version before entering the same build pipeline as explicit version requests.

## CLI and Explorer separation

The CLI is a standalone application. Explorer is an optional application that consumes it for builds; the CLI never depends on Explorer. Explorer owns the web UI, not a second build engine.

Whether Explorer lives beside the CLI or becomes a separate product, repository, or Go module is intentionally undecided. [The application boundaries and integration contracts](docs/architecture.md#application-and-dependency-boundaries) must support either choice. CLI delivery does not wait for Explorer.

## Working principles

- Prefer a small coordinator of apko, Docker, and Cosign over a new build platform.
- Keep exact package selection and dependency resolution evidence explicit.
- Separate successful image creation, publication, signing, and attestation outcomes.
- Never store real passwords, tokens, private keys, or copied credentials in documentation or fixtures.
- Do not introduce remote Konflux execution, registry inventory, or vulnerability scanning as prerequisites for local builds.

## Operator documentation later

Once the build workflow is implemented and exercised, replace this landing page with the verified operator guide and add `docs/registry-signing.md` for detailed publication and verification instructions. Preserve links to the rebuild documents. Do not publish invented defaults or unexercised commands as current operator instructions.
