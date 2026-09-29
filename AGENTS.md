# Lupetto agent instructions

## Project context

This is a clean-room rebuild of a lost local Wolfi-to-OCI tool. The documentation currently precedes implementation. Do not claim a command, default, schema, or workflow is implemented without checking source and exercising behavior.

The overwritten older checkout is explicitly excluded. Do not inspect, copy, or use it to infer the lost implementation. Do not modify sibling repositories or use their deployment state or credentials.

## Read before working

1. [README](README.md): current status and documentation map.
2. [Scope](docs/scope.md): compatibility targets and non-goals.
3. [Architecture](docs/architecture.md): ownership and integration boundaries.
4. [Decisions](docs/decisions.md): constraints, proposals, and unresolved choices.
5. [Implementation checklist](docs/implementation-plan.md): the single implementation progress record.
6. [Verification](docs/verification.md): required observable checks.

Work on the requested scope. Resolve prerequisite decisions explicitly; do not promote a recommendation to an accepted historical fact. Keep product scope changes visible and obtain approval before removing specified behavior.

## Architecture boundaries

- The CLI is a standalone application. Explorer is optional and must not be required to build, install, run, test, or release the CLI.
- Explorer product identity, repository, and Go-module packaging remain undecided. Do not assume one module or create multiple modules solely to anticipate a split.
- CLI/core code must not import Explorer code, templates, handlers, or UI configuration.
- Explorer must not import build/publication/signing internals. It invokes the configured CLI through an explicitly compatible machine-readable contract.
- Keep catalog access separate from build execution. Shared packages or schemas need explicit ownership; do not mutate private build state from Explorer.
- Keep one exact-build pipeline. Major selectors resolve to an exact package/version within a snapshot and architecture before entering that pipeline.
- Prefer existing apko, Docker, and Cosign capabilities over custom solvers, signing systems, remote APIs, or job services.
- Go is the recommended implementation language; tool versions and dependencies still need deliberate selection and verification.

## Behavioral and security invariants

- Preserve exact APK revisions and retain dependency-lock and snapshot evidence. Never silently substitute an unavailable package/version.
- Validate generated SPDX against the resolved lock before calling it validated evidence.
- Distinguish image creation, Docker loading, registry publication, image signing, and SPDX attestation outcomes. Partial success is not complete success.
- Use the pushed immutable registry digest for signing and attestation, not a local Docker image ID.
- Keep registry support generic. Preserve the specified Docker publication path and rejection of publishing with `--no-load` unless a contract change is approved.
- Use Docker’s credential store and process-environment Cosign password input. Never pass passwords as command arguments or log secret-bearing inputs.
- HTTP registry access and verification without transparency-log evidence are local-development exceptions, not production defaults.
- Never commit credentials, tokens, private keys, secret-bearing logs, or local runtime databases/workspaces. Use synthetic fixtures and generic examples.
- Do not push images, sign/publish artifacts, use live credentials, or mutate remote infrastructure without authorization for the exact target/scope. Prefer isolated local verification; a checklist item is not authorization to touch a live registry.

## Implementation and verification

Use existing patterns once code exists. Avoid speculative abstractions and duplicate build paths. Keep exported interfaces and their consumers consistent; do not silently break the CLI contract used by Explorer.

Mark checklist items complete only with observed proof, recorded beside the item. Leave incomplete or blocked items unchecked with a short explanation. Maintain decisions and verification details in their existing documents rather than duplicating status lists.

For behavioral changes, exercise the affected command or scenario. Add focused regression tests for plausible bugs; do not treat argument-echo mocks as proof that external tools interoperate. Verify web changes in the actual browser.

Once Go code exists, run focused checks and `go test ./...` in the affected implemented modules before delivery. Until then, validate documentation links, anchors, examples, and internal consistency; state that application tests are unavailable rather than implying they passed.

Report changed files, exact verification commands/results, and remaining limitations. Keep operator instructions aligned with actual CLI parsing/help and exercised behavior.

## Version control

Use this repository’s Git history; do not import the overwritten checkout’s history as implementation evidence. Preserve unrelated work and avoid destructive resets or cleanup.

For authorized work, make frequent, small commits at coherent, verified checkpoints rather than accumulating all changes in one final commit. Stage only files belonging to the checkpoint; never include unrelated work. Review staged content for secrets and generated runtime artifacts before each commit. Push or configure remotes only when explicitly requested. Never push or publish merely because local verification succeeded.
