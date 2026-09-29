# Implementation checklist

[Documentation home](../README.md) · [Decisions](decisions.md) · [Verification](verification.md)

This is the single implementation checklist. Only the standalone CLI bootstrap is complete; the build pipeline and remaining implementation items are pending. Mark an item complete only after its observable behavior is verified; record the command/result or evidence reference beside it. Track blockers beside the affected item and design choices in the decision record, rather than creating a second status list.

The CLI and Explorer are separate workstreams. The CLI can ship after its implementation and release checks below; it does not wait for Explorer. Explorer remains part of the full compatibility scope, but its product/repository/module packaging is undecided.

## CLI workstream

### 1. Prove an exact local build

- [ ] Resolve the first-build decisions: Go/module identity, pinned apko, invocation mode, host/target architecture, repository/keyring trust, and image configuration.
- [ ] Define workspace ownership, artifact retention, output names, and the machine-readable build result.
- [x] Establish the Go module and standalone `lupetto` entry point without Explorer dependencies. Verified with `go test ./...` (pass), `go run ./cmd/lupetto --help` (exit 0), and `go run ./cmd/lupetto build wolfi-base --apk-version 1.2.3-r12` (explicit failure, no image/SBOM); the parser does not build yet.
- [ ] Implement exact APK version selection, including the packaging revision, without silently substituting versions.
- [ ] Implement apko configuration, dependency locking, and image composition; retain the inputs and resulting artifacts.
- [ ] Define and implement SPDX/lock consistency rules, including architecture identity and legitimate non-APK SPDX entries.
- [ ] Implement the exact-version SBOM command using the same resolution/evidence logic; establish whether image composition is required.
- [ ] Implement Docker loading and explicit no-load behavior.
- [ ] Handle cancellation and failures without reporting successful builds or validated evidence; retain useful, non-secret diagnostics.
- [ ] Exercise a real exact-version build and SBOM generation, inspect image contents, and confirm lock/SPDX agreement and Docker loading. Record tool versions and the exercised host/target pair.

**Completion:** an exact local build is usable independently of catalog conveniences, publication, and Explorer. Unvalidated evidence is never labeled validated.

### 2. Add snapshots and major selection

- [ ] Resolve catalog decisions: SQLite driver/schema, snapshot identity, duplicate imports, database flags, and ingest/query command names.
- [ ] Implement snapshot ingestion, provenance retention, and package/version queries.
- [ ] Define package-family mappings and major semantics only where needed; use APK-compatible version ordering.
- [ ] Resolve major selectors deterministically within an identified snapshot and target architecture; display and retain the exact selection.
- [ ] Route exact and major selections into the same exact-build pipeline.
- [ ] Reject ambiguous mappings, conflicting selectors, missing matches, and unavailable APK bytes without fallback.
- [ ] Exercise revision ordering, architecture filtering, and retained build selections after a newer snapshot is imported.

**Completion:** operators can ingest/browse snapshots and use either selector form. No general Products framework is required merely to resolve versions.

### 3. Publish and sign

- [ ] Define image naming/tagging, repository-prefix validation, flag/environment precedence, and incomplete-configuration errors.
- [ ] Implement generic registry/repository settings, including nested prefixes, using Docker credential-store authentication.
- [ ] Reject publication with `--no-load` before publication side effects.
- [ ] Implement Docker tag/push and capture the pushed immutable registry digest, not a local image ID.
- [ ] Select a supported Cosign version, signing-config format, and registry compatibility mode.
- [ ] Implement image signing followed by a signed `spdxjson` attestation of the validated document, both bound to the same pushed digest.
- [ ] Keep `COSIGN_PASSWORD` in the process environment and prevent secrets from entering arguments, logs, or retained evidence.
- [ ] Report build, publication, signing, and attestation outcomes separately, including partial success.
- [ ] Exercise real publication and verification of both signature and attestation, including wrong-key/digest and partial-failure cases.
- [ ] Exercise production-compatible verification separately from clearly labeled local HTTP/offline variants.

**Completion:** the built image and its signed evidence are verifiable in a compatible registry. Publication alone cannot be mistaken for completed signing and attestation.

### CLI release gate

- [ ] Run applicable selection, build, evidence, and publication scenarios from [verification](verification.md); record actual outcomes and unexercised cases.
- [ ] Run `go test ./...` in the CLI’s implemented Go module and record the result.
- [ ] Verify CLI help and every documented command/flag against actual parsing and exercised behavior.
- [ ] Replace the root landing page with a verified CLI operator guide and create `docs/registry-signing.md`, with cross-links and no duplicated signing prose.
- [ ] Document prerequisites, ingest/browse commands, exact/major selection, workspace retention, architecture support, publication, signing, verification, and security/evidence limitations.
- [ ] Confirm standalone CLI installation and operation without Explorer; check documentation links and remove obsolete vendor-specific configuration claims.

**Completion:** the CLI is independently deliverable. Preserve links to these rebuild records and state clearly that Explorer is not yet delivered if its workstream remains pending.

## Explorer workstream

### 4. Add Explorer as an optional application

- [ ] Decide Explorer product/repository/module packaging without introducing a CLI dependency on Explorer.
- [ ] Define supported CLI request/result versions, artifact references, exit/error semantics, cancellation, and incompatible-version behavior.
- [ ] Choose the catalog access boundary and its ownership/versioning; keep private build state out of Explorer’s write path.
- [ ] Establish the separate Explorer entry point and UI package without imports of build, publication, or signing internals.
- [ ] Define database/listen settings, supported environment inputs, safe local HTTP controls, and policy for non-loopback access.
- [ ] Implement package/version pages, package metadata, snapshot provenance, and accurate local Docker image availability.
- [ ] Implement exact build requests through the configured CLI with explicit build enablement, bounded concurrency, cancellation, and defined restart behavior.
- [ ] Consume machine-readable CLI results for job outcomes; do not infer success from human-readable progress logs.
- [ ] Retain immutable SBOM evidence for downloads independently of disposable workspaces.
- [ ] Exercise browsing, a real exact build, progress/failure handling, and SBOM download; confirm read-only operation does not require signing credentials.

**Completion:** Explorer is a consumer of an explicitly compatible standalone CLI, not a second build engine. The CLI remains installable and runnable without it.

### 5. Complete browsing semantics

- [ ] Define Products and package-series presentation against traceable data sources.
- [ ] If Products carry runtime recipes, make those inputs explicit and retain them with build evidence; do not guess runnable defaults from an APK name.
- [ ] Identify and implement the recipe-history source and package association; represent missing history honestly.
- [ ] Verify that UI labels distinguish local images, generated evidence, and external registry state without claiming unsupported registry inventory or scans.

**Completion:** grouping and history reflect defined sources. Removing any original scope item requires an explicit scope decision, not an unchecked item silently disappearing.

### Explorer release gate

- [ ] Run Explorer-specific [verification scenarios](verification.md), including request safety, concurrency, cancellation, and durable downloads, against the actual browser surface.
- [ ] Exercise Explorer against a separately built supported CLI; reject incompatible contracts clearly.
- [ ] Check import/dependency boundaries and confirm Explorer cannot overwrite build outcomes through private state.
- [ ] Run `go test ./...` in each Go module involved in the Explorer release and record the result.
- [ ] Verify Explorer help and add operator instructions for its actual database/listen settings, build controls, CLI configuration, registry/signing options, and supported environment inputs.
- [ ] Check links, security warnings, and evidence distinctions; keep detailed registry/signing instructions in their dedicated guide.

**Completion:** the Explorer workflow and its compatibility requirements are documented from exercised behavior, without coupling the CLI’s release lifecycle to the UI.
