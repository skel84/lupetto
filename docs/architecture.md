# Proposed architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Verification](verification.md)

This is a rebuild proposal, not recovered source structure. A local Go module now contains a standalone CLI, read-only discovery from the live signed Wolfi index, and a generic local OCI build path with apko-generated architecture SPDX/lock identity validation; persistent snapshot catalog ingestion and broader runtime build defaults remain undecided.

The [approved next milestone](decisions.md#publication-first-roadmap-user-approved) extends the existing live signed-index exact-build path with registry publication, Cosign image signing, and signed SPDX attestation. Persistent catalog ingestion/querying is deferred and is not a dependency of publication/signing or the standalone CLI release. Retain per-build snapshot and lock evidence without introducing SQLite or Explorer into that path.

## Components

Treat `lupetto` and `lupetto-explorer` as separate applications. The CLI is independently useful; Explorer is an optional consumer, not a required part of the build engine. Whether they share a repository, Go module, release, or product identity remains open.

| Component | Responsibility |
| --- | --- |
| Catalog | Import snapshots, retain provenance, query package versions, resolve selectors. |
| Build implementation | Turn an exact request into configuration, resolved lock, image, SPDX, and validation outcome. |
| Local loading/publication/signing | Export/load the validated image locally; later tag/push, obtain a registry digest, then invoke signing and attestation. |
| CLI | Parse operator input, run the shared operations, report results and failures. |
| Explorer | Browse catalog/evidence and launch the configured CLI for builds. |

Prefer `net/http`, server-rendered HTML, and small amounts of JavaScript over a separately deployed frontend. Use SQLite for catalog queries and local evidence, not a distributed job service.

Keep boundaries explicit without creating a general plugin framework or a service per component.

## Application and dependency boundaries

The separation is a design requirement regardless of source layout:

- The CLI and core packages must not import Explorer code, templates, HTTP handlers, or UI configuration.
- Explorer owns its HTTP server, UI assets, browsing presentation, and local job supervision. It must not import build, publication, or signing internals.
- Explorer submits builds through the configured CLI executable. The CLI owns package selection, build execution, evidence validation, publication, and signing semantics.
- Installing, running, testing, or releasing the CLI must not require running or installing Explorer.
- An Explorer release may depend on a documented compatible CLI version; the CLI must not require a matching Explorer release.

```text
Explorer UI → CLI adapter → lupetto executable → build/publish/sign
     │
     └─────→ catalog/evidence access

lupetto has no dependency on Explorer
```

### Packaging is not decided

If initially colocated, a simple layout could be:

```text
cmd/lupetto/           CLI entry point
cmd/lupetto-explorer/  Explorer entry point
internal/explorer/      HTTP handlers, templates, assets, CLI adapter
internal/catalog/       UI-independent catalog access
internal/build/         Build implementation used by the CLI
```

This is an illustrative layout, not a commitment to one `go.mod`. Separate repositories/modules or a separate Explorer product remain valid choices. Do not introduce shared release requirements merely because source is colocated.

### Integration contracts

Before enabling Explorer builds, define the CLI request/result contract: exact selection and snapshot identity, result format/version, artifact references, exit/error semantics, cancellation, and supported CLI versions. Use machine-readable results rather than parsing human-oriented progress messages. Reject incompatible versions clearly. No new command flags or protocol schema are implied by this document.

Catalog access is a separate decision. A colocated implementation may share a UI-independent catalog package, but that does not make its Go API or SQLite schema a supported external interface. Explorer must not write build-engine state through private tables.

Before extracting Explorer, choose either an explicitly versioned catalog query/export contract or a deliberately supported shared library/schema. Keep catalog access behind an Explorer-side adapter so the choice does not spread through handlers. Explorer owns its download index and retained evidence; ingest validated CLI results rather than updating build outcomes itself.

A separate Explorer product does not inherently require a remote service. Keep the local CLI execution model unless a remote workflow is separately requested; do not add an HTTP build API, plugin system, or queue service solely to anticipate extraction.

## External tools

The exact-build path invokes native apko 1.4.5 with a signed Wolfi index/key and exact package lock, producing a local OCI layout and validated per-architecture SPDX. Read-only `discover` verifies the same signed index and pinned key without invoking apko or building an image. APK version ordering uses a pinned apko 1.4.5 Go dependency. The [local-loading decision](decisions.md#local-docker-loading-decisions-resolved-before-implementation) adds a post-validation Docker archive export/load/identity check to this same path; `--no-load` and `sbom` skip it. Cosign signing remains a future stage; no containerized apko build has been exercised.

Use explicit argument arrays, not shell interpolation. Propagate cancellation, capture failures, and avoid logging secret-bearing environment values. Prefer structured output and artifact files where available. Any necessary parsing of Docker push output needs fixtures for supported tool versions and must fail if a valid digest cannot be established.

Cosign remains optional until signing is requested. Do not design a Lupetto key store or a new signing-config file format.

## One exact-build pipeline

```text
CLI selector → snapshot-scoped resolution → exact build request
                                                │
                                    apko config + dependency lock
                                                │
                                        image + SPDX output
                                                │
                                         evidence validation
                                                │
                                    optional local archive/load/inspect
                                                │
                                         artifact/result record
```

The implemented `sbom --apk-version` command invokes the same selector and image-composition function as `build` but remains image-only; apko writes the architecture SPDX during the build. The apko index SPDX is supplemental and not lock-validated. Local loading consumes the already-validated OCI image, not another build or resolution path. Historical snapshot ingestion and any future Explorer integration remain separate decisions.

A selected top-level version does not pin its dependency closure. A snapshot does not preserve the referenced APK bytes. Do not promise historical rebuildability unless the required artifacts and toolchain inputs remain available.

## Artifact and data ownership

The unique, mode-0700 user-cache build workspace retains signed index/key, config, lock, OCI image, architecture/index SPDX, and a versioned local `result.json` only after all requested stages succeed. The version-3 readable-naming record retains primary `imageReference` and unique `buildReference`, separate loaded/skipped outcome, and verified local Docker image ID alongside snapshot, exact APK, architecture, apko version, artifact paths, and validated SPDX checksum. The sole apko composition/export/import uses the unique name; readable tagging follows verified import and uses the verified image ID, then checks the readable name's ID/platform. A readable version tag is mutable, not immutable build identity; concurrent builds are not an atomic multi-tag transaction. Skipped builds record intended names without touching Docker. The archive is retained when loading is attempted; a local image ID is not a registry digest. This is not an Explorer compatibility contract, and older result records/images are not migrated. Failures retain partial diagnostics/workspaces without a success record or validated-evidence success output; confirmed unique import followed by tag/inspect failure is partial local success with uncertain readable-tag effects, not rollback. Never record private keys, passwords, or tokens.

SQLite owns catalog queries and immutable Explorer SBOM evidence. Workspace paths alone are insufficient for immutable downloads: retain the document bytes or a durable content-addressed copy and its checksum. Deleting a temporary workspace must not silently destroy retained evidence.

Avoid competing mutable descriptions of the same build. Final workspace results describe execution; Explorer may index them and report transient local job progress.

## Publication boundary

Preserve the specification’s sequence:

```text
build/validate → Docker load → tag/push → pushed digest
                                            │
                                      image signature
                                            │
                                      SPDX attestation
```

Use the pushed manifest/index digest, not a local Docker image ID. Bind both signing operations to the same immutable registry reference. Attest the validated document; do not regenerate unrelated SPDX during publication.

Report stage outcomes separately. A successful push followed by failed signing is published but not successfully signed. Do not imply that publication can be rolled back atomically.

apko also supports direct publication, but adopting it would change the compatibility contract and remove the reason publishing rejects `--no-load`. Do not implement two publication paths without a concrete need.

## Explorer boundary

Recommended initial deployment: local-only, build execution disabled unless explicitly enabled. Listen defaults and non-loopback access policy remain decisions, not existing behavior.

Build-enabled Explorer can execute tools using the operator’s credentials. Protect build-triggering requests from cross-origin abuse and validate selections server-side. Treat package metadata as untrusted content and escape it in HTML.

Start with bounded local build execution rather than a queue service. Cancellation, concurrency limits, and restart behavior must be explicit before enabling builds.

## Upstream references

- [apko composition and publication](https://github.com/chainguard-dev/apko)
- [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [ORAS documentation](https://oras.land/docs/) — useful OCI artifact context, not a required dependency.
- [Cosign attestation options](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
- [Cosign attestation verification](https://docs.sigstore.dev/cosign/verifying/attestation/)

Upstream documentation describes upstream tools, not Lupetto support. Pin and exercise versions before writing operator commands.
