# Proposed architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Verification](verification.md)

This is a rebuild proposal, not recovered source structure. A local Go module now contains a standalone CLI, read-only discovery from the live signed Wolfi index, a generic local OCI build path with apko-generated architecture SPDX/lock identity validation, default Docker loading, and the first registry-publication checkpoint implementation. Real Lupetto publication interoperability has not yet been recorded; signing, persistent snapshot catalog ingestion, and broader runtime build defaults remain pending.

The [approved roadmap](decisions.md#publication-first-roadmap-user-approved) extends the existing live signed-index exact-build path first with registry publication, then Cosign image signing and signed SPDX attestation. The publication source contracts below do not establish observed registry interoperability or implemented signing. Persistent catalog ingestion/querying is deferred and is not a dependency of publication/signing or the standalone CLI release. Retain per-build snapshot and lock evidence without introducing SQLite or Explorer into that path.

## Components

Treat `lupetto` and `lupetto-explorer` as separate applications. The CLI is independently useful; Explorer is an optional consumer, not a required part of the build engine. Whether they share a repository, Go module, release, or product identity remains open.

| Component | Responsibility |
| --- | --- |
| Catalog | Import snapshots, retain provenance, query package versions, resolve selectors. |
| Build implementation | Turn an exact request into configuration, resolved lock, image, SPDX, and validation outcome. |
| Local loading/publication/signing | Export/load the validated image locally; tag/push from its verified ID, capture and verify immutable registry identity; signing and attestation are future stages. |
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

The exact-build path invokes native apko 1.4.5 with a signed Wolfi index/key and exact package lock, producing a local OCI layout and validated per-architecture SPDX. Read-only `discover` verifies the same signed index and pinned key without invoking apko or building an image. APK version ordering uses a pinned apko 1.4.5 Go dependency. The [local-loading decision](decisions.md#local-docker-loading-decisions-resolved-before-implementation) adds a post-validation Docker archive export/load/identity check to this same path; `--no-load` without publication and `sbom` skip it. Publication uses the supported Docker 27.4 push-summary grammar and subsequent immutable pull/save/content verification. Cosign signing remains a future stage; no containerized apko build has been exercised.

Use explicit argument arrays, not shell interpolation. Propagate cancellation, capture safe local failures, and avoid logging secret-bearing environment values. Publication uses a separate secret-safe subprocess adapter, not the capturing/live local executor: discard auth-bearing tool diagnostics, sanitize failures, and feed push stdout only to a bounded summary parser retaining the validated digest. Docker inspect retains only a bounded, re-encoded identity object for internal checks. Do not retain unmatched lines, credential-helper output, command transcripts, environment, or Docker configuration. Structured artifact records hold outcomes, not tool transcripts.

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
                                   optional tag/push/digest capture
                                                │
                                   immutable pull/save/content check
                                                │
                                         artifact/result record
```

The implemented `sbom --apk-version` command invokes the same selector and image-composition function as `build` but remains image-only; apko writes the architecture SPDX during the build. It ignores publication environment inputs and rejects publication flags and `--no-load`; signing flags are not implemented. The apko index SPDX is supplemental and not lock-validated. Local loading and publication consume the already-validated OCI image and verified Docker ID, not another build or resolution path. Historical snapshot ingestion and any future Explorer integration remain separate decisions.

A selected top-level version does not pin its dependency closure. A snapshot does not preserve the referenced APK bytes. Do not promise historical rebuildability unless the required artifacts and toolchain inputs remain available.

## Artifact and data ownership

The unique, mode-0700 user-cache build workspace retains signed index/key, config, lock, OCI image, architecture/index SPDX, and a versioned local `result.json` only after all requested stages succeed. The version-3 readable-naming record retains primary `imageReference` and unique `buildReference`, separate loaded/skipped outcome, and verified local Docker image ID alongside snapshot, exact APK, architecture, apko version, artifact paths, and validated SPDX checksum. The sole apko composition/export/import uses the unique name; readable tagging follows verified import and uses the verified image ID, then checks the readable name's ID/platform. A readable version tag is mutable, not immutable build identity; concurrent builds are not an atomic multi-tag transaction. Skipped builds record intended names without touching Docker. The archive is retained when loading is attempted; a local image ID is not a registry digest. This is not an Explorer compatibility contract, and older result records/images are not migrated. Failures retain partial diagnostics/workspaces without a success record or validated-evidence success output; confirmed unique import followed by tag/inspect failure is partial local success with uncertain readable-tag effects, not rollback. Never record private keys, passwords, or tokens.

The local-only version-3 format remains unchanged. Publication success writes private version-4 `result.json`, preserving the local evidence while adding separate build/publication/signing/attestation outcomes, unique remote reference, captured pushed digest, immutable reference, and publication identity-verification status. Signing and attestation are `skipped` at this checkpoint. The mode-0600 `docker-published.tar` retains immutable pull/save content for verification. No successful record is written until every requested stage and finalization succeeds.

Publication-requested workflows return a typed `workflowFailure` carrying sanitized separate build/load/publication/verification/signing/attestation outcomes, workspace, and any captured digest. The CLI consumes this type instead of parsing error strings, and a separate mode-0600 version-4 `failure.json` retains partial outcomes when a workspace exists. A captured-but-unverified digest remains recorded after verification failure, but cannot authorize signing or imply publication success. Final record failure can follow confirmed publication; failure-record writing must not hide the original failure. Do not migrate old records or expand this private evidence format into an Explorer contract.

SQLite owns catalog queries and immutable Explorer SBOM evidence. Workspace paths alone are insufficient for immutable downloads: retain the document bytes or a durable content-addressed copy and its checksum. Deleting a temporary workspace must not silently destroy retained evidence.

Avoid competing mutable descriptions of the same build. Final workspace results describe execution; Explorer may index them and report transient local job progress.

## Publication boundary

The implemented publication checkpoint preserves the specification's Docker sequence, with a content-verification gate before any future signing:

```text
build/validate → Docker load → tag/inspect/push → pushed digest
                                                    │
                                      immutable pull/save/content check
                                                    │ future
                                              image signature
                                                    │ future
                                              SPDX attestation
```

Only `build` resolves `--registry` / `LUPETTO_REGISTRY` and `--repository` / `LUPETTO_REPOSITORY`, independently. An explicit flag overrides its matching environment input; explicitly empty flags are errors, not environment fallback. Empty/unset environment settings are absent. Both absent skips publication; exactly one present fails. Reject duplicates, invalid configuration, and publication with `--no-load` before tool checks, workspace creation, network activity, or building. `sbom` ignores the environment inputs and rejects explicit publication flags.

Registry is an unambiguous validated authority, not a URL. Repository is a nested lower-case OCI prefix without tags, digests, empty components, or `.`/`..`. Validate the complete eventual reference with pinned `github.com/distribution/reference`, rejecting normalization that changes the intended registry/prefix or lengths that exceed parser limits. No operator-supplied prefix is truncated or hashed.

Derive `HOST/PREFIX/<APK-component>:<local-readable-tag>-build-<workspace-suffix>` from the resolved actual APK, reusing exactly the local literal-or-SHA-256-fallback APK component and exact-version/OCI-architecture tag. A too-long combined tag gets a deterministic SHA-256 fallback for the entire combined tag. Keep unchanged exact APK identity in evidence. Tag from the verified Docker image ID, not a mutable readable alias, inspect for the same ID/platform, then push. Docker's existing credential store is the only authentication path; do not login, collect configuration, or pass credentials.

Require exactly one supported Docker 27.4 digest summary for the expected unique tag; absent, malformed, wrong-tag, conflicting, or repeated summaries fail closed. Construct `REPO@sha256:<digest>` from the pushed manifest/index digest, never the local Docker image ID. A successful push process alone does not verify publication identity.

Pull and save that immutable reference, then require its saved config digest to match the source OCI config and hash the actual uncompressed saved layers in manifest order against the source config's ordered `rootfs.diff_ids`. Validate platform and reject ambiguous/malformed archives. Comparing only saved config claims is not layer proof; remote manifest serialization may change without changing built-image content. Publication is `published` with identity verified only after these checks. Preserve a captured digest with unverified status on later failure.

Report confirmed local loading, publication, identity verification, signing, and attestation separately through the typed outcomes and records above. Tag/push/pull failure or cancellation may already have changed local/remote tags, published an image, or pulled content; no rollback is attempted and no complete-success summary is printed. Authentication-bearing tool diagnostics are suppressed by the separate safe adapter. Real Lupetto publication smoke evidence remains pending.

Signing and attestation are not implemented here. Their future operations must bind to the same verified immutable registry reference and attest the existing validated architecture document, not regenerated or supplemental index SPDX. A successful publication followed by failed signing would be published but not successfully signed; this is a future partial-success rule, not an implemented signing claim.

apko also supports direct publication, but adopting it would change the compatibility contract and remove the reason publishing rejects `--no-load`. Do not implement two publication paths without a concrete need. Generic placeholder examples are in the [README](../README.md#publish-the-same-built-image), explicitly not evidence of exercised remote publication.

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
