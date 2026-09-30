# Proposed architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Registry/signing guide](registry-signing.md) · [Verification](verification.md)

This records current rebuild boundaries and proposed future components, not recovered historical source structure. A local Go module contains a standalone CLI, read-only discovery from the live signed Wolfi index, a generic OCI build path with apko-generated architecture SPDX/lock identity validation, default Docker loading, and optional registry publication, Cosign signing, and signed SPDX attestation. Persistent snapshot catalog ingestion, Explorer, and runnable service recipes remain deferred. Current source contracts are distinct from observed interoperability in the [verification record](verification.md); local HTTP/offline checks do not establish production HTTPS/TUF/transparency-log behavior.

The [approved roadmap](decisions.md#publication-first-roadmap-user-approved) extends the existing live signed-index exact-build path with publication, then image signing and signed SPDX attestation. Persistent catalog ingestion/querying is deferred and is not a dependency of publication/signing or the standalone CLI release. Retain per-build snapshot and lock evidence without introducing SQLite or Explorer into that path. The [operator guides](../README.md) describe usage, while this document describes ownership and execution boundaries.

## Components

Treat `lupetto` and `lupetto-explorer` as separate applications. The CLI is independently useful; Explorer is an optional consumer, not a required part of the build engine. Whether they share a repository, Go module, release, or product identity remains open.

| Component | Responsibility |
| --- | --- |
| Catalog | Import snapshots, retain provenance, query package versions, resolve selectors. |
| Build implementation | Turn an exact request into configuration, resolved lock, image, SPDX, and validation outcome. |
| Local loading/publication/signing | Export/load the validated image; tag/push from its verified ID; verify immutable registry content; sign and attest the same verified pushed digest. |
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

The exact-build path invokes native apko 1.4.5 with a signed Wolfi index/key and exact package lock, producing a local OCI layout and validated per-architecture SPDX. Read-only `discover` verifies the same signed index and pinned key without invoking apko. APK ordering uses the pinned apko Go dependency. Post-validation Docker archive export/load/identity checking consumes the same image; `--no-load` without publication/signing and `sbom` skip Docker. Publication uses the supported Docker 27.4 push-summary grammar and subsequent immutable pull/save/content verification. Requested signing checks exactly Cosign v3.1.3 before workspace/network/build/publication work. No containerized apko build or multi-platform path is implied.

Use explicit argument arrays, not shell interpolation. Propagate cancellation, capture safe local failures, and avoid logging secret-bearing environment values. Publication uses a separate secret-safe subprocess adapter, not the capturing/live local executor: discard auth-bearing tool diagnostics, sanitize failures, and feed push stdout only to a bounded summary parser retaining the validated digest. Docker inspect retains only a bounded, re-encoded identity object for internal checks. Do not retain unmatched lines, credential-helper output, command transcripts, environment, or Docker configuration. Structured artifact records hold outcomes, not tool transcripts.

Cosign remains optional until signing is requested. Its separate secret-safe adapter discards sign/attest stdout/stderr and returns sanitized failures; the bounded version probe retains only parsed version information. Inherit `COSIGN_PASSWORD` without copying it into arguments, logs, or evidence. Do not design a Lupetto key store or signing-config schema. Optional upstream configuration and HTTP/offline versus production-default policy are documented in the [registry/signing guide](registry-signing.md), not duplicated here.

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
                                    optional immutable image signature
                                                │
                                 optional validated SPDX attestation
                                                │
                                         artifact/result record
```

The implemented `sbom --apk-version` command invokes the same selector and image-composition function as `build` but remains image-only; apko writes the architecture SPDX during the build. It ignores publication/signing environment inputs and rejects all explicit publication/signing flags and `--no-load`. The index SPDX is supplemental and not lock-validated. Loading/publication consume the already-validated image and verified Docker ID, not another build/resolution path. Signing consumes verified immutable publication identity; attestation reuses the existing validated architecture document and rechecks its recorded checksum. Historical snapshot ingestion and Explorer integration remain separate decisions.

A selected top-level version does not pin its dependency closure. A snapshot does not preserve the referenced APK bytes. Do not promise historical rebuildability unless the required artifacts and toolchain inputs remain available.

## Artifact and data ownership

The unique, mode-0700 user-cache build workspace retains signed index/key, config, lock, OCI image, architecture/index SPDX, and a versioned local `result.json` only after all requested stages succeed. The version-3 readable-naming record retains primary `imageReference` and unique `buildReference`, separate loaded/skipped outcome, and verified local Docker image ID alongside snapshot, exact APK, architecture, apko version, artifact paths, and validated SPDX checksum. The sole apko composition/export/import uses the unique name; readable tagging follows verified import and uses the verified image ID, then checks the readable name's ID/platform. A readable version tag is mutable, not immutable build identity; concurrent builds are not an atomic multi-tag transaction. Skipped builds record intended names without touching Docker. The archive is retained when loading is attempted; a local image ID is not a registry digest. This is not an Explorer compatibility contract, and older result records/images are not migrated. Failures retain partial diagnostics/workspaces without a success record or validated-evidence success output; confirmed unique import followed by tag/inspect failure is partial local success with uncertain readable-tag effects, not rollback. Never record private keys, passwords, or tokens.

Local-only/SBOM version 3 remains unchanged. Publication-only success writes private mode-0600 version-4 `result.json`; signing-requested success uses version 5. Both preserve local evidence and separate build/load/publication/signing/attestation outcomes, unique remote reference, captured pushed digest, immutable reference, and publication identity-verification status. Signing/attestation are `skipped` when not requested; requested but unreached stages are `not-attempted`. The mode-0600 `docker-published.tar` retains immutable pull/save content for verification. No successful record is written until every requested stage and finalization succeeds.

Publication/signing workflows return a typed `workflowFailure` carrying sanitized separate build/load/publication/verification/signing/attestation outcomes, workspace, and any captured digest. The CLI consumes this type instead of parsing error strings, and a separate private mode-0600 `failure.json` retains partial outcomes when a workspace exists. A captured-but-unverified digest remains recorded after verification failure but cannot authorize signing or imply publication success. Signing failure preserves confirmed publication and prevents attestation; attestation failure preserves confirmed publication/signing. Final-record failure can follow confirmed publication/signing/attestation without complete workflow success. Failure-record writing must not hide the original failure. Do not migrate old records or expand this private format into an Explorer contract.

The deferred catalog/Explorer design assigns SQLite catalog queries and immutable downloaded SBOM evidence, not current build execution state. Workspace paths alone are insufficient for immutable Explorer downloads: retain document bytes or a durable content-addressed copy and its checksum. Deleting a workspace must not silently destroy evidence that Explorer claims to retain.

Avoid competing mutable descriptions of the same build. Final workspace results describe execution; Explorer may index them and report transient local job progress.

## Publication boundary

Publication preserves the specification's Docker sequence, with a content-verification gate before optional signing:

```text
build/validate → Docker load → tag/inspect/push → pushed digest
                                                    │
                                      immutable pull/save/content check
                                                    │ optional
                                              image signature
                                                    │ optional
                                              SPDX attestation
```

Only `build` resolves `--registry` / `LUPETTO_REGISTRY` and `--repository` / `LUPETTO_REPOSITORY`, independently. An explicit flag overrides its matching environment input; explicitly empty flags are errors, not environment fallback. Empty/unset environment settings are absent. Both absent skips publication; exactly one present fails. Reject duplicates, invalid configuration, and publication with `--no-load` before tool checks, workspace creation, network activity, or building. `sbom` ignores the environment inputs and rejects explicit publication flags.

Registry is an unambiguous validated authority, not a URL. Repository is a nested lower-case OCI prefix without tags, digests, empty components, or `.`/`..`. Validate the complete eventual reference with pinned `github.com/distribution/reference`, rejecting normalization that changes the intended registry/prefix or lengths that exceed parser limits. No operator-supplied prefix is truncated or hashed.

Derive `HOST/PREFIX/<APK-component>:<local-readable-tag>-build-<workspace-suffix>` from the resolved actual APK, reusing exactly the local literal-or-SHA-256-fallback APK component and exact-version/OCI-architecture tag. A too-long combined tag gets a deterministic SHA-256 fallback for the entire combined tag. Keep unchanged exact APK identity in evidence. Tag from the verified Docker image ID, not a mutable readable alias, inspect for the same ID/platform, then push. Docker's existing credential store is the only authentication path; do not login, collect configuration, or pass credentials.

Require exactly one supported Docker 27.4 digest summary for the expected unique tag; absent, malformed, wrong-tag, conflicting, or repeated summaries fail closed. Construct `REPO@sha256:<digest>` from the pushed manifest/index digest, never the local Docker image ID. A successful push process alone does not verify publication identity.

Pull and save that immutable reference, then require its saved config digest to match the source OCI config and hash the actual uncompressed saved layers in manifest order against the source config's ordered `rootfs.diff_ids`. Validate platform and reject ambiguous/malformed archives. Comparing only saved config claims is not layer proof; remote manifest serialization may change without changing built-image content. Publication is `published` with identity verified only after these checks. Preserve a captured digest with unverified status on later failure.

Report confirmed local loading, publication, identity verification, signing, and attestation separately through typed outcomes and records. Failure/cancellation may already have changed tags, published/pulled content, signatures, or attestations; there is no rollback or complete-success summary. Authentication-bearing publication/signing diagnostics are suppressed by separate safe adapters. Recorded observations and unexercised scenarios are in [verification](verification.md).

Signing and attestation require the same verified immutable registry reference. Attestation checksum-checks and uses the existing validated architecture document, not regenerated or supplemental index SPDX. A successful publication followed by failed signing remains published but not successfully signed; successful signing followed by failed attestation remains signed but not attested. No secret key/config paths, contents, passwords, or environment/tool transcripts are serialized into the result/failure evidence.

apko also supports direct publication, but adopting it would change the compatibility contract and remove the reason publishing rejects `--no-load`. Do not implement two publication paths without a concrete need. Configuration and explicitly labeled production/local templates live in the [registry/signing guide](registry-signing.md); templates are not observed production proof.

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
