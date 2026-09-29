# Proposed architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Verification](verification.md)

This is a rebuild proposal, not recovered source structure. Go is the recommended language; no module, dependencies, or runtime defaults have been selected yet.

## Components

Treat `lupetto` and `lupetto-explorer` as separate applications. The CLI is independently useful; Explorer is an optional consumer, not a required part of the build engine. Whether they share a repository, Go module, release, or product identity remains open.

| Component | Responsibility |
| --- | --- |
| Catalog | Import snapshots, retain provenance, query package versions, resolve selectors. |
| Build implementation | Turn an exact request into configuration, resolved lock, image, SPDX, and validation outcome. |
| Publication/signing | Load/tag/push, obtain a registry digest, then invoke signing and attestation. |
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

Initially invoke pinned apko, Docker, and Cosign tools rather than embedding their internals. The choice of native versus containerized apko needs an exercised build before it is finalized.

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
                                         artifact/result record
```

Explorer invokes this CLI rather than implementing another resolver or builder. The SBOM command must reuse the same resolution/evidence logic; whether it requires image composition is an implementation decision to settle through apko behavior.

A selected top-level version does not pin its dependency closure. A snapshot does not preserve the referenced APK bytes. Do not promise historical rebuildability unless the required artifacts and toolchain inputs remain available.

## Artifact and data ownership

A build workspace retains the input configuration, resolved lock, generated SPDX, image artifact, diagnostics, and a machine-readable result. File names and result schema are deliberately not specified yet.

The result should identify the selected snapshot, exact package/version, target architecture, relevant tool versions, evidence identities, and outcomes of requested stages. Never record private keys, passwords, or tokens.

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
