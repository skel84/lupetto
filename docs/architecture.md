# Architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Registry/signing guide](registry-signing.md) · [Verification](verification.md)

This document describes ownership and execution boundaries: what lives where and which way dependencies point. It does not restate operator contracts; those are owned by the [operator guide](../README.md) (build, loading, evidence, records) and the [registry/signing guide](registry-signing.md) (publication, signing, verification), with rationale in [decisions](decisions.md). It records the current rebuild, not recovered historical source structure.

One local Go module contains the standalone CLI: read-only discovery from the live signed Wolfi index, one exact-build pipeline with apko composition and SPDX/lock validation, default Docker loading, and optional direct registry publication, Cosign signing, and SPDX attestation. Persistent catalog ingestion, Explorer, and runnable service recipes are deferred.

## Components

`lupetto` and `lupetto-explorer` (the registry-comparison dashboard) are separate programs in this repository and Go module, shipped together in one container image. The CLI is independently useful; Explorer is an optional consumer that integrates only through the CLI's JSON output. See the [dashboard decision](decisions.md#registry-comparison-dashboard-user-approved-2026-10-01).

| Component | Responsibility | Status |
| --- | --- | --- |
| Index access and selection | Fetch and verify the signed APKINDEX, parse it, resolve names/providers and selectors to one exact APK. | `internal/wolfi` |
| Build pipeline | Exact request → apko config and lock → OCI layout → installed-package and SPDX validation → optional load, publication, signing, attestation → version-6 record. | `internal/build` |
| CLI | Parse arguments, render progress, print human or `--json` output, `doctor`, `discover`. | `cmd/lupetto` |
| Status | Compare products-file tracks with the index, registry images (by annotation), and Wolfi security fixes; read-only. | Planned (`lupetto status`) |
| Catalog | Import snapshots, retain provenance, query versions, resolve selectors historically. | Deferred |
| Explorer | Dashboard: render `status`/`discover` JSON, launch `lupetto build` jobs. | Planned (`cmd/lupetto-explorer`) |

For Explorer, prefer `net/http`, server-rendered HTML, and small amounts of JavaScript over a separately deployed frontend, and SQLite for catalog queries—not a distributed job service. Keep boundaries explicit without a plugin framework or a service per component.

## Source layout and dependency direction

```text
cmd/lupetto/          arguments, terminal progress (implements build.Reporter), human/--json output, doctor, discover
internal/build/       pipeline: apko, validation, Docker load, OCI publication, Cosign, records, workflow failures
internal/build/buildtest/   shared test fixtures (OCI layouts, in-process registry, signing helpers)
internal/wolfi/       signed index fetch/verification, parsing, selection, discovery ordering
internal/wolfi/wolfitest/   shared test fixtures (signed index generation)

cmd/lupetto ──▶ internal/build ──▶ internal/wolfi
      └──────────────────────────────▶ internal/wolfi
```

- `internal/wolfi` imports nothing else from the module; `internal/build` imports only `internal/wolfi`. Neither imports terminal rendering: the pipeline reports progress through a small `Reporter` carried in the context, and the CLI supplies the renderer.
- `cmd/lupetto` makes no apko, Docker, Cosign, or registry calls itself; `doctor` only checks `PATH`.
- Both packages are module-internal. This is not a public Go API and does not decide Explorer packaging.

## Application and dependency boundaries

These hold regardless of future packaging:

- The CLI and its packages never import Explorer code, templates, HTTP handlers, or UI configuration.
- Explorer owns its HTTP server, UI assets, presentation, and local job supervision. It must not import build, publication, or signing internals; it runs the configured CLI executable.
- Installing, running, testing, or releasing the CLI never requires Explorer. An Explorer release may require a compatible CLI version, not the reverse.

```text
Explorer UI → CLI adapter → lupetto executable → build/publish/sign
     │
     └─────→ catalog/evidence access

lupetto has no dependency on Explorer
```

### Integration contracts

The CLI's machine-readable result is the version-6 record printed by `--json` and retained as `result.json`/`failure.json` ([format](../README.md#results-records-and---json)). Before Explorer launches builds, it still needs explicit rules for supported CLI/record versions, cancellation, concurrency, and incompatible-version handling. Never parse human progress or summary text.

Catalog access is a separate decision. A colocated, UI-independent catalog package would not make its Go API or SQLite schema a supported external interface, and Explorer must not write build state through private tables. Before extracting Explorer, choose a versioned query/export contract or a deliberately supported shared library/schema, behind an Explorer-side adapter. Keep the local CLI execution model; do not add an HTTP build API, plugin system, or queue service in anticipation.

## External tools and network boundaries

| Boundary | Mechanism | Diagnostics |
| --- | --- | --- |
| Wolfi index and key | Go HTTPS client; key pinned by SHA-256; index signature verified before use. | Errors reported. |
| apko 1.4.5 | Subprocess with explicit argument arrays (`lock`, `build`). | Streamed live to stderr and captured on failure. |
| Docker (loading only) | Subprocess: `image load`, `image inspect`, `image save` (identity fallback), `image tag`. | `load` output streamed; inspect output parsed internally. |
| OCI registry | In-process go-containerregistry client: push from the OCI layout, digest-addressed readback; Docker-config-only keychain; loopback-only plain HTTP guard. | Sanitized to fixed classifications; registry bodies never surfaced. |
| Cosign v3.1.3 | Separate secret-safe subprocess adapter; inherits `COSIGN_PASSWORD` from the environment. | All output discarded; only a bounded version probe is parsed. |

All subprocesses use argument arrays (no shell interpolation), propagate cancellation, and never receive secrets as arguments. Records never contain environment or credentials. Publication/signing workflows record only sanitized stage messages; local-only failure records may include captured apko or Docker load output (capped at 8 KiB), as the CLI already prints.

## One exact-build pipeline

```text
CLI selector or exact version → signed-index resolution → exact APK
                                        │
                           apko config + dependency lock
                                        │
                        OCI layout + architecture SPDX
                                        │
                  installed-package + SPDX/lock validation
                                        │
              optional Docker load (archive, import, identity, readable tag)
                                        │
          optional push from layout → readback by digest (manifest, tag, config, layers)
                                        │
             optional Cosign signature → optional SPDX attestation (same digest)
                                        │
                     version-6 result.json (or failure.json at any stage)
```

Selectors resolve to one exact APK before entering the pipeline; `sbom` uses the same path without load, publication, or signing. Loading and publication consume the already-validated layout—there is no second resolution or build. Publication does not depend on loading. Signing requires verified publication; attestation reuses the checksum-checked validated architecture SPDX.

A selected top-level version does not pin its dependency closure, and a retained index does not preserve APK bytes. Do not promise historical rebuildability unless those artifacts and toolchain inputs remain available.

## Artifact and data ownership

Each build owns a unique mode-0700 user-cache workspace and its private records (listed in the [operator guide](../README.md#retained-evidence-and-failures)). The workspace record is the single description of that execution; there is no second mutable status store. Readable local tags are mutable conveniences, not build identity; the unique build reference, local OCI manifest digest, and pushed immutable digest identify a build.

The deferred catalog/Explorer design owns SQLite catalog data and immutable downloaded SBOM evidence, not build execution state. Workspace paths alone are insufficient for durable Explorer downloads: retain document bytes or a content-addressed copy with its checksum, so deleting a workspace cannot silently destroy evidence Explorer claims to keep. Explorer may index workspace records and report transient job progress.

## Explorer boundary

Recommended initial deployment: local-only, build execution disabled unless explicitly enabled. Listen defaults and non-loopback access policy remain open decisions.

Build-enabled Explorer executes tools with the operator's credentials: protect build-triggering requests from cross-origin abuse, validate selections server-side, and escape package metadata as untrusted HTML. Start with bounded local execution rather than a queue; define cancellation, concurrency limits, and restart behavior before enabling builds.

## Upstream references

- [apko](https://github.com/chainguard-dev/apko)
- [go-containerregistry](https://github.com/google/go-containerregistry)
- [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Cosign attestation options](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
- [Cosign attestation verification](https://docs.sigstore.dev/cosign/verifying/attestation/)

Upstream documentation describes upstream tools, not Lupetto support. Pin and exercise versions before writing operator commands.
