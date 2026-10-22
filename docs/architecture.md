# Architecture

[Documentation home](../README.md) · [Scope](scope.md) · [Registry/signing guide](registry-signing.md) · [Verification](verification.md)

This document describes ownership and execution boundaries: what lives where and which way dependencies point. It does not restate operator contracts; those are owned by the [operator guide](../README.md) (build, loading, evidence, records) and the [registry/signing guide](registry-signing.md) (publication, signing, verification), with rationale in [decisions](decisions.md). It records the current rebuild, not recovered historical source structure.

One local Go module contains the standalone CLI and optional Explorer backend. The CLI provides read-only signed-index discovery and registry/security comparison plus one exact-build pipeline with apko composition, SPDX/lock validation, optional Docker loading, direct registry publication, and Cosign signing/attestation. The embedded HTML dashboard and combined non-root container are implemented; persistent catalog ingestion and runnable service recipes remain deferred. See [container evidence](verification.md#combined-container-checkpoint-5) for the exercised deployment bounds.

## Components

`lupetto` and `lupetto-explorer` are separate programs in this repository and Go module, shipped together in the root `Containerfile` image with apko 1.4.5, Cosign v3.1.3, and CA certificates. The CLI is independently useful; Explorer is an optional consumer that integrates only through CLI JSON. The image runs as UID/GID 65532 with cache/evidence on `/var/cache/lupetto`, no Docker daemon/socket, and builds disabled by default. See the [dashboard decision](decisions.md#registry-comparison-dashboard-user-approved-2026-10-01) and [operator container guide](../README.md#combined-container).

| Component | Responsibility | Status |
| --- | --- | --- |
| Index access and selection | Fetch and verify the signed APKINDEX, parse it, resolve names/providers and selectors to one exact APK. | `internal/wolfi` |
| Build pipeline | Exact request → apko config and lock → OCI layout → installed-package, image-config, and SPDX validation → optional load, publication, signing, attestation → version-6 record. | `internal/build` |
| CLI | Parse arguments, render progress, print human or `--json` output, `doctor`, `discover`, `status`, `verify`. | `cmd/lupetto` |
| Signature status | Read-only Cosign signature and SPDX-attestation verification of one registry digest against a configured public key; lists Sigstore artifacts through the shared registry keychain/guard. | `internal/verify` |
| Status | Compare products-file tracks with the index, registry images (by annotation), and Wolfi security fixes; read-only. | `internal/status` |
| Catalog | Import snapshots, retain provenance, query versions, resolve selectors historically. | Deferred |
| Explorer | CLI-only adapter, cached comparison/discovery, safe HTTP routes and Go rendering seam, single supervised build with bounded live stderr and history. | Backend, embedded templates/static assets, and combined linux/amd64 container implemented (`cmd/lupetto-explorer`, `internal/explorer`, root `Containerfile`). |

Explorer uses `net/http`, `html/template`, embedded assets, and in-memory caches/jobs without a database or distributed job service. The optional historical catalog remains separate and deferred. The [UI rendering contract](../internal/explorer/web/CONTRACT.md) defines the implemented rendering seam.

## Source layout and dependency direction

```text
cmd/lupetto/          arguments, terminal progress (implements build.Reporter), human/--json output, doctor, discover
internal/build/       pipeline: apko, validation, Docker load, OCI publication, Cosign, records, workflow failures
internal/build/buildtest/   shared test fixtures (OCI layouts, in-process registry, signing helpers)
internal/wolfi/       signed index fetch/verification, parsing, selection, discovery ordering
internal/imageconfig/ optional image configuration (entrypoint): validation, annotation encoding, comparison
internal/registry/    shared registry settings/naming, Docker-config-only authentication, loopback HTTP guard, sanitized errors
internal/status/      strict products YAML, registry/index/security comparison, digest-keyed installed-package cache
internal/verify/      read-only signature/attestation status of one registry digest (`lupetto verify`)
internal/images/      read-only build history across builds roots and local Docker inventory (`lupetto images`)
internal/storage/     build-workspace roots: durable data root (LUPETTO_DATA_DIR/OS data dir) and legacy cache root
internal/wolfi/wolfitest/   shared test fixtures (signed index generation)
cmd/lupetto-explorer/ flags, signal-aware HTTP/CLI shutdown
internal/explorer/    own JSON decoding/view models, subprocess adapter, caches, job runner, HTTP safety/rendering seam
internal/explorer/web/ embedded dashboard templates/static assets, UI contract

cmd/lupetto ──▶ internal/build ──▶ internal/wolfi
      └──────────────────────────────▶ internal/wolfi
      └────────▶ internal/status ──▶ internal/wolfi, internal/registry
      └────────▶ internal/verify ──▶ internal/status, internal/registry
      └────────▶ internal/images ──▶ internal/build, internal/storage, internal/wolfi
                 internal/build ──▶ internal/registry, internal/storage, internal/imageconfig
                 internal/status ──▶ internal/imageconfig

cmd/lupetto-explorer ──▶ internal/explorer ──(argv + JSON)──▶ lupetto executable
```

- `internal/wolfi` imports nothing else from the module and owns the shared installed-APK-database parser; `internal/registry`, `internal/storage`, and `internal/imageconfig` likewise import no in-module packages. `internal/imageconfig` is the one rule for the optional image entrypoint that `internal/build` writes and `internal/status` compares. `internal/storage` is the one CLI rule for where build workspaces live: `internal/build` (the only writer) and `internal/images` (a reader) share it. Explorer keeps its own copy of that root resolution because it must not import CLI packages. `internal/build` and `internal/status` consume those shared boundaries independently, and status never imports the build pipeline.
- `cmd/lupetto` makes no apko, Docker, Cosign, or registry calls itself; `doctor` only checks `PATH`. The CLI owns status table/JSON presentation, not comparison logic.
- These packages are module-internal, not a public Go API. Explorer defines its own JSON decoding types and imports none of `internal/build`, `internal/wolfi`, `internal/status`, `internal/registry`, `internal/verify`, `internal/images`, `internal/products`, `internal/storage`, or `cmd/lupetto`; its `go list -deps` boundary test also verifies the CLI never imports Explorer.

## Application and dependency boundaries

These hold regardless of future packaging:

- The CLI and its packages never import Explorer code, templates, HTTP handlers, or UI configuration.
- Explorer owns its HTTP server, UI assets, presentation, and local job supervision. It must not import build, publication, or signing internals; it runs the configured CLI executable.
- Installing, running, testing, or releasing the CLI never requires Explorer. An Explorer release may require a compatible CLI version, not the reverse.

```text
Explorer UI → CLI adapter → lupetto executable → build/publish/sign
     └─────→ cached status/discovery documents from the CLI

lupetto has no dependency on Explorer
```

### Integration contracts

Explorer requires kind `status` version 2, kind `discover` version 1, and the version-6 build record printed by `--json` ([format](../README.md#results-records-and---json)); mismatches are explicit incompatible-CLI errors. Status severity fields are decoded as optional metadata; Explorer still owns its decoding types and never imports comparison packages. Stdout is bounded JSON, not progress. Builds pass argument arrays with `--json`, adding `--no-load` unless the build loads locally (local builds always; publish builds when the inventory reports Docker available), inherit operator settings only through environment, and never import comparison/build internals. One build runs at a time, with a 1 MiB stderr tail and 50 in-memory jobs. SIGTERM asks the signal-aware CLI to cancel; a five-second deadline kills an unresponsive CLI. Records preserve partial stage outcomes and cancellation has no rollback.

Catalog access is a separate decision. A colocated, UI-independent catalog package would not make its Go API or SQLite schema a supported external interface, and Explorer must not write build state through private tables. Before extracting Explorer, choose a versioned query/export contract or a deliberately supported shared library/schema, behind an Explorer-side adapter. Keep the local CLI execution model; do not add an HTTP build API, plugin system, or queue service in anticipation.

## External tools and network boundaries

| Boundary | Mechanism | Diagnostics |
| --- | --- | --- |
| Wolfi index and key | Go HTTPS client; key pinned by SHA-256; index signature verified before use. | Errors reported. |
| apko 1.4.5 | Subprocess with explicit argument arrays (`lock`, `build`). | Streamed live to stderr and captured on failure. |
| Docker (loading only) | Subprocess: `image load`, `image inspect`, `image save` (identity fallback), `image tag`. | `load` output streamed; inspect output parsed internally. |
| OCI registry | In-process go-containerregistry client: push from the OCI layout, digest-addressed readback; Docker-config-only keychain; loopback-only plain HTTP guard. | Sanitized to fixed classifications; registry bodies never surfaced. |
| Cosign v3.1.3 | Separate secret-safe subprocess adapter; inherits `COSIGN_PASSWORD` from the environment. `verify` runs only `cosign verify` / `verify-attestation` with a public key. | Signing: all output discarded; only a bounded version probe is parsed. `verify`: bounded stdout parsed; stderr only pattern-matched to classify outages, never surfaced. |

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

Each build owns a unique mode-0700 workspace under the durable data root's `lupetto/builds/` and its private records (listed in the [operator guide](../README.md#retained-evidence-and-failures); see the [durable build evidence decision](decisions.md#durable-build-evidence-location-user-approved-2026-10-02)). Workspaces from before 2026-10-02 remain in the legacy user-cache `lupetto/builds/` and are only read. The user cache holds only regenerable data (status's installed-package and severity caches). The workspace record is the single description of that execution; there is no second mutable status store. Readable local tags are mutable conveniences, not build identity; the unique build reference, local OCI manifest digest, and pushed immutable digest identify a build.

The deferred catalog/Explorer design owns SQLite catalog data and immutable downloaded SBOM evidence, not build execution state. Workspace paths alone are insufficient for durable Explorer downloads: retain document bytes or a content-addressed copy with its checksum, so deleting a workspace cannot silently destroy evidence Explorer claims to keep. Explorer may index workspace records and report transient job progress.

## Explorer boundary

Implemented defaults: `127.0.0.1:8080`, builds disabled unless explicitly enabled, no login, no persistence. Non-loopback use requires an operator-controlled authenticating network boundary. A TLS-terminating ingress must preserve the external Host; Explorer accepts either HTTP/HTTPS Origin on that exact authority and does not trust forwarded headers.

POST-only refresh/build/cancel require a per-process CSRF form token and same-origin browser headers. Every listener enforces an explicit Host allowlist against DNS rebinding, including wildcard listeners used by containers/port-forwarding; defaults permit only localhost/127.0.0.1/[::1], while ingress operators list external names with repeatable `--allowed-host`. `html/template` escaping, self-only CSP with frame rejection, nosniff/referrer controls, bounded forms/output, and server timeouts apply. Status refreshes single-flight at startup/interval/manual/after-build, retaining last-good facts separately from errors; cached discovery supports bounded package browsing. JSON read views expose the same models as the implemented templates. See [server evidence](verification.md#explorer-server-checkpoint-3), [dashboard UI evidence](verification.md#explorer-dashboard-ui-checkpoint-4), and [non-root combined-container evidence](verification.md#combined-container-checkpoint-5); none establishes authentication or production registry/signing interoperability.

## Upstream references

- [apko](https://github.com/chainguard-dev/apko)
- [go-containerregistry](https://github.com/google/go-containerregistry)
- [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Cosign attestation options](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
- [Cosign attestation verification](https://docs.sigstore.dev/cosign/verifying/attestation/)

Upstream documentation describes upstream tools, not Lupetto support. Pin and exercise versions before writing operator commands.
