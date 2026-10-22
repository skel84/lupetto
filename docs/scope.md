# Scope and behavior

[Documentation home](../README.md) · [Registry/signing guide](registry-signing.md) · [Decisions](decisions.md)

## Evidence boundary

The original operator-documentation request supplies the workflow targets below. Product-specific command and environment names here are adapted to Lupetto, not recovered historical spellings. The request is not executable proof. The lost source, tests, defaults, and database schema are unavailable; the overwritten checkout must not be used to fill those gaps.

Architecture and selection rules proposed for the rebuild are identified separately. The standalone CLI discovers exact versions in the live signed Wolfi index, composes local OCI images for exact package names or version-matched providers, validates apko-generated architecture SPDX APK identities against the resolved lock, and checks local tool availability. Default Docker loading and explicit `--no-load` extend the same pipeline; publication verifies the pushed immutable image's content before optional Cosign signing and SPDX attestation. The current source contract is described in the [operator guides](../README.md); observed local/registry interoperability and unexercised cases remain distinguished in [verification](verification.md). Production HTTPS/TUF/transparency-log verification is not established by local HTTP/offline checks. Persistent snapshot ingestion, historical catalog queries, Explorer, and runnable service recipes remain deferred.

## Local workflow to restore

1. Read the current signed Wolfi APKINDEX and discover matching packages. Persistent snapshot ingestion and catalog browsing are deferred.
2. Select an exact package/version directly or resolve a major selector to one.
3. Compose an OCI image locally using apko and retain its resolved dependency lock.
4. Generate SPDX evidence and validate its APK package contents against that lock.
5. Load the image into local Docker unless loading is explicitly disabled.
6. Optionally tag/push to a compatible OCI registry and obtain the pushed immutable digest.
7. Optionally sign that digest and publish the generated SPDX as a signed Cosign attestation of type `spdxjson`.

This is image composition from APK packages, not source compilation of those packages.

The [user-approved publication-first roadmap](decisions.md#publication-first-roadmap-user-approved) prioritizes registry publication, signing, and SPDX attestation using the existing live-index build path. Persistent catalog/history and Explorer remain compatibility targets, but neither blocks that workflow or the standalone CLI release. Per-build signed-index/lock/evidence retention remains required; an index archive alone is not an APK archive or a guarantee of historical rebuildability.

## CLI compatibility targets

The commands below are implemented. `build` loads into local Docker by default (`--no-load` skips it) and can optionally publish, sign, and attest, with or without loading. `sbom` composes a new image through the same exact-build pipeline and never loads, publishes, or signs. Build/SBOM `--json` prints the unchanged version-6 result record; discovery has its own kind `discover`, version-1 document. Angle-bracket terms must be replaced with actual values; [`--help`](../README.md#prerequisites-and-installation) is authoritative for flag spelling.

```text
lupetto discover <package-or-provider>
lupetto discover --json [<package-or-provider>]
lupetto status --products <file> [--registry <authority> --repository <prefix>] [--json]
lupetto build <package-or-provider> <dotted-numeric-selector> [--no-load] [--json] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]
lupetto build <package-or-provider> --apk-version <exact-apk-version> [--no-load] [--json] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]
lupetto sbom <package-or-provider> --apk-version <exact-apk-version> [--json]
```

An exact APK version includes the packaging revision, such as `-rN`. Selecting an upstream version alone does not distinguish its packaging revisions.

`status` compares tracked published images with the signed live index and the unsigned Wolfi security-fix feed; its separate `kind: status`, version-2 JSON document contains per-track facts and errors plus best-effort advisory severity that never changes state derivation. It is read-only and not a vulnerability scan. `inspect --json <registry-digest-reference>` reports the immutable installed package set through the same registry/cache boundary. Products-file tracking, exit semantics, and security limitations are defined in the [operator guide](../README.md#compare-published-images-with-wolfi).

Where behavior is specified:

| Topic | Owner |
| --- | --- |
| Image names, loading, retained evidence, version-6 records, `--json` | [Operator guide](../README.md) |
| Registry/signing inputs and precedence, publication and readback, Cosign, verification, partial outcomes | [Registry/signing guide](registry-signing.md) |
| Why each contract was chosen, and what it superseded | [Decisions](decisions.md) |

Output-directory flags, an Explorer compatibility contract, and runtime image recipes remain undecided. Two explicit, recorded image options exist: an optional OCI [entrypoint](../README.md#image-entrypoint) and an optional [CA certificate bundle](../README.md#ca-certificate-bundle); neither is a recipe, and neither is guessed from the package name. Failures and cancellation are nonzero, retain the workspace without a success record, and never roll back local or remote side effects.

### Numeric selection: implemented live-index rule

- Select against one identified snapshot and target architecture.
- Match leading dotted upstream version components within exact package names or matching-version providers; when distinct APKs tie at the chosen version, prefer the single APK named exactly as requested, and reject any other ambiguous selection.
- Choose the highest matching APK version using APK-compatible ordering, not lexical sorting or generic SemVer assumptions.
- Display and record the exact package/version before building.
- Reject conflicting selectors, ambiguous mappings, and missing matches. Never fall back to another major.

Both selector forms enter the same exact-build pipeline. A major selector may resolve differently after a snapshot changes; retain the resolution used for each build.

## Dashboard (Explorer) scope

The user-approved [registry-comparison dashboard](decisions.md#registry-comparison-dashboard-user-approved-2026-10-01) is the first Explorer target: compare images published to a registry with the latest signed-index versions, show known security fixes those images are missing, browse index packages, and build images from the UI. It is a separate `lupetto-explorer` program that integrates only through the CLI's JSON output and runs as one container without a database. Kubernetes and Tekton/Konflux compatibility is the long-term direction, not current scope.

Restoring package metadata, recipe history, snapshot provenance, durable SBOM downloads, and local Docker image availability remains in the full compatibility target. The specification also names Products and package series; the dashboard's products file defines tracked package/selector groupings and their two optional image options (entrypoint, CA bundle), not runtime recipes.

Local Docker availability is not registry availability. Missing security fixes are not a vulnerability scan, and signature status is not shown.

## Evidence distinctions

| Evidence | Meaning |
| --- | --- |
| Lupetto-generated SPDX | apko-derived package evidence validated against the resolved lock. |
| Registry-attested SPDX | That generated document signed as claims bound to an immutable image digest. |
| Explorer SQLite SBOM record | Retained local immutable evidence available for download. |
| Registry-vendor scanner SBOM | Separate vendor-generated evidence, when offered by that registry. |

These are not interchangeable or automatically synchronized. Signature validity does not establish SBOM completeness or absence of vulnerabilities.

## Non-goals and security boundary

Remote Konflux/Tekton execution (until a later checkpoint), policy enforcement, full vulnerability scanning (the dashboard reports only known fixed vulnerabilities from Wolfi's security feed), source-package builds, and production credential/key management are outside this local rebuild.

HTTP registry access is local-development only. Production use requires HTTPS, least-privilege registry credentials, and protected signing keys. Keyless/KMS interoperability and production key management are not established by upstream Cosign support. See the [operator security boundaries](registry-signing.md).

Signing without transparency-log evidence can authenticate the key and signed claims but does not provide public Rekor inclusion/auditability.
