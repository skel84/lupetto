# Scope and behavior

[Documentation home](../README.md) · [Decisions](decisions.md)

## Evidence boundary

The original operator-documentation request supplies the workflow targets below. Product-specific command and environment names here are adapted to Lupetto, not recovered historical spellings. The request is not executable proof. The lost source, tests, defaults, and database schema are unavailable; the overwritten checkout must not be used to fill those gaps.

Architecture and selection rules proposed for the rebuild are identified separately. The CLI discovers exact versions in the live signed Wolfi index, composes local OCI images for exact package names or version-matched providers, validates apko-generated architecture SPDX APK identities against the resolved lock, and checks local tool availability. Default build loading and explicit `--no-load` extend that same pipeline under the [resolved local-loading contract](decisions.md#local-docker-loading-decisions-resolved-before-implementation); `sbom` remains image-only. Observed interoperability and limitations are recorded in [verification](verification.md#local-docker-loading-evidence). Snapshot ingestion, publication, and signed evidence remain unimplemented.

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

The generic signed-index `discover` command, numeric-selector/exact-APK `build` forms, and exact-version `sbom` command below are implemented. `build` loads into local Docker by default; `--no-load` skips Docker. `sbom` composes a new image using the same exact-build pipeline, not a separate metadata-only path, and never loads Docker; it rejects `--no-load`. Angle-bracket terms must be replaced with actual values.

```text
lupetto discover <package-or-provider>
lupetto build <package-or-provider> <dotted-numeric-selector> [--no-load]
lupetto build <package-or-provider> --apk-version <exact-apk-version> [--no-load]
lupetto sbom <package> --apk-version <exact-apk-version>
```

An exact APK version includes the packaging revision, such as `-rN`. Selecting an upstream version alone does not distinguish its packaging revisions.

The specification names `--no-load`; registry publication rejects it in the compatibility workflow because publication uses the locally loaded Docker image. Publication is not implemented. Output-directory flags, public Explorer result contracts, and runtime image recipes remain undecided. Current builds use a retained local user-cache workspace, primary `lupetto/<resolved-apk>:<exact-apk-version>-<oci-architecture>` reference, and additional unique `lupetto/local:build-<workspace-suffix>` reference. The [readable naming decision](decisions.md#readable-local-image-references-user-approved) keeps compatible exact identities literal and uses deterministic SHA-256 component fallbacks for Docker-incompatible syntax/length. The readable tag can move after rebuilding; the version-3 private result retains both names and distinguishes loaded/skipped with a verified local ID only after successful loading/tagging. No-load/SBOM references are intended names, not proof of tag creation. Failures/cancellation are nonzero and retain the workspace without a success record; local image/tag side effects are not rolled back.

### Registry and signing

| Flag | Proposed Lupetto environment input |
| --- | --- |
| `--registry` | `LUPETTO_REGISTRY` |
| `--repository` | `LUPETTO_REPOSITORY` |
| `--cosign-key` | `LUPETTO_COSIGN_KEY` |
| `--cosign-signing-config` | `LUPETTO_COSIGN_SIGNING_CONFIG` |
| `--cosign-allow-http` | `LUPETTO_COSIGN_ALLOW_HTTP` |

`--repository` is an OCI repository prefix and supports nested paths such as `team/lupetto/images`. No registry vendor is required.

Docker registry authentication uses Docker’s credential store. `COSIGN_PASSWORD` is process environment input, never a command argument. Configuration precedence and partial-configuration errors must be decided before implementation.

### Major selection: proposed deterministic rule

- Select against one identified snapshot and target architecture.
- Match the requested major within an unambiguous package or explicitly mapped package family.
- Choose the highest matching APK version using APK-compatible ordering, not lexical sorting or generic SemVer assumptions.
- Display and record the exact package/version before building.
- Reject conflicting selectors, ambiguous mappings, and missing matches. Never fall back to another major.

Both selector forms enter the same exact-build pipeline. A major selector may resolve differently after a snapshot changes; retain the resolution used for each build.

## Explorer scope

Restore package/version browsing, local image availability, exact direct builds, generated SBOM downloads, package metadata, recipe history, and snapshot provenance.

The specification also names Products and package-series browsing. Their meanings must be defined before implementation: a grouping label and a runtime image recipe are different concepts. Deferring them during implementation does not remove them from the full compatibility target.

Proposed Explorer flags are `--enable-builds`, `--lupetto-binary`, and `--build-directory`, plus the registry/signing settings above. Database/listen flag spellings, defaults, and other environment equivalents are unknown. Do not invent historical values.

Local Docker availability is not registry availability. Do not imply that the UI displays registry contents, vulnerability findings, signature status, or remote jobs.

## Evidence distinctions

| Evidence | Meaning |
| --- | --- |
| Lupetto-generated SPDX | apko-derived package evidence validated against the resolved lock. |
| Registry-attested SPDX | That generated document signed as claims bound to an immutable image digest. |
| Explorer SQLite SBOM record | Retained local immutable evidence available for download. |
| Registry-vendor scanner SBOM | Separate vendor-generated evidence, when offered by that registry. |

These are not interchangeable or automatically synchronized. Signature validity does not establish SBOM completeness or absence of vulnerabilities.

## Non-goals and security boundary

Remote Konflux execution, policy enforcement, registry-discovery UI, vulnerability scanning, source-package builds, and production credential/key management are outside this local rebuild.

HTTP registry access is local-development only. Production use requires HTTPS, least-privilege registry credentials, and protected signing keys or an appropriately designed keyless workflow. Keyless support in upstream Cosign is not evidence that Lupetto supports it.

Signing without transparency-log evidence can authenticate the key and signed claims but does not provide public Rekor inclusion/auditability.
