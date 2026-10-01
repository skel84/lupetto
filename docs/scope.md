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

The commands below are implemented. `build` loads into local Docker by default (`--no-load` skips it) and can optionally publish, sign, and attest, with or without loading. `sbom` composes a new image through the same exact-build pipeline and never loads, publishes, or signs. `--json` prints the version-6 result record. Angle-bracket terms must be replaced with actual values; [`--help`](../README.md#prerequisites-and-installation) is authoritative for flag spelling.

```text
lupetto discover <package-or-provider>
lupetto build <package-or-provider> <dotted-numeric-selector> [--no-load] [--json] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]
lupetto build <package-or-provider> --apk-version <exact-apk-version> [--no-load] [--json] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]
lupetto sbom <package-or-provider> --apk-version <exact-apk-version> [--json]
```

An exact APK version includes the packaging revision, such as `-rN`. Selecting an upstream version alone does not distinguish its packaging revisions.

Where behavior is specified:

| Topic | Owner |
| --- | --- |
| Image names, loading, retained evidence, version-6 records, `--json` | [Operator guide](../README.md) |
| Registry/signing inputs and precedence, publication and readback, Cosign, verification, partial outcomes | [Registry/signing guide](registry-signing.md) |
| Why each contract was chosen, and what it superseded | [Decisions](decisions.md) |

Output-directory flags, an Explorer compatibility contract, and runtime image recipes remain undecided. Failures and cancellation are nonzero, retain the workspace without a success record, and never roll back local or remote side effects.

### Numeric selection: implemented live-index rule

- Select against one identified snapshot and target architecture.
- Match leading dotted upstream version components within exact package names or matching-version providers; reject ambiguous selections.
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

HTTP registry access is local-development only. Production use requires HTTPS, least-privilege registry credentials, and protected signing keys. Keyless/KMS interoperability and production key management are not established by upstream Cosign support. See the [operator security boundaries](registry-signing.md).

Signing without transparency-log evidence can authenticate the key and signed claims but does not provide public Rekor inclusion/auditability.
