# Decisions and open questions

[Documentation home](../README.md) · [Implementation checklist](implementation-plan.md)

Status vocabulary:

- **Constraint:** supplied explicitly by the rebuild context or original specification.
- **Proposed:** recommended design, not confirmed implementation or user approval.
- **Open:** information is missing; decide or recover it before the dependent milestone.

## Constraints

| ID | Decision | Reason |
| --- | --- | --- |
| C1 | Exclude the overwritten checkout completely. | It is not the lost implementation and must not supply presumed behavior. |
| C2 | Restore the local apko-based image workflow, not remote Konflux execution. | This is the workflow described by the operator request. |
| C3 | Preserve exact APK selection and major-selector compatibility targets. | Both command forms are explicitly named; convenience selection must resolve to an exact build request. |
| C4 | Keep generic OCI publication and digest-bound signed SPDX attestations. | No registry vendor is required; unsigned attachment is not equivalent evidence. |
| C5 | Separate specification, proposals, and verified behavior. | No surviving implementation of the lost tool is available in this workspace. |
| C6 | Keep Explorer optional and structurally separate from the CLI. | The CLI must stand alone; whether Explorer is colocated or a separate product is intentionally undecided. |

## Scoped bootstrap decisions

- The first standalone CLI used Go 1.27.1 (the locally exercised toolchain), the temporary local module path `lupetto`, and the standard library only. The later generic selector adds a pinned apko 1.4.5 Go dependency for APK-compatible version comparison; the apko executable remains separately pinned for image builds. A public module identity and older supported Go versions remain undecided.
- At CLI bootstrap, exact-request parsing required an APK revision (`-rN`) but did not perform catalog lookup or image builds. The PostgreSQL 17 first-image path below subsequently resolved major/minor selectors; generic signed-index package/provider selection now supersedes its package restriction. Neither stage establishes a catalog or validated SBOM evidence.
- apko was absent at CLI bootstrap and was subsequently installed locally through Homebrew as 1.4.5 on macOS/amd64. Installing a tool does not pin the version for Lupetto builds or settle repository/keyring, image configuration, and build-evidence decisions.
- The `doctor` command checks executable discovery on `PATH` for apko and Docker (needed by the planned default image-build/load path), with Cosign optional for signing. Missing required tools produce a nonzero status; missing optional Cosign is reported without blocking. Advice is OS-specific, but the command never installs tools or asserts version/daemon compatibility. The first-image decision below pins apko for this build path.

## Scoped first-image decisions: PostgreSQL 17 (historical, superseded where noted)

- Initially mapped only `postgresql` to the exact Wolfi APK name `postgresql-17`. This package-only restriction is **superseded** by generic signed-index selection below. A missing match remains an error, not a substitute or archival fetch.
- Use the official Wolfi repository at `https://packages.wolfi.dev/os` and its [documented signing key](https://github.com/wolfi-dev/os#readme) at `https://packages.wolfi.dev/os/wolfi-signing.rsa.pub`; the key's observed SHA-256 is `f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc`. Verify the downloaded APKINDEX signature against that pinned key **before** major/minor selection or unavailable-version reporting, and retain the signed archive and its SHA-256. apko also uses the pinned key without signature bypass and locks the selected exact package/checksum before image creation; if the live repository changed in between, fail rather than substitute.
- Use native apko 1.4.5 with an `x86_64` target on the exercised darwin/amd64 host, emit a local OCI layout, and retain its input config, index, key, and apko dependency lock in a unique user-cache build workspace. No runnable PostgreSQL recipe, Docker load, publication, signing, or validated SBOM is implied. Other host/target pairs remain unverified.
- Probe evidence: `apko lock --arch x86_64 --output <lock> <config>` and `apko build --arch x86_64 --sbom=false --vcs=false --lockfile <lock> <config> <tag> <existing-output-directory>/` produced an OCI layout with `postgresql-17` version `17.10-r1` in `usr/lib/apk/db/installed`. At the observed amd64 index snapshot, `17.1`, `17.2`, and `17.3` were absent. These upstream apko probes preceded the separate Lupetto build recorded in [verification](verification.md#scoped-postgresql-17-image-evidence).

## Generic signed-index selection (implemented image-only slice)

- Resolve a requested name from signed APKINDEX records whose APK `P` name matches exactly **or** whose `p` provides field declares that name at the same exact APK version. Requested virtual providers may be namespaced (for example, `cmd:curl` resolves to the real `curl` APK); validate their segments but validate actual APK names separately. This avoids package-specific aliases: Wolfi advertises `postgresql` through versioned APKs, `nginx` through mainline/stable APKs, and `valkey` through both unversioned and versioned APKs. Do not guess from arbitrary name prefixes or silently choose between equally ranked providers.
- A dotted numeric selector (major, minor, or patch) matches the corresponding leading upstream numeric components; choose the highest matching APK version and packaging revision using apko's pinned APK-compatible version comparator, not lexical or generic SemVer sorting. `--apk-version` requires an exact revision. No match is an explicit unavailable-version error; equal-ranked distinct package/byte candidates are ambiguous errors. The signed index is retained and apko still locks the exact selected package and checksum before image composition.
- Keep the same image-only apko pipeline and user-cache workspace for every requested package. nginx and Valkey are real interoperability checks, not source-level package allowlists or product recipes. Numeric selector support does not imply full package-family mapping for every Wolfi naming convention, a generic catalog, or runnable images.

## Live signed-index discovery (scoped CLI command)

- `lupetto discover <package-or-provider>` reads the current Wolfi APKINDEX for the host architecture, verifies its signature using the same pinned key as `build`, and lists each complete record with exact APK `P` name and `V` version matching the requested name or its same-version `p` provider. Sort by APK-compatible version descending, then by actual package name for equal versions; show the signed archive SHA-256 and architecture. Reject missing/invalid names and report no matches explicitly. Do not invent package-family mappings, omit older matching entries, or silently resolve ambiguity between equal-version providers.
- Discovery reads metadata only: it does not invoke apko, create a build workspace, check downloadable APK bytes or dependencies, or claim every listed version is buildable. This is **not** snapshot ingestion, historical archive support, machine-readable Explorer output, or a second build pipeline. Exact builds still resolve and validate their own index, lock, and image independently.

## Exact-build SPDX evidence decisions (current milestone)

- Keep the existing minimal apko configuration, verified Wolfi index/key, exact selection, and single-architecture lock/build path. Use native apko 1.4.5 `build --sbom-path <workspace>/sbom --sbom-formats spdx` with the resolved lock; an explicit output path keeps apko 1.4.5's SPDX files in the private workspace rather than the invocation directory when writing an OCI layout. Retain `sbom-x86_64.spdx.json` as the validated architecture document and `sbom-index.spdx.json` as supplemental, **not independently lock-validated**, index evidence.
- Compare the lock's complete `contents.packages` set of `(name, version, architecture)` identities (reject missing fields/duplicates) with apko's SPDX 2.3 architecture document. apko 1.4.5 emits a `distro=wolfi` APK purl for every locked package and may also emit a separate `origin=...` APK purl derived from the installed APK database for each package. Require the `distro` set to equal the lock; if any `origin` entries are present, require that set to equal the lock too. Allow one entry per identity in each set, never treat the two kinds as duplicate packages. Require the matching `arch`, Wolfi namespace, and package name/version; reject missing/extra/changed identities and malformed or ambiguous APK references. Container image/layer, OS, and build-recipe entries are legitimate non-APK entries and are excluded from this comparison; they are not certified by it. This is lock consistency, not an independent audit of every installed dependency or proof that a discovered version is buildable.
- Continue using a unique mode-0700 user-cache workspace with mode-0600 inputs and retained image, lock, generated SPDX, and checksum. On success, write `result.json` with a versioned local evidence record (snapshot SHA-256, selected APK name/version, target architecture, apko version, artifact paths, validated SPDX SHA-256). Failures retain partial files and print the workspace but write no success result or claim validated evidence. This local record is not an Explorer compatibility protocol; that contract remains open.
- `lupetto sbom <package-or-provider> --apk-version <exact-revision>` uses the **same** signed-index resolution, lock, image composition, and validation as `build`, then reports the validated SPDX file. apko 1.4.5 generates the architecture document during composition, so no alternative metadata-only SBOM is claimed. Numeric selectors for `sbom`, Docker loading, and publication remain outside this slice.

## Local Docker loading decisions (resolved before implementation)

- `build` loads into the configured local Docker daemon by default; `--no-load` is a valueless, single-use build flag that skips Docker entirely. Keep `sbom` image-only through the same exact-build function; reject `sbom --no-load` rather than silently broadening that command's flags. No daemon start, Docker context changes, registry access, credentials, publication, or signing are part of this milestone.
- Initially exposed only `lupetto/local:build-<workspace-suffix>`, using the unique `image-<suffix>` workspace identifier. The user-approved readable-reference decision below supersedes that as the main displayed name, while retaining it for composition/import and per-build traceability. Registry naming remains a separate decision.
- After the existing OCI package check and lock/SPDX validation, export the already-built single image as a Docker-compatible archive with `go-containerregistry v0.22.1` (the version pinned by apko 1.4.5), then run `docker image load --input <workspace>/docker-image.tar`. This is format conversion, not another apko invocation or build path. Retain the archive for diagnostics. Inspect the exact reference after loading and require a valid local image ID and matching OS/architecture; do not parse human-readable load output as identity proof. If the inspected ID equals the source OCI config digest, identity is directly established. Otherwise save that exact imported reference with `docker image save --output <workspace>/docker-loaded.tar <reference>` and require the saved image's config digest to equal the source OCI config digest using the upstream archive reader. Retain the saved archive privately. Never accept an unrelated ID solely because loading returned zero.
- The initial assumption that Docker's inspected `.Id` always equals its config digest was **replaced after a real failed smoke**: Docker 27.4.0 with its containerd image store returned the imported Docker-schema-2 manifest digest as `.Id`, while `docker save` preserved exactly the source config and layer bytes. The fallback verifies content rather than guessing a backend-specific ID transformation. The result's local image ID is Docker's inspected identifier, not necessarily a config digest and never a registry publication identity.
- The first local-loading result used version 2 with one local image reference, separate Docker-load status (`loaded` or `skipped`), and the verified local image ID when loaded; readable naming below extends this to version 3 with both references. This ID is **not** a pushed registry digest. Write `result.json` and print successful image/SPDX/load outcomes only after every requested stage succeeds; no-load and SBOM success explicitly say loading was skipped. This is not an Explorer compatibility contract.
- Load/archive/inspect/saved-identity failures return nonzero, identify the failed stage, local reference, and retained workspace, and write no success record or validated-evidence success output. State that composition completed but loading was not confirmed. Cancellation propagates through external commands and archive writes; check cancellation before final success recording. Once a load has begun, failure/cancellation may leave an imported image/tag; do not claim rollback or automatically delete images. If loading was confirmed but result recording fails, report that partial local success explicitly.
- Preserve non-secret diagnostics; do not persist Docker configuration, environment values, or credentials. External command cancellation is best-effort: stopping the client cannot undo daemon work. Verification evidence and unexercised cases belong in [verification](verification.md#local-docker-loading-evidence) and the single checklist.

## Readable local image references (user-approved)

- Make `lupetto/<resolved-actual-apk-name>:<exact-apk-version>-<oci-architecture>` the primary operator-facing reference, for example `lupetto/busybox-static:1.38.0-r2-amd64`, `lupetto/postgresql-17:17.10-r1-amd64`, or `lupetto/nginx-stable:1.30.2-r0-amd64`. Derive it only after signed-index selection, from the actual APK identity rather than a requested provider/selector. Map `x86_64` to `amd64` and `aarch64` to `arm64` using the existing architecture mapping. Validate with the pinned upstream Docker reference parser.
- Preserve generic APK selection when an exact name/version cannot be represented directly in Docker syntax. Use deterministic, collision-resistant SHA-256 component fallbacks instead of lowercasing, replacing characters lossily, truncating, substituting an APK, or failing an otherwise supported selection. Reserve `apk-sha256-` for fallback repository components (names starting with that prefix also use the fallback); tag fallbacks start `_apk-sha256-`, which cannot be confused with ordinary APK versions beginning with an alphanumeric character. Retain/display the unchanged exact APK name/version in evidence. Ordinary Docker-compatible identities retain the literal requested format.
- Keep `lupetto/local:build-<workspace-suffix>` as the unique additional reference. Compose/export/load and verify through this reference first, reusing the existing pipeline and saved-config identity fallback. After confirmed import, use `docker image tag <verified-local-image-ID> <readable-reference>`, then inspect the readable reference and require that same local ID/platform. Tag from the verified ID, not from a mutable reference. Do not add another build, registry operation, image cleanup, or automatic migration/retagging of older images.
- The readable version tag is intentionally mutable: a later successful build can replace it because dependencies, snapshot, or inputs may differ at the same top-level APK revision. The unique build tag and retained workspace preserve the earlier build reference; neither tag is a registry publication digest. Concurrency does not create an atomic multi-tag transaction: identity verification can fail if another build replaces the readable tag during finalization, and a previously successful readable tag can move later.
- Add both references to a version-3 private local result: `imageReference` is the readable primary name and `buildReference` is the unique name; preserve selected APK, snapshot, artifacts, validation, and loaded/skipped fields. Print both in the final successful CLI summary and selection progress. No-load and `sbom` record/display the intended names but do not invoke Docker or claim either is loaded. This remains a private record, not an Explorer compatibility contract.
- A readable tag/inspect failure or cancellation returns nonzero, writes no success record, and reports that the unique image was imported/verified while readable tagging was not confirmed and may already have changed local tags. Preserve stage/reference/workspace diagnostics and do not attempt rollback. Final result-record failures after both tags are confirmed report partial local success as before. No schema migration or change to `sbom` loading semantics is part of this request.
- Verification belongs in [verification](verification.md#readable-local-image-reference-evidence) and the single checklist: test ordinary/provider/architecture derivation, safe fallback identities, tagging from verified ID, dual-reference outcomes, no-load/SBOM, and tag/inspect/cancellation failure reporting; exercise a real local build with both references.

## Live build feedback decisions

- `build` and `sbom` report human-oriented stage progress on stderr by default, alongside live apko lock/build and Docker load output. Keep stdout's final artifact/evidence/load summary success-only; feedback itself does not change the evidence schema (the later readable-naming request introduces version 3). Discovery/doctor are unchanged. No new verbosity flags or persistent log artifact are needed for this request.
- In an interactive stderr terminal, show an ASCII spinner with the active stage and elapsed time while work is underway; clear/redraw it around live log output and stop/clear it before final success or failure reporting. Redirected stderr and `TERM=dumb` receive plain logs with no animation or terminal control sequences. Do not invent percentage completion.
- Keep each animated frame within the terminal width, leaving the last column unused to avoid autowrap; re-read the width for resized terminals. Use a conservative 80-column fallback when dimensions cannot be obtained, and suppress frame content if the terminal is too narrow. Full static stage/tool logs may wrap normally, but animation must not create scrolling.
- Stages cover tool check, workspace, index/key fetch and verification, exact selection, apko lock/composition, installed-package/SPDX validation, Docker archive/load/identity verification (including the saved-config fallback), and final result recording. Report exact selection and local references before composition, but do not claim validated SPDX or successful loading before those requested stages finish. Keep no-load/SBOM semantics; local names and any readable-tag stages follow the user-approved naming decision above.
- Stream only the actual lock/build/load tool diagnostics. Tool-version output and Docker inspect identity JSON remain internal parsing inputs. Never print process environment, full command arguments, Docker configuration, or credentials; do not add credential-bearing operations. Keep captured tool failures available and preserve cancellation/partial-success semantics.
- Progress rendering is CLI-owned presentation, not another execution engine. Serialize log/spinner writes, stop and join renderer work on success/failure/cancellation, and ensure a rendering failure does not turn a successful build into a false tool failure. Verification must cover live delivery before tool completion, plain-output behavior, terminal animation/cleanup, and failure/cancellation; record observed results in [verification](verification.md#live-build-feedback-evidence).

## Publication-first roadmap (user-approved)

- Prioritize generic registry publication, then Cosign image signing and a signed `spdxjson` attestation of the already-validated architecture SPDX, both bound to the same pushed immutable registry digest.
- Use the existing live signed-index discovery/selection and single exact-build pipeline. Preserve signed-index/key, exact APK revision, dependency lock, validated SPDX, and per-build provenance; no persistent database is required for correctness of this workflow.
- Defer persistent snapshot ingestion, SQLite catalog queries, and historical selection until there is a concrete catalog/history or Explorer need. This changes implementation priority and the standalone CLI release gate, not the full compatibility scope: catalog and Explorer targets remain pending rather than being deleted or marked complete.
- Historical metadata can support comparisons, pinned snapshot selection, and browsing, but does not preserve APK bytes or guarantee historical rebuildability. Existing per-build evidence retention remains required.
- The immediate prerequisite decisions are registry naming/prefix validation, configuration precedence and incomplete-input errors, pushed-digest capture, separate stage/partial-success reporting, and supported Cosign signing/attestation/verification behavior. Local readable tags do not settle registry naming or establish immutable publication identity.
- Implement and verify coherent checkpoints: registry publication first, then signing/attestation and their verification. Preserve Docker credential-store authentication, publication rejection with `--no-load`, process-environment `COSIGN_PASSWORD`, and clearly separated production HTTPS/transparency-log requirements versus local-development exceptions.
- This priority approval does not authorize publication/signing against a live registry, use of existing credentials/keys, or remote infrastructure changes. Obtain authorization for the exact verification target/scope; prefer isolated local checks. The [implementation checklist](implementation-plan.md) remains the single progress record.

## Proposed design choices

| ID | Proposal | Tradeoff |
| --- | --- | --- |
| P1 | Go for the CLI and Explorer, with independently runnable binaries. | Repository/module/product packaging remains open; SQLite driver selection affects CGO and cross-compilation. |
| P2 | Invoke pinned upstream tools instead of embedding their internals. | Smaller integration surface; tool compatibility and output handling need verification. |
| P3 | CLI-owned exact-build pipeline; Explorer invokes a documented CLI contract. | Avoids divergent semantics and imports of build internals; independent releases need explicit compatibility handling. |
| P4 | Package/version browsing first; Products and recipe history later. | Gets the core usable earlier without removing full-scope requirements. |
| P5 | Server-rendered Explorer with SQLite and bounded local jobs. | Fewer moving parts; not a multi-user remote build service. |
| P6 | Start with one explicit target architecture. | Reduces digest/SBOM association complexity; this does not establish a historical host restriction. |
| P7 | Major selection uses the highest matching APK version in a specified snapshot. | Predictable within that snapshot; exact family mapping and version rules still need definition. |

## Open decisions by dependency

### Scoped exact-build choices versus later contracts

The current Go/module, apko invocation, host-target mapping, repository trust, and minimal image choices are recorded above. The exact-build evidence format, retention, and SBOM composition behavior are resolved for the implemented local path. Runnable service recipes, a stable external machine-readable Explorer result contract, older supported Go/tool versions, and historical snapshot rebuild guarantees remain undecided; none are implied by the local `result.json`.

### Before catalog selectors

- SQLite driver and schema; snapshot identity and duplicate-import semantics.
- Catalog ingest/query command names and database selection flags.
- Catalog-specific package-family mappings and snapshot semantics beyond the implemented signed-index name/provider match and APK-compatible comparator.
- Missing historical APK behavior: explicit failure versus an explicitly designed archival input source; never silently substitute another version.

### Before publication/signing

- Image naming/tagging and repository-prefix validation.
- Flag/environment precedence and errors for incomplete configuration.
- Supported Cosign release, signing-config format, and registry compatibility mode.
- Production versus local/offline verification settings, exercised separately.
- Meaning and reporting of partial publication/signing success.

### Before Explorer

- Colocated application or separate product; repository/module ownership and release packaging. This decision does not block the standalone CLI.
- CLI request/result compatibility contract, including format versions and unsupported-version behavior.
- Catalog access boundary: UI-independent shared package initially, or supported query/export interface; any shared schema needs explicit ownership/versioning.
- Database/listen flags, defaults, and supported environment equivalents.
- CLI result consumption, build cancellation/concurrency, and restart behavior.
- Safe local HTTP controls and policy for non-loopback access.
- Exact definition of Products and package series.
- Recipe-history source and association to packages; an APKINDEX alone must not be assumed to contain recipe history.
- Durable immutable SBOM storage/download behavior and local image identity matching.

## Recording a resolved decision

Update the applicable row or question with the chosen behavior, rationale, affected contracts, and verification evidence. Preserve a brief explanation when replacing a choice. Do not label a recommendation as accepted solely because implementation would be convenient.
