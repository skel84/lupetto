# Implementation checklist

[Documentation home](../README.md) · [Decisions](decisions.md) · [Verification](verification.md)

This is the single implementation checklist. The standalone CLI, tool check, live signed-index discovery, generic local build, per-architecture SPDX/lock identity validation, default local Docker loading/explicit no-load, and registry publication are complete within the scoped verified path; Cosign signing and signed SPDX attestation are next, while persistent catalog ingestion remains deferred. Mark an item complete only after its observable behavior is verified; record the command/result or evidence reference beside it. Track blockers beside the affected item and design choices in the decision record, rather than creating a second status list.

The CLI and Explorer are separate workstreams. The CLI can ship after its implementation and release checks below; it does not wait for Explorer. Explorer remains part of the full compatibility scope, but its product/repository/module packaging is undecided.

**Approved priority:** registry publication is implemented and verified within the scope recorded below; next implement Cosign image signing and signed SPDX attestation, using the current live signed-index exact-build path. Persistent catalog/snapshot-history work is deferred and is not a prerequisite for those stages or the standalone CLI release. Per-build snapshot/lock/evidence retention remains mandatory; catalog and Explorer remain in full scope. See the [decision record](decisions.md#publication-first-roadmap-user-approved).

## CLI workstream

### 1. Prove an exact local build

- [x] Resolve the scoped first-build decisions: local Go/module identity, native apko 1.4.5, darwin/amd64 → linux/x86_64, pinned Wolfi repository/key, and minimal image configuration. `go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1` and `build nginx 1.30` both exited 0 using the signed index and apko 1.4.5; see [exact-build SPDX evidence](verification.md#exact-build-spdx-evidence). Public module identity, other hosts, and runtime recipes remain open.
- [x] Define workspace ownership, artifact retention, output names, and a scoped machine-readable local build result. The Valkey exact build retained signed index, lock, image, architecture/index SPDX, and `result.json` under a unique private user-cache workspace; independent inspection confirmed the record's selected identity and SPDX checksum. The record is not yet an Explorer compatibility contract; see [decisions](decisions.md#exact-build-spdx-evidence-decisions-current-milestone).
- [x] Establish the Go module and standalone `lupetto` entry point without Explorer dependencies. At bootstrap `go test ./...` passed, `go run ./cmd/lupetto --help` exited 0, and builds explicitly failed before implementation. The PostgreSQL 17 image-only path is separately verified below; broader CLI functionality remains pending.
- [x] Report missing apko/Docker and optional Cosign executables with OS-specific install guidance. `go run ./cmd/lupetto doctor` reported missing apko and exit 1 before installation, then all three found and exit 0 after `brew install apko`; `apko version` reported 1.4.5 on darwin/amd64. This checks `PATH`, not tool compatibility or the Docker daemon.
- [x] First-image slice: resolve `postgresql 17` and available `17.N` to an exact Wolfi `postgresql-17` revision and create a local OCI layout with apko 1.4.5. `go run ./cmd/lupetto build postgresql 17` selected `17.10-r1` and exited 0 on darwin/amd64; independent OCI-layer inspection found `postgresql-17` `17.10-r1` for `x86_64`. `17.1`, `17.2`, `17.3` each returned an explicit unavailable-version error (exit 1), while available `17.10` built successfully. This does not complete the generic catalog, validated SBOM, Docker-load, or full exact-build checklist items below.
- [x] Generalize image-only selection to signed APKINDEX exact `P` package names and matching-version `p` providers without package-specific aliases. On darwin/amd64 with apko 1.4.5, `go run ./cmd/lupetto build nginx 1.30`, `nginx 1.31`, `valkey 9.0`, and `valkey 9.1` all exited 0 with `nginx-stable@1.30.2-r0`, `nginx-mainline@1.31.6-r2`, `valkey-9.0@9.0.4-r0`, and `valkey-9.1@9.1.2-r1`; independent OCI-layer/lock inspection matched each selected actual APK, version, and architecture. `go run ./cmd/lupetto build postgresql 17` and `build nginx --apk-version 1.30.2-r0` also exited 0 after generalization. See [verification](verification.md#generic-image-only-selection-evidence). This does not complete catalog snapshot ingestion, generic runnable recipes, SPDX, or Docker loading.
- [x] Preserve exact APK revisions and reject unavailable revisions without substitution in the earlier image-only path. `go run ./cmd/lupetto build nginx --apk-version 1.30.2-r0` selected and built `nginx-stable@1.30.2-r0` (exit 0); `go run ./cmd/lupetto build postgresql --apk-version 13.14-r999` exited 1 with an explicit unavailable-version error instead of substituting another revision. Archival availability remains unverified; the later SPDX milestone is recorded separately below.
- [x] Compose local OCI images with apko configuration and a retained dependency lock and signed-index inputs. The earlier nginx 1.30/1.31 and Valkey 9.0/9.1 image-only builds in [verification](verification.md#generic-image-only-selection-evidence) exited 0; independent inspection checked the selected top-level lock entry, OCI layer digest, and installed APK identity. `apko.yaml`, `lock.json`, signed `APKINDEX.tar.gz`, key, and OCI layout were retained in each user-cache workspace. Later SPDX validation and Docker loading are recorded separately below.
- [x] Define and implement SPDX/lock consistency for complete Wolfi APK identity sets, target architecture, and apko's duplicate `distro`/installed `origin` purl kinds while excluding legitimate non-APK entries. `go test ./cmd/lupetto -run 'TestValidateSPDX|TestParseBuild|TestHelp' -count=1` passed, and independent inspection of the exact Valkey build found 20 locked x86_64 identities matching all 20 `distro` and 20 `origin` entries in its generated architecture SPDX; see [verification](verification.md#exact-build-spdx-evidence).
- [x] Implement `sbom <package-or-provider> --apk-version <exact-revision>` through the same signed-index selection, lock, image composition, and validation path. `go run ./cmd/lupetto sbom valkey --apk-version 9.1.2-r1` exited 0, retained a new OCI layout and SPDX, and reported the architecture document and SHA-256; a numeric selector is rejected before a build. See [verification](verification.md#exact-build-spdx-evidence).
- [x] Implement Docker loading and explicit no-load behavior. `go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1` exited 0 and loaded `lupetto/local:build-3176376060` with verified config/platform on the local Docker 27.4.0 containerd store. `build valkey --apk-version 9.1.2-r1 --no-load` and exact-version `sbom`, each with an unreachable `DOCKER_HOST`, exited 0 with skipped status and no Docker archives/image IDs. The source uses one apko build and post-validation archive export; see [local loading decisions](decisions.md#local-docker-loading-decisions-resolved-before-implementation) and [observed evidence](verification.md#local-docker-loading-evidence).
- [x] Handle cancellation and failures without reporting successful builds or validated evidence; retain useful, non-secret diagnostics. The focused local-load/CLI orchestration command in [verification](verification.md#local-docker-loading-evidence) passed with no-success stdout/record assertions across composition, validation, archive, load/inspect/save, and canceled/failing finalization; confirmed-load/result-record failures explicitly report partial success. A real build with an unreachable local `DOCKER_HOST` exited 1, retained its workspace/archive, and created no result record. No real daemon cancellation/rollback is claimed.
- [x] Exercise a real exact-version build and SBOM generation, inspect image contents, confirm lock/SPDX agreement **and Docker loading**. The loaded build and image-only no-load/SBOM runs in [local-load verification](verification.md#local-docker-loading-evidence) selected `valkey-9.1@9.1.2-r1`; independent inspection confirmed its installed x86_64 identity, all 20 lock/SPDX identities, checksums, version-2 loaded/skipped outcomes, and imported image config/platform. Verified on darwin/amd64 → linux/amd64 with apko 1.4.5 and Docker 27.4.0; real classic-store loading and other host-target pairs remain unexercised.
- [x] Show live build/SBOM stage and tool logs on stderr with an interactive ASCII spinner/elapsed time; preserve success-only stdout and current image naming. A real `build busybox-static 1` streamed apko and Docker load output and exited 0. PTY/plain/dumb/narrow-resized-terminal scenarios, focused race-enabled feedback tests, and `go test ./...` passed; independent lifecycle review found no remaining defect after the width fix. See [observed feedback evidence and limitations](verification.md#live-build-feedback-evidence). No persistent log artifact or percentage-completion contract was added.
- [x] Add primary `lupetto/<resolved-apk>:<exact-version>-<oci-architecture>` references while retaining unique build tags and reporting both in private version-3 results. Real `build busybox-static 1` and `build nginx 1.30` exited 0 and Docker inspection confirmed each readable/unique pair points to the same verified local image ID/platform. No-load/SBOM succeeded with an unreachable Docker endpoint, recorded intended names only, and left the loaded primary tag unchanged. Focused race-enabled naming/dual-tag/failure tests and `go test ./...` passed; independent contract/source review found no defect. See [readable-reference evidence and remaining limitations](verification.md#readable-local-image-reference-evidence). Existing images/records are not migrated; readable tags are mutable and concurrency/tag failure does not imply rollback.
- [x] List exact versions from the current signed Wolfi index for a requested package name or matching-version provider on the host architecture. `go run ./cmd/lupetto discover postgresql`, `discover nginx`, and `discover valkey` each exited 0 on darwin/amd64 and listed 50, 45, and 21 x86_64 entries respectively from verified APKINDEX SHA-256 `7cd29d236cabd62a2d629af43c935d9860effef8fdb934ee4d600fb6de3d49fd`; `discover no-such-lupetto-package` returned an explicit no-match error (exit 1). This is read-only live-index metadata, **not** buildability proof, imported snapshot queries, or Explorer browsing. See [verification](verification.md#live-signed-index-discovery-evidence).

**Completion:** an exact local build is usable independently of catalog conveniences, publication, and Explorer. Unvalidated evidence is never labeled validated.

### 2. Publish, sign, and attest (registry complete; signing next)

Take two coherent checkpoints: first registry configuration/tag/push and verified pushed-digest reporting; then Cosign image signing, signed SPDX attestation, and verification of both against that same digest. Resolve the [publication/signing decisions](decisions.md#before-publicationsigning) before each dependent change; leave unverified outcomes unchecked.

The external-binary authenticated loopback run, immutable-content inspection, corrected focused race-enabled gate, passing full `go test ./...`, `git diff --check`, CLI-help exit 0, and independent contract/source reviews are recorded in [registry publication evidence](verification.md#authenticated-registry-publication-evidence). These complete the scoped registry checkpoint. The upstream synthetic-image signature prerequisite is not Lupetto signing/attestation completion; those items remain unchecked.

- [x] Define image naming/tagging, repository-prefix validation, flag/environment precedence, and incomplete-configuration errors. The final focused race-enabled publication tests passed, and the real nested-prefix run used the resolved actual APK component and exact revision/build tag; see [publication evidence](verification.md#authenticated-registry-publication-evidence).
- [x] Implement generic registry/repository settings, including nested prefixes, using Docker credential-store authentication. A fresh isolated synthetic credential helper authenticated the external-binary nested-prefix run; the final focused and full test gates passed. See [publication evidence](verification.md#authenticated-registry-publication-evidence).
- [x] Reject publication with `--no-load` before publication side effects. The real publication arguments plus `--no-load`, with `PATH=/nonexistent`, exited 2 and emitted no success stdout; the final focused tests passed. See [pre-tool rejection evidence](verification.md#authenticated-registry-publication-evidence).
- [x] Implement Docker tag/push and capture the pushed immutable registry digest, not a local image ID. The real loopback run parsed the push summary and independently verified manifest/config/rootfs content at the same repository's immutable reference; the corrected digest-provenance regression and final gates passed. See [publication evidence](verification.md#authenticated-registry-publication-evidence).
- [ ] Select a supported Cosign version, signing-config format, and registry compatibility mode.
- [ ] Implement image signing followed by a signed `spdxjson` attestation of the validated document, both bound to the same pushed digest.
- [ ] Keep `COSIGN_PASSWORD` in the process environment and prevent secrets from entering arguments, logs, or retained evidence.
- [ ] Report build, publication, signing, and attestation outcomes separately, including partial success. The real anonymous push failure recorded completed build/loaded local image, failed publication, and skipped signing/attestation without success stdout or `result.json`; see [failure evidence](verification.md#authenticated-registry-publication-evidence). Lupetto signing/attestation outcomes remain unimplemented.
- [ ] Exercise real publication and verification of both signature and attestation, including wrong-key/digest and partial-failure cases.
- [ ] Exercise production-compatible verification separately from clearly labeled local HTTP/offline variants.

**Completion:** the built image and its signed evidence are verifiable in a compatible registry. Publication alone cannot be mistaken for completed signing and attestation.

### CLI release gate

- [ ] Run applicable selection, build, evidence, and publication scenarios from [verification](verification.md); record actual outcomes and unexercised cases.
- [x] Run `go test ./...` in the implemented CLI Go module: passed after registry publication, following the final focused race-enabled publication/progress command recorded in [verification](verification.md#authenticated-registry-publication-evidence). `git diff --check` passed and `go run ./cmd/lupetto --help` exited 0. This verifies code tests, not pending signing/attestation acceptance or unexercised host/store/concurrency scenarios.
- [ ] Verify CLI help and every documented command/flag against actual parsing and exercised behavior.
- [ ] Replace the root landing page with a verified CLI operator guide and create `docs/registry-signing.md`, with cross-links and no duplicated signing prose.
- [ ] Document prerequisites, live-index discovery, numeric/exact selection, workspace retention, architecture support, publication, signing, verification, and security/evidence limitations; label deferred catalog/Explorer workflows as unimplemented rather than inventing ingest/browse commands.
- [ ] Confirm standalone CLI installation and operation without Explorer; check documentation links and remove obsolete vendor-specific configuration claims.

**Completion:** the CLI is independently deliverable with the verified live-index build/publication/signing workflow and its applicable release checks. Persistent catalog/history and Explorer do not block this release. Preserve links to these rebuild records and clearly identify deferred workflows as unimplemented.

### 3. Persistent catalog and historical selection (deferred)

Resume when there is a concrete catalog/history or Explorer need. These items are retained full-scope work, not prerequisites for publication/signing or the standalone CLI release. Existing live-index numeric/exact selection already enters the same build pipeline; the pending selector tasks below concern persistent imported snapshots. Snapshot metadata does not preserve APK bytes.

- [ ] Resolve catalog decisions: SQLite driver/schema, snapshot identity, duplicate imports, database flags, and ingest/query command names.
- [ ] Implement snapshot ingestion, provenance retention, and package/version queries.
- [ ] Define package-family mappings and major semantics only where needed; use APK-compatible version ordering.
- [ ] Resolve major selectors deterministically within an identified snapshot and target architecture; display and retain the exact selection.
- [ ] Route exact and major selections into the same exact-build pipeline.
- [ ] Reject ambiguous mappings, conflicting selectors, missing matches, and unavailable APK bytes without fallback.
- [ ] Exercise revision ordering, architecture filtering, and retained build selections after a newer snapshot is imported.

**Completion:** operators can ingest/browse snapshots and use either selector form. No general Products framework is required merely to resolve versions.

## Explorer workstream

### 4. Add Explorer as an optional application

- [ ] Decide Explorer product/repository/module packaging without introducing a CLI dependency on Explorer.
- [ ] Define supported CLI request/result versions, artifact references, exit/error semantics, cancellation, and incompatible-version behavior.
- [ ] Choose the catalog access boundary and its ownership/versioning; keep private build state out of Explorer’s write path.
- [ ] Establish the separate Explorer entry point and UI package without imports of build, publication, or signing internals.
- [ ] Define database/listen settings, supported environment inputs, safe local HTTP controls, and policy for non-loopback access.
- [ ] Implement package/version pages, package metadata, snapshot provenance, and accurate local Docker image availability.
- [ ] Implement exact build requests through the configured CLI with explicit build enablement, bounded concurrency, cancellation, and defined restart behavior.
- [ ] Consume machine-readable CLI results for job outcomes; do not infer success from human-readable progress logs.
- [ ] Retain immutable SBOM evidence for downloads independently of disposable workspaces.
- [ ] Exercise browsing, a real exact build, progress/failure handling, and SBOM download; confirm read-only operation does not require signing credentials.

**Completion:** Explorer is a consumer of an explicitly compatible standalone CLI, not a second build engine. The CLI remains installable and runnable without it.

### 5. Complete browsing semantics

- [ ] Define Products and package-series presentation against traceable data sources.
- [ ] If Products carry runtime recipes, make those inputs explicit and retain them with build evidence; do not guess runnable defaults from an APK name.
- [ ] Identify and implement the recipe-history source and package association; represent missing history honestly.
- [ ] Verify that UI labels distinguish local images, generated evidence, and external registry state without claiming unsupported registry inventory or scans.

**Completion:** grouping and history reflect defined sources. Removing any original scope item requires an explicit scope decision, not an unchecked item silently disappearing.

### Explorer release gate

- [ ] Run Explorer-specific [verification scenarios](verification.md), including request safety, concurrency, cancellation, and durable downloads, against the actual browser surface.
- [ ] Exercise Explorer against a separately built supported CLI; reject incompatible contracts clearly.
- [ ] Check import/dependency boundaries and confirm Explorer cannot overwrite build outcomes through private state.
- [ ] Run `go test ./...` in each Go module involved in the Explorer release and record the result.
- [ ] Verify Explorer help and add operator instructions for its actual database/listen settings, build controls, CLI configuration, registry/signing options, and supported environment inputs.
- [ ] Check links, security warnings, and evidence distinctions; keep detailed registry/signing instructions in their dedicated guide.

**Completion:** the Explorer workflow and its compatibility requirements are documented from exercised behavior, without coupling the CLI’s release lifecycle to the UI.
