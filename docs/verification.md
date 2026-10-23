# Verification criteria

[Documentation home](../README.md) · [Scope](scope.md) · [Implementation checklist](implementation-plan.md)

**Current status: live signed-index discovery, generic local OCI images with scoped architecture SPDX/lock identity validation, default local Docker loading with explicit no-load behavior, and authenticated loopback registry publication are verified within their recorded scopes.** The installed standalone CLI has now also completed real local HTTP/offline Cosign signing and signed SPDX attestation, with trusted-key verification, wrong-key/unrelated-digest rejection, and separate real signing/attestation partial-failure proofs; see [checkpoint 2 evidence](#local-cosign-signing-and-spdx-attestation-evidence). The final focused race and full Go test gates passed, completing signing acceptance within that local scope. Persistent snapshot ingestion and Explorer scenarios remain future acceptance criteria.

Use focused regression tests for uncertain behavior and real smoke runs for external-tool integration. Do not replace a real build or registry check with mocks that merely echo arguments.

Under the [approved publication-first roadmap](decisions.md#publication-first-roadmap-user-approved), registry publication, image signing, and signed SPDX attestation are implemented and verified within the recorded local scopes below. Persistent snapshot ingestion/history and Explorer checks remain deferred full-scope criteria, not prerequisites for that milestone or the standalone CLI release. Existing live-index selection, exact revision preservation, lock/SPDX validation, local loading, and per-build provenance checks still apply.

For this documentation-only reprioritization, relative links/heading anchors across the six required docs, checklist task/status preservation and milestone-order checks, `git diff --check`, and `go test ./...` passed (`ok lupetto/cmd/lupetto (cached)`). Independent read-only review found no concrete findings. Earlier source/untracked work was unchanged. No registry publication, signing, credentials, remote infrastructure changes, or new application behavior were exercised.

## Tool availability

On macOS/amd64, `go run ./cmd/lupetto doctor` initially reported missing apko (exit 1) with `brew install apko`, while Docker and Cosign were found. After `HOMEBREW_NO_AUTO_UPDATE=1 brew install apko`, `apko version` reported 1.4.5 and `go run ./cmd/lupetto doctor` reported all three present (exit 0). `docker --version` reported 27.4.0 and `cosign version` reported v3.1.3. These are executable checks, not build compatibility, Docker daemon availability, or signing verification.

## Publication/signing prerequisite and design tooling evidence

The preimplementation baseline `go test ./...` passed. Tool checks found Docker client/server 27.4.0 with a linux/x86_64 daemon, apko 1.4.5, and installed Cosign v3.1.3 (confirmed by the JSON `GitVersion` field).

Upstream `cosign generate-key-pair --output-key-prefix /temporary/throwaway` generated encrypted signing keys outside the repository; a separate wrong-key test pair was also generated there. These probes used inherited `COSIGN_PASSWORD`; no password value or key material is recorded here. `cosign signing-config create --out /temporary/local-signing-config.json` exited 0 and generated a Sigstore protobuf v0.2 configuration without services. The `/temporary/…` paths denote disposable locations outside the repository. Key/config generation does **not** establish sign/attest interoperability.

A disposable `registry:3` instance used synthetic bcrypt credentials and a fresh isolated `DOCKER_CONFIG` outside the repository, bound only to `127.0.0.1` on a high port. An anonymous `/v2/` request was rejected with HTTP 401. This establishes the local authentication prerequisite only, not publication, image signing, or SPDX attestation implementation or verification.

At the prerequisite stage, the required designer route was unavailable; explicit parent design was the fallback, and independent contract review was still underway. No designer approval is claimed. The final independent contract/source reviews completed with no concrete findings; see [publication evidence](#authenticated-registry-publication-evidence).

## Scoped PostgreSQL 17 image evidence

On darwin/amd64 targeting linux/amd64, with apko 1.4.5, `go run ./cmd/lupetto build postgresql 17` exited 0 after verifying the downloaded APKINDEX signature with the pinned Wolfi key. It selected `postgresql-17@17.10-r1` from APKINDEX SHA-256 `d296da0b216382d0e825cd1a71bebeaf0fb06e887f3e8b6b9ba15db544d5a27e`. The workspace was `<user cache>/lupetto/builds/postgresql-17-2725349457`, outside the repository. Independent inspection of the OCI manifest/layer, apko lock, and `usr/lib/apk/db/installed` found exactly `postgresql-17` `17.10-r1` on `x86_64`; the OCI layer digest matched its bytes. `go run ./cmd/lupetto build postgresql 17.10` and `go run ./cmd/lupetto build postgresql --apk-version 17.10-r1` also exited 0 with `17.10-r1` after signature verification. Each of `go run ./cmd/lupetto build postgresql 17.1`, `17.2`, and `17.3` exited 1 with an explicit unavailable-version error, without producing an image. This is not SBOM/lock consistency validation, historical version archival, Docker loading, or evidence of a runnable database image.

## Generic image-only selection evidence

On darwin/amd64 targeting linux/amd64, with native apko 1.4.5 and Go 1.27.1, these CLI commands exited 0 against the signed x86_64 APKINDEX SHA-256 `d296da0b216382d0e825cd1a71bebeaf0fb06e887f3e8b6b9ba15db544d5a27e`:

| Command (`go run ./cmd/lupetto …`) | Actual selected APK | Dependency lock entries |
| --- | --- | ---: |
| `build nginx 1.30` | `nginx-stable@1.30.2-r0` | 24 |
| `build nginx 1.31` | `nginx-mainline@1.31.6-r2` | 24 |
| `build valkey 9.0` | `valkey-9.0@9.0.4-r0` | 20 |
| `build valkey 9.1` | `valkey-9.1@9.1.2-r1` | 20 |

Independent Python inspection of each retained `lock.json`, `image/index.json`, manifest, gzipped OCI layer, and `usr/lib/apk/db/installed` confirmed **one** selected APK with the listed name/version and `x86_64` architecture, and recomputed the APKINDEX SHA-256 and OCI manifest/layer blob digests. The two nginx workspaces were `image-457571588` and `image-2441904520`; the two Valkey workspaces were `image-2740558045` and `image-753964998` under the user's cache `lupetto/builds` directory. The lock check concerns the selected APK, not a validated dependency/SBOM comparison. `go run ./cmd/lupetto build postgresql 17` still selected `postgresql-17@17.10-r1`, and `go run ./cmd/lupetto build nginx --apk-version 1.30.2-r0` selected `nginx-stable@1.30.2-r0`, both exit 0 through the same generic pipeline. Availability may change with the live index; neither Docker load nor runnable service behavior was tested.

`go test ./cmd/lupetto -run 'TestSelectPackage' -count=1` and `go test ./...` both passed after the ambiguity regression fix. `go run ./cmd/lupetto --help` exited 0 and listed generic package/provider syntax. `go run ./cmd/lupetto build nginx 1.99` exited 1 with an explicit unavailable-version error after signed-index verification. The latest post-fix `go run ./cmd/lupetto build nginx 1.31` again exited 0 with `nginx-mainline@1.31.6-r2`.

## Live signed-index discovery evidence

On darwin/amd64, `go run ./cmd/lupetto discover postgresql`, `go run ./cmd/lupetto discover nginx`, and `go run ./cmd/lupetto discover valkey` exited 0 and listed 50, 45, and 21 exact `x86_64` package/version records respectively from the current verified Wolfi APKINDEX SHA-256 `7cd29d236cabd62a2d629af43c935d9860effef8fdb934ee4d600fb6de3d49fd`. PostgreSQL entries ranged from `postgresql-13@13.14-r5` to `postgresql-18@18.6-r3`; nginx entries ranged from `nginx-stable@1.26.3-r43` to `nginx-mainline@1.31.6-r2`. These are metadata ranges in one live index, not proof every intervening release or dependency is available.
The oldest listed PostgreSQL/nginx revisions were separately exercised with `build` against a prior index SHA-256 `dfe656658059d5862709f8273977282be6830de65efe519dc6db1f7349ce637d`; both exited 0 with OCI layouts. Other listed older revisions were not all built.

`go run ./cmd/lupetto discover no-such-lupetto-package` reported no indexed versions (exit 1, no image). `go test ./cmd/lupetto -run 'TestDiscover|TestParseBuild|TestSelectPackage|TestVerifyAPKINDEX' -count=1` passed using synthetic index records to check revision ordering, architecture filtering, exact P/provider matching, duplicate providers, and invalid CLI arguments. Discovery fetches and verifies metadata without a build workspace or apko invocation; it does not check downloadable APK bytes, dependency resolution, runnable services, or historical snapshots.

After the discover and shared signing-key helper changes, `go test ./cmd/lupetto -run 'TestDiscover|TestParseBuild|TestSelectPackage|TestVerifyAPKINDEX|TestHelp' -count=1` and `go test ./...` passed. `go run ./cmd/lupetto --help` exited 0 and showed `discover`; `go run ./cmd/lupetto build postgresql 13` still exited 0 with `postgresql-13@13.14-r5` against the verified index SHA-256 above. `go run ./cmd/lupetto build postgresql --apk-version 13.14-r999` exited 1 with an explicit unavailable-version error, not an image.

After the namespaced-provider validation fix, `go run ./cmd/lupetto discover cmd:curl` listed the real `curl` APK’s exact revisions on x86_64 from signed index SHA-256 `91f8a3d020ce29ead8e65b85cd28d967c3374f59e198b1fdf4b1e48edc989d90`, and `go run ./cmd/lupetto build cmd:curl 8.22` exited 0 with `curl@8.22.0-r3` and an OCI layout. Focused tests reject empty/duplicate namespace separators and malformed *actual* APK names for both exact and numeric builds. Focused and full Go tests passed after this fix. This provider is an index-backed example, not a built-in package mapping.

## Exact-build SPDX evidence

On darwin/amd64 targeting linux/x86_64 with Go 1.27.1 and native apko 1.4.5, `go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1` exited 0 after signed-index verification (APKINDEX SHA-256 `91f8a3d020ce29ead8e65b85cd28d967c3374f59e198b1fdf4b1e48edc989d90`), resolving `valkey-9.1@9.1.2-r1`. Workspace `image-4244130841` under the user cache retained the image, lock, `sbom/sbom-x86_64.spdx.json`, supplemental `sbom/sbom-index.spdx.json`, and `result.json`; the architecture SPDX SHA-256 was `0123ce3bca17703a6741746ddb999265afaeded3a98441a77671d1effc61ceb8`. `go run ./cmd/lupetto sbom valkey --apk-version 9.1.2-r1` separately exited 0 using the same build path and a new workspace `image-3297163657`, with validated SPDX SHA-256 `eb6a9a7247a0fa9d2593dbb5bec956c75a861152f04942e66d3e995941d46137`. `go run ./cmd/lupetto build nginx 1.30` also exited 0 through the shared path, selecting `nginx-stable@1.30.2-r0` and generating validated architecture SPDX in `image-1419386885`.

Independent Python inspection of `image-3297163657` decoded `lock.json`, both kinds of APK purls in the architecture SPDX, `result.json`, OCI index/manifest/layer, and the layer's `usr/lib/apk/db/installed`. It found 20 unique locked x86_64 APK identities, exactly the same 20 `distro=wolfi` and 20 `origin=...` SPDX identities; the result's SPDX checksum matched the document bytes; the selected `valkey-9.1@9.1.2-r1` appeared in the installed database with `A:x86_64`; and the OCI manifest/layer blob digests matched their bytes. The index SPDX is retained but not independently lock-validated; the check does not certify all installed dependencies against the image. A failed local probe before accounting for apko's separate `origin` entries retained partial files in `image-3382270545` but had **no** `result.json` and reported no successful/validated evidence.

`go test ./cmd/lupetto -run 'TestValidateSPDX|TestSBOM|TestSelectPackage|TestParseBuild|TestHelp' -count=1` and `go test ./...` passed after the final changes (`ok lupetto/cmd/lupetto`). Synthetic cases cover missing, extra, changed, wrong-architecture, duplicate, and malformed APK identities, legitimate non-APK entries, and exact-version command parsing. `go run ./cmd/lupetto --help` exited 0 and listed both build selector forms and exact-version `sbom`; `git diff --check` passed. A check of relative links and heading anchors in the six existing project documents found no broken targets. No Docker load, publication, signing, or other host-target pair was exercised.

### SPDX purl percent-encoding regression (2026-10-01)

On darwin/amd64 → linux/amd64 with apko 1.4.5, `go run ./cmd/lupetto discover nginx` listed `nginx-stable@1.28.1-r1` in signed APKINDEX SHA-256 `4b17ba456b9e15aaa5bdb1f16ac165aec06b4bb5463aee67b82f4329a32b3f5f`. `go run ./cmd/lupetto sbom nginx --apk-version 1.28.1-r1 --json` then exited 0, retaining workspace `image-1315235331` and a version-6 succeeded record with `spdxValidated: true`. Independent Python inspection percent-decoded the purl components and confirmed exactly 22 unique lock identities equal all 22 `distro` and 22 `origin` SPDX identities, including `libstdc++@16.2.0-r1` encoded as `libstdc%2B%2B` in both purl kinds. The architecture SPDX SHA-256 matched the record: `313aa47a9cd7f8875de4f648e31b029d46000f535ec851df774facecbfe31cbd`.

`go test ./internal/build -run 'TestValidateSPDX|TestParseAPKRefPercentEncoding' -count=1` passed. Regressions cover encoded/literal plus signs, encoded version characters, namespace and qualifier decoding, one-time decoding, case-sensitive identities, malformed percent escapes, and mismatched decoded names; all existing set/architecture/qualifier checks remain enforced. `gofmt -w internal/build/spdx.go internal/build/spdx_test.go`, `go test ./...`, `go test -race ./...`, and `git diff --check` passed; the full non-race gate passed on retry after an initial 180-second timeout. This SBOM-only scenario did not load, publish, sign, or use registry credentials; supplemental index SPDX remains unvalidated.

## Local Docker loading evidence

On darwin/amd64 → linux/x86_64 with Go 1.27.1, native apko 1.4.5, and Docker client/server 27.4.0, `docker info --format '{{.ServerVersion}} {{.OSType}}/{{.Architecture}}'` reported `27.4.0 linux/x86_64`. The configured Docker endpoint was a local Unix socket; no daemon was started or Docker context changed.

The first `go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1` smoke returned exit 1 at identity inspection and retained workspace `image-3977557696` without `result.json`. The import archive preserved the OCI config bytes, but Docker's containerd image store reported the imported Docker-schema-2 manifest digest as `.Id`, not the config digest. Independent inspection with `docker image save` confirmed identical source/saved config bytes and layer digest. The [decision](decisions.md#local-docker-loading-decisions-resolved-before-implementation) was corrected before implementing a saved-config fallback; the failed import remains locally because rollback/deletion is intentionally not performed.

After that correction, these commands all exited 0 from the same verified x86_64 APKINDEX SHA-256 `cf95f2fd652a46a41ab4844ea56e2f7df7f24eff59b5bb362ee99aab5d5cfc17`, selecting `valkey-9.1@9.1.2-r1`:

| Command | Workspace under the user's cache `lupetto/builds/` | Outcome |
| --- | --- | --- |
| `go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1` | `image-3176376060` | Loaded `lupetto/local:build-3176376060`; inspected local ID `sha256:eadc76d84aff2587221c0b240255c34f7331fedb91b0a65522d6cabd991b4bec`, linux/amd64. |
| `env DOCKER_HOST=unix:///tmp/lupetto-verification-no-daemon.sock go run ./cmd/lupetto build valkey --apk-version 9.1.2-r1 --no-load` | `image-52537317` | Loading skipped; success despite unreachable Docker endpoint. |
| `env DOCKER_HOST=unix:///tmp/lupetto-verification-no-daemon.sock go run ./cmd/lupetto sbom valkey --apk-version 9.1.2-r1` | `image-1767638092` | Same image-only SBOM behavior; loading skipped. |

Independent Python inspection of all three workspaces recomputed index, OCI manifest/layer/config, and validated SPDX checksums; found the exact selected APK in `usr/lib/apk/db/installed`; and matched all 20 locked x86_64 identities with all 20 `distro=wolfi` and 20 `origin=...` SPDX identities. It checked version-2 result outcomes, no image IDs/archives for skipped loading, and mode-0600 import/saved archives and result for the loaded build. Its saved Docker config digest `sha256:9a8bc1caaf27e2d4a41e32a1d4cf4058dafb768d8f459d00b003e6d2f6932f2a` matched the source OCI config. A separate identity-only `docker image inspect` matched the recorded local ID/platform. The loaded build's validated SPDX SHA-256 was `517300f0b82bd9460174a373d680756be30719096d2858ccff6d723be9e07938`.

The same default exact build with `env DOCKER_HOST=unix:///tmp/lupetto-verification-no-daemon.sock` exited 1 at `Docker load`, reported the reference/stage/workspace and uncertain-side-effect warning, and printed no build/SPDX success output. Workspace `image-2093345319` retained OCI layout, generated SPDX, and `docker-image.tar`, but no `result.json` or saved-image fallback archive. This exercised real client failure reporting without changing the live daemon or using credentials.

Final focused regressions passed with `go test ./cmd/lupetto -run 'Test(ParseBuild|SBOM|RunRejectsInvalidBuild|HelpDescribes|Docker|ContextWriter|ResultCanceled|LocalCommand|BuildLocal|CheckImagePackage|CheckSelectedLock|ValidateSPDX)' -count=1` (`ok lupetto/cmd/lupetto`), followed by passing `go test ./...`. Synthetic signed-index/OCI/SPDX orchestration covers default load, no-load, unchanged SBOM, one apko composition, content-validation failures, archive/load/inspect/saved-config failures, and cancellation at selection/tool/archive/result stages. The fallback tests reject a changed config, missing saved tag, malformed archive, and canceled/failed save; matching config-ID fixtures skip the save. Failures require nonzero/no success stdout/no success record, and confirmed-load/result-record failures report partial success. These fixtures are not daemon interoperability proof; the real smoke above supplies that evidence for the containerd store only. Independent lifecycle review found no remaining blocker after the identity fix. `git diff --check` passed and all relative links/heading anchors in the six required documents were checked successfully; nothing was staged or committed.

`go run ./cmd/lupetto --help` exited 0 and documented default loading, both build forms with `--no-load`, image-only `sbom`, and no publication. Remaining limitations: other host/target pairs and a real classic Docker image-store import are unexercised; daemon-side cancellation cannot be rolled back, and no real daemon cancellation was attempted. These checks do not establish runnable service recipes, publication, signing, persistent ingestion, or an Explorer contract.

## Live build feedback evidence

`docker image inspect --format '{{json .RepoTags}} {{.Id}} {{.Os}}/{{.Architecture}}' lupetto/local:build-3533367003` confirmed the user's BusyBox image exists at that exact reference with ID `sha256:0b6726aa05ccf35c476df11d7982e055b41e6cddb6bbd2629d9407986b7310b0` and linux/amd64. At that feedback checkpoint, APK names were not Docker repository/tag substrings and no image rename was made; readable aliases are introduced by the later naming evidence below.

On darwin/amd64 with native apko 1.4.5 and local Docker 27.4.0, `go run ./cmd/lupetto build busybox-static 1` exited 0 and loaded `lupetto/local:build-280183234`, with local ID `sha256:8261b1bd92f8bb4d072f8322ae859937e51072d04e1b12a8effe21368d88e17b`. The run displayed stages for tools, signed index/key, selection, lock/composition, installed APK/SPDX validation, export/load/inspect, saved-config fallback, and result recording. Real apko package-install diagnostics and Docker's load line were streamed before the final success summary. It selected `busybox-static@1.38.0-r2` from APKINDEX SHA-256 `d3dd9079efb184a35256aa25ab8687161ecf57b45e3cd5eebb53f4ecea07daa2`; workspace `image-280183234` retained validated SPDX SHA-256 `aae3ada3be51dd9284eaba330468dfae47fb28c3061c49cf6788493d35e2bb91`.

Python PTY capture set stderr to a real terminal and stdout to a separate pipe, explicitly setting `TERM=xterm`. `go run ./cmd/lupetto build busybox-static 1 --no-load` exited 0 (workspace `image-3793575479`), emitted its first stderr output at 0.71 seconds during a 5.14-second run, and rendered 84 spinner draw/clear sequences alongside live apko logs. The final stderr ended with a cleared animation line; stdout alone held the successful validated-SPDX/artifact summary and skipped loading. `go run ./cmd/lupetto build busybox 1` in the same PTY deliberately exercised ambiguous selection: exit 1, no success stdout, a cleared spinner before the error. With `TERM=dumb`, that same failure had no animation escape sequences.

With stdout/stderr captured as separate ordinary pipes, `go run ./cmd/lupetto sbom busybox-static --apk-version 1.38.0-r2` exited 0 (workspace `image-432699722`), emitted live apko/stage logs on stderr with no escape characters or carriage returns, and kept validated evidence and skipped-load summary on stdout. Tool-version and inspect-identity parsing remain internal; no environment/credential/argument dump or persistent log file was added.

After the independent review found and prompted a fix for narrow-terminal wrapping, a real PTY run of `TERM=xterm go run ./cmd/lupetto build busybox-static 1 --no-load` started at 20 columns and resized to 30. It exited 0 (workspace `image-3655953555`), rendered 58 frames, capped frames at 19 and then 29 ASCII bytes, and cleared the spinner at completion. Full static logs may wrap; animated frames leave the last cell unused. Tiny-width behavior and unknown-size 80-column fallback are regression-tested rather than claimed as additional real terminal observations.

Final `go test -race ./cmd/lupetto -run 'Test(LiveCommand|CommandParsingOutput|CommandRendererFailure|Progress|CLIClosesProgress|BuildLocalLoadAndSkippedStageOrchestration|BuildLocalFailedStagesNeverReportSuccess|HelpDescribesCurrentCapabilities)' -count=1` passed, followed by passing `go test ./...`. Gated helper subprocesses prove live output arrives before process completion and that captured version/inspect inputs stay unchanged; tests cover nonfatal rendering errors, split control sequences, log/spinner serialization, no late writes, worker join on close/cancellation, final-output cleanup ordering, and stage/no-load/SBOM/failure orchestration. Independent source review found no remaining actionable defect after the narrow-width fix. No real daemon cancellation was attempted; output behavior on other operating systems remains unexercised. Build names, evidence schema, and the single build pipeline are unchanged.

`go run ./cmd/lupetto --help` exited 0 and described stderr diagnostics and the interactive ASCII spinner. `git diff --check` passed, relative links/heading anchors in all six required documents passed, and the Git index remained empty. Existing uncommitted work was preserved; nothing was staged, committed, pushed, or signed.

## Readable local image reference evidence

With native apko 1.4.5 and local Docker client/server 27.4.0 on darwin/amd64 → linux/amd64, the following commands exited 0 against signed x86_64 APKINDEX SHA-256 `878d91f9bf84bd92a529012b82d8dec5311df90fcecec678135835b8239d4826`:

| Command | Primary readable reference | Retained unique reference | Verified local image ID |
| --- | --- | --- | --- |
| `go run ./cmd/lupetto build busybox-static 1` | `lupetto/busybox-static:1.38.0-r2-amd64` | `lupetto/local:build-3992811795` | `sha256:c0436a4e891ddec04921948265035d5c76744f5e79cae2496cc88dba18443bd0` |
| `go run ./cmd/lupetto build nginx 1.30` | `lupetto/nginx-stable:1.30.2-r0-amd64` | `lupetto/local:build-2744714582` | `sha256:de0491eada27ce7298d222204563b79789d1721e8f2b39d03da68944c13e2ee4` |

`docker image inspect --format '{{json .RepoTags}} {{.Id}} {{.Os}}/{{.Architecture}}'` with all four exact references confirmed each readable/unique pair has the same ID and linux/amd64 platform and both tags are present. Selection progress and the final summary displayed both names; composition/export/import retained the unique name, followed by verified-ID tagging and readable-name inspection. No existing image was automatically migrated or renamed.

Independent Python inspection of workspaces `image-3992811795` and `image-2744714582` recomputed index/OCI/config/layer/SPDX checksums, checked the selected installed APK, and matched all 3 BusyBox and 24 nginx locked identities with both corresponding SPDX `distro` and `origin` sets. The version-3 records contained the primary `imageReference`, unique `buildReference`, loaded status, and the inspected local ID; mode-0600 results were retained. The import archive tagged only the unique reference; the saved Docker image's config digest matched the original OCI config. Validated SPDX SHA-256 values were `1e0630dea10947ec28c69d872f49ca6d567088ab331dadb672a79abf71aa968d` and `80db6363db05e63097e90c12ab99b94cc91e90bafc1367f1a03c1f5f9f37a963`, respectively.

`env DOCKER_HOST=unix:///tmp/lupetto-verification-no-daemon.sock go run ./cmd/lupetto build busybox-static 1 --no-load` and the same environment with `go run ./cmd/lupetto sbom busybox-static --apk-version 1.38.0-r2` both exited 0. Workspaces `image-2875388210` and `image-1464868907` retained version-3 intended references and skipped status, no Docker image IDs or archives, and matching lock/SPDX identities. The already-loaded readable BusyBox tag's ID was unchanged afterward. Printed names in skipped builds do not assert tag creation or point an existing tag to the new artifacts.

Final `go test -race ./cmd/lupetto -run 'TestReadableImageReference|TestBuildLocal|TestDocker|TestResultCanceledFinalization|TestSBOM|Test.*Progress' -count=1` and `go test ./...` passed (`ok lupetto/cmd/lupetto`). Naming tests cover literal BusyBox/PostgreSQL/nginx versions, resolved providers, amd64/arm64 mapping, reserved component namespaces, invalid syntax, normalized Docker repository length boundaries, tag length, and deterministic non-lossy fallback distinctions. Orchestration tests preserve one apko composition and assert tagging from the verified local ID, both references/results/summary, skipped behavior, tag/inspect/ID/platform/cancellation failures without success output/records, and partial local success on final record failure. The existing progress cleanup fixture was updated to expect the two new naming lines without weakening its renderer-join guards.

The bounded private runtime/result contract and final source received independent reviewer approval with no findings. The configured tools rejected the required `designer` route as unavailable (only scout/reviewer/security-reviewer/task/sonic were exposed, with no custom-model override); explicit parent design and the independent reviewer validation were used rather than claiming designer validation. Other architectures, real SHA-fallback package builds, concurrent replacement of readable tags, and real daemon-side tag/cancellation failures remain unexercised. The readable tag is mutable and local side effects are not rolled back; unique tags/workspaces remain the per-build references. Publication, signing, persistent catalog, service recipes, and Explorer remain outside this change.

`docker image ls --format '{{.Repository}}:{{.Tag}} {{.ID}}' lupetto/busybox-static` and the same command for `lupetto/nginx-stable` listed the readable tags with IDs `c0436a4e891d` and `de0491eada27`. `git diff --check` and relative documentation link/heading-anchor checks passed. The Git index remained empty; existing uncommitted work was preserved, nothing was staged or committed, and no artifacts were pushed or signed.

## Authenticated registry publication evidence

> **Historical (superseded mechanism).** This section and the two Cosign sections below record the earlier Docker tag/push/pull/save publication path and version 4/5 records, replaced on 2026-10-01 by [direct OCI publication](#direct-oci-publication-and-version-6-record-evidence). They remain valid observations of that earlier implementation.

A separately built executable, `go build -o <temporary>/lupetto ./cmd/lupetto`, exited 0. `<temporary>` denotes a disposable directory outside the repository. With a fresh `DOCKER_CONFIG` referring only to an isolated synthetic credential helper, and with no `COSIGN_PASSWORD` in the environment, the following external-binary command exited 0:

```text
<temporary>/lupetto build busybox-static 1 --registry 127.0.0.1:54355 --repository tests/lupetto-test-01c1b8dd6fc2/nested/images
```

The run used darwin/amd64 → linux/amd64, native apko 1.4.5, Docker client/server 27.4.0, and a synthetic-authenticated `registry:3` bound only to loopback over HTTP. It selected `busybox-static@1.38.0-r2` for `x86_64` from signed APKINDEX SHA-256 `fd15fdec22fb176cf494f49643bdbaeba5f8eec36f9260f5c8e7e9b7dd0da76a`. Workspace `image-1214665509`, under the user cache outside the repository, retained validated architecture SPDX SHA-256 `9413e7672063b7ac84bb44ea201a373a77ce66eb33c51af87876738dbb000bbe` and a version-4 result with publication `verified: true`.

The remote reference was `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/nested/images/busybox-static:1.38.0-r2-amd64-build-1214665509`. Its immutable reference was `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/nested/images/busybox-static@sha256:6d074e64afbface35554ec1e23fba3c84639435fb10409d4483592d48f668539`, obtained by parsing the Docker push summary and then proving the content at that immutable registry reference. That digest equaled the inspected local Docker manifest ID in this exercised store; equality is an observation, **not** use of the local ID as a substitute for a pushed digest.

Independent retrieval of the immutable manifest using synthetic authentication recomputed its SHA-256 and matched the pushed digest. The remote config digest matched the original OCI config. Retrieval of the compressed remote layers recomputed their blob hashes and actual ordered uncompressed hashes; those uncompressed hashes matched the original config's rootfs diffIDs. This independently establishes the remotely stored config/rootfs identity, not merely the presence of a tag or push-summary line.

The same publication arguments plus `--no-load`, with `PATH=/nonexistent`, exited 2 with empty stdout. This exercised rejection before external-tool lookup or publication side effects. Repeating the real BusyBox publication build with a fresh empty external Docker configuration, without existing credentials, exited 1 at push. Workspace `image-988594844` retained no `result.json` and produced no success stdout; its `failure.json` recorded build `completed`, load `loaded`, publication `failed`, signing/attestation `skipped`, stage `publication`, and the safe message `publication push failed`. Authentication diagnostics were not leaked. The loaded local image remains a partial side effect; no rollback is claimed.

Earlier gate attempts exposed two corrected test regressions: a publication fixture incorrectly required the pushed digest to differ from a local manifest ID, and an older progress test expected the pre-publication exact stdout. The publication regression now checks pushed-digest provenance, and the progress assertion reflects the current summary. Final `go test -race ./cmd/lupetto -run 'Test(Publication|ResolvePublication|ValidatePublication|Registry|RunPublication|BuildPublication|ExecutePublication|PushSummary|CLIClosesProgress)' -count=1` passed, followed by passing `go test ./...` and `git diff --check`. `go run ./cmd/lupetto --help` exited 0. Independent contract/source review through two lenses completed with no concrete findings. These gates complete the scoped registry checkpoint, not Lupetto signing or attestation.

Actual signature prerequisite verification on a synthetic image also succeeded using an upstream-generated no-service signing configuration. This is upstream Cosign interoperability evidence, not Lupetto signing or SPDX attestation implementation. Production HTTPS/transparency-log verification remains unexercised. Push-summary parsing intentionally supports a strict grammar; other Docker versions have not been verified. No secret values, credential configurations, keys, or runtime files were committed.

## Local Cosign signing and SPDX attestation evidence

Checkpoint 2 used the same isolated synthetic-authenticated HTTP `registry:3` at `127.0.0.1:54355`, with a fresh nested repository prefix, disposable encrypted keys and upstream-generated no-service signing config outside the repository, and an isolated `DOCKER_CONFIG`. The host/target was darwin/amd64 → linux/amd64; native apko was 1.4.5, Docker client/server 27.4.0, and upstream Cosign v3.1.3. This is an observed **Lupetto** interoperability run, not merely the earlier synthetic-image prerequisite.

The observed command forms below retain the actual target and prefix. `<temporary>` substitutes the disposable directory outside the checkout; it is not a literal path or a production instruction. Key/config contents and password values are deliberately omitted. Go installation and the installed absolute-binary help, doctor, and discovery commands ran in an environment **without `COSIGN_PASSWORD`** and each exited 0. Only the actual signing build below inherited `COSIGN_PASSWORD`; it also exited 0:

```text
env GOBIN=<temporary>/bin go install ./cmd/lupetto
<temporary>/bin/lupetto --help
<temporary>/bin/lupetto doctor
<temporary>/bin/lupetto discover busybox-static
<temporary>/bin/lupetto build busybox-static 1 --registry 127.0.0.1:54355 --repository tests/lupetto-test-01c1b8dd6fc2/signed/nested/images --cosign-key <temporary>/throwaway.key --cosign-signing-config <temporary>/local-signing-config.json --cosign-allow-http
```

The last command selected `busybox-static@1.38.0-r2` for `x86_64` from verified APKINDEX SHA-256 `550f367b5eaaac0532ac767106d8223e68781494461d2513c3e7ee8d57d0cb91`. Workspace `<user cache>/lupetto/builds/image-974928037` retained validated architecture SPDX SHA-256 `a3087fbd0bbfe83b4a225cacca0b629a20eac8d8a5dc1d7291314482007b838c` and a private version-5 `result.json`. It recorded build `completed`, Docker load `loaded`, publication `published` with `verified: true`, signing `signed`, and attestation `attested`. Its unique published tag was `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static:1.38.0-r2-amd64-build-974928037`.

Both actual Cosign argument audits used exactly this same immutable reference:

```text
127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static@sha256:5b1c28b46aca9d18fd9d744f74052d37681ac03e67692359763fa913188e574e
```

The audit recorded only the nonsecret boolean `passwordPresent: true` and confirmed no password argument; it did not record the password. The Docker wrapper temporarily replaced the freshly built readable alias `lupetto/busybox-static:1.38.0-r2-amd64` with an unrelated synthetic image during remote tagging, then restored it. The published config/source-content validation still succeeded, exercising publication from the verified local ID rather than the mutable alias. Both wrappers **delegated to actual Docker/Cosign binaries**; they were not argument-echo mocks. This establishes the observed alias-replacement case, not an atomic multi-tag or general concurrency guarantee.

With `IMMUTABLE` set to the exact reference above and `PUBLIC_KEY` set to the separately trusted throwaway public key outside the checkout, both real verification commands exited 0:

```bash
cosign verify --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog --type spdxjson "$IMMUTABLE"
```

Independent inspection checked the verified signature claims and decoded attestation statement, requiring the exact subject repository and pushed digest. The statement's `predicateType` was `https://spdx.dev/Document`; its predicate was semantically equal as JSON to the retained validated architecture SPDX. The document checksum matched the result record, and all three locked APK identities agreed with both the SPDX `distro=wolfi` purl set and the installed `origin` purl set. This is neither validation of the supplemental index SPDX nor a vulnerability/completeness/runtime-readiness certification.

Repeating the same two verification forms with the wrong public key rejected both (exit 1 each). A real unrelated synthetic image was pushed into the **same exact repository** at `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static@sha256:38863a056169f921360a99605ba980374bb663e60dd730129bef6039ae1a78ac`, deliberately without a signature or attestation there. With the trusted public key and that unrelated reference, real `cosign verify` exited 10 and `cosign verify-attestation --type spdxjson` exited 1. Thus the negative digest check used an existing image in the intended repository, not a missing-image lookup.

The negative command forms were as follows, with `WRONG_PUBLIC_KEY` denoting the separate wrong public key and `UNRELATED` set to the exact existing unrelated reference above. Exit codes were 1, 1, 10, and 1 respectively:

```bash
cosign verify --key "$WRONG_PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
cosign verify-attestation --key "$WRONG_PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog --type spdxjson "$IMMUTABLE"
cosign verify --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog "$UNRELATED"
cosign verify-attestation --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog --type spdxjson "$UNRELATED"
```

Additional real installed-binary compatibility checks used an unreachable `DOCKER_HOST`. `build busybox-static --apk-version 1.38.0-r2 --no-load` exited 0 and retained workspace `image-350811122`; `sbom busybox-static --apk-version 1.38.0-r2` exited 0 and retained workspace `image-1088045541`. Both retained version-3 results with loading `skipped` and no Docker image IDs or Docker archives. The SBOM run additionally ignored all five deliberately invalid publication/signing environment settings: `LUPETTO_REGISTRY`, `LUPETTO_REPOSITORY`, `LUPETTO_COSIGN_KEY`, `LUPETTO_COSIGN_SIGNING_CONFIG`, and `LUPETTO_COSIGN_ALLOW_HTTP`. This preserves image-only SBOM behavior rather than silently enabling publication or signing.

With `PATH=/nonexistent`, three actual upfront rejection checks each exited 2 with empty stdout: `sbom` with explicit `--cosign-allow-http=false`, `build` with a signing key but no publication target, and a loopback publication/signing build without explicit HTTP consent. These checks establish argument/configuration rejection before external-tool lookup, not tool invocation or registry side effects.

### Real signing and attestation partial failures

Two additional runs repeated the exact installed-binary build command above against the same isolated prefix. The signing-failure run supplied a deliberately incorrect throwaway-key password **only through inherited `COSIGN_PASSWORD`**, with its value omitted here. Actual upstream Cosign attempted signing; Lupetto exited 1 with empty stdout and no `result.json`. Workspace `image-4099220242` retained private version-5 `failure.json`: stage `signing`, build `completed`, load `loaded`, publication `published` with `verified: true`, signing `failed`, attestation `not-attempted`, `sideEffectsPossible: true`, and sanitized error `image signing failed`. Its published immutable reference was `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static@sha256:15e310db2cbb8afc7ea7cda09e6d0e92ebd94d9a56f685f67dc5f7099294d9a2`.

The attestation-failure run used an external wrapper delegating to **real Cosign**, changing only the inherited password for the `attest` invocation. Real image signing used the correct inherited password and succeeded; actual upstream attestation then failed with the deliberately wrong throwaway password. This was controlled environment injection, not a fake success/error or argument-echo mock. Lupetto exited 1 with empty stdout and no `result.json`. Workspace `image-3072750206` retained private version-5 `failure.json`: stage `attestation`, build `completed`, load `loaded`, publication `published` with `verified: true`, signing `signed`, attestation `failed`, `sideEffectsPossible: true`, and sanitized error `SPDX attestation failed`.

With `PARTIAL_IMMUTABLE` set to `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static@sha256:12e1d904ebda6ab73f80b3d1780dd53c8aa1de253cd859d88a4ce69714862fa0`, these actual verification commands exited 0 and 1 respectively:

```bash
cosign verify --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog "$PARTIAL_IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --allow-http-registry --insecure-ignore-tlog --type spdxjson "$PARTIAL_IMMUTABLE"
```

This independently establishes the persisted valid image signature and rejection of completed attestation for that partial run. Captured output and both failure records were checked against the actual registry/key password values and incorrect-password canaries; none appeared, and upstream password/error diagnostics were not exposed. Failed clients can leave remote/local side effects: these observations do not establish rollback or rule out every possible post-upload failure.

The parent additionally checked signing/publication success and failure runtime JSON, captured CLI output, and the nonsecret argument audit against all actual throwaway key/registry passwords and encrypted private-key contents; none appeared. Retained JSON omitted key/config paths. Results, failure records, and Docker archives were mode 0600; build workspaces were mode 0700. The owned disposable registry was stopped successfully and its `--rm` container removed; synthetic credentials/helper/config and both throwaway keypairs were removed outside the checkout. Nonsecret logs, the initial user-work backup, and cache build workspaces were retained. No image/tag rollback or deletion and no Git push were performed.

Earlier gate attempts exposed a strict-boolean test false positive: its substring assertion matched part of the fixed error text rather than a leaked input value. The assertion was corrected to require the exact sanitized constant `LUPETTO_COSIGN_ALLOW_HTTP must be true or false`; production boolean parsing behavior was unchanged. Final `go test -race ./cmd/lupetto -run 'Test(Signing|ResolveSigning|ValidateSigning|BuildSigning|ExecuteSigning|Cosign|SignAndAttest|Publication|BuildPublication|CLIClosesProgress)' -count=1` passed, followed by passing `go test ./...` and `git diff --check`.

Source and regression coverage in `cmd/lupetto/signing.go`, `signing_options_test.go`, `signing_test.go`, and `build_signing_test.go` checks independent flag/environment precedence, strict environment booleans, literal-loopback HTTP consent, invalid configuration rejection before external boundaries, exact Cosign v3.1.3 preflight, inherited password handling with discarded diagnostics, and signing/attesting the same verified canonical pushed digest using the existing validated SPDX. Tests also cover one composition, private version-5 success/failure evidence, cancellation and typed partial outcomes, and disabled signing for local/publication-only/no-load/SBOM paths. Parser/help coverage and standalone installation evidence complement these source checks; the real external-tool proofs above remain distinct from synthetic regression fixtures.

Independent signing security/lifecycle source review through two lenses completed with no findings. `gopls` was unavailable to the parent; the passing compiler/test gates are recorded above, not substituted with a claimed language-server check. This verification update does not change the [single checklist](implementation-plan.md#cli-workstream). Production command templates and documentation links are not additional executed production verification.

After the latest source changes, the final release gates `go test ./... -count=1`, `go test -race ./... -count=1`, and `git diff --check` all passed. Relative links and heading anchors across all seven required/operator documentation files passed, as did `bash -n` for all 18 Bash-fenced example blocks; the latter checks syntax only, not production execution. The parent reviewed the exact staged 18 source/test/documentation files for scope and content: no actual throwaway credentials, passwords, encrypted private-key material, or key/config/runtime artifact files were present, and the index matched working-tree bytes at that check. Final independent review through two lenses found no code, scope, or security defects; its sole finding was a stale operator-guide local-acceptance phrase being corrected separately. These are observed release checks, not a claim of a final commit hash or executed production templates.

Production HTTPS, TUF/default-service interaction, and Rekor/transparency-log verification remain **unexercised**, not authorized by this local proof. The explicitly selected upstream-generated config had no services, and verification intentionally used the local-only transparency-log exception. No production credentials/keys or targets were used, and no secret values, credentials, key/config files, or runtime evidence files were committed.

## Direct OCI publication and version-6 record evidence

Observed 2026-10-01 on darwin/amd64 → linux/amd64 with Go 1.27.1, native apko 1.4.5, Docker client/server 27.4.0 (containerd store, used only for scenario C), and Cosign v3.1.3. The binary was built from commit `b64e6aa` with `go build -o <temporary>/lupetto ./cmd/lupetto`; the same scenarios had also passed against the earlier commits `10defc8` and `1671d04`. The target was a disposable `registry:3` bound only to `127.0.0.1` over HTTP, with htpasswd authentication using a freshly generated synthetic password. Throwaway Cosign keys and an upstream no-service signing config were generated outside the repository. Passwords reached processes only through files and the process environment, never command arguments. `<temporary>` and `$REG` stand for the disposable binary directory and `127.0.0.1:<port>`. All runs selected `busybox-static@1.38.0-r2` (x86_64) from signed APKINDEX SHA-256 `c1a5e80a38c1bb10b0ee92bda2c063f8b036d2e59bbb5400f8367bd0eb2c2663`.

| Scenario | Command (plus environment) | Exit | Observed record |
| --- | --- | --- | --- |
| A. Publish, no Docker | `build busybox-static 1 --no-load --json --registry $REG --repository tests/final2/publish`, `DOCKER_HOST` unreachable | 0 | v6 `succeeded`; load `skipped`; publication `published`, `verified: true`; digest `sha256:0d2b1262…7939` equal to `evidence.imageDigest`. |
| B. Publish + sign + attest, no Docker | as A plus `--cosign-key`, `--cosign-signing-config`, `--cosign-allow-http`; `COSIGN_PASSWORD` exported | 0 | publication `published`/verified; signing `signed`; attestation `attested`; digest `sha256:b396849c…5cef`. |
| C. Load + publish | `build busybox-static 1 --registry $REG --repository tests/final2/loaded` | 0 | Human summary: Docker loaded with readable and build references, published, immutable `…@sha256:c1ae15f5…fe3d`. |
| D. No credentials | as A with an empty `DOCKER_CONFIG` | 1 | v6 `failed`; `failure.stage` `publication`; error `publication push failed (HTTP 401)`; no digest; `result.json` absent; `failure.json` mode 0600 and byte-identical to stdout. |
| E. SBOM | `sbom busybox-static --apk-version 1.38.0-r2 --json`, `DOCKER_HOST` unreachable | 0 | v6 `command: sbom`; all optional stages `skipped`. |
| F. Credential helper | as A with `DOCKER_CONFIG` containing only `{"credsStore":"lupettoe2e"}`; a synthetic `docker-credential-lupettoe2e` on `PATH` returned the registry credentials and wrote a random canary to stderr | 0 | publication `published`/verified (scenario D shows anonymous access fails), so the helper's credentials were used; the canary appeared in neither Lupetto stdout nor stderr. |

For A, B, E, and F, `--json` stdout was byte-identical to the workspace `result.json` (mode 0600). Progress showed the four publication stages; scenario A/B/F workspaces contained no Docker archives, confirming that Docker was not used.

Independent checks:

- An authenticated `curl` (credentials from a mode-0600 netrc file) fetched scenario A's manifest by digest. Its SHA-256 equaled the recorded digest, and its bytes equaled both the retained `published-manifest.json` (mode 0600) and the local OCI layout's manifest blob, proving the manifest was pushed unchanged.
- `cosign verify` and `cosign verify-attestation --type spdxjson`, both with `--allow-http-registry --insecure-ignore-tlog`, against B's immutable reference: trusted key exit 0 and 0; wrong key exit 1 and 1. The decoded attestation had `predicateType` `https://spdx.dev/Document`, a predicate equal as JSON to the validated architecture SPDX, and a subject digest equal to the pushed digest.
- None of the outputs, records, or workspace JSON files contained the registry password, the Cosign password, or the helper canary.

Gates on the final tree: `gofmt -l cmd internal` empty; `go vet ./...` passed; `go test -count=1 ./...` and `go test -race -count=1 ./...` passed (`ok` for `cmd/lupetto`, `internal/build`, `internal/wolfi`). Hermetic tests use an in-process OCI registry for tampering (manifest, media type, tag body, config, layer), a layout replaced after validation (refused before any network request), the loopback HTTP guard and token-realm requests, Docker-config-only authentication (Podman auth ignored), credential helpers in a re-executed subprocess with captured stderr, sanitization (including uppercase registry-supplied canary codes), cancellation, `--no-load` publication and signing, and version-6/`--json` records for every failure stage. Independent final review found no blockers; its three findings (bind the pushed manifest to the validated digest, and two documentation precision fixes) were applied.

Limitations:

- A plain `docker pull` of the pushed reference was not exercised: the Docker Desktop daemon runs in a VM and cannot reach a registry bound to the host's loopback interface.
- `127.0.0.2` listener tests are skipped on macOS, which cannot bind that address; injected-dialer tests cover the HTTP fallback for that address instead.
- Production HTTPS/TUF/Rekor remains unexercised, as do non-loopback registries, other hosts and architectures, and other registry implementations.
- During an earlier intermediate run (before the final password rotation), the synthetic registry and Cosign passwords briefly appeared in local `htpasswd`, `curl`, and `env` process arguments in the test harness itself, not in Lupetto. Those disposable values were rotated before the final run, and the harness was corrected to use stdin, a netrc file, and shell `export`.

One `go test -race ./...` run during package extraction hung for 10 minutes in the pre-existing fake-`cosign` exec test and was not reproduced: an immediate rerun, 20 targeted race iterations, and four later full race runs all passed.

## Image annotations and discovery JSON (checkpoint 1)

Observed 2026-10-01 on darwin/amd64 → linux/amd64 with Go 1.27.1 and native apko 1.4.5. An exact staged checkpoint-1 tree was exported with `git checkout-index --all --prefix=<temporary-tree>/`, excluding the concurrently developed checkpoint-2 files, and compiled with `go build -o <temporary>/lupetto-cp1 ./cmd/lupetto`. No remote registry or existing credentials were used: a disposable `registry:3` was started with `docker run --rm -d --name <owned-name> -p 127.0.0.1:54985:5000 registry:3`, and `DOCKER_CONFIG` pointed to a new directory containing only `{}`. `DOCKER_HOST` was an unreachable local socket.

These actual commands exited 0; `SOURCE_DATE_EPOCH=1` was inherited deliberately to exercise replacement of a conflicting reproducible-build epoch:

```bash
SOURCE_DATE_EPOCH=1 <temporary>/lupetto-cp1 build busybox-static \
  --apk-version 1.37.0-r56 --no-load --json \
  --registry 127.0.0.1:54985 --repository tests/status/images
SOURCE_DATE_EPOCH=1 <temporary>/lupetto-cp1 sbom busybox-static \
  --apk-version 1.37.0-r56 --json
<temporary>/lupetto-cp1 discover --json cmd:curl
<temporary>/lupetto-cp1 discover --json
```

The build retained workspace `image-2154979337`, selected `busybox-static@1.37.0-r56`, and recorded APKINDEX SHA-256 `4ef1cfe0f53a73cf245e0cfbadb53252b004f8f0f74ae858ec0666a8feef6887`. Independent Python inspection of the OCI layout's manifest blob found exactly these identity annotations:

```json
{
  "lupetto.apk.architecture": "x86_64",
  "lupetto.apk.name": "busybox-static",
  "lupetto.apk.version": "1.37.0-r56",
  "lupetto.index.sha256": "4ef1cfe0f53a73cf245e0cfbadb53252b004f8f0f74ae858ec0666a8feef6887",
  "org.opencontainers.image.created": "2026-10-01T14:59:31Z",
  "org.opencontainers.image.version": "1.37.0-r56"
}
```

The manifest SHA-256 was `sha256:51ff7537f57c5386d302626fecfa04363b38effd38c9abe59db12f69b8c4c111`. An independent HTTP GET by digest to the isolated registry found bytes equal to the local manifest and mode-0600 `published-manifest.json`; the version-6 result reported publication `published` / `verified: true` and loading `skipped`. The SBOM run retained `image-2125561630`, with all six manifest annotations, created `2026-10-01T15:00:08Z`, and manifest digest `sha256:6e9fc91d2c5afa685a3d93aee6d85c5d7ef40213d4de67d63608c2751017f68b`; loading/publication/signing remained skipped. This confirms actual build time rather than inherited epoch or APK build time, without post-build manifest mutation.

Both discovery documents decoded as `kind: discover`, `version: 1`, architecture `x86_64`, and index SHA-256 `d964ce3f46ed46ff422e0e542ebffc601a58ef8bc8c96ebd05c708e3c6c949e8`. Named `cmd:curl` returned 45 exact entries with descriptions; all-packages discovery returned 15,494 unique, alphabetically ordered actual APK names with latest versions and descriptions, omitting the requested `package` field. Both stdout documents ended in a newline. Index hashes differ between operations because the live repository changed; no snapshot identity across separate invocations is promised.

Scoped annotation/epoch/installed-reader/discovery regressions passed. Independent source review found no correctness defect; its newline-consistency suggestion was applied and tested. On the exact staged source tree exported above, `go test ./...` and `go test -race ./...` both passed (`cmd/lupetto`, `internal/build`, `internal/wolfi`; fixture packages have no tests). The same owned registry is retained temporarily for checkpoint 2, then removed; this proof does not exercise production authentication/TLS, other architectures, historical rebuildability, or any dashboard.

## Registry status (checkpoint 2)

Observed 2026-10-01 on darwin/amd64 → linux/amd64, Go 1.27.1 and apko 1.4.5, using the same owned anonymous `registry:3` at `127.0.0.1:54985` as checkpoint 1. A throwaway `DOCKER_CONFIG` contained only `{}` and Docker loading was disabled with an unreachable `DOCKER_HOST`. No existing credentials, signing inputs, non-loopback publication, or remote mutation were used. The integrated CLI was built with `go build -o <temporary>/lupetto ./cmd/lupetto`.

The products file used in the actual run was:

```yaml
version: 1
products:
  - package: busybox-static
    selectors: ["1", "1.37", "99"]
  - package: openssl
    selectors: ["3.6"]
  - package: valkey
    selectors: ["9.1"]
```

Actual command forms (the older BusyBox publication was the checkpoint-1 command above) were:

```bash
<temporary>/lupetto-cp1 build openssl --apk-version 3.6.1-r3 \
  --no-load --json --registry 127.0.0.1:54985 --repository tests/status/images
<temporary>/lupetto status --products <temporary>/products.yaml \
  --registry 127.0.0.1:54985 --repository tests/status/images --json
<temporary>/lupetto build busybox-static 1 --no-load --json \
  --registry 127.0.0.1:54985 --repository tests/status/images
<temporary>/lupetto status --products <temporary>/products.yaml \
  --registry 127.0.0.1:54985 --repository tests/status/images --json
<temporary>/lupetto status --products <temporary>/products.yaml \
  --registry 127.0.0.1:54985 --repository tests/status/images
```

All five completed commands exited 0. Before the latest selector build, BusyBox tracks `1`/`1.37` were `update-available` with installed `1.37.0-r56`; OpenSSL `3.6` was `update-available`; `busybox-static 99` was an isolated unavailable-selector `error`, and `valkey 9.1` was `not-built`. Publishing the latest selector resolved `busybox-static@1.38.0-r2`, workspace `image-2587130907`, digest `sha256:f6df53c7e981f592d40826c74dfa231884d3c27c34e4bfcd4e29a1a538ebd386`, with publication verified and loading skipped. Its real manifest carried the six annotations with created `2026-10-01T15:22:15Z`; the shared-registry extraction preserved publication readback. Broad track `1` then became `current`, while `1.37` still selected its older matching image and remained `update-available`.

OpenSSL's older image was retained in `image-3669020712` and published with verified digest `sha256:9731a9b4169fedd82ef6ee54f13344c72e109afca98f758d4d5589429a6c7017`. Independent Python HTTP GETs fetched each newest manifest/layer by digest, rehashed the compressed blobs, extracted `usr/lib/apk/db/installed`, and matched the complete reported installed identity lists (three APKs for BusyBox, nine for OpenSSL). Independently fetched index records and secdb entries matched all reported outdated identities and exact missing-fix IDs. OpenSSL had four missing-fix groups (`3.6.2-r0`, `3.6.3-r0`, `3.6.3-r4`, `3.6.3-r5`), all available before selected `3.6.5-r1` and `reachableByTrack: true`. The index also showed `libcrypto3`/`libssl3` updates, but the feed did not advertise those exact subpackage names; no origin mapping was invented. The exact `busybox-static` package was absent from the security feed, explaining its empty fix set despite newer indexed revisions.

The first live status attempt exited 1 because the security feed contained an unparseable `opa-envoy` fixed-version key `1.1.0-r1-r0`; a temporary probe using the pinned apko version comparator independently confirmed that this was the only unparseable nonzero key. The user approved explicit unevaluated-fix reporting rather than guessed ordering. The completed runs report `security.unevaluatedFixCount: 1` with IDs `CVE-2025-22866` / `GHSA-3whm-j4xm-rv8x`; human output contains the warning and an `UNEVALUATED` column. None of these tracked images install that package, so their issue arrays are empty; hermetic coverage exercises an installed affected package. The feed's exact SHA-256 was independently recomputed as `53698b27fcd59e79ab46862ab0a6ebd591af373ab322628e500ed867167e31a3`.

Complete real status JSON after publishing the latest BusyBox image follows (reformatted only; loopback target and public facts contain no secrets):

```json
{
  "version": 1,
  "kind": "status",
  "computedAt": "2026-10-01T15:22:23.943739Z",
  "architecture": "x86_64",
  "registry": "127.0.0.1:54985",
  "repository": "tests/status/images",
  "indexSHA256": "267936aa59d7ea43ec91ae2482e539eb7e73f09684bc5648cd31018648b2b015",
  "security": {
    "url": "https://packages.wolfi.dev/os/security.json",
    "sha256": "53698b27fcd59e79ab46862ab0a6ebd591af373ab322628e500ed867167e31a3",
    "unsigned": true,
    "fixedOnly": true,
    "wolfiOnly": true,
    "unevaluatedFixCount": 1,
    "unevaluatedFixes": [
      {
        "name": "opa-envoy",
        "fixedVersion": "1.1.0-r1-r0",
        "ids": [
          "CVE-2025-22866",
          "GHSA-3whm-j4xm-rv8x"
        ]
      }
    ]
  },
  "tracks": [
    {
      "package": "busybox-static",
      "selector": "1",
      "state": "current",
      "latest": {
        "name": "busybox-static",
        "version": "1.38.0-r2",
        "architecture": "x86_64"
      },
      "repository": "127.0.0.1:54985/tests/status/images/busybox-static",
      "images": [
        {
          "digest": "sha256:f6df53c7e981f592d40826c74dfa231884d3c27c34e4bfcd4e29a1a538ebd386",
          "tags": [
            "1.38.0-r2-amd64-build-2587130907"
          ],
          "name": "busybox-static",
          "version": "1.38.0-r2",
          "architecture": "x86_64",
          "created": "2026-10-01T15:22:15Z",
          "annotations": {
            "lupetto.apk.architecture": "x86_64",
            "lupetto.apk.name": "busybox-static",
            "lupetto.apk.version": "1.38.0-r2",
            "lupetto.index.sha256": "267936aa59d7ea43ec91ae2482e539eb7e73f09684bc5648cd31018648b2b015",
            "org.opencontainers.image.created": "2026-10-01T15:22:15Z",
            "org.opencontainers.image.version": "1.38.0-r2"
          }
        },
        {
          "digest": "sha256:51ff7537f57c5386d302626fecfa04363b38effd38c9abe59db12f69b8c4c111",
          "tags": [
            "1.37.0-r56-amd64-build-2154979337"
          ],
          "name": "busybox-static",
          "version": "1.37.0-r56",
          "architecture": "x86_64",
          "created": "2026-10-01T14:59:31Z",
          "annotations": {
            "lupetto.apk.architecture": "x86_64",
            "lupetto.apk.name": "busybox-static",
            "lupetto.apk.version": "1.37.0-r56",
            "lupetto.index.sha256": "4ef1cfe0f53a73cf245e0cfbadb53252b004f8f0f74ae858ec0666a8feef6887",
            "org.opencontainers.image.created": "2026-10-01T14:59:31Z",
            "org.opencontainers.image.version": "1.37.0-r56"
          }
        }
      ],
      "newest": {
        "digest": "sha256:f6df53c7e981f592d40826c74dfa231884d3c27c34e4bfcd4e29a1a538ebd386",
        "tags": [
          "1.38.0-r2-amd64-build-2587130907"
        ],
        "name": "busybox-static",
        "version": "1.38.0-r2",
        "architecture": "x86_64",
        "created": "2026-10-01T15:22:15Z",
        "annotations": {
          "lupetto.apk.architecture": "x86_64",
          "lupetto.apk.name": "busybox-static",
          "lupetto.apk.version": "1.38.0-r2",
          "lupetto.index.sha256": "267936aa59d7ea43ec91ae2482e539eb7e73f09684bc5648cd31018648b2b015",
          "org.opencontainers.image.created": "2026-10-01T15:22:15Z",
          "org.opencontainers.image.version": "1.38.0-r2"
        }
      },
      "installed": [
        {
          "name": "busybox-static",
          "version": "1.38.0-r2",
          "architecture": "x86_64"
        },
        {
          "name": "ca-certificates-bundle",
          "version": "20260909-r2",
          "architecture": "x86_64"
        },
        {
          "name": "wolfi-baselayout",
          "version": "20230201-r30",
          "architecture": "x86_64"
        }
      ],
      "outdated": [],
      "missingFixes": [],
      "unevaluatedFixes": [],
      "artifactCount": 0,
      "unidentifiedCount": 0
    },
    {
      "package": "busybox-static",
      "selector": "1.37",
      "state": "update-available",
      "latest": {
        "name": "busybox-static",
        "version": "1.37.0-r61",
        "architecture": "x86_64"
      },
      "repository": "127.0.0.1:54985/tests/status/images/busybox-static",
      "images": [
        {
          "digest": "sha256:51ff7537f57c5386d302626fecfa04363b38effd38c9abe59db12f69b8c4c111",
          "tags": [
            "1.37.0-r56-amd64-build-2154979337"
          ],
          "name": "busybox-static",
          "version": "1.37.0-r56",
          "architecture": "x86_64",
          "created": "2026-10-01T14:59:31Z",
          "annotations": {
            "lupetto.apk.architecture": "x86_64",
            "lupetto.apk.name": "busybox-static",
            "lupetto.apk.version": "1.37.0-r56",
            "lupetto.index.sha256": "4ef1cfe0f53a73cf245e0cfbadb53252b004f8f0f74ae858ec0666a8feef6887",
            "org.opencontainers.image.created": "2026-10-01T14:59:31Z",
            "org.opencontainers.image.version": "1.37.0-r56"
          }
        }
      ],
      "newest": {
        "digest": "sha256:51ff7537f57c5386d302626fecfa04363b38effd38c9abe59db12f69b8c4c111",
        "tags": [
          "1.37.0-r56-amd64-build-2154979337"
        ],
        "name": "busybox-static",
        "version": "1.37.0-r56",
        "architecture": "x86_64",
        "created": "2026-10-01T14:59:31Z",
        "annotations": {
          "lupetto.apk.architecture": "x86_64",
          "lupetto.apk.name": "busybox-static",
          "lupetto.apk.version": "1.37.0-r56",
          "lupetto.index.sha256": "4ef1cfe0f53a73cf245e0cfbadb53252b004f8f0f74ae858ec0666a8feef6887",
          "org.opencontainers.image.created": "2026-10-01T14:59:31Z",
          "org.opencontainers.image.version": "1.37.0-r56"
        }
      },
      "installed": [
        {
          "name": "busybox-static",
          "version": "1.37.0-r56",
          "architecture": "x86_64"
        },
        {
          "name": "ca-certificates-bundle",
          "version": "20260909-r1",
          "architecture": "x86_64"
        },
        {
          "name": "wolfi-baselayout",
          "version": "20230201-r30",
          "architecture": "x86_64"
        }
      ],
      "outdated": [
        {
          "name": "busybox-static",
          "architecture": "x86_64",
          "installedVersion": "1.37.0-r56",
          "latestVersion": "1.38.0-r2"
        },
        {
          "name": "ca-certificates-bundle",
          "architecture": "x86_64",
          "installedVersion": "20260909-r1",
          "latestVersion": "20260909-r2"
        }
      ],
      "missingFixes": [],
      "unevaluatedFixes": [],
      "artifactCount": 0,
      "unidentifiedCount": 0
    },
    {
      "package": "busybox-static",
      "selector": "99",
      "state": "error",
      "error": "unavailable index version for track",
      "images": [],
      "installed": [],
      "outdated": [],
      "missingFixes": [],
      "unevaluatedFixes": [],
      "artifactCount": 0,
      "unidentifiedCount": 0
    },
    {
      "package": "openssl",
      "selector": "3.6",
      "state": "update-available",
      "latest": {
        "name": "openssl",
        "version": "3.6.5-r1",
        "architecture": "x86_64"
      },
      "repository": "127.0.0.1:54985/tests/status/images/openssl",
      "images": [
        {
          "digest": "sha256:9731a9b4169fedd82ef6ee54f13344c72e109afca98f758d4d5589429a6c7017",
          "tags": [
            "3.6.1-r3-amd64-build-3669020712"
          ],
          "name": "openssl",
          "version": "3.6.1-r3",
          "architecture": "x86_64",
          "created": "2026-10-01T15:09:28Z",
          "annotations": {
            "lupetto.apk.architecture": "x86_64",
            "lupetto.apk.name": "openssl",
            "lupetto.apk.version": "3.6.1-r3",
            "lupetto.index.sha256": "1d7b49278270a61616f535ece217004f33b80adce58bf8d0809279bfaa0f0e62",
            "org.opencontainers.image.created": "2026-10-01T15:09:28Z",
            "org.opencontainers.image.version": "3.6.1-r3"
          }
        }
      ],
      "newest": {
        "digest": "sha256:9731a9b4169fedd82ef6ee54f13344c72e109afca98f758d4d5589429a6c7017",
        "tags": [
          "3.6.1-r3-amd64-build-3669020712"
        ],
        "name": "openssl",
        "version": "3.6.1-r3",
        "architecture": "x86_64",
        "created": "2026-10-01T15:09:28Z",
        "annotations": {
          "lupetto.apk.architecture": "x86_64",
          "lupetto.apk.name": "openssl",
          "lupetto.apk.version": "3.6.1-r3",
          "lupetto.index.sha256": "1d7b49278270a61616f535ece217004f33b80adce58bf8d0809279bfaa0f0e62",
          "org.opencontainers.image.created": "2026-10-01T15:09:28Z",
          "org.opencontainers.image.version": "3.6.1-r3"
        }
      },
      "installed": [
        {
          "name": "ca-certificates-bundle",
          "version": "20260909-r1",
          "architecture": "x86_64"
        },
        {
          "name": "glibc-2.44",
          "version": "2.44-r7",
          "architecture": "x86_64"
        },
        {
          "name": "glibc-2.44-locale-posix",
          "version": "2.44-r7",
          "architecture": "x86_64"
        },
        {
          "name": "ld-linux-2.44",
          "version": "2.44-r7",
          "architecture": "x86_64"
        },
        {
          "name": "libcrypto3",
          "version": "3.6.1-r3",
          "architecture": "x86_64"
        },
        {
          "name": "libgcc",
          "version": "16.2.0-r1",
          "architecture": "x86_64"
        },
        {
          "name": "libssl3",
          "version": "3.6.1-r3",
          "architecture": "x86_64"
        },
        {
          "name": "openssl",
          "version": "3.6.1-r3",
          "architecture": "x86_64"
        },
        {
          "name": "wolfi-baselayout",
          "version": "20230201-r30",
          "architecture": "x86_64"
        }
      ],
      "outdated": [
        {
          "name": "ca-certificates-bundle",
          "architecture": "x86_64",
          "installedVersion": "20260909-r1",
          "latestVersion": "20260909-r2"
        },
        {
          "name": "libcrypto3",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "latestVersion": "3.6.5-r1"
        },
        {
          "name": "libssl3",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "latestVersion": "3.6.5-r1"
        },
        {
          "name": "openssl",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "latestVersion": "3.6.5-r1"
        }
      ],
      "missingFixes": [
        {
          "name": "openssl",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "fixedVersion": "3.6.2-r0",
          "availableVersion": "3.6.5-r1",
          "ids": [
            "CVE-2026-28386",
            "CVE-2026-28387",
            "CVE-2026-28388",
            "CVE-2026-28389",
            "CVE-2026-28390",
            "CVE-2026-31789",
            "CVE-2026-31790",
            "GHSA-7x88-9hgc-69gf",
            "GHSA-fgpp-q3px-3xhc",
            "GHSA-h2cc-wx97-xp8v",
            "GHSA-j79m-9jxq-788r",
            "GHSA-q457-vx59-3fqg",
            "GHSA-rpg5-467j-c25q",
            "GHSA-vgxx-5xj5-q97x"
          ],
          "reachableByTrack": true
        },
        {
          "name": "openssl",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "fixedVersion": "3.6.3-r0",
          "availableVersion": "3.6.5-r1",
          "ids": [
            "CVE-2026-34180",
            "CVE-2026-34181",
            "CVE-2026-34182",
            "CVE-2026-34183",
            "CVE-2026-35188",
            "CVE-2026-42764",
            "CVE-2026-42765",
            "CVE-2026-42766",
            "CVE-2026-42767",
            "CVE-2026-42768",
            "CVE-2026-42769",
            "CVE-2026-42770",
            "CVE-2026-45445",
            "CVE-2026-45446",
            "CVE-2026-45447",
            "CVE-2026-7383",
            "CVE-2026-9076",
            "GHSA-3c8f-qq7h-7qv6",
            "GHSA-3cxm-476w-ghm2",
            "GHSA-4jgc-cj59-f9mm",
            "GHSA-58mv-qqmv-gqgv",
            "GHSA-5m8f-m8jv-3rp3",
            "GHSA-5pg7-f6xv-j6m4",
            "GHSA-7phf-qpm5-q6p3",
            "GHSA-f5vx-f6jp-89j6",
            "GHSA-f684-cpcq-j565",
            "GHSA-f9v2-4w9p-2cwc",
            "GHSA-gxhg-7jx8-m22j",
            "GHSA-q98x-73c3-57gj",
            "GHSA-rpj2-p5pj-r33v",
            "GHSA-v446-xwfm-x7mr",
            "GHSA-vc8w-w49c-4jgj",
            "GHSA-vm8w-j6fw-jc7r",
            "GHSA-w853-v86g-gv7j"
          ],
          "reachableByTrack": true
        },
        {
          "name": "openssl",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "fixedVersion": "3.6.3-r4",
          "availableVersion": "3.6.5-r1",
          "ids": [
            "CVE-2026-54876",
            "GHSA-5cfw-78wc-wvjq"
          ],
          "reachableByTrack": true
        },
        {
          "name": "openssl",
          "architecture": "x86_64",
          "installedVersion": "3.6.1-r3",
          "fixedVersion": "3.6.3-r5",
          "availableVersion": "3.6.5-r1",
          "ids": [
            "CVE-2026-14456",
            "GHSA-9x89-v382-mjh7"
          ],
          "reachableByTrack": true
        }
      ],
      "unevaluatedFixes": [],
      "artifactCount": 0,
      "unidentifiedCount": 0
    },
    {
      "package": "valkey",
      "selector": "9.1",
      "state": "not-built",
      "latest": {
        "name": "valkey-9.1",
        "version": "9.1.2-r1",
        "architecture": "x86_64"
      },
      "repository": "127.0.0.1:54985/tests/status/images/valkey-9.1",
      "images": [],
      "installed": [],
      "outdated": [],
      "missingFixes": [],
      "unevaluatedFixes": [],
      "artifactCount": 0,
      "unidentifiedCount": 0
    }
  ]
}
```

The human run produced the same five states and counts (BusyBox `1`: 0 outdated/0 fix groups; BusyBox `1.37`: 2/0; OpenSSL `3.6`: 4/4; unavailable/unbuilt tracks: 0/0). A further `status --json` run exited 0, retained the same installed sets, and did not rewrite the three digest-keyed cache files. Independent permission checks found the cache directory mode 0700 and each record mode 0600; hermetic tests additionally prove cached runs issue no layer reads. Fresh index checksums changed between requests (`267936aa…b015` for recorded JSON and `dfe112e2…cc5c` for the independent follow-up/human run), while independently checked package/fix facts agreed. This is not an atomic upstream index/feed snapshot.

A separate attempted older `nginx@1.28.1-r1` build composed its image but exited 1 during the existing SPDX validation, with publication not attempted and retained workspace `image-556573540`. Independent lock/SPDX inspection found apko's `libstdc%2B%2B` purls, which the pre-existing validator does not URL-decode before name comparison. That unrelated validator behavior was not changed; OpenSSL supplied the real missing-fix proof instead. Indexed APK metadata still does not guarantee a successful validated build.

Hermetic coverage uses `internal/build/buildtest`'s authenticated in-process registry and `wolfitest` signed index fixtures: annotation classification; modern/legacy Cosign-like artifact and unannotated counts; selector/provider isolation; APK-version/created/digest ordering; all states; exact package/architecture comparison; secdb zero and fix availability; reachability; malformed-key warning/affected-track reporting; digest/config/layer tampering; bounded multilayer overlays and whiteouts; private cache reuse/corruption/failures; HTTP guard/authentication/sanitized 401 detail; redirected blob reads above 4 MiB; cancellation and global failures. The CLI parser/output tests cover independent flag/environment precedence, ignored signing environment inputs, exit-0 track errors, exit-1 global errors, exit-2/no-stdout invocation errors, help dispatch, human warnings and output failures. Independent follow-up source review found no concrete remaining defect.

Final integrated gates before the checkpoint-2 commit: `go test ./...` and `go test -race ./...` passed for `cmd/lupetto`, `internal/build`, `internal/registry`, `internal/status`, and `internal/wolfi` (fixture packages have no tests). `go run ./cmd/lupetto --help` exited 0 and listed status with its read-only/version/exit contract. `go list -f '{{join .Imports "\n"}}' ./internal/status ./internal/registry` confirmed status imports only shared Wolfi/registry code and registry imports no in-module packages. Relative links/anchors across all eight Markdown files passed; `bash -n` passed for 21 Bash-fenced blocks (syntax only, not production execution), and the complete JSON embedded above was parsed and required to equal the actual observed status document.

The owned `docker stop <owned-name>` exited 0; because the registry was started with `--rm`, subsequent `docker container inspect <owned-name>` exited 1 and confirmed its removal. No credentials or private keys were created. Public temporary scenario logs and private user-cache workspaces/cache records remain outside the checkout. No Git push or registry/tag cleanup outside this disposable owned registry was performed.

Status review follow-up: `go test ./internal/status ./internal/wolfi -run 'Test(GOOnlyAndUnrecognisedOnlySecurityEntries|Malformed|SecurityFeedFixedOnlyAndHTTPS|MetadataLimitsFollowOriginalRequestAcrossRedirects|DiscoverAllPackagesLatestDescriptions|RunStatesSelectorsSecurityAndCache)' -count=1` passed. GO-only dependency fixes now produce `fixes-available` with the advisory retained; unsupported-only IDs remain explicit source/affected-track unevaluated evidence, including original unsupported IDs. The redirected metadata fixture now includes repository `x/blobs/y`: its manifests/tag-list responses are still capped at 4 MiB while actual digest blob endpoints are not. Nameless APKINDEX records are ignored both at a record separator and at EOF, so all-packages browsing does not fail on them. The initial focused attempt found an unused import after endpoint matching changed; removing it and repeating the exact command passed. Full/race checkpoint gates are recorded after completion below; no live registry or credentials were used for this follow-up.

Before the follow-up commit, the exact staged tree was exported with `git checkout-index --all --prefix=<temporary-tree>/` to exclude concurrently developed, untracked Explorer files. In that tree, `go test ./...` and `go test -race ./...` both passed for the five implemented CLI packages; fixture packages had no tests. Staged source bytes were checked against this tested copy. The CLI JSON schema remains version 1 with existing unevaluated fields; no image build/publication or remote mutation was needed for these regression fixes.

Limitations: production registry TLS/authentication, non-loopback registries, other hosts/architectures and a real redirected external-storage registry were not exercised. The real registry was anonymous; authenticated behavior is covered hermetically and prior publication evidence. Gzip/uncompressed OCI/Docker layers are supported; zstd installed-layer extraction reports a track error. Status is not a signature report, vulnerability scan, future dependency solver, historical archive, or dashboard. The feed is unsigned and fixed-only, and exact subpackage matching can leave coverage gaps; consumers must inspect unreachable/unevaluated warnings even for `current` tracks.

## Selection and snapshots

Persistent catalog import/history checks in this section are deferred. Exercise the existing live-index selectors and retained per-build provenance for publication/signing without requiring a catalog database; retaining an index alone does not establish historical APK availability.

- Import a controlled snapshot and verify package metadata and provenance against its input.
- Resolve a major with multiple upstream versions and packaging revisions; verify APK-compatible ordering and architecture filtering.
- Verify that exact selection preserves the requested `-rN` revision.
- Reject conflicting selectors, ambiguous family mappings, missing versions, and unavailable package bytes without substitution.
- Preserve the exact selection used by a build when a newer snapshot is later imported.

## Build and SPDX evidence

- Run the CLI against an available real Wolfi package/version; inspect the image’s package contents and compare them with the selected version and resolved lock.
- Verify the resolved APK package set against SPDX using the agreed comparison rules. Deliberate missing, extra, or changed APK entries must fail validation; legitimate non-APK SPDX entries must follow the defined policy.
- Verify Docker loading and no-load behavior independently.
- Exercise the SBOM command through its chosen real resolution path, not an unrelated fixture document.
- Cancel or fail a build and confirm it does not report success or validated evidence. Preserve useful diagnostics without secrets.

## Publication and signatures

Use isolated test targets and synthetic credentials/keys; publication/signing against a live registry or use of existing credentials/keys requires authorization for the exact target/scope. Roadmap priority and unchecked acceptance criteria are not that authorization. Local HTTP/offline success must not be reported as production HTTPS/transparency-log verification.

- Publish to a compatible test registry under a nested repository prefix; verify that the reported digest resolves to the pushed artifact.
- Publish with `--no-load` and an unreachable Docker endpoint; confirm Docker is not used and the digest is still verified by readback.
- Tamper with registry responses (manifest, tag body, config, layer) and confirm publication fails unverified without signing.
- Sign and attest the same immutable digest, then verify both with the trusted public key.
- Inspect the verified attestation subject and SPDX predicate; compare the predicate with the validated local evidence.
- Verify that a wrong key or unrelated image digest cannot satisfy the expected signature/attestation checks.
- Exercise push failure and signing/attestation failure separately; report partial success accurately.
- Confirm secrets are not passed in password arguments or included in logs, result files, or downloaded evidence.

The production verification forms below were exercised against Harbor v2.15.2 with public Rekor; see [production Harbor evidence](#production-harbor-registry-and-public-rekor-verification-2026-10-02). The [operator guide](registry-signing.md#verify-signature-and-spdx-attestation) documents both these forms and the separately labeled local variants exercised in [checkpoint 2](#local-cosign-signing-and-spdx-attestation-evidence):

```text
cosign verify --key /path/to/lupetto.pub registry.example.com/team/lupetto/<image>@sha256:<digest>
cosign verify-attestation --key /path/to/lupetto.pub --type spdxjson registry.example.com/team/lupetto/<image>@sha256:<digest>
```

The pinned Cosign v3.1.3 local HTTP/no-service forms were exercised above; the production forms were exercised in [production Harbor evidence](#production-harbor-registry-and-public-rekor-verification-2026-10-02). Local HTTP access and verification without transparency-log evidence require separately labeled variants; never make them production defaults. Successful cryptographic verification does not prove absence of vulnerabilities, SBOM completeness, or policy compliance.

## Explorer

- Build/install and exercise CLI selection, image creation, and evidence generation without installing or starting Explorer.
- Verify dependency boundaries: core/CLI packages do not import Explorer; Explorer does not import build/publication/signing internals.
- Exercise Explorer against a separately built supported CLI executable, not only a same-checkout development invocation.
- Reject unsupported request/result contract versions clearly; do not interpret human-readable logs as successful machine results.
- Verify catalog access through its chosen boundary and ensure Explorer cannot overwrite build outcomes through private state.

- Open the real UI and verify package/series navigation, metadata, and snapshot provenance.
- Confirm build controls are unavailable when builds are disabled and that requests cannot bypass that restriction.
- Launch an exact build, observe its real result, and verify local-image availability against Docker.
- Download the retained SBOM and check its content identity. Removing an eligible temporary workspace must not destroy immutable evidence.
- Exercise cancellation/failure and the chosen concurrency limit without mixing workspaces or results.
- Verify HTML escaping of package metadata and rejection of unauthorized cross-origin build requests.
- Check Products and recipe history against their defined data sources; do not present absent data as a completed history.

### Explorer server (checkpoint 3)

Observed on darwin/amd64 with Go 1.27.1, native apko 1.4.5, Docker 27.4.0, and an owned disposable anonymous `registry:3`. This checkpoint implements the backend only: HTML/CSS/JavaScript and the combined container remain unimplemented, so no real-browser or unprivileged-container proof is claimed.

Hermetic fake-CLI tests exercise exact kind/version rejection, success and failure records, empty invocation stdout, status success/error with last-good retention, single-flight startup/interval/manual/after-build refresh, queuing a fresh comparison when a build finishes during an older refresh, validated selector/exact argv, builds-disabled 403, concurrent-build 409, POST-only routes, CSRF body-only tokens, Origin/Sec-Fetch-Site checks, loopback Host rejection, HTTPS Origin over a plain HTTP backend without trusting forwarded headers, package filtering/result bounds and named-discovery concurrency, live stderr delivery/tail truncation/offset cursors, successful-cancel races, graceful SIGTERM cancellation with parsed failure record, forced kill after grace, history eviction, HTTP shutdown, and in-test `html/template` escaping/missing-template errors. The stdout-limit regression exercises real pipe draining above 32 MiB; the bounded writer deliberately does not embed `bytes.Buffer` (which would promote `ReadFrom` and bypass `Write` via `io.Copy`). Import tests run `go list -deps` and reject Explorer imports of CLI/build/Wolfi/status/registry internals, plus reverse CLI imports of Explorer.

Focused commands `go test ./internal/explorer ./cmd/lupetto-explorer -count=1` and the cancellation/output-limit/ingress/concurrency regression selections were run during development; the final integrated gates are recorded below. These fixtures verify orchestration, not apko/registry interoperability.

Real smoke commands built independent executables with `go build -o <tmp>/lupetto ./cmd/lupetto` and `go build -o <tmp>/lupetto-explorer ./cmd/lupetto-explorer`, both exit 0. Started `docker run -d --rm --name <owned-name> -p 127.0.0.1:60371:5000 registry:3`, then the external Explorer binary with `--listen 127.0.0.1:60372 --products <tmp>/products.yaml --lupetto-binary <tmp>/lupetto --enable-builds --refresh-interval 15m`. The products file tracked `busybox-static` selector `"1"`. An isolated HOME and empty synthetic Docker client configuration were used; existing Lupetto signing/publication inputs and Cosign password were cleared. Only `LUPETTO_REGISTRY=127.0.0.1:60371` / `LUPETTO_REPOSITORY=tests/explorer/images` configured the build target; no registry/key/credential arguments were passed or environment values logged.

Actual `curl --silent --show-error --max-time 30` interactions:

- `GET /healthz`: 200 `ok`; `GET /`: 500 with the expected missing `overview` template message; `GET /?format=json`: 200, initial computed-at `2026-10-01T15:56:20.02269Z`, track `not-built`, no refresh error.
- Read the per-process CSRF token from the JSON view, then `POST /builds` with `Origin: http://127.0.0.1:60372` and URL-encoded `csrfToken`, `package=busybox-static`, `selector=1`: 303 to the job. `/jobs?format=json` and `/jobs/1?format=json`: 200; job reached `succeeded`, exit 0, selected `busybox-static@1.38.0-r2` for `x86_64`.
- Parsed version-6 stages: build `completed`, load `skipped`, publication `published` and `verified: true`; signing/attestation `skipped`. Published digest `sha256:f7b8c372e5fd70d7b5d5a460a6c13ec61c897bd4846d6817f6ffc91c602a80dc`.
- Without manual refresh, overview recomputed at `2026-10-01T15:57:00.027144Z`: `current`, newest digest exactly equal to the job publication digest, three installed APKs, no refresh error. `/tracks/busybox-static/1?format=json`: 200, one image and the same three installed identities.
- `/jobs/1/logs?offset=0`: 200 JSON, 1,470 bytes of actual CLI/apko stderr, `done: true`, `truncated: false`. `/packages?q=busybox&format=json`: 200 with six matches; `/packages/busybox-static?format=json`: 200 with nine indexed versions.
- SIGTERM to Explorer exited 0; `docker stop <owned-name>` exited 0 and subsequent `docker container inspect <owned-name>` exited nonzero, confirming `--rm` cleanup. No remote publication, signing, credentials, or private keys were used. Runtime JSON/logs/workspaces remain outside the checkout, not committed.

Limitations: the real run proves loopback anonymous direct publication/readback and server orchestration, not authenticated production HTTPS, signing, a real browser, an authenticating ingress deployment, a combined container, other hosts/architectures, or cancellation during a real external build. Ingress-Origin/cancellation/partial-failure/secret-safe argv behavior is covered hermetically. No persistent catalog/jobs, durable SBOM download, image runtime recipe, or vulnerability scanner is introduced; the unsigned fixed-only Wolfi feed and unreachable/unevaluated warnings remain necessary presentation limitations.

Final backend gates: `gofmt -w` on the eight new Explorer Go files, `go test ./...`, `go test -race ./...`, `go run ./cmd/lupetto-explorer --help`, and `git diff --check` passed. The first normal full-suite attempt timed out after 180 seconds while a race suite ran concurrently; the non-concurrent retry passed in 23 seconds. The race gate passed in 36 seconds, including Explorer's 22-second hermetic suite. The actual help listed the required products path, loopback listen/PATH binary defaults, builds off, and 15-minute interval. Independent backend review findings (ingress Origin handling, cancel-vs-success race, stdout-limit diagnostics, discovery concurrency) were fixed and regression-tested; frontend correctness review found no issue with empty embed placeholders/named escaped Go rendering seam. No browser/visual review is claimed.

After the final Markdown-only rendering-contract corrections, sequential `go test ./... && go test -race ./...` passed again (cached), and frontend correctness review found no actionable issue in the complete contract versus models/routes/forms/log polling. Final relative links/anchors across the five changed Markdown files and `bash -n` for all 14 Bash blocks in those files passed (syntax only). The 15-file staged scope contained no runtime CSRF token, private-key material, JSON/YAML/key/config artifacts, HTML/CSS/JavaScript implementation, or unstaged drift; `git diff --cached --check` passed. No push was performed.

#### Host allowlist follow-up

Independent review identified DNS rebinding when a container listens on `0.0.0.0` but is exposed only through loopback Docker/Kubernetes port-forwarding: the earlier loopback-listener-only Host check did not protect that deployment. Every request now checks an operator-configured allowlist before routing/CSRF-token exposure. Repeatable `--allowed-host` defaults to localhost/127.0.0.1/[::1] at any valid port; explicit values replace defaults. A host without port permits any port, host:port requires the exact port, IPv6 literals are bracketed/canonicalized, and DNS names are case-insensitive. Ingress operators list their external hostname; forwarded headers remain ignored. This supplements, not replaces, authentication/network boundaries and POST CSRF/Origin checks.

Removed the test's post-Start write to `server.config.RefreshInterval`, which could race the startup ticker read. Focused `go test ./internal/explorer ./cmd/lupetto-explorer -run 'TestAllowedHostsForEveryListener|TestExplicitAllowedHostsAndPorts|TestInvalidAllowedHostConfiguration|TestStartupIntervalAndPostBuildRefresh|TestRequestSafety|TestHelpAndInvalidFlags' -count=1` passed. Cases include wildcard/IPv6 listeners, rebound GET/POST even with known valid CSRF and matching Origin, explicit ingress HTTPS Origin, repeated hosts, port restrictions, bracketed IPv6, malformed flags, and replacement of defaults.

Real HTTP smoke: built `go build -o <tmp>/lupetto-explorer ./cmd/lupetto-explorer`, ran it on `0.0.0.0:<ephemeral-port>` with `/usr/bin/false` as an intentionally failing/no-network CLI (builds disabled), and exercised actual `curl --header 'Host: …'` requests over loopback. Default localhost and `[::1]:8443` health requests returned 200; `rebound.example.invalid` overview JSON returned 403 without a CSRF token. Restarted with two flags (`--allowed-host dashboard.example.invalid:8443 --allowed-host '[::1]'`): configured external host:8443 returned 200, wrong port and localhost returned 403, IPv6 at another port returned 200. Both instances exited 0 on SIGTERM. No credentials, registry, build/publication or external network requests were used; logs/binaries stayed outside the checkout.

Follow-up `gofmt -w` on the six affected Go files, sequential `go test ./... && go test -race ./...`, and `git diff --check` passed (56 seconds for both suites). Independent backend review found no Host-allowlist bypass or remaining startup-interval race. Port-qualified entries deliberately require the port in the actual Host header; browsers commonly omit default `:80`/`:443`, so ingress operators should use the documented bare-host entry rather than infer a protocol/port from untrusted proxy headers.


### Explorer dashboard UI (checkpoint 4)

Observed on darwin/amd64 with Go 1.27.1, native apko 1.4.5, Docker 27.4.0, an owned disposable anonymous `registry:3`, and the tool's managed headless Chromium 150. The UI is `internal/explorer/web/templates/*.html` (six contract page names plus shared partials), `web/static/app.css` (system fonts, light/dark via `prefers-color-scheme`) and `web/static/app.js` (live log polling, auto-reload while a status refresh/discovery load/build runs, build-button disabling while a build runs; text inserted with text nodes only). Pages work without JavaScript except live logs and auto-reload.

Real-browser finding and fix: the first UI-triggered build returned 403 `same-origin Origin is required`. Captured request headers showed Chromium sending `Origin: null` on the form POST because the server sent `Referrer-Policy: no-referrer`. The server now sends `Referrer-Policy: same-origin` (no referrer to any other origin); `Origin: null` is still rejected, including with `Sec-Fetch-Site: same-origin` (new `TestRequestSafety` case), and the header test asserts the exact value. After the change the same click sent `Origin: http://127.0.0.1:61872` and was accepted. `CONTRACT.md` and the README Explorer section were corrected.

Setup: `go build -o <tmp>/lupetto ./cmd/lupetto` and `go build -o <tmp>/lupetto-explorer ./cmd/lupetto-explorer`; `docker run -d --rm --name <owned-name> -p 127.0.0.1:61871:5000 registry:3`; products `busybox-static` `["1", "1.37"]`, `openssl` `["3.6"]`, `valkey` `["9.1"]` (availability checked with `lupetto discover`); isolated HOME, empty `DOCKER_CONFIG` (`{}`), `COSIGN_PASSWORD` unset, only `LUPETTO_REGISTRY=127.0.0.1:61871` / `LUPETTO_REPOSITORY=tests/explorer-ui/images`; Explorer `--listen 127.0.0.1:61872 --products <file> --lupetto-binary <tmp>/lupetto --enable-builds`. Exercised in the browser:

- Overview: computed-at, architecture, registry/repository, index SHA-256, feed URL/SHA-256, unsigned/fixed-only/Wolfi-only warnings, the one source-wide unevaluated `opa-envoy` entry (`1.1.0-r1-r0`) with linked CVE/GHSA/GO IDs; four `not-built` rows.
- Clicking **Build** for `busybox-static 1` redirected to the job page; the log streamed live (`Live — updating…`), and on `done` the page reloaded to job state `succeeded`, record outcome `succeeded`, selection `busybox-static 1.38.0-r2`, five separate stages (build `completed`, load and signing/attestation `skipped (not requested)`, publication `published` with digest `sha256:352855a2…` and immutable reference, “identity verified”), evidence (apko 1.4.5, SPDX validated). Without manual refresh the overview then showed `current` with that digest.
- Package browser: unfiltered view showed 15,516 matches with the truncation notice; search `openssl` gave 52 matches; the `openssl` page listed exact versions with per-version forms. **Build 3.6.1-r0** sent `apkVersion` and succeeded; track `openssl 3.6` became `update-available` (latest `3.6.5-r1`), 3 outdated APKs (`libcrypto3`, `libssl3`, `openssl`), 5 reachable missing-fix groups (fixed in `3.6.1-r3` … `3.6.3-r5`) with NVD/GitHub links carrying `rel="noopener noreferrer"`, image tags/digest/created/annotations, and 9 installed APKs in a collapsed section.
- `busybox-static 1.37` built from the overview became `current` with one outdated APK (`busybox-static` 1.38.0-r2 outside the selector) and the “empty list is not ‘no vulnerabilities’” wording. While it ran, a second overview tab showed all four Build buttons disabled with “Build running: job #1”.
- Cancel: **Build valkey 9.1**, then **Cancel build** after ~2 s: page showed `cancellation requested`, then reloaded to `canceled` plus record outcome `failed`, the side-effects warning, Explorer diagnostic, `Failed at stage: build`, and publication `not attempted (earlier stage failed)`. The jobs list showed both jobs, the in-memory history note, both state columns and exit codes `1`/`0`.
- **Refresh status** showed the disabled “Refreshing…” button and in-progress banner; the page auto-reloaded about 4 s later with a newer computed-at.
- CSP: a `securitypolicyviolation` listener injected before load recorded no violations on `/`, two track pages, `/packages`, a search, two package pages (including `cmd:curl`), `/jobs` and both job pages; a deliberately injected inline script was recorded (`script-src-elem`), proving the listener worked.
- With JavaScript disabled, the search form and the refresh form (303 back to `/`) worked. A 390 px light-mode viewport kept tables horizontally scrollable and facts stacked.
- Restarted without `--enable-builds`: “Builds disabled” notes, zero `/builds` forms on overview, track and package pages, and a direct same-origin `fetch` POST to `/builds` with a valid token returned 403 `builds are disabled…`.

Cleanup: Explorer SIGTERM exited 0 each time; `docker stop <owned-name>` exited 0 and `docker container inspect` then failed, confirming removal. No signing, credentials or remote registries were used; workspaces stayed under the temporary HOME.

`TestEmbeddedTemplatesRenderRepresentativeModels` executes all six pages against full and empty models (nil pointers, zero times, exit code 0, partial-failure record, canceled without record, truncated log, unreachable and unevaluated fixes, builds enabled/disabled) and checks escaping of hostile strings, absence of inline script/style/handlers, the advisory link forms, and that build/cancel controls are absent when builds are disabled. `TestEmbeddedStaticAssetsServed` checks the embedded assets.

Limitations: one browser engine (Chromium) and one host; not tested with Firefox/Safari, a screen reader, an authenticating ingress or the combined container. No `fixes-available` or unreachable-fix track occurred in the real data; those render paths are covered by the template test only. The overview model has no `Running` flag, so build-button disabling there relies on JavaScript (the server still returns 409). Template-only exit-code handling prints `-1` with an explanatory note rather than a distinct label, because templates cannot dereference `*int` for comparison.

Gates: `gofmt -l` clean; `go vet ./internal/explorer`, `go test ./...` and `go test -race ./...` passed.

Review follow-up (four minor findings from frontend review of `7a6b189`), re-verified in headless Chromium against real binaries and a fresh owned loopback `registry:3` (removed afterwards; `docker container inspect` then failed). Products were `busybox-static` `["1", "9"]` and `valkey` `["9.1"]`. Explorer ran with `--lupetto-binary` set to a test wrapper. The wrapper fails only the all-packages `discover --json` call (exit 1, synthetic message) and `exec`s the real CLI for everything else.

- Build controls recover: while job 1 (`busybox-static 1`) ran, a second tab on `/packages/busybox-static` showed all 9 exact-build buttons disabled, each with a “Build running: job #1” link. After the job succeeded, the same document (no reload) showed 0 disabled buttons and 0 notes. The guard keeps polling `/jobs?format=json` only while it holds controls disabled.
- Error tracks are not shown as empty results: the unavailable selector `busybox-static 9` produced CLI state `error` (`unavailable index version for track`). The overview showed “unknown” for newest image and outdated APKs, and “unknown (track error)” for missing fixes. The track page showed “Unknown … not an empty result” for missing fixes, outdated packages and installed packages, and said the missing image list “does not establish that no image exists”. Non-error tracks keep their previous wording, and lists that are present on an error track are marked as possibly incomplete.
- The live log is bounded: on a real running job page (`valkey 9.1`, job 2), log responses were intercepted in the browser to return three synthetic 600,000-character chunks. The `<pre>` then held exactly 1,048,576 characters of log text with a single leading “[earlier output discarded]” marker, and requests still advanced by the absolute `nextOffset`. After the interception was removed, the real `done` response reloaded the page to the job's `succeeded` record.
- Discovery failure stops polling: `/packages` rendered the failure and the loading banner. The first poll returned `lastError` without a document, so the banner was replaced (as text) with “Loading failed; polling stopped. Reload the page to retry.” and the error. The resource count of `format=json` requests stayed at 1 over the next 10 s. While a loaded document is being refreshed in the background, the page no longer shows the loading banner.
- No CSP violations on the seven pages visited (listener as above).

`TestEmbeddedTemplatesDistinguishTrackErrorsFromEmptyResults` covers the error-track wording on the track and overview pages, the attributes that stop discovery polling, and the absence of the banner during a background refresh. `node --check` passed for `app.js`. Gates passed again: `gofmt -l`, `go test ./...` and `go test -race ./...`.


### Combined container (checkpoint 5)

Observed 2026-10-01 on Docker Desktop 4.37.2 / Docker client-server 27.4.0, darwin/amd64 host → **linux/amd64** container. `docker build --platform linux/amd64 -f Containerfile -t lupetto-explorer:container-check .` exited 0, building both Go programs with Go **1.27.1**, `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, and the embedded UI available in the checkout. Nothing was pushed outside the owned loopback registry.

Pinned inputs:

| Input | Observed pin / result |
| --- | --- |
| Runtime base | `cgr.dev/chainguard/wolfi-base@sha256:d59fd2d1d21e913b12a8d56064e9aaf61f818289bd18b17132a0c4fde2358cea` |
| Go builder | `golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414` |
| apko | Exact signed Wolfi APK `apko=1.4.5-r0`, downloaded using `apk add --no-cache` from `https://packages.wolfi.dev/os`; version output `GitVersion: v1.4.5`, Go 1.27.1, linux/amd64. The inspected x86_64 index SHA-256 was `e900136fbae4fb62454a3da0e9898571efdaa5a4dab92ce45b23a07d59fee9fd`. |
| Cosign | No `cosign@3.1.3-rN` entry in that observed Wolfi index. [Upstream `cosign-linux-amd64` v3.1.3 release](https://github.com/sigstore/cosign/releases/tag/v3.1.3), verified at build time and in the final runtime against pinned SHA-256 `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` from [upstream checksums](https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt). Version output `v3.1.3`, Go 1.26.4, linux/amd64. |
| Final local image | `lupetto-explorer:container-check`, image ID `sha256:31671d925ba24719a3de129dfef849f1f506051402430a045849b5ad689b80c6`; `docker image inspect` reported **92,372,054 bytes** (88.1 MiB). This is Docker's reported image size, not a compressed registry-transfer estimate. |

The first APK-based image exposed an actual compatibility bug: Lupetto accepted only `GitVersion: 1.4.5`, whereas the Wolfi package prints `v1.4.5`. It failed before creating a workspace or publishing. `RequireApkoVersion` now permits those **two exact spellings only**; `go test ./internal/build -run TestRequireApkoVersionExactReleaseSpellings -count=1` passed, including rejection of `1.4.50`, `v1.4.50`, development suffixes, adjacent versions, extra `v`, empty version, and a failed probe even with otherwise-valid output. No tool version requirement was relaxed.

All runtime verification containers used image-default UID/GID **65532:65532**, `--cap-drop=ALL --security-opt=no-new-privileges`. `/proc/self/status` showed `CapEff: 0000000000000000`. There was no privileged mode, added capability, Docker socket, or daemon in the image. `lupetto doctor` found apko and Cosign and exited **1 solely for missing Docker**; doctor checks PATH rather than versions. This is intentional and acceptable: the dashboard always passes `--no-load`, and the following real image-only build succeeded.

The disposable registry used `docker run -d --rm --name lupetto-container-registry-check -p 127.0.0.1:60881:5000 -p 127.0.0.1:60882:8080 registry:3`. Explorer/CLI containers used `--network container:lupetto-container-registry-check`: `127.0.0.1:5000` was therefore registry loopback **inside** the container, preserving Lupetto's plain-HTTP guard. Both host-published ports were loopback-only. Synthetic products tracked `busybox-static` selector `"1"`; an empty `{}` Docker config file and products file were mounted read-only at `/etc/lupetto/docker/config.json` and `/etc/lupetto/products.yaml`, with `DOCKER_CONFIG=/etc/lupetto/docker`. No existing registry credentials, keys, signing configuration, or password were used.

Commands and observed outcomes (each CLI command was `docker run --rm` with the network/security/mount settings above and `--entrypoint lupetto`):

| Command / interaction | Result |
| --- | --- |
| `LUPETTO_REGISTRY=127.0.0.1:5000 LUPETTO_REPOSITORY=tests/container/cli lupetto build busybox-static 1 --no-load --json` | Exit 0; `busybox-static@1.38.0-r2`, signed-index SHA-256 `5cf2bd255d67b8b49742a43280cc876535e1275d9f4e759c90e3527ebbdcac27`; version-6 record: build `completed`, load `skipped`, validated SPDX, publication `published`, `verified: true`. Immutable digest `sha256:5c483fc03b8750a406b25485a6e7d34574a1f8da55268e080939430e3f272104`. Signing/attestation skipped. |
| Same environment, `lupetto status --products /etc/lupetto/products.yaml --json` | Exit 0; track `current`, newest digest exactly the published digest, three installed APK identities. |
| Image **default entrypoint and CMD**, mounted products/config/cache volume, repository `tests/container/dashboard` | `/healthz`: 200 `ok`; `GET /?format=json`: `buildsEnabled: false`; valid-CSRF same-Origin `POST /builds`: 403. |
| Same entrypoint with CMD replaced by `--listen 0.0.0.0:8080 --products /etc/lupetto/products.yaml --enable-builds` | Initial overview `not-built`. `curl --silent --show-error --max-time 30` POST with `Origin: http://127.0.0.1:60882`, form `csrfToken` read from JSON, `package=busybox-static`, `selector=1`: 303 to `/jobs/1`. JSON job reached `succeeded`, exit 0, version-6 record: build `completed`, load `skipped`, publication `published`, `verified: true`. |
| `GET /jobs/1?format=json`, then `GET /?format=json` without manual refresh | BusyBox `1.38.0-r2`; signed-index SHA-256 `47b46fe2ee80cdf214959cb9a5b8304bcb0eec4b541dc57d1fc0410d6a3a572a`; published digest `sha256:25423aaac818f20224fa8e3fc80a788a84d815815e57921a8af31a5b9013219c`. Overview automatically became `current` at `2026-10-01T17:05:35.646856074Z` with the same newest digest. `/healthz`: 200; embedded overview HTML: 200. |

The dashboard mounted a fresh named volume at `/var/cache/lupetto`. Ownership was `65532:65532`, mode 0700; real evidence included `/var/cache/lupetto/lupetto/builds/image-2008221524/result.json`. `HOME=/var/cache/lupetto/home` and `XDG_CACHE_HOME=/var/cache/lupetto` put retained workspaces/cache on the declared volume. A reused/bind-mounted volume must have suitable ownership; the image does not start as root to repair operator mounts.

After the UI review fixes (`12ef02c`) and all-listener Host allowlist (`cde4ff0`) landed, the final image above was rebuilt and the complete smoke repeated, again with zero effective capabilities:

- Exact tool versions/checksum and doctor outcome were unchanged. CLI prefix `tests/container/final-cli`: build exit 0, `busybox-static@1.38.0-r2`, index SHA-256 `441b771c3dd15ee01da85f19d2cd5bd1cd0f17f1d379f0954d8d137ad8ab2cb8`, verified publication digest `sha256:d62b1dc69627d1c953c5dc91324a57b07784161adb2c8b64ad37b5f51ca55114`; CLI status exit 0, `current`.
- Final default-CMD instance: `/healthz` 200, builds disabled, valid same-Origin/CSRF build POST 403. `GET /?format=json` with `Host: attacker.example` returned **403**, confirming DNS-rebinding protection also covers the container's `0.0.0.0` listener rather than trusting its port mapping.
- Final enabled instance used fresh prefix `tests/container/final-dashboard`: initial `not-built`; same curl POST received 303; job 1 `succeeded`, exit 0, same BusyBox/index identity above, verified publication digest `sha256:ad95deef3c974342102b6c27f68b96d7a53068abda415fb4cb50da0931d0f0c3`. Automatic overview refresh at `2026-10-01T17:20:50.819749779Z` became `current` with exactly that digest. HTML and `/healthz` were 200. Retained `image-535253055/result.json` was mode **0600**, UID/GID 65532:65532, on the reused cache volume.

Final gates after those checkpoints: `gofmt -w internal/build/build.go internal/build/apko_version_test.go`, sequential `go test ./... && go test -race ./...`, and `git diff --check` all passed. The rebuilt image was then exercised as above, not assumed equivalent to the earlier image. Owned Explorer/default containers and the registry were stopped/removed; `docker container inspect` of every verification name exited 1, and `docker volume rm lupetto-container-cache-check` exited 0. The failed initial builder container was also removed. Only the locally built image is intentionally retained; runtime products/config/JSON/logs were outside the checkout, not committed. No image push to any external registry was performed.

The final image's `--help` exited 0 and included the repeatable `--allowed-host`, builds-disabled default, products path, and background-refresh options. Syntax-only `bash -n` validation passed for all ten README Bash blocks; container guide/verification targets and anchors were checked. These checks did not execute the generic production-registry examples.

Limitations: linux/amd64 only; anonymous loopback HTTP publication, not authenticated production HTTPS/signing/transparency-log proof; no credential-helper or private-key interoperability was claimed. The image includes the upstream Cosign binary but no signing was requested. A successful BusyBox build proves the exercised apko lock/build/publication path works unprivileged, not every package selection or runtime recipe. No extra runtime privileges were required. Container UI proof here is curl/JSON plus HTML 200, not a second browser run. Live Wolfi dependency/index availability can change; exact APK pinning fails closed if removed, and the base-plus-tool recipe is not an archived, byte-reproducible dependency snapshot.

### Combined container (redesign round)

Observed 2026-10-01 on darwin/amd64 with Docker Desktop **4.37.2**, host Docker client/server **27.4.0** (containerd image store), targeting **linux/amd64**. This supersedes the checkpoint-5 products path, missing-Docker doctor result, and publish-only dashboard assumptions; the earlier evidence remains historical.

`docker build --platform linux/amd64 -f Containerfile -t lupetto-explorer:container-redesign-check .` exited **0**. The image retains the digest-pinned Go **1.27.1** builder and Wolfi base recorded above, exact `apko=1.4.5-r0`, SHA-256-verified upstream Cosign **v3.1.3**, and adds exact signed Wolfi `docker-cli=28.5.0-r0` from `https://packages.wolfi.dev/os`. Docker 28.5.0 was deliberately selected from the available Wolfi versions and exercised against the existing 27.4.0 daemon; no daemon is installed.

| Inspection | Observed result |
| --- | --- |
| `docker image inspect lupetto-explorer:container-redesign-check` | Image ID `sha256:1da3f097af56a0e5d5d422dfe48b11f5c27012addc3bf1976ee0b9da3be1e6eb`; **111,697,886 bytes (106.5 MiB)**, Docker-reported size, not compressed transfer size; linux/amd64. |
| Image config | User `65532:65532`; entrypoint `/usr/local/bin/lupetto-explorer`; CMD `--listen 0.0.0.0:8080 --products /etc/lupetto/products/products.yaml`. |
| In-container `apko version` | `GitVersion: v1.4.5`, Go 1.27.1, linux/amd64. |
| In-container `docker --version` | `Docker version 28.5.0, build 887030f`; socket-free invocation does not require a daemon. |
| In-container `cosign version` / `sha256sum /usr/local/bin/cosign` | `v3.1.3`, Go 1.26.4, linux/amd64; `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`. |
| `docker run --rm --cap-drop=ALL --security-opt=no-new-privileges --entrypoint sh lupetto-explorer:container-redesign-check -c 'id; grep CapEff /proc/self/status; apko version; docker --version; cosign version; sha256sum /usr/local/bin/cosign; lupetto doctor'` | Exit **0**; UID/GID 65532; `CapEff: 0000000000000000`; doctor found **all three** tools. Doctor checks PATH, not daemon connectivity. |

Synthetic fixtures were created outside the checkout: `<tmp>/products/products.yaml` held `version: 1` and `busybox-static` selector `"1"`, with an empty `{}` Docker config at `<tmp>/config.json`. On this Desktop bind mount, the disposable products directory/file were writable by UID 65532 (modes 0777/0666); these permissive throwaway fixture modes are **not** the Linux deployment recommendation. The README instead documents ownership by UID/GID 65532. No existing Docker credentials, signing keys, passwords or registry credentials were mounted. Every runtime container used `--cap-drop=ALL --security-opt=no-new-privileges`; none used root UID, privileged mode, or added capabilities.

The default and read-only instances used the image's entrypoint/CMD, no socket, a shared fresh named cache volume, and loopback-only ports:

```bash
# CHECK_ROOT denotes the disposable directory prepared above.
docker run -d --rm --name lupetto-redesign-default-check \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:60912:8080 \
  --mount "type=bind,src=$CHECK_ROOT/products,dst=/etc/lupetto/products" \
  --mount "type=bind,src=$CHECK_ROOT/config.json,dst=/etc/lupetto/docker/config.json,readonly" \
  --mount type=volume,src=lupetto-redesign-cache-check,dst=/var/cache/lupetto \
  lupetto-explorer:container-redesign-check
```

The read-only counterpart was `lupetto-redesign-readonly-check` on `127.0.0.1:60913:8080` with `,readonly` appended to the **directory** mount. `curl --silent --show-error --max-time 30` fetched `/?format=json` (including its CSRF token) and build-detail `?format=json` routes; the real browser fetched `/images`. POSTs sent `Origin: http://127.0.0.1:<port>` and `--data-urlencode csrfToken=<token-from-JSON>` plus `package=xz` and `selector=5`.

| Scenario | Observed result |
| --- | --- |
| Default no-socket `GET /?format=json` | `buildsEnabled: false`; inventory kind `images` v1; `docker.available: false`, reason `Docker is unreachable or image listing failed`, empty Docker images. With no registry configured, status separately reported its explicit registry/repository configuration error. |
| `POST /products/add`, then `/products/remove` | Both **303**; actual host file gained `xz` selector `"5"`, then lost it, preserving the BusyBox track. These were CLI-owned atomic directory replacements, not in-container-only writes. |
| Default `POST /builds` with valid CSRF/Origin and `mode=local` | **403**, builds disabled. |
| Read-only directory `POST /products/add` | **400**; rendered `read-only file system` plus `The products file and its directory must be writable (mount the directory, not a single file)`. Host products bytes remained unchanged; read views worked. |
| Real headless Chromium, `/images` at 1440×960 | Rendered `DOCKER Unavailable` and `Docker isn’t available` explanation, not “zero images”; screenshot inspected, no browser errors. |

An initial synthetic fixture omitted `version: 1` and was correctly rejected; after correcting it, the complete successful add/remove/read-only sequence above was repeated. One immediate POST during the host's fixture rewrite also saw invalid YAML; subsequent reads and atomic CLI edits used the valid fixture. Neither fixture error is counted as a successful tracking check.

For the optional socket scenarios, the owned anonymous registry and enabled dashboard shared a network namespace, so `127.0.0.1:5000` was genuinely **loopback inside the container**:

```bash
docker run -d --rm --name lupetto-redesign-registry-check \
  -p 127.0.0.1:60914:5000 -p 127.0.0.1:60915:8080 registry:3
docker run -d --rm --name lupetto-redesign-enabled-check \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --network container:lupetto-redesign-registry-check \
  --mount "type=bind,src=$CHECK_ROOT/products,dst=/etc/lupetto/products" \
  --mount "type=bind,src=$CHECK_ROOT/config.json,dst=/etc/lupetto/docker/config.json,readonly" \
  --mount type=volume,src=lupetto-redesign-cache-check,dst=/var/cache/lupetto \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  --group-add 0 \
  -e LUPETTO_REGISTRY=127.0.0.1:5000 \
  -e LUPETTO_REPOSITORY=verify/container-redesign \
  lupetto-explorer:container-redesign-check \
  --listen 0.0.0.0:8080 --products /etc/lupetto/products/products.yaml --enable-builds
```

Desktop's mounted **VM** socket was UID/GID **0:0**, mode **0660** (`ls -ln` / `stat -c '%g %a'` inside a throwaway container). UID 65532 without the supplementary group got permission denied from `docker version`; adding **only** `--group-add 0` made it reachable. The enabled instance remained UID/GID 65532 with supplementary group 0 and zero effective capabilities. **Socket access still grants host-root-equivalent control**; neither non-root UID nor dropped capabilities constrains the remote Docker daemon. This is an explicitly opted-in trusted smoke instance, not the default deployment.

| Command / interaction | Observed result |
| --- | --- |
| `docker exec lupetto-redesign-enabled-check lupetto images --json` | Exit **0**, `docker.available: true`; all **16** pre-existing Lupetto Docker image IDs and all **18** tags matched host `docker image ls --format '{{json .}}' 'lupetto/*'`. |
| Same-origin CSRF `POST /products/add`, `package=xz selector=5` | **303**; host products file updated, enabling an exact inventory join for the local build. |
| `curl ... -H 'Origin: http://127.0.0.1:60915' --data-urlencode csrfToken=<token> --data-urlencode package=xz --data-urlencode selector=5 --data-urlencode mode=local http://127.0.0.1:60915/builds` | **303** to `/builds/1`; its `?format=json` reached `succeeded`, exit **0**, `xz@5.8.4-r0` / x86_64, version-6 result, validated SPDX, build `completed`, load `loaded`, publication/signing/attestation `skipped` despite registry environment. |
| Host `docker image inspect lupetto/xz:5.8.4-r0-amd64 lupetto/local:build-476693960` | Both tags resolved to **the same loaded host image** `sha256:383b5f63c67036c7e1f06b6e3866b7c73fadeb35ae420c404bcf5f615d45091a`, linux/amd64. |
| `GET /?format=json` after local build | `xz` version row joined that Docker ID with the retained successful build record; local identity source `build-record`; registry remained `not-built` (correctly distinct from local presence). |
| Same curl build POST with `package=busybox-static selector=1 mode=publish` | **303** to `/builds/2`; JSON reached `succeeded`, exit **0**, `busybox-static@1.38.0-r2`; load `skipped`, publication `published`, `verified: true`; signing/attestation skipped. |
| Automatic `GET /?format=json` refresh after publication | BusyBox became **`current`** with newest digest exactly `sha256:add4c6f69b7490b0aae38f5c25112447993e2f19d019b5b7064275eed677d864`, matching the build's verified immutable publication reference under `127.0.0.1:5000/verify/container-redesign/busybox-static`. No manual refresh needed. |
| Real Chromium `/images` on the enabled container | `DOCKER Connected`; BusyBox registry version/up-to-date verdict and XZ `5.8.4-r0` in Docker / local-only verdict rendered; screenshot inspected; no browser errors. |

Both builds used signed-index SHA-256 `c7a4940f7e77bed2ab706e09f45832452afb55118c0b27350d3a02eb79b5c788`. Local OCI digest was `sha256:cd6e2a2ad40a5bfc3cefa02830f66c76db5ef3a925c49459f70eb6fa2e8e815c`; local validated SPDX SHA-256 `60c4ac484f435c8e5300b2b5fa132ef1082103c7a302d0b737d3b651d289bc9b`. Published BusyBox validated SPDX SHA-256 was `ffa468517d57a0eb2a07d22da005b54612919a3baaa7f857ba595f1a7c221844`. Both `result.json` files under `/var/cache/lupetto/lupetto/builds/image-{476693960,2953465368}/` were UID/GID **65532:65532**, mode **0600**; cache root was mode **0700**.

Cleanup: `docker stop` removed all four `--rm` runtime containers (default, read-only, enabled, registry); individual `docker container inspect` checks exited **1** with `No such container`. `docker volume rm lupetto-redesign-cache-check` exited **0**. `docker image rm lupetto/xz:5.8.4-r0-amd64 lupetto/local:build-476693960` exited **0**, deleting the loaded test image; inspecting its ID then exited **1**. A before/after comparison confirmed **all pre-existing Lupetto image IDs and tags were unchanged**. Only the rebuilt combined image is retained locally. No external registry/image publication, production credentials or signing were involved.

Limits: linux/amd64 and this Docker Desktop/containerd-store combination only; Linux socket-GID instructions are documented but not exercised on a native Linux host. No authenticated HTTPS registry, signing/transparency-log, credential helper, macOS host-endpoint bind variant, other browser/architecture, or runtime service recipe is claimed. Live Wolfi index/dependency availability remains mutable despite exact tool pins. The browser look confirms actual container rendering, not a repeat of the full redesign interaction suite.

Final gates ran **serially after container verification**: `go test ./...` passed (47.9 seconds), then `go test -race ./...` passed (34.5 seconds), all packages. No Go files changed, so no formatting rewrite was needed. README Bash syntax checks passed for all **15** fenced Bash blocks; the two new verification command blocks also passed syntax checking. All **110** relative links/anchors in the three changed guides passed validation; `git diff --check` passed. Staged whitespace/secret checks and content review were performed before the single commit. These syntax checks do not execute the generic production examples.

## Release evidence

Once code exists, run the following in each implemented Go module. A CLI release requires its applicable checks, not a completed Explorer:

```bash
go test ./...
```

Record the exact command and outcome, tool versions, exercised host/target architectures, CLI-help checks, real build/registry outcomes, and browser observations. Report unexercised scenarios explicitly.

Re-read all published flags and examples against parsing/help. Check relative documentation links and ensure no registry vendor is required. Never copy real credentials or secret-bearing command output into verification records.

## Registry inspect redesign checkpoint

On darwin/amd64 with native apko 1.4.5, an isolated `registry:3` was started with `docker run -d --rm --name lupetto-inspect-severity-verify -p 127.0.0.1:55217:5000 registry:3`. The standalone inspect checkpoint executable was built from an isolated source snapshot to exclude concurrently edited severity/products files. Discovery (`discover --json openssl`) observed signed APKINDEX SHA-256 `04046c7881081fc9a9d0b19487634a29ef8a090e403166feb261a563f7015d3f` and available `openssl@3.6.1-r0`.

`build openssl --apk-version 3.6.1-r0 --no-load --json --registry 127.0.0.1:55217 --repository verify/inspect` exited 0 with an unreachable `DOCKER_HOST` and isolated empty Docker configuration. It retained workspace `image-219582448` and published verified immutable reference `127.0.0.1:55217/verify/inspect/openssl@sha256:01ed339715e7e7cca834d57d4e3adbdea755efc81050fe2379fba4f7ba68ecc9`. `inspect --json <that-reference>` exited 0 with `kind: inspect`, `version: 1`, annotation identity `openssl@3.6.1-r0` / `x86_64`, actual creation time, and **9 packages**. `status --products <isolated-file> --registry 127.0.0.1:55217 --repository verify/inspect --json` exited 0, reported `update-available` with five missing-fix groups, and its installed list was exactly equal to inspect's packages.

`go test ./internal/status ./cmd/lupetto -run 'TestInspect|TestRegistryAnnotations' -count=1` passed. Authenticated in-process registry tests cover annotated and unannotated images, immutable reads, cached reruns with no blob/tag requests, sanitized authentication failures, invalid/tag/credential-bearing references, JSON and invocation/failure exit semantics. Existing installed-reader tests retain compressed/config/diffID validation, overlays/whiteouts, private cache checks and bounds. Live verification is anonymous loopback HTTP, not production HTTPS or signature verification; no SPDX extraction or vulnerability scan is claimed.

Post-reboot checkpoint gates ran sequentially on the exact exported staged tree: `go test ./... -count=1 -timeout=180s` and `go test -race ./... -count=1 -timeout=180s` both passed (all packages), as did the staged whitespace/secret-marker check. Earlier attempts were interrupted by the host's macOS process-policy daemon outage; they are not counted as passing gates. After Docker Desktop restarted, `docker rm -f lupetto-inspect-severity-verify` reported `No such container`, confirming the original disposable registry no longer existed.

## Products management (redesign round)

The products-only staged tree was exported with `git checkout-index --all --prefix=<temporary-tree>/` so concurrently developed inspect/severity work was excluded. `gofmt` on the owned Go files and `go test ./internal/products ./internal/status ./cmd/lupetto -run 'TestProducts' -count=1` passed. On that exported tree, `go test ./...` passed; the first `go test -race ./...` hit the pre-existing Explorer forced-kill timing assertion (`TestShutdownAndForcedKill/true`), and an immediate full race rerun passed. The CLI was built with `go build -o <temporary>/lupetto ./cmd/lupetto`.

Against a disposable products directory, the actual executable's `products add cmd:curl 8.2 --products <file> --json` exited **1** with empty stdout when the file was absent. Adding `--create` exited **0**, returned kind `products`, version 1, and created the file. Repeating the pair exited **0** with `changed: false` and `Already tracked; no changes`; `list --json` and whole-package `remove --json` exited **0**, the latter returning `products: []`. With mode 0400 on the file or mode 0500 on its directory, adding a new pair exited **1**, with explicit read-only diagnostics and empty stdout.

Hermetic regressions verify comment round-trips (document, version, package, selectors), preserved product order and mode 0640, selector and whole-package removal, final-product removal/listing, duplicate-argument/existing-track idempotence (byte-identical no-op), separate entries for the same package, malformed names/selectors/YAML, unknown fields/document versions, missing-file consent, read-only file/directory failures, no leftover temporary file, no changed original on failure, and exit-2 empty stdout. Edits use YAML nodes, a same-directory temporary file, fsync and rename. No network or Docker operation was invoked. Concurrent editor serialization, ACL preservation, and retaining comments attached to removed nodes are not claimed.

## Advisory severity redesign checkpoint

The corrected contract never treats secdb co-listing as alias identity. After the host reboot, `go build -o /tmp/lupetto-severity-cli ./cmd/lupetto` built the standalone CLI. A fresh owned `registry:3` used `docker run -d --rm --name lupetto-inspect-severity-postreboot -p 127.0.0.1:55217:5000 registry:3`. `discover --json openssl` observed signed APKINDEX SHA-256 `4953b43e5ff05eeb41ee163974e4de3f4d43f9aa4fd30b1f08724b9ca0d8e53a` and available exact `3.6.1-r0`.

`build openssl --apk-version 3.6.1-r0 --no-load --json --registry 127.0.0.1:55217 --repository verify/severity` exited 0 with an unreachable `DOCKER_HOST` and isolated empty Docker configuration. It retained workspace `image-2322911871` and published verified immutable reference `127.0.0.1:55217/verify/severity/openssl@sha256:1c3c2717ca3d3e49ae99466f082fd8f53a264ae8077662b87e7bb1e188bec129`. Severity observations used a **fresh disposable HOME cache**, with `NVD_API_KEY` absent, and this actual command twice:

```bash
/tmp/lupetto-severity-cli status --products "$PRODUCTS_FILE" \
  --registry 127.0.0.1:55217 --repository verify/severity --json
```

`PRODUCTS_FILE` was the isolated products file tracking `openssl 3.6`. Both runs exited 0 as status **version 2**, retained `update-available`, and listed five missing-fix groups and nine installed packages. The first took 24.78s including index/feed/registry work; the second took 27.59s. The 20s severity budget does not cover other status work. Counts below are **unique advisory IDs across missing fixes and the one global malformed-key warning**, not advisory occurrences: 57 IDs total (54 installed-image IDs plus three global `opa-envoy` warning IDs).

| Observation | GitHub own (`ghsa`) | NVD (`nvd-cvss-v3.1`) | True OSV alias (`osv-alias:CVE-2025-22866`) | Unknown/pending | Failed fetches |
| --- | ---: | ---: | ---: | ---: | ---: |
| First status | 28 | 0 | 0 | 29 | 0 |
| Second status | 28 | 4 | 1 | 24 | 0 |
| Follow-up `--severity-budget 0` | 28 | 4 | 1 | 24 | 0 |

The first run resolved advisory-owned GitHub facts before NVD rate waits could consume the budget. The second preserved **all 28 prior cache files byte-for-byte**, including original fetch timestamps, and added five entries. The true OSV alias was `GO-2025-3447` → `CVE-2025-22866`; the CVE itself retained its NVD source, while the independently fetched co-listed GHSA retained its own GitHub source. No `osv`, `ghsa-alias`, v4.0, v3.0 or v2 source was needed/resolved in this scoped live run; those fallback/metric cases are covered hermetically. Cache-only coverage was identical, with no severity fetches; files were mode 0600 and the directory mode 0700. `inspect --json <published-digest>` returned packages exactly equal to the second status's installed list. Human cache-only output showed 4 critical / 18 high / 6 medium / 2 low / 24 unknown installed-image advisory IDs, one explained global warning, and the non-fatal enrichment summary.

Manual source checks: [NVD CVE-2026-2673](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-2673) contained v3.1 secondary metric **MEDIUM**, score 6.5, matching `medium` / `nvd-cvss-v3.1`; [NVD CVE-2026-14456](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-14456) contained v3.1 secondary metric **HIGH**, score 7.5, matching `high` / `nvd-cvss-v3.1`. [GitHub GHSA-wj64-gh9j-xm82](https://api.github.com/advisories/GHSA-wj64-gh9j-xm82) identifies CVE-2026-2673 but its own unreviewed severity is **high**; OSV returned 404 for that GHSA. The corrected output therefore reports **high** / `ghsa` for the GHSA and **medium** / `nvd-cvss-v3.1` for the CVE, preserving the independent assessments rather than transferring the CVE's severity.

Corrected focused proof: `go test -race ./internal/status ./cmd/lupetto ./internal/explorer -run 'TestSeverity|TestStatus|TestCompatibilityAndRecordParsing|TestInspect' -count=1 -timeout=180s` passed. Hermetic HTTP fakes cover NVD metric/version/primary precedence and v2 field location, own OSV/GitHub precedence, true OSV/GitHub aliases, independent co-listed advisories, NVD-only CVE-alias traversal, GO alias-only/cycle handling, legacy co-list-cache rejection, skipped vector-only records, advisory-first budget ordering, pending/cancellation, 7d/1h cache expiry, unchanged cached timestamps, private/symlink cache handling, response bounds and 403/429 handling. Integration tests verify maximum severity, every ID including unsupported unevaluated IDs, summary counts, empty arrays, cache-only mode, unchanged states/reachability and Explorer v2 decoding/rejection of v1. Independent read-only review of the corrected source found no actionable in-scope issue.

Final severity checkpoint gates ran sequentially on the exact exported staged tree, excluding concurrently edited Explorer redesign files: `go test ./... -count=1 -timeout=180s` and `go test -race ./... -count=1 -timeout=180s` both passed (all packages). Owned Go files were formatted with `gofmt`; staged whitespace/secret-marker checks passed. Relative documentation links/anchors and all README Bash blocks passed source/syntax validation; this does not execute production examples.

Limitations: severity is cached best-effort metadata, not scanning or state derivation; pending coverage fills on later runs. Vector-only OSV facts are skipped rather than guessed, and upstream assessments can disagree. There is no alias inference from secdb fix grouping. The key-enabled rate was tested with a synthetic header/fake service, not a real NVD key. Production HTTPS registry authentication and signature verification are not established by this anonymous loopback run. `docker rm -f lupetto-inspect-severity-postreboot` succeeded after all observations, removing the owned registry.

## Local inventory (redesign round)

Observed on darwin/amd64 → linux/amd64 with native apko 1.4.5 and the existing local Docker Unix-socket context. Publication/signing `LUPETTO_*` settings were removed from the smoke subprocess environment, so neither build contacted a registry or invoked Cosign. `go build -o <temporary>/lupetto ./cmd/lupetto` produced the actual binary. Commands and observations:

| Command | Exit | Observed result |
| --- | --- | --- |
| `build busybox-static 1 --json` | 0 | Version-6 succeeded record, workspace `image-2540244885`, load `loaded`, both readable and unique references confirmed. |
| `build busybox-static 1 --no-load --json` with unreachable `DOCKER_HOST` | 0 | Version-6 succeeded record, workspace `image-2597739611`, load `skipped`, no local image ID or confirmed references. |
| `images --json` | 0 | Kind `images`, version 1; **48 retained records**, **22 unsupported older versions**, Docker available with **15 distinct image IDs**. |
| `images --json` with `DOCKER_HOST=unix:///tmp/lupetto-images-unreachable.sock` | 0 | Same record paths/history; `docker: {available: false, reason: "Docker is unreachable or image listing failed", images: []}`. |

Both builds selected `busybox-static@1.38.0-r2` / `x86_64` from signed index SHA-256 `e46122abf406a3f3a0f7ac5c0e86e9466fbae51d4e209b0f252a082f72deb2a6`. The loaded image ID was `sha256:f3994f215facb4201eac72a63576bb7ae543bd0513b4fe9fba822a6c0bca5965`; inventory reported tags `lupetto/busybox-static:1.38.0-r2-amd64` and `lupetto/local:build-2540244885`, creation `2026-10-01T19:34:57Z`, byte size **1,254,717**, and exact APK identity from the build record. The no-load unique reference `lupetto/local:build-2597739611` was absent from all Docker tags.

Independent `docker image ls --no-trunc --filter 'reference=lupetto/*' --format '{{.ID}} {{.Repository}}:{{.Tag}}'` matched **every inventory image ID and Lupetto tag exactly**, not just the new BusyBox image. For both new workspaces, the inventory's embedded record equaled both build stdout and retained `result.json`; each `spdx.present` was true and independently rehashing its document matched the reported SHA-256. Both entries had retained actual build timestamps. Workspaces and the explicitly loaded image remain local; no inventory cleanup, retagging or deletion was performed.

After formatting the owned Go files, `go test ./internal/images ./cmd/lupetto -run TestImages -count=1 -timeout=120s`, `go test ./... -timeout=180s`, and `go test -race ./... -timeout=180s` all passed. Hermetic fixture/fake-Docker tests cover result/failure outcomes, ordering, unknown versions without parsing their fields, retained request/selection/evidence/stages, read-only `image ls`/`inspect` argv, tag deduplication, record-ID and unambiguous-readable-tag identity, conflicting/fallback/unique-only unknown identities, optional/unreachable/missing Docker versus an available empty daemon, malformed records/IDs/metadata, record count/file-size bounds, bounded Docker output and suppressed stderr canaries, deleted/changed/outside-workspace SPDX, cancellation, JSON schema, human table presence and exit-1/2 empty stdout. An oversized Docker-output regression exposed embedded `bytes.Buffer.ReadFrom` bypassing the writer cap; the buffer is now a named field and the full gates passed after that fix.

Host macOS executable-policy startup delays initially timed out Go/Docker commands; after recovery, the successful gates/scenarios above ran serially with other agents' full gates paused. An optional subsequent standalone `docker image inspect` timed out at process launch and is not additional evidence; inventory metadata here is the successfully parsed Docker response. This proof is local inventory, not signature verification, a vulnerability scan, a retention service or immutable Docker-tag identity. The current combined container still has no opt-in Docker CLI/socket configuration; that later deployment work remains unchecked.

## Explorer backend information-architecture redesign

The backend retains the CLI-only boundary and requires exact JSON kinds/versions: status v2; discover/products/images/inspect v1; live build stdout and supported retained records v6. `gofmt` on the owned backend files and `go test ./internal/explorer -count=1` passed. Hermetic fake-CLI tests cover every new page route and tab, server-side search/filters/verdicts, unique advisory severity counts, exact APK name/version/architecture joins, digest inspect caching and incompatible documents, sibling-selector and registry/local package comparisons, persistent/live history deduplication, seven-stage live/record progress (including log truncation), products edits and refreshes, empty tracking, read-only errors, duplicate fields, and local versus publish argv/environment isolation. SPDX tests reject outside-cache/workspace paths, traversal, file/directory/cache-root symlinks, unvalidated/mismatched evidence and checksum changes; existing Host/Origin/CSRF, single-build, cancellation and escaping regressions remain passing.

After the backend and rebuilt UI sources were final, the serial whole-tree gates `go test ./... -count=1 -timeout=180s` and `go test -race ./... -count=1 -timeout=180s` both passed, including the CLI/Explorer dependency-boundary tests. No other full suite or Docker build ran concurrently.

A final SPDX safety review additionally covered a regular document being replaced by a FIFO after inventory: the confined open is nonblocking and checks the actual opened object's regular-file type, so a special file cannot indefinitely hold an HTTP worker. The focused race command `go test -race ./internal/explorer -run '^TestDashboard(RoutesAndEvidence|SPDXPathSafety|SiblingCompareAndRootSymlink|SPDXRejectsFIFO)$' -count=1 -timeout=60s` passed; both whole-tree gates above passed again with the fix.

Backend review regressions were addressed without UI changes: live publication now follows the CLI's actual push/readback stage strings; unreadable inventory rows accept an unknown/empty modification time; shared inventory/inspect reads use single-flight loads outside cache locks (server-owned timeouts, nonblocking shell snapshots, and invalidation during an in-flight read); products mutations are serialized per server; `cosign-version` failures mark Sign while unknown failure stages mark no invented stage; failed/skipped NVD requests leave CVEs pending and uncached, with OSV fallback allowed only after NVD successfully reports no severity. `go test -race ./internal/explorer -run '^TestDashboard' -count=1 -timeout=120s` and `go test -race ./internal/status -run '^TestSeverity' -count=1 -timeout=120s` passed, including concurrent reads, client cancellation, shutdown, overlapping tracking POSTs, malformed-history timestamps, actual stage strings, and NVD retry/cache precedence.

The review-fix whole-tree gates `go test ./... -count=1 -timeout=180s` and `go test -race ./... -count=1 -timeout=180s` both passed serially, also covering the concurrently completed Docker unknown-versus-empty template fixes.

Real smoke used separately built binaries (`go build -o <temporary>/ ./cmd/lupetto ./cmd/lupetto-explorer`), isolated HOME/cache and empty Docker configuration, native apko 1.4.5, Docker 27.4.0, and an owned `registry:2` started with `docker run --detach --rm --name lupetto-explorer-backend-registry --publish 127.0.0.1:0:5000 registry:2` (assigned `127.0.0.1:55000`). Explorer listened on `127.0.0.1:8114`, enabled builds, and inherited that registry plus repository `backend-smoke/images`; Docker used the existing local Unix socket. No external registry, credential, signing key or remote infrastructure was used.

| Scenario | Observed result |
| --- | --- |
| Start with `version: 1; products: []`, `GET /?format=json` | Explicit `empty: true`, Docker available; no misleading registry comparison failure. |
| Same-origin CSRF-protected `POST /products/add`, `package=openssl`, `selector=3.6` | Redirected to `/?tracked=openssl`; the real products YAML contained the new track and status refreshed. |
| `POST /builds`, `package=openssl`, `apkVersion=3.6.1-r0`, `mode=publish` | Job succeeded; resolve/build/validate completed, load skipped, publication published and verified, sign/attest skipped. Registry digest `sha256:12263cdde8853533c904c69a9645d9c710ce85bed195441d7000171fbb8fbfbc`. |
| `POST /builds`, `package=openssl`, `apkVersion=3.6.5-r1`, `mode=local` while registry environment remained configured | Job succeeded; Docker load `loaded`, readable and unique references confirmed, publication/sign/attest skipped. Local image ID `sha256:c815b3907ca2f3ff138087a874aaffa6697259111494bcbb99a21c1099027d9e`. |
| `GET /?format=json` after both builds | One `openssl/3.6` track, Update available. Exact `3.6.5-r1` row joined one local Docker image and one retained build; `3.6.1-r0` row joined one registry image and one retained build. The critical summary counts tracks, matching `?filter=critical`, not individual advisory IDs. |
| Local build's `GET /builds/{record-id}/sbom` | HTTP 200, `application/spdx+json`, attachment disposition; downloaded SHA-256 `d029b0012d319c7797460355a1eeeda1608588c3985c5570bb5ed8b5af8ceb15` exactly matched CLI inventory evidence. |
| `GET /images/openssl/3.6?tab=compare&from=<registry-digest>&to=<local-build-key>&format=json` | Registry set had 9 packages, local validated SPDX set had 15: 6 added, 0 removed, 3 changed, 6 unchanged. The changed packages were openssl, libcrypto3 and libssl3 (`3.6.1-r0` → `3.6.5-r1`). |
| Restart Explorer with the same isolated cache | Both builds appeared as persistent history with `live: false`, identical stage outcomes and working SPDX download; raw logs were unavailable (`hasLog: false`). The same checksum and comparison counts were reproduced. |

The owned server exited cleanly on SIGTERM; the owned registry was stopped/auto-removed. Both Docker smoke tags were inspected to confirm the owned image ID before removing only those tags/image. Private temporary workspaces/proof remain outside the checkout. This is darwin/amd64 local-loopback evidence, not production HTTPS, arm64, signature/attestation verification, a vulnerability scan or durable SBOM storage. Local Docker-only images are not security-assessed; a same-version retained build is presence/evidence, not proof that a mutable Docker tag identifies that build. Deleted/changed SPDX is unavailable; registry-attestation downloads remain deferred.


## Rebuilt dashboard UI (redesign round)

The dashboard UI was rebuilt in the user-chosen direction **B · Pista** from `design/mockup/` (left rail, dense product ledger, monospace versions/digests, square corners, 4-segment severity meter plus text, light and dark via `prefers-color-scheme`; theme A and the mockup's sample data and theme switcher are not shipped). It remains server-rendered `html/template` (`internal/explorer/web/templates/{layout,partials,icons,images,image,catalog,builds,tracking}.html`) with one stylesheet and one progressive-enhancement script; the route/view-model/form contract is [`internal/explorer/web/CONTRACT.md`](../internal/explorer/web/CONTRACT.md). JavaScript only polls live build stages and the log, reloads after a status check or build ends, opens the "Track a product" `<dialog>` (the opener is a link to the plain `/products/track` page), and disables build buttons while a build runs; server text is inserted with text nodes only.

Observed 2026-10-01 on darwin/amd64, Go 1.27.1, native apko 1.4.5, Docker 27.4.0, and the tool's managed headless Chromium 150.0.7871.24. Setup: binaries from `go build -o <tmp>/bin/lupetto ./cmd/lupetto` and `./cmd/lupetto-explorer`; an owned `docker run -d --name lupetto-ui-registry -p 127.0.0.1:55200:5000 registry:2`; isolated `HOME`; only `LUPETTO_REGISTRY=127.0.0.1:55200`, `LUPETTO_REPOSITORY=lui/images`; no signing key or credentials. Three older OpenSSL images (`3.6.1-r0`, `3.6.2-r0`, `3.6.4-r0`) were first published with the CLI (`build openssl --apk-version … --no-load --json`, exit 0) so that real missing fixes with severities exist. Products: `openssl` `["3.6", "3.6.1"]`, `busybox-static` `["1"]`, `valkey` `["99.9"]` (deliberately unavailable). Explorer: `--listen 127.0.0.1:8188 --enable-builds`; a second instance on `:8189` without `--enable-builds`, with `LUPETTO_REGISTRY=127.0.0.1:1`, an unreachable `DOCKER_HOST` and a read-only products directory; a third on `:8190` with `products: []`.

Exercised in the browser:

- **Images:** summary tiles and filters (`?filter=critical` returned only `openssl 3.6.1`, matching the tile after the backend fix); per-track Registry/Local/Latest/severity meter (`openssl 3.6.1`: critical/high/medium/low/unknown counts plus "4 need another version"), verdict chips, primary POST actions; `valkey 99.9` rendered "Unable to compare" with the CLI error and "Unknown (track error)", never "None found"; Docker-only local images and build-record-only versions shown separately.
- **Image detail tabs** for `openssl 3.6.1` with the sibling switcher: overview (verdict, registry/local/recent builds, version strip), vulnerabilities (scope line, rebuild banner with action, five severity tiles, "Fixed by rebuilding" and "Needs another version" tables with one row per advisory ID, NVD/GitHub links, per-ID severity source, data note), packages (registry set with "Newer in Wolfi"/missing-fix columns; local build set with **Download SPDX (JSON)** — `fetch` of `/builds/record-…/sbom` returned 200 `application/spdx+json` with an attachment disposition and an SPDX document), compare (GET form; registry `3.6.1-r0` → registry `3.6.4-r0` showed 0 added, 0 removed, 3 changed — `libcrypto3`, `libssl3`, `openssl` — 6 unchanged; registry vs local build of the same version showed identical packages), builds.
- **Builds:** clicking **Build & publish** for `postgresql 17` (tracked through the dialog) redirected to `/builds/1`; stages advanced live (resolve done → build in progress) and the log streamed, then the page reloaded to Succeeded with publication reference/digest, SPDX link "validated against lock", inputs and the raw log behind its toggle. **Build locally** for `busybox-static 1.38.0-r2` on the catalog page advanced resolve → build → validate → load without a reload and finished with the Docker reference and image ID (publication/sign/attest "Skipped · not requested"). An `openssl 3.6` update cancelled after ~2 s showed Canceled, the side-effects warning, the Explorer diagnostic, build "Failed" and later stages "Not attempted · earlier stage failed". A retained record whose publication was interrupted showed "Failed at Publish", the failure error, the side-effects warning and "Digest not verified — not a confirmed publication". While a build ran, the Images page showed the building banner, the nav count, and every build button disabled with "Another build is running".
- **Catalog:** search (`openssl`, 54 matches), Tracked chip/Open, Track opening the dialog prefilled, per-package exact versions with both build modes; read-only instance rendered both buttons disabled and zero `/builds` forms.
- **Tracking:** dialog add (`postgresql 17`) redirected to `/?tracked=postgresql` with the confirmation banner. With JavaScript disabled (`page.setJavaScriptEnabled(false)`), "Track a product" navigated to `/products/track`; adding `valkey 9.1` and then **Stop tracking valkey 9.1** returned `/?tracked=valkey` and `/?untracked=valkey`, and the products YAML returned to its prior content. On the read-only products directory the page re-rendered with the CLI's "products directory is read-only" error.
- **States:** read-only/Docker-unavailable/registry-unreachable instance (both banners, red Registry and Docker rail indicators, every track in error with its CLI message, "not in registry" 0 because error tracks are not evidence of absence); empty products ("No products tracked yet" with Track/Browse actions); first check in progress ("Checking your images…", auto-reload).
- **Accessibility and layout:** Tab order skip link → brand → nav → Track → summary tiles → search → filter → Apply → products, each with a visible 3 px focus outline (the search field via its wrapper); Enter on "Track a product" opened the dialog with focus in the package field; Escape closed it and returned focus to the opener. At 390 px no page scrolled horizontally (`scrollWidth` 390 on nine pages); ledger rows and tables stack into labelled cards. Light and dark were captured for the main screens.
- **CSP:** a `securitypolicyviolation` listener installed by an init script recorded no violations on 14 pages (home with filters, all five tabs, error track, catalog list/search/package, builds list/detail, tracking) or during live builds; a deliberately injected inline script and `style` attribute were recorded, proving the listener.

Cleanup: every Explorer instance exited 0 on SIGTERM; `docker rm -f lupetto-ui-registry` succeeded and `docker container inspect` then failed. The locally loaded `lupetto/busybox-static:1.38.0-r2-amd64` image and the temporary HOME remain outside the checkout.

Screenshots: `/tmp/lupetto-ui-shots/*.webp` (real UI) next to `/tmp/lupetto-mockup-shots/b-*.webp` (mockup B, same viewport); not committed. Noticeable deviations from the mockup, all because the data is not available from the CLI contract or templates cannot compute it: no product descriptions and a two-letter mark from the package name; absolute dates instead of relative ages ("4 weeks ago"); the track dialog takes a package and free-text selectors instead of index-derived version checkboxes with a preview; the catalog lists packages flat with their newest version and an exact-version page instead of version-stream chips and a major-version family page; build rows have no duration or "started from"; image detail is one tracked version with a sibling switcher rather than one page with every track's panel; vulnerabilities list one row per advisory ID with its raw severity source; a registry outage appears as per-track errors (the CLI reports it per track) rather than one "Can't reach the registry" banner, and the rail's registry dot reflects the last comparison (`Shell.RegistryState`: red with "Last comparison had errors" whenever any track errored, including the unavailable `valkey 99.9`), not a separate health check; footer has no CLI version.

`TestEmbeddedTemplatesRenderRepresentativeModels` renders all seven page templates against full, empty, loading, error, read-only, building, live, partial-failure, canceled and unreadable-record models with hostile strings, and checks escaping, the absence of inline script/style/handlers, a CSRF field in every POST form, absent build/cancel controls when builds are disabled, both build modes, SPDX/compare/stage wording and advisory links. `TestEmbeddedTemplatesDistinguishTrackErrorsFromEmptyResults` checks that error tracks never render as empty results and that a clean-looking result always carries the feed limitations. `TestEmbeddedStaticAssetsServed` checks the assets (no `innerHTML`, single Pista theme).

Gates on the combined backend/UI tree: `gofmt -l internal/explorer cmd` clean, `node --check internal/explorer/web/static/app.js` passed, `go test ./internal/explorer -run TestEmbedded` passed, and `go test ./... -count=1` followed by `go test -race ./... -count=1` passed (run once, serially).

Frontend review follow-up (five minor findings on `6f6ab29`), re-checked in the same headless Chromium against freshly built binaries, a new owned loopback `registry:2` (one CLI-published `busybox-static 1.38.0-r2`) and a registry-unreachable instance; both Explorer instances exited 0 on SIGTERM and the registry was removed (`docker container inspect` then failed):

- Catalog initial discovery failure: Explorer used a wrapper that fails only `discover --json` (synthetic message) and `exec`s the real CLI otherwise. `/catalog` issued exactly one `format=json` poll, replaced the loading state with "Loading failed … Polling stopped" plus the CLI error as text (`role="alert"`), and made no further requests or reloads over the next 16 s.
- Error track without images (registry `127.0.0.1:1`): the overview's Registry column read "Registry contents could not be determined because of the error above." and never "Nothing published yet".
- Overview of a clean track ("Missing fixes … None found") now carries the security-data note; the note appears exactly once on the Overview and Vulnerabilities tabs.
- Accessibility tree (Puppeteer `accessibility.snapshot`) at 1440 px and 390 px: the main navigation links are named Images, Catalog, Builds even when their labels are visually collapsed, and both product tables expose all seven column headers while the second table's header row is visually hidden (1 px). No horizontal scroll at 390 px; no CSP violations.

Backend review follow-up (P3): the image overview's Local Docker panel and the Images ledger say "No images in local Docker" only when `Shell.DockerState` is `available`; an unknown (`""`, e.g. inventory failed before any successful load) or `unavailable` state reads "Local Docker state unknown or unavailable" / "Docker state unknown", covered by four template cases; `go test ./...` and `go test -race ./...` (run serially by ExplorerBackendV2 with this change in the tree) passed. New template/static regressions cover the discovery-failure poll attributes, the error-track registry wording, exactly one data note on both tabs, and the absence of `display: none` on nav labels and table headers. Gates after the fixes: `gofmt -l` clean, `node --check` passed, `go test ./... -count=1` and `go test -race ./... -count=1` passed (serial, heavy slot announced).

Limitations: one browser engine (Chromium), one host; no Firefox/Safari or screen-reader pass; the 1 MiB log-trim path was not re-exercised with oversized output in this round; no signing key was used, so signed/attested outputs are covered by the template test only. The container is unchanged (still listed separately in the plan).

## Dashboard publish builds also load locally (2026-10-01)

This implements the [approved loading contract](decisions.md#dashboard-redesign-and-local-inventory-user-approved-2026-10-01): `POST /builds` in publish mode reads the current inventory snapshot without a new CLI call, retains `request.load` and optional `request.loadReason` on the job, and omits `--no-load` only when Docker is available. Shell JSON exposes `publishLoad` and `publishLoadReason` for pre-submit labels/help; build-item JSON exposes `mode`, `load` and `loadReason`. Running stages follow the stored loading decision; finished stages remain the CLI record's outcomes. Local mode still loads and excludes publication/signing environment settings. The existing post-build inventory invalidation makes newly loaded images visible without waiting for the 15-second TTL.

Focused regression command `go test ./internal/explorer -run 'TestDashboardPublishLoad|TestDashboardBuildModes|TestDashboardLocalEnvironment|TestDashboardEmptyTracking|TestCompatibilityAndRecordParsing' -count=1` passed. Coverage includes available/unavailable/unknown Docker argv and immutable decisions, no inventory CLI call during POST, publication/signing environment inheritance, local-only environment suppression, running publish+load stages, decoding a load+publish+sign+attest version-6 record, authoritative final stages including load failure before publication, JSON fields, and inventory invalidation/re-read.

Real smoke used serial `go build -o <temporary>/lupetto ./cmd/lupetto` and `go build -o <temporary>/lupetto-explorer ./cmd/lupetto-explorer` on darwin/amd64 → linux/amd64, native apko 1.4.5, Docker client/server 27.4.0 (containerd store), and Cosign v3.1.3. The owned registry was started by `docker run --rm -d --name lupetto-load-publish-smoke-n7qml_9p -p 127.0.0.1:59126:5000 registry:3`. It was anonymous and bound only to loopback; `DOCKER_CONFIG` pointed to an isolated `{}` configuration. A disposable Cosign key and no-service signing config were generated outside the checkout with `cosign generate-key-pair --output-key-prefix <temporary>/local` and `cosign signing-config create --out <temporary>/local-signing-config.json`, with `COSIGN_PASSWORD` supplied only through the process environment. Explorer inherited registry `127.0.0.1:59126`, repository `tests/load-on-publish/images`, that key/config and explicit `LUPETTO_COSIGN_ALLOW_HTTP=true`; products tracked `busybox-static` selector `"1"`. Both builds were started by same-origin CSRF-protected HTTP `POST /builds`, `package=busybox-static`, `selector=1`, `mode=publish`, returning 303 to `/builds/1`.

| Scenario | Observed result |
| --- | --- |
| Explorer at `127.0.0.1:59127`, `DOCKER_HOST=unix://$HOME/.docker/run/docker.sock` | Initial shell JSON: Docker `available`, `publishLoad: true`; running load stage `pending`. Job succeeded with exit 0, `request.load: true`, build `completed`, load `loaded`, publication `published` and verified, signing `signed`, attestation `attested`. |
| Loaded image evidence | Selected `busybox-static@1.38.0-r2` / x86_64 from signed index SHA-256 `d6f632e5e144164d0412f6c4cde1da140e15ded0688e9c0098bed96ad4a816ba`. Local references `lupetto/busybox-static:1.38.0-r2-amd64` and `lupetto/local:build-774179193` identified `sha256:5d092208b440150576a3b17eb8080547332f90292a177780e989e513f0d9acbb`. `docker image ls --no-trunc --format '{{json .}}' lupetto/busybox-static:1.38.0-r2-amd64` confirmed that ID. The immediate post-build inventory JSON contained that same ID, both tags and the exact APK identity. |
| Publication and SPDX evidence | Published immutable digest `sha256:b30c610576c582ecc35838ca2f4022da08c96b1b85d75c4006e4071ca21c419c`; validated architecture SPDX SHA-256 `094c46a0811beb29f7a1e1bd0c6387c714a801a5deff4058ec7e866f47c5e81d`. |
| Explorer at `127.0.0.1:59128`, `DOCKER_HOST=unix:///tmp/lupetto-load-publish-unreachable-n7qml_9p.sock` | Initial shell JSON: Docker `unavailable`, `publishLoad: false`, reason `Docker is unreachable or image listing failed`. The job retained the identical reason and `request.load: false`; it succeeded with exit 0, load `skipped`, publication `published` and verified, signing `signed`, attestation `attested`. Published digest `sha256:1687584da7ed13fbb4c7a1970fc0fffeda1ac308d89c13e15a85e6c8325ca41c`; validated SPDX SHA-256 `2ef02ade687579655152eef002de62a802f1b8a2560fa97baf7f10bdd9ac90cf`. |
| Trusted-key local verification of both builds | `cosign verify --key <temporary>/local.pub --allow-http-registry --insecure-ignore-tlog <immutable-reference>` and `cosign verify-attestation --key <temporary>/local.pub --allow-http-registry --insecure-ignore-tlog --type spdxjson <immutable-reference>` each exited 0 for both digests. Independently decoded attestation subjects matched the published digests; both predicates exactly matched the retained validated architecture SPDX JSON. |

Cleanup: both owned Explorer processes exited 0 on SIGTERM; the owned registry was stopped and auto-removed, confirmed by a failing `docker container inspect`. The user's pre-existing readable BusyBox tag was restored to its original ID `sha256:17549144ce5297a0ba93966bbe685bc23e28620af7278640c0d3bf8a2a64fbd6` before the test's unique tag/image was removed; a subsequent inspect confirmed the restored ID and absence of the test's unique reference. The temporary keys, signing/Docker configurations, binaries and the two owned cache workspaces (`image-774179193`, `image-3059637561`) were removed. The user's LAN deployment and port 8080 were untouched. This is isolated local HTTP/no-service signing proof, not production HTTPS, TUF/Rekor/transparency-log, arm64 or other Docker-store proof.

Final combined backend/UI gates: `gofmt -w` on the changed Explorer Go files, then serial `go test ./... -count=1 -timeout=180s` and `go test -race ./... -count=1 -timeout=180s` both passed, including the new template/live-stage regressions. The initial full-test invocation failed only the existing products-file-mode assertion because a prior command had left the shared process environment at umask `077` (`0640` creation became `0600`); repeating the gates with child-process umask `022` passed without a source change. No heavy job ran concurrently.

UI verification on the same source tree (`ab535ec` plus the UI committed as `2eb9e82`) used headless Chromium, independently built real binaries, an owned anonymous loopback `registry:3` at `127.0.0.1:59209`, empty Docker client configuration, and four Explorer instances on `127.0.0.1:18471`–`18474`. Two used the real local Docker socket and two used an unreachable socket; two delayed the real CLI build by 12 seconds solely to observe live polling. No Cosign key was configured in this separate UI run.

- Images, image-detail actions/header/empty state, and catalog help displayed “also loads into local Docker” with Docker available; with Docker unavailable they displayed “publish only: Docker unavailable” and the inventory reason. Template regressions also covered unknown Docker availability.
- A real catalog publish of `wolfi-baselayout@20230201-r30` with Docker available finished with Load “Loaded”, Publish “Published”, Docker reference `lupetto/wolfi-baselayout:20230201-r30-amd64`, and Inputs “publish requested · no signing · Docker load requested”. While running, Load read “Waiting” and Mode said it also loads into local Docker.
- Real publish-only builds of `busybox-static@1.38.0-r2` and `wolfi-baselayout` with unreachable Docker finished with Load “Skipped · Docker is unreachable or image listing failed”, Publish “Published”, and Inputs explaining the no-load reason. That reason persisted across JavaScript live polls on both build detail and the Builds “Running now” card while resolve/build advanced.
- A `securitypolicyviolation` listener on every checked page reported no CSP violations; a deliberately injected inline script triggered it, confirming the listener. `go test ./internal/explorer -run TestEmbedded -count=1` and `go test ./internal/explorer -count=1` passed. The new `TestEmbeddedTemplatesShowPublishLoadDecision` covers pre-submit labels/help, live and finished stages, unknown Docker, history without a decision reason and the running-build card. Independent read-only frontend implementation review found no blockers; escaping, CSP, CSRF and accessible text remained intact.

UI-smoke cleanup removed all four owned servers, its registry/container volume, loaded `wolfi-baselayout` and unique build tags, and seven owned build workspaces. The pre-existing BusyBox tag remained at `sha256:17549144ce5297a0ba93966bbe685bc23e28620af7278640c0d3bf8a2a64fbd6`; the user deployment and port 8080 remained untouched.

After the UI commit `2eb9e82` landed on backend commit `ab535ec` and the independent frontend review was clean, the required single rebuild `docker build --platform linux/amd64 -f Containerfile -t lupetto-explorer:load-on-publish .` succeeded (68.51 seconds). `docker image inspect lupetto-explorer:load-on-publish --format '{{.Id}} {{.Os}}/{{.Architecture}} user={{.Config.User}} size={{.Size}}'` reported image ID `sha256:dc76c1b5d382fea6c1e558d7ce5d14e76fa8e5ac4eac52c3cb5e7c3d8b4d53ce`, `linux/amd64`, configured user `65532:65532`, size `111698927` bytes. The build compiled both real binaries serially and verified the pinned Cosign download checksum. The new image tag is retained; no running deployment was replaced or restarted. The behavior/browser smoke above used native binaries from the same source, not a new container deployment.

## Production Harbor registry and public Rekor verification (2026-10-02)

This exercises the [production registry decision](decisions.md#production-registry-verification-and-signature-status-user-approved-2026-10-02) against a real HTTPS registry with real authentication. The user authorized pushing, signing, and attesting to the private Harbor project `lupetto` only.

**Environment.** darwin/amd64 → linux/amd64; Go 1.27.1; native apko 1.4.5; Docker client/server 27.4.0; Cosign v3.1.3. Binaries were built with `go build -o <temporary>/bin/ ./cmd/...`. Registry: Harbor v2.15.2 (`goharbor/harbor-core:v2.15.2`) at `<private-registry>`, private project `lupetto` (20 GiB quota), repository prefix `lupetto/images`. Harbor presented a publicly trusted certificate for `<private-registry>` (Let's Encrypt on the LAN ingress; Google Trust Services at the Cloudflare edge) and was verified by the host trust store with no TLS exception.

**Network path.** Public DNS resolves the name to two Cloudflare edge addresses. From the operator LAN, `curl --resolve <private-registry>:443:<address> https://<private-registry>/v2/` returned the expected 401 for 12/12 requests to one edge address and to the LAN ingress `<LAN ingress address>`, but only 3/12 to the other (TCP resets). `crane ls` and the first `status` attempt failed with resets on that address, reported by Lupetto as the sanitized `registry tag listing failed`. The operator added `<LAN ingress address> <private-registry>` to the host `/etc/hosts`. Every result below used that path with normal TLS verification. This is an operator-network workaround, not a Lupetto change.

**Authentication through a credential helper.** `~/.docker/config.json` uses `credsStore: desktop` (macOS Keychain). The user ran `docker login <private-registry> -u 'robot$lupetto+push' --password-stdin` for a project-scoped Harbor robot (push/pull, artifact read/list, tag list/create). `docker-credential-desktop list` showed `https://<private-registry>` → `robot$lupetto+push`; no secret was printed or retained. Note: a process without access to the user's GUI session could not write to the login Keychain (`User interaction is not allowed`), so the login had to be run from the user's terminal; Lupetto itself only reads the helper.

| Check | Observed result |
| --- | --- |
| `lupetto status --json --products <busybox-static "1"> --registry <private-registry> --repository lupetto/images` with the helper, before any push | Exit 0; track `not-built` (missing repository in the private project). |
| Same with `DOCKER_CONFIG=<empty directory>` | Exit 0; track `error`, `registry tag listing failed (HTTP 401; UNAUTHORIZED)`. Anonymous reads of the private project are refused. |
| `lupetto build busybox-static 1 --registry <private-registry> --repository lupetto/images --json` (no signing inputs) | Exit 0, version-6 record `succeeded`: selected `busybox-static@1.38.0-r2`/x86_64 from signed index SHA-256 `79ed0ac1d3f6cf17d4879a570f4409461ad1e4d3efbdde036fc336ba2dac296b`; loaded `sha256:8c1107f7ea624121e730e7a725642625218fdf0b4642a26755b19fa7fdc371e1`; published and verified `<private-registry>/lupetto/images/busybox-static@sha256:bb5fb0a1e28c6d2824426d23a4a950f4c46a28df3ae7e4711a096decbeaca229`; signing and attestation `skipped`. |
| Production signing build: same command plus `--cosign-key <key outside repository>`, `COSIGN_PASSWORD` only in the process environment, no signing config and no HTTP allowance (upstream TUF/Rekor defaults) | Exit 0 in 62 s, record `succeeded`: loaded `sha256:2bca5165e9d3019c13406fc2f9c6a6719f7244ad9d7ed9f819d7cf9e7e4a891f`; published and verified `…/busybox-static@sha256:51d58ea221442872592d82765d212048a9c925a5c61fd37aca6c6772f2b5fd72` (tag `1.38.0-r2-amd64-build-1646028280`); signing `signed`; attestation `attested`. A literal search for the password in the JSON record and captured stderr found 0 matches. |
| `cosign verify --key lupetto.pub <immutable reference>` (no insecure flags) | Exit 0: “claims were validated”, “existence of the claims in the transparency log was verified offline”, “verified against the specified public key”. Both returned claims name `docker-manifest-digest` `sha256:51d58ea2…`. |
| `cosign verify-attestation --key lupetto.pub --type spdxjson <immutable reference>` | Exit 0 with the same three checks. The decoded in-toto statement has predicate type `https://spdx.dev/Document` and the single subject `<private-registry>/lupetto/images/busybox-static` with `sha256` `51d58ea2…`. The decoded predicate equals the retained `sbom/sbom-x86_64.spdx.json` as parsed JSON; that file's SHA-256 `1b5d504201c8e96fcbd124664a3011a08f9eecad54c28578ae0c9091c552b758` equals `evidence.spdxSHA256`. |
| Storage and transparency log | `cosign tree` showed one `https://sigstore.dev/cosign/sign/v1` and one `https://spdx.dev/Document` artifact, both as OCI referrers (artifact type `application/vnd.dev.sigstore.bundle.v0.3+json`, subject `sha256:51d58ea2…`). Each Sigstore bundle carries one DSSE 0.0.1 transparency-log entry with an inclusion proof and checkpoint plus one RFC 3161 timestamp. The public log at `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=…` returned entries 3050708878 (signature, integrated 2026-10-02T07:40:06Z) and 3050711464 (attestation, 07:40:15Z). These entries are public and permanent. |
| Unsigned image `…@sha256:bb5fb0a1…` | `cosign verify` exit 10, `no signatures found`; `cosign verify-attestation` exit 1, `no matching attestations`. |
| Wrong key (separately generated pair) against `…@sha256:51d58ea2…` | Both commands exit 1: `failed to verify log inclusion: transparency log certificate does not match`. |
| `lupetto status --json` after both pushes | Exit 0, version 2: track `current`; both images listed by annotations (newest `sha256:51d58ea2…`), 3 installed packages, `artifactCount` 0 (the untagged referrers are not listed as tags). |
| `lupetto inspect --json …@sha256:51d58ea2…` | Identity `busybox-static` `1.38.0-r2` `x86_64`, 3 packages. |

**Finding for signature status.** Cosign v3.1.3 stores both the image signature and the SPDX attestation as DSSE bundles, and `cosign verify --key` returned **both** as claims (the second with `critical.type` `https://spdx.dev/Document`). Exit status 0 of `cosign verify` therefore does not alone prove an image signature: an attestation-only image could pass it. The signature-status command must require a verified claim of type `https://sigstore.dev/cosign/sign/v1` naming the digest.

**Dashboard against Harbor.** Binaries were built from commit `273b4d6` in a separate detached worktree. `lupetto-explorer --listen 127.0.0.1:18480 --products <copy of the four-product LAN file> --lupetto-binary <built lupetto> --enable-builds` ran natively. It inherited `LUPETTO_REGISTRY=<private-registry>`, `LUPETTO_REPOSITORY=lupetto/images`, `LUPETTO_COSIGN_KEY=<production key>` and `COSIGN_PASSWORD` from the environment, and used the same `desktop` credential helper.

- `/healthz` returned 200. The Images page compared `<private-registry>/lupetto/images` with the Wolfi index: `busybox-static 1` showed registry `1.38.0-r2` with 2 images and verdict Up to date; nginx 1.30, openssl 3.6 and postgresql 17 showed Not in registry.
- A same-origin, CSRF-token `POST /builds` with `package=openssl`, `selector=3.6`, `mode=publish` returned 303 to `/builds/1`. That build succeeded with exit 0, and every stage reported Done, Loaded, Published, Signed or Attested. It loaded `lupetto/openssl:3.6.5-r1-amd64` (`sha256:59d1275e2ffaf2deaca57738ba0f280cd4182e492a829003987ba0e9ad8eab78`) and published `<private-registry>/lupetto/images/openssl@sha256:8c5b41b664533f862cb286be025dcf5b149fdb2bb4f569726c5c88044b54d7d1`.
- Independent `cosign verify --key` and `cosign verify-attestation --key --type spdxjson` both succeeded with transparency-log verification. They returned sign and SPDX claims for that digest; the decoded predicate equalled the retained 63-package `sbom-x86_64.spdx.json`.
- Headless Google Chrome (`--headless=new`, 1440×1100) screenshots of `/` and `/builds/1` showed the refreshed state: openssl 3.6 with registry `3.6.5-r1`, Up to date. The build detail showed Signature Signed and SBOM attestation Attested. The server was stopped with SIGTERM.

This is the CLI-backed dashboard before signature status existed; its Signed/Attested labels come from the build record, not from registry verification.

Limitations: one registry product/version (Harbor v2.15.2) and one host combination; public Rekor with a key (no keyless/Fulcio identity, no private Sigstore); Cloudflare path bypassed on the operator host as described. The containerized LAN deployment against Harbor is not yet recorded here. Registry signature status (`lupetto verify` and the dashboard) is recorded in [signature status evidence](#signature-status-lupetto-verify-and-dashboard-2026-10-02).

## Signature status: lupetto verify and dashboard (2026-10-02)

This exercises the [signature-status decision](decisions.md#production-registry-verification-and-signature-status-user-approved-2026-10-02) against the [production Harbor images](#production-harbor-registry-and-public-rekor-verification-2026-10-02) and an owned loopback registry. Binaries were built from the working tree that became commits `d0ba01a` (CLI) and `e9c1448` (Explorer). Trust was the production public key (DER SHA-256 `e40a60bb039a613bbfc92ac6a21d5607ecf071129dc4809b4505cefb7d055b7b`, reported as `trust.publicKeySHA256`); registry reads used the `desktop` credential helper. No password or private key was used for verification.

| Check | Observed result |
| --- | --- |
| `lupetto verify --json --cosign-public-key lupetto.pub <private-registry>/lupetto/images/busybox-static@sha256:51d58ea2…` | Exit 0 in 4 s, empty stderr: `transparencyLog: verified`; signature `signed` (1 artifact); attestation `attested`, predicate type `https://spdx.dev/Document`, SBOM SHA-256 `ec3c88a1…`, 17 SPDX packages. |
| Same for the unsigned `…/busybox-static@sha256:bb5fb0a1…` | Exit 0: `unsigned` / `absent`, 0 artifacts each (Cosign not run). |
| Same for the UI-built `…/openssl@sha256:8c5b41b6…` | Exit 0: `signed` / `attested`, 63 SPDX packages. |
| BusyBox digest with a separately generated wrong public key | Exit 0: `invalid` / `invalid` (“Cosign verify rejected the artifacts (exit 1)”), fingerprint of the wrong key reported. |
| `--sbom-out <new file>` on the BusyBox digest | File mode 0600, SHA-256 equal to the reported `sbom.sha256`; as sorted parsed JSON it equals the predicate decoded from the earlier independent `cosign verify-attestation` output, whose predicate equalled the retained SPDX. |
| Legacy simple-signing: owned `registry:3` on loopback, `cosign sign --new-bundle-format=false --use-signing-config=false --tlog-upload=false --allow-http-registry` with a throwaway key | `sha256-<digest>.sig` tag returned 200; `lupetto verify --cosign-allow-http` reported `signed` / `absent`, `transparencyLog: skipped-local`; with a wrong key `invalid` (exit 12). Registry, key, and workspace were removed. |

**Dashboard.** `lupetto-explorer --listen 127.0.0.1:18481 --products <copy of the four-product LAN file> --lupetto-binary <built lupetto>` ran natively with `LUPETTO_REGISTRY=<private-registry>`, `LUPETTO_REPOSITORY=lupetto/images`, and `LUPETTO_COSIGN_PUBLIC_KEY` set to the public key; builds were disabled.

- `?format=json` reported `shell.signatures.enabled: true`; after the background checks `signaturesPending` was false and the newest BusyBox and OpenSSL images were `signed`, `attested`, `transparencyLog: verified`, with that key fingerprint.
- Headless Google Chrome (`--headless=new`) at 1400 px: Images showed a **Signed** chip under the registry column of BusyBox 1 and OpenSSL 3.6. The BusyBox detail listed `sha256:51d58ea22144` as Signed with “SBOM attested · 17 packages”, the check time, key `e40a60bb039a`, and a download link, and `sha256:bb5fb0a1e28c` as Unsigned with “No SBOM attestation”. The same page at 390 px kept every chip readable. (The page header buttons and tabs overflow at that width; this predates and is unrelated to signature status.)
- `GET /images/busybox-static/1/sbom/sha256:51d58ea2…`: 200 in 4 s, `Content-Type: application/spdx+json`, `Content-Disposition: attachment; filename="lupetto-busybox-static-1.38.0-r2-51d58ea22144.spdx.json"`, the CSP/nosniff headers, bytes identical to the CLI `--sbom-out` file; no `lupetto-explorer-sbom-*` directory remained in `TMPDIR`. After the review fixes the OpenSSL download returned `Content-Length: 51672` and the expected SHA-256 `a9d4aaeb…`. The unsigned digest returned 409; a disallowed `Host` returned 403.

**Gates.** `gofmt -l .` empty; `go test ./... -count=1` passed (a first run under full parallel load timed out two unrelated Explorer polling tests at their 5 s wait, `TestDashboardEmptyTrackingAndLiveStagesRetained` and `TestLiveLogsTruncationCancellationAndHistory`; `go test ./internal/explorer` alone and the repeated full run passed); `go test -race ./... -count=1` passed.

Limitations: `verify` uses Cosign's default trust, so a custom signing config cannot be verified on a non-loopback registry; Cosign failures that match no outage pattern are reported `invalid` (Explorer re-checks them after minutes). The containerized LAN dashboard against Harbor was not run. The build workspaces of the Harbor runs were removed from `~/Library/Caches/lupetto` on 2026-10-02 at about 09:59 local time by an unidentified process (re-running the `cmd/lupetto`, `internal/status`, and signing `internal/build` tests with marker files did not reproduce it); the SPDX comparisons above rely on copies and hashes taken before that.

## Compose file (2026-10-02)

The root `compose.yaml` documented in [Compose](../README.md#compose) was exercised on darwin with Docker 27.4.0 and Docker Compose 2.31.0, with a placeholder registry (`registry.example.invalid`), an empty Docker config, a copy of a products file, a throwaway public key, no private key or password, and host port `127.0.0.1:18482`:

- `docker compose config -q` without `LUPETTO_REGISTRY` failed with “required variable LUPETTO_REGISTRY is missing a value”; with the env file it succeeded. Merged with an override like the README example, `environment` gained `LUPETTO_COSIGN_PUBLIC_KEY` and `COSIGN_PASSWORD: null` (taken from the invoking shell), and `command` was replaced.
- `up -d --build` with the override: the container ran as `65532:65532` with `CapDrop [ALL]`, `no-new-privileges:true`, restart `unless-stopped`, and a port bound only to `127.0.0.1`. `/healthz` with the allowed Host returned 200 and an unlisted Host returned 403. `?format=json` reported `buildsEnabled: true`, `shell.signatures.enabled: true`, and the configured registry/repository.
- The base file alone reported `buildsEnabled: false` and signatures not checked, with the missing-key reason. `down -v` removed the container, network, and test volume.

Not exercised: signing, the Docker socket override, or a real registry through Compose. The native and `docker run` evidence above covers those paths.

## Durable build evidence location (2026-10-02)

This exercises the [durable build evidence decision](decisions.md#durable-build-evidence-location-user-approved-2026-10-02) on darwin/amd64 → linux/amd64 with Go 1.27.1, native apko 1.4.5, and Docker 27.4.0. Every run used a scratch directory as `HOME`, `XDG_CACHE_HOME`, and `LUPETTO_DATA_DIR`, no registry, no signing, and no Docker daemon access; the scratch data was deleted afterwards.

| Check | Observed result |
| --- | --- |
| New CLI: `lupetto build busybox-static 1 --no-load --json` with `LUPETTO_DATA_DIR=<scratch>/data` | Exit 0, `succeeded`, `busybox-static@1.38.0-r2`/`x86_64` from signed index `bd7a2596…`. Workspace `<scratch>/data/lupetto/builds/image-2399381474`; `<scratch>/data`, `lupetto`, `builds`, and the workspace were all mode 0700; `lockPath`/`spdxPath` pointed into it, `spdxValidated: true`. Nothing was written to the isolated user cache's `lupetto/`. |
| Pre-change CLI built from `git archive HEAD` (commit `7bb496f`), same command and environment | Exit 0; workspace in the legacy root `<scratch>/home/Library/Caches/lupetto/builds/image-2519046598`. |
| New CLI `lupetto images --json`, same environment, unreachable `DOCKER_HOST` | Exit 0, `kind: images`, version 1, two `supported` records (legacy and data root), both `spdx.present: true`; Docker reported unavailable. |
| `LUPETTO_DATA_DIR=relative/data` | `images --json` exit 1 and `build … --no-load --json` exit 2, both with `invalid configuration: LUPETTO_DATA_DIR must be an absolute path, got "relative/data"` and empty stdout. |
| Native `lupetto-explorer` (builds disabled, empty products file), same environment | `/builds?format=json` listed both records with SPDX links; each `GET /builds/{id}/sbom` returned 200 `application/spdx+json` whose SHA-256 equalled that record's `spdxSHA256` (`3c46e0cc…` data root, `18a2684f…` legacy root). |
| `docker build --platform linux/amd64 -f Containerfile -t lupetto-explorer:durable-data .` | Exit 0, image `sha256:7e161120…`. Config volumes `/var/cache/lupetto` and `/var/lib/lupetto`; `XDG_DATA_HOME=/var/lib/lupetto`. In a throwaway `--rm` container: `uid=65532(nonroot)`, `/var/lib/lupetto` `drwx------ nonroot nonroot`, `images --json` exit 0 with empty history, and a relative `LUPETTO_DATA_DIR` exit 1 with the invalid-configuration error. |
| `docker compose config` (Compose 2.31.0) with placeholder required variables | Mounted named volumes `cache` → `/var/cache/lupetto` and `data` → `/var/lib/lupetto`, named `lupetto-cache` and `lupetto-data`; `LUPETTO_DATA_VOLUME=custom-data` renamed only the data volume. Compose was not started. |

Hermetic regressions: `internal/storage` (override, relative override rejected, per-OS defaults through an injected platform/environment, missing/relative bases, legacy root deduplication, leaf-package import check); `internal/build` (workspace directly under `<data>/lupetto/builds` with mode 0700, refusal below a symlinked builds root, data-root error before any workspace); `internal/images` (records from data and legacy roots merged newest first, legacy-only history, an aliased root read once, the 1,000-record bound spanning roots, relative override error); `cmd/lupetto` (relative override exits 2 before the build callback for `build` and `sbom`, `images` exits 1, help text); `internal/explorer` (HTTP SPDX download for builds in either root, refusal of a workspace outside both roots, of cross-root SPDX evidence, and of a symlinked legacy root while the data root still serves, relative override error, and the Explorer copy of the data-root rule). Explorer test helpers now isolate `HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `LOCALAPPDATA`, and `LUPETTO_DATA_DIR`; the real user cache and data directories were unchanged after the test runs.

**Gates.** `gofmt -l .` empty. `go vet` passed for `internal/storage`, `internal/images`, `internal/explorer`, `cmd/lupetto`, and `cmd/lupetto-explorer`; `go vet ./internal/build` reports only the existing unkeyed-composite findings in the unchanged `internal/build/registry_test.go` and passes with `-composites=false`. `go test ./... -count=1` passed. Under heavy unrelated host load (load average about 20 from other processes), `go test -race ./... -count=1` passed every package except `internal/status`'s `TestSeverityRateWaitHonorsBudget`, whose 30 ms budget also fails intermittently at commit `7bb496f` (2/10 with and 3/10 without `-race`); `go test -race ./cmd/lupetto ./internal/status -count=1` then passed. `TestSignatureCacheTTLAndBuildInvalidation` also failed intermittently at `7bb496f` (3/8 under `-race`): it waited for the CLI to start a check, not for the result that resets the cache to be stored. The test now keeps showing the page until the reset result is queued, and passed 12/12 under `-race`.

Not exercised: Linux and Windows default data roots on a real host (covered by the injected-platform tests only), and a container build/history across a restart with mounted named volumes.

## Unsigned publication warning and signing requirement (2026-10-02)

This exercises the [unsigned publication decision](decisions.md#unsigned-publication-warning-and-optional-signing-requirement-user-approved-2026-10-02) on darwin/amd64 → linux/amd64 with Go 1.27.1, native apko 1.4.5, Docker 27.4.0, a throwaway `registry:2` container on a random loopback port (`127.0.0.1:62986`), and headless Google Chrome 154 driven over CDP from Node 22. Every run used scratch `LUPETTO_DATA_DIR`/`XDG_CACHE_HOME` directories, a scratch `DOCKER_CONFIG` containing `{}`, all `LUPETTO_*` signing/publication inputs cleared except those named, no key, no password, and no remote registry. The registry container, Explorer, and Chrome were stopped afterwards.

| Check | Observed result |
| --- | --- |
| `lupetto build busybox-static 1 --no-load --registry 127.0.0.1:62986 --repository test/images` | Exit 0. The first stderr line was `lupetto: warning: publishing without signing: the image will be pushed with no Cosign signature or SPDX attestation; set --cosign-key / LUPETTO_COSIGN_KEY to sign, or --require-signing / LUPETTO_REQUIRE_SIGNING=true to refuse unsigned publication`, followed by the usual stage lines. Stdout: `busybox-static@1.38.0-r2`, `Immutable reference: 127.0.0.1:62986/test/images/busybox-static@sha256:186fccc1…`, `Image signing: skipped`, `SPDX attestation: skipped`. |
| Same with `--json` | Exit 0; the warning appeared exactly once on stderr. Stdout was one version-6 `succeeded` record with publication `published`, signing and attestation `skipped`, and contained no `warning`. |
| `LUPETTO_REQUIRE_SIGNING=true` with the same publish arguments; separately `--require-signing --json` | Each exited **2** with `lupetto: unsigned publication refused: signing is required (--require-signing / LUPETTO_REQUIRE_SIGNING) but no Cosign key is set (--cosign-key / LUPETTO_COSIGN_KEY)`, 0 bytes of stdout, no stage lines, and the builds directory listing unchanged (2 workspaces before and after). |
| `LUPETTO_REQUIRE_SIGNING=yes` with the publish arguments | Exit 2, `LUPETTO_REQUIRE_SIGNING must be true or false`. |
| `LUPETTO_REQUIRE_SIGNING=true lupetto build busybox-static 1 --no-load` (no publication) | Exit 0, no warning, `Registry publication: skipped`. |
| `lupetto-explorer --enable-builds --listen 127.0.0.1:63008` with `LUPETTO_REGISTRY=127.0.0.1:62986`, `LUPETTO_REPOSITORY=test/images`, no `LUPETTO_COSIGN_KEY`, products `busybox-static` `1` and `1.37` | `/?format=json` reported `shell.publishSigning: "unsigned"`. At 1440 px and with a 390 px device-metrics viewport, Images, the `busybox-static` catalog page, and the `1.37` image detail (publish action) showed “Published images will be unsigned.”; `scrollWidth` equalled the viewport width on every page and the notice's right edge was at 378 px on the 390 px viewport. The `1` detail, whose action was a local build, showed no notice. The only console error was the existing favicon 404. |
| Same with `LUPETTO_REQUIRE_SIGNING=true` | `publishSigning: "refused"`; the same pages showed “Publishing will be refused.” at both widths without horizontal scroll. A CSRF/Origin `POST /builds` (`mode=publish`, `busybox-static` `1.37`) returned 303; the job ended `failed`, exit code 2, no record, its log held the refusal line, and no workspace was created. |

Screenshots stayed in the session scratch directory (`overview-`, `catalog-`, `image-` × `unsigned`/`refused` × `desktop`/`390`, plus `image-local-action-390.png`); they are not committed.

Hermetic regressions: `internal/build` (`TestResolveSigningRequireSigning`: precedence, empty environment as unset, strict booleans, refusal only for keyless publication, the one-line warning text); `cmd/lupetto` (`require_signing_test.go`: flag parsing, refusal before any service call or workspace with failing fake services, invalid values exit 2, non-publishing and keyed builds proceed, `sbom` rejecting every flag form and ignoring the environment, and a real loopback-registry pipeline asserting the warning is the first stderr line exactly once and absent from stdout, the record, signed, and local builds); `internal/explorer` (`publish_signing_test.go`: state from presence only, notices on the served dashboard and JSON in the key/unsigned/refused/disabled states, template placement; the local-build environment test drops `LUPETTO_REQUIRE_SIGNING` and the publish test inherits it). Removing the refusal check or the local-build stripping made those tests fail.

**Gates.** `gofmt -l .` empty. `go vet` passed for `cmd/lupetto`, `cmd/lupetto-explorer`, and `internal/explorer`; `go vet ./internal/build` reports only the existing unkeyed-composite findings in the unchanged `internal/build/registry_test.go` and passes with `-composites=false`. `go test ./... -count=1` passed. `go test -race ./... -count=1` passed every package except the unchanged `internal/images`, where `TestImagesDockerUnavailableAndEmpty` or `TestImagesHistoryAndDocker` hit its 10 s fake-Docker timeout while unrelated host builds kept the load average between 35 and 88; `go test -race ./internal/images -count=1` and `-count=3` passed on their own.

Not exercised: signing (covered by earlier evidence; the warning is absent from signed builds in the pipeline test), the container or Compose with the new variable, and a real Harbor publish. An invalid `LUPETTO_REQUIRE_SIGNING` value in Explorer's environment shows the unsigned notice; the CLI then rejects the publish build with exit 2.

## Keyless signing option (2026-10-20)

This records the hermetic evidence for the [keyless signing decision](decisions.md#keyless-signing-with-an-identity-token-file-2026-10-20) on darwin/arm64 with Go 1.27.1. No Cosign, apko, Docker, registry, or Fulcio/Rekor service was invoked: every check below runs through the fake command adapter or the pure option resolver.

| Check | Observed result |
| --- | --- |
| `internal/build` `TestResolveSigningKeylessIdentityTokenFile` | A flag or environment token file enables signing with no key; a flag overrides the environment path; config, loopback consent, and `--require-signing` behave as with a key; a key and a token together, a nonexistent path, a directory, an explicitly empty flag, a token without publication, and loopback without consent are rejected before any work. |
| `internal/build` `TestSignAndAttestKeylessPassesTokenPathNeverTokenAndDisablesAmbientProviders` | The token file holds the signing canary; `sign` and `attest` received exactly `--yes --identity-token <path> --oidc-disable-ambient-providers` plus the immutable reference (and `--type spdxjson --predicate`), no argument equaled `--key`, and no argument contained the canary. |
| `internal/build` `TestResolveSigningDoesNotInspectSecretsOrOverriddenEnvironment` | Updated: `LUPETTO_COSIGN_IDENTITY_TOKEN_FILE` is the only environment name consulted when key, config, HTTP consent, and requirement are explicit; `COSIGN_PASSWORD` is still never read. |
| `cmd/lupetto` `TestParseBuildIdentityTokenFlag` | Separate and inline forms parse into `SigningFlags.IdentityTokenFile`; a missing value, a following flag as value, and duplicates are rejected. `sbom` continues to reject the flag with the other signing flags. |
| `internal/explorer` `TestPublishSigningState`, local-build environment tests | A set token file yields the same `key` state as a key (no unsigned or refused notice); an empty value is `unsigned`. Local-mode builds exclude `LUPETTO_COSIGN_IDENTITY_TOKEN_FILE` with the other publication/signing variables. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./... -count=1` passed.

Not exercised: a real Fulcio token exchange, Rekor entry, or registry push with a keyless signature; verification of a keyless signature by certificate identity; the container or Compose with the new variable. `lupetto verify` and the Explorer signature status still trust one public key and were not changed.

## Status rebuild signal (2026-10-20)

This records the evidence for the [status rebuild signal decision](decisions.md#status-rebuild-signal-2026-10-20) on darwin/arm64 with Go 1.27.1 (index architecture `aarch64`).

| Check | Observed result |
| --- | --- |
| `cmd/lupetto` `TestStatusExitCodeSignalsRebuildAndErrors` | All-`current` and empty track lists exit 0; any `not-built`, `update-available`, or `fixes-available` exits 3; any `error` exits 4, including alongside a rebuildable track; table and `--json` output are written in every case; the same documents exit 0 without the flag. |
| `cmd/lupetto` `TestParseStatus`, `TestStatusDispatchAndHelp` | A duplicate `--exit-code` and `--exit-code=true` are rejected; help names the flag. |
| Real `status` run, live signed Wolfi index and security feed, go-containerregistry in-memory registry on `127.0.0.1:5055`, empty repository `lab`, `--severity-budget 0` | Products `busybox-static ["1"]`: track `not-built`; exit 0 without the flag, 3 with `--exit-code` and with `--exit-code --json`, empty stderr. Products `busybox-static ["1", "999"]`: `not-built` plus `error` (`unavailable index version for track`); exit 0 without the flag, 4 with it, empty stderr. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./... -count=1` passed.

Not exercised live: exit 0 with `--exit-code` (needs a published current image; covered by the hermetic test), and a Tekton or other scheduler consuming the signal.

## Explicit target architecture (2026-10-20)

This records the evidence for the [explicit target architecture decision](decisions.md#explicit-target-architecture-2026-10-20). Hermetic checks ran on darwin/arm64 with Go 1.27.1; the real run used darwin/amd64 binaries on the x86_64 macintel host with apko 1.4.5, no Docker daemon, and a go-containerregistry in-memory registry on `127.0.0.1:5055`.

| Check | Observed result |
| --- | --- |
| `internal/build` `TestBuildIdentityAnnotationsAndScopedEpoch` | Now requests the non-host architecture: the index selection, `apko lock --arch`, `apko build --arch`, the `lupetto.apk.architecture` annotation, and the result all use the requested target. Forcing the pipeline back to the host lookup fails the test. |
| `cmd/lupetto` `TestTargetArchFlags` | `build`, `discover`, and `status` normalize `amd64`/`arm64` to `x86_64`/`aarch64`, in separate and inline forms; no flag leaves the host default; `riscv64`, empty, missing, and duplicate values are rejected. |
| `internal/status` `TestRunUsesRequestedArchitecture` | The architecture set by the CLI reaches the status comparison. |
| Real `discover --json busybox-static --arch arm64` | `architecture: aarch64` with the aarch64 APKINDEX checksum. |
| Real `build busybox-static 1 --arch arm64 --no-load --json --registry 127.0.0.1:5055 --repository lab` | Exit 0; record version 6 with `selection.architecture: aarch64` (`1.38.0-r3`), build `completed`, load `skipped` with readable reference `lupetto/busybox-static:1.38.0-r3-arm64`, publication `published` and `verified` at `…-arm64-build-…`; signing skipped (no key). |
| Independent `crane config` / `crane manifest` by digest | Config `linux` / `arm64`; OCI image manifest with `lupetto.apk.architecture: aarch64`. |
| Real `status --arch aarch64 --exit-code` | Track `current` at `1.38.0-r3` and exit 0; this is also the live exit-0 case for the [status rebuild signal](#status-rebuild-signal-2026-10-20). Host-architecture `status --exit-code`: `not-built`, exit 3. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./... -count=1` passed.

Not exercised: loading a foreign-architecture image into Docker, an arm64 host, foreign-architecture signing and attestation (the Cosign path is architecture-independent but was not run here), and a multi-architecture image index.

## Keyless identity verification (2026-10-20)

This records the evidence for the [keyless identity verification decision](decisions.md#keyless-identity-verification-2026-10-20) on darwin/arm64 with Go 1.27.1 and Cosign v3.1.3. The real checks were read-only against a public image signed by its publisher; nothing was signed or pushed.

| Check | Observed result |
| --- | --- |
| `internal/verify` `TestKeylessIdentityTrust` | Both Cosign calls receive `--certificate-identity-regexp … --certificate-oidc-issuer …` and no `--key`; `trust` echoes the policy without a key fingerprint; the matched claim's `Subject`/`Issuer` become `signature.identity`. |
| `internal/verify` `TestNewRequestTrustSelection` | No trust input, a key plus an identity, an identity without an issuer, an issuer alone, both identity forms, and an invalid regexp are rejected; an exact identity with an issuer is accepted. |
| `cmd/lupetto` `TestVerifyIdentityFlagsOverrideEnvironment` | A flag issuer combines with an environment identity; a key flag on top of an environment identity exits 2 with the exclusion message. Existing key-mode CLI and package tests pass unchanged. |
| `internal/explorer` `TestKeylessSignerIdentityIsCheckedAndShown` | With only `LUPETTO_COSIGN_CERTIFICATE_IDENTITY_REGEXP`/`…_OIDC_ISSUER` set, Explorer runs the check, reports `signed`, exposes `Signer` (no key fingerprint), and renders "signer …" on the image detail. |
| Real `lupetto verify --certificate-identity-regexp '^https://github.com/chainguard-images/images/' --certificate-oidc-issuer https://token.actions.githubusercontent.com cgr.dev/chainguard/static@sha256:fe55470f…d327` | Exit 0; transparency log `verified`; signature `signed` (1 legacy `.sig` artifact); SPDX `attested` (1 `.att`, 3 packages); signer `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`, issuer `https://token.actions.githubusercontent.com`. |
| Same digest, exact identity from `LUPETTO_COSIGN_CERTIFICATE_IDENTITY`/`…_OIDC_ISSUER`, `--json --sbom-out` | `trust` holds `certificateIdentity`/`certificateOIDCIssuer` and no key fingerprint; `signature.identity` as above; SBOM file mode 0600 matching the reported SHA-256 `d0a266c1…`. |
| Same digest with identity regexp `^https://github.com/someone-else/`, and separately with issuer `https://accounts.google.com` | Signature `invalid` (Cosign exit 12) and attestation `invalid` (exit 1) in both; exit 0 as a completed check. |
| `LUPETTO_COSIGN_PUBLIC_KEY=/nonexistent` plus `--certificate-identity`/`--certificate-oidc-issuer` | Exit 2, "verify trusts either a public key or a certificate identity, not both", before any key read or network access. |

| Real `lupetto verify --certificate-identity-regexp '^https://github.com/skel84/lupetto/' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/skel84/lupetto@sha256:d71271fc…831b` (the v0.1.0 release image, signed keylessly by this repository's release workflow) | Exit 0; transparency log `verified`; signature `signed` (1 artifact); signer `https://github.com/skel84/lupetto/.github/workflows/release.yml@refs/tags/v0.1.0`; SPDX attestation `absent` (the release workflow signs only). The same digest with regexp `^https://github.com/someone-else/` reported `invalid`. The image pulls anonymously. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./... -count=1` passed.

Not exercised: a keyless signature made by `lupetto build --cosign-identity-token` (the release image is signed by the workflow's own `cosign sign`), an OCI bundle referrer signed keylessly (the public image uses legacy `.sig`/`.att` tags), the Explorer page in a real browser, and the container or Compose with the new variables.

## Image entrypoint (v0.2.0)

This records the evidence for the [image entrypoint decision](decisions.md#image-entrypoint-2026-10-22), observed 2026-10-22 on darwin/amd64 (x86_64 host) with Go 1.27.1, apko 1.4.5, Docker 27.4.0, Google Chrome 155 (headless, driven over the DevTools protocol), and a disposable `crane registry serve` (crane 0.21.6) on `127.0.0.1:55310` with repository `e2e/images`, no credentials or signing key. All runs used a scratch `LUPETTO_DATA_DIR`; afterwards the registry, Explorer, and browser were stopped and the scratch data and browser profile deleted; the loaded test images stayed in the local Docker store.

**Unchanged output without an entrypoint (v0.1.0 digest stability).** Digests are not reproducible across separate builds in any release: each build pins a new creation time, and apko writes `/etc/apko.json` with the absolute keyring path inside the random build workspace. The proof therefore shows that, given v0.1.0's inputs, the new code renders the same apko inputs and apko composes the same image:

| Check | Observed result |
| --- | --- |
| `internal/build` `TestApkoConfigWithoutImageOptionsMatchesV010` | `apkoConfig` without options renders a literal copy of the v0.1.0 configuration byte for byte. Making the entrypoint block unconditional fails it. |
| `internal/build` `TestRunWithoutImageOptionsKeepsV010Inputs` | The real pipeline up to `apko build` (fake apko, fixed clock) writes exactly that configuration, passes the same `--build-date`/`--arch` arguments, and encodes a record with no `entrypoint` key; with an entrypoint it appends only the annotation line and the `entrypoint.command` block. |
| `internal/build` `TestBuildIdentityAnnotationsAndScopedEpoch` (unchanged) | Still sees exactly the six identity annotations without an entrypoint. |
| v0.1.0 binary (built from tag `v0.1.0` in a temporary worktree): `build busybox-static --apk-version 1.38.0-r3 --arch x86_64 --no-load --json` | Image digest `sha256:ab1fc825…c7d4`, `apko.yaml` SHA-256 `ca3c1159…cdaed2`, created `2026-10-22T15:27:11Z`, index `dd423977…701e`. |
| New `apkoConfig` (temporary, uncommitted test harness) for that workspace's key path, selection, created time, and index digest | Byte-identical to v0.1.0's `apko.yaml` (625 bytes). |
| `apko build` re-run with v0.1.0's `apko.yaml`, `lock.json`, `--build-date 2026-10-22T15:27:11Z`, and `SOURCE_DATE_EPOCH=1792682831` into a fresh directory | Digest `sha256:ab1fc825…c7d4`, identical to the v0.1.0 build. |
| New pipeline (`RunWith`, real apko, same index, clock fixed to the same second) in a new workspace | Succeeded; `apko.yaml` and `lock.json` equal v0.1.0's after replacing the workspace path. Its digest `sha256:e75914e1…` differs; comparing the two layers member by member (317 each) shows the only difference is `etc/apko.json`, whose `keyring` names the workspace path. Two v0.1.0 builds differ the same way. |

Status does not compare digests: a product without `entrypoint` and an image without `lupetto.image.entrypoint` compare equal, so existing tracks keep their state (unit and real checks below).

**Entrypoint behaviour.**

| Check | Observed result |
| --- | --- |
| `internal/imageconfig` tests | Validation accepts absolute clean paths with arguments (spaces, `#`, leading `-`) and rejects empty lists, relative, non-clean, and trailing-slash paths, empty elements, single quotes, control characters, invalid UTF-8, oversized elements, and more than 32 elements. Annotations round-trip; absent means none; malformed JSON, non-strings, empty arrays, and relative paths are errors. |
| `internal/build` `TestApkoConfigEntrypoint`, `TestCheckImageEntrypoint`, `TestRunRejectsInvalidEntrypointBeforeExternalBoundaries` | The config adds a seventh annotation and `entrypoint.command` with each element single-quoted. The image check accepts direct, relative- and absolute-symlinked (`/bin` → `usr/bin`, `/sbin` → `/usr/../usr/bin`), and hard-linked executables; rejects missing paths, directories, non-executable files, dangling and looping symlinks, and files used as directories with a message naming the package; and rejects a config entrypoint that differs from the request (including one set when none was requested, and a split element). An invalid request fails before any command runs. |
| `cmd/lupetto` `TestParseBuildEntrypoint` | Separate and inline forms keep order; a missing value, a separate value starting with `-`, an empty element, a relative path, and a single quote exit 2. |
| `internal/status` `TestRunImageConfigurationState`, `TestParseProductsEntrypoint` | `current` when both sides have none or match; `config-changed` when added, removed, or changed, and over `fixes-available`; `update-available` outranks it; a malformed annotation is a track `error`. The track's `entrypoint` appears only when requested. Products reject a scalar, empty, null, relative, numeric, boolean, nested, or quoted-apostrophe entrypoint. |
| `internal/products` `TestProductsKeepEntrypointAcrossMutations` | `add`/`remove` keep a product's entrypoint; a mutation of a file with an invalid entrypoint is rejected. With the real binary, `products add kyverno 2`, `add curl 8`, and `remove kyverno 1` on a commented file kept the comments and the entrypoint, and `products list --json` returned it only for kyverno. |
| `cmd/lupetto` `TestStatusExitCodeSignalsRebuildAndErrors` | `config-changed` exits 3, and 4 alongside an `error`. |
| `internal/explorer` `TestHTTPBuildUsesTrackedProductEntrypoint`, `TestHTTPBuildRefusedWithoutReadableProducts`, `TestValidateBuildEntrypoint`, verdict and template tests | A tracked package's build runs `build cmd:curl 1.2 --no-load --entrypoint=/usr/bin/curl --entrypoint=-s '--entrypoint=two words' --json` and ignores a forged `entrypoint` form field; an untracked package gets none; an unreadable products file returns 503 without starting a job. `config-changed` maps to "Configuration changed", kind `rebuild`, action "Rebuild". The build page lists the recorded entrypoint (escaped). |
| Real `build busybox-static 1 --no-load --json --entrypoint /bin/busybox --entrypoint=echo --entrypoint 'two words'` | Succeeded; record `request.entrypoint` `["/bin/busybox","echo","two words"]`; OCI config `Entrypoint` the same three elements and no `Cmd`; annotation `lupetto.image.entrypoint` `["/bin/busybox","echo","two words"]`. The layer has `bin -> usr/bin`, so the check resolved a real symlink. |
| Real `build busybox-static 1 --no-load --entrypoint /usr/bin/kyverno` | Build stage failed: `entrypoint /usr/bin/kyverno is not usable in the image of busybox-static@1.38.0-r3 and its dependency closure: /usr/bin/kyverno does not exist`. |
| Real `build kyverno 1 --entrypoint /usr/bin/kyverno --no-load` and `build memcached 1 --entrypoint /usr/bin/memcached --entrypoint=-u --entrypoint memcached --no-load --json` (the README examples) | Both succeeded (`kyverno 1` selected `kyverno-1.18`; memcached `1.6.45-r5` with the three-element entrypoint recorded). |

**End to end against the loopback registry.**

| Step | Observed result |
| --- | --- |
| `build busybox-static 1 --json` (load and publish, no entrypoint) | Published `sha256:bb98ee3d…`; record without `entrypoint`. `status --exit-code` with products `busybox-static ["1"]`: `current`, exit 0. |
| Product gains `entrypoint: [/bin/busybox]` | `status --exit-code`: `config-changed`, exit 3. `docker run --rm lupetto/busybox-static:1.38.0-r3-amd64 --help` failed with `exec: "--help": executable file not found in $PATH`, the args-only failure this change addresses. |
| `build busybox-static 1 --entrypoint /bin/busybox --json` | Published `sha256:58b73c5e…`; `status --exit-code`: `current`, exit 0. The same args-only `docker run … --help` printed the BusyBox banner, `docker run … echo args-only works` printed its argument, and the image config held `Entrypoint ["/bin/busybox"]`. |
| Explorer (`--enable-builds`, real CLI) with the product changed to `[/bin/busybox, sh]`, in headless Chrome | The Images page showed the "Configuration changed" verdict chip (rebuild style) and a "Rebuild" button (screenshot inspected). Clicking it started job 1, which ran with `--entrypoint=/bin/busybox --entrypoint=sh`, succeeded (loaded and published), and kept `entrypoint` in the job request. After the refresh the track was `current` / "Up to date" with annotation `["/bin/busybox","sh"]`; `docker run … -c 'echo shell-entrypoint ok'` ran through the shell. The build page from history showed `Entrypoint: "/bin/busybox" "sh"`. The only browser console error was the existing missing-favicon 404. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./...` passed.

Not exercised: an aarch64 entrypoint build, signing or attesting an image with an entrypoint (the Cosign path is unchanged), a real Kubernetes Deployment with an args-only chart, the combined container, and browsers other than Chrome.

## Exact-name provider precedence (v0.2.0)

This records the evidence for the [exact-name provider precedence decision](decisions.md#exact-name-provider-precedence-2026-10-22), observed 2026-10-22 on darwin/amd64 with Go 1.27.1 and apko 1.4.5 against the live signed x86_64 Wolfi index (it was republished during the session: `db3d0…8562`, later `99551…c615`). No registry, Docker load, or signing was involved.

| Check | Observed result |
| --- | --- |
| `internal/wolfi` `TestSelectPackagePrefersExactNameAmongEqualProviders` | `busybox` with selector `1`, selector `1.38.0`, and `--apk-version 1.38.0-r3` selects the `busybox` APK over `busybox-full`/`busybox-static` providing `busybox` at the same version, with a repeated identical index entry and other-architecture and older entries present. A newer provider still wins over an older exact-name APK, in either index order. A single provider is still selected; two providers without an exact-name APK stay ambiguous on both paths. |
| `internal/wolfi` `TestSelectPackageRejectsAmbiguousRevisionAndProvider` | Two builds of one name at one version, two non-exact providers, and two exact-name builds alongside a provider remain ambiguous for a selector and `--apk-version`. |
| Mutations | Accepting several exact-name candidates fails the ambiguity test; removing the preference fails the new test; preferring an exact name before version ranking fails the newer-provider case. |
| Live-index comparison (before implementing) | Of the requested names and selectors the old rule rejected as ambiguous, the chosen rule resolved 19, including `busybox 1` → `busybox@1.38.0-r3`, and changed no other selection; preferring exact names before version ranking would have changed 97 selections to older versions. |
| v0.1.0 binary: `build busybox 1 --no-load` and `build busybox --apk-version 1.38.0-r3 --no-load` | Both failed: `ambiguous package providers for busybox at 1.38.0-r3` / `…for busybox@1.38.0-r3`. |
| New binary, same two commands with `--json` | Both succeeded with selection `busybox` `1.38.0-r3`, build `completed`, `spdxValidated: true`; the apko lock holds `busybox` `1.38.0-r3` (plus `wolfi-baselayout`, `ca-certificates-bundle`, glibc, `libgcc`, `libxcrypt`, `libcrypt1`), so apko installed the selected APK, not a provider. The earlier [progress-rendering run](#live-build-feedback-evidence) that used `build busybox 1` as an ambiguous example now selects `busybox`. |
| New binary, `build cmd:CMakeLists.txt --apk-version 3.12.3-r0 --no-load` and `build cmd:CMakeLists.txt 3.12 --no-load` | Still fail: `ambiguous package providers for cmd:CMakeLists.txt@3.12.3-r0` and `…at 3.12.4-r1` (several `gdal-tools-py3.*` providers, no `cmd:CMakeLists.txt` APK). A live scan found 189 exact versions resolved by the exact-name rule and 5,895 provider versions that stay ambiguous. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./...` passed.

## CA certificate bundle (v0.2.0)

This records the evidence for the [CA certificate bundle decision](decisions.md#ca-certificate-bundle-2026-10-22), observed 2026-10-22 on darwin/amd64 with Go 1.27.1, apko 1.4.5, Docker 27.4.0, headless Google Chrome 155, and a disposable `crane registry serve` on `127.0.0.1:55310` (repository `e2e/images`, no credentials or signing). Afterwards the registry, Explorer, and browser were stopped and the scratch data and browser profile deleted; the loaded test images stayed in the local Docker store.

| Check | Observed result |
| --- | --- |
| `internal/imageconfig` `TestCABundleOption` | The option adds only `lupetto.image.ca-bundle: "true"`, round-trips alone and with an entrypoint, and compares unequal to its absence; `""`, `false`, `TRUE`, `yes`, and `1` are malformed. |
| `internal/build` `TestApkoConfigCABundle`, `TestCheckImageCABundle`, `TestApkoConfigWithoutImageOptionsMatchesV010`, `TestRunWithoutImageOptionsKeepsV010Inputs` | The configuration is the v0.1.0 bytes plus one unpinned `ca-certificates-bundle` package line and the annotation; the bundle is listed once when it is the selected APK. The image check accepts the file directly and through a symlinked parent, and rejects a missing file, a directory, and a dangling symlink with a message naming the package; without the option the file is not required. Records without the option have no `caBundle` key. |
| `cmd/lupetto` `TestParseBuildCABundle` | `--ca-bundle` sets the option; repeated and `=true` forms exit 2. |
| `internal/status` `TestRunCABundleState`, `TestParseProductsCABundle`; `internal/products` `TestProductsKeepCABundleAcrossMutations` | `current` when requested and built; `config-changed` when added or removed; a malformed annotation is a track error; the track carries `caBundle: true` only when requested. Products accept `true`/`false` and reject a quoted string, `yes`, a number, null, and a list; `add`/`remove` keep the field. |
| Mutation | Making `Equal` ignore the bundle fails the status and `imageconfig` tests. |
| `internal/explorer` `TestHTTPBuildUsesTrackedProductEntrypoint`, template tests | A tracked product with `caBundle: true` builds with `--ca-bundle` before `--json` and a forged `caBundle` form field is ignored; the job request keeps `caBundle`; the build page shows a "CA bundle" row only when requested. |
| Real `build external-dns-0.21 0 --ca-bundle --no-load --json` | Succeeded (`0.21.0-r9`); `request.caBundle: true`; apko packages `external-dns-0.21=0.21.0-r9` and `ca-certificates-bundle`; lock `wolfi-baselayout 20230201-r30`, `ca-certificates-bundle 20260909-r3`, `external-dns-0.21 0.21.0-r9` (without the flag the lock held only `external-dns-0.21`); annotation `lupetto.image.ca-bundle: true`; `etc/ssl/certs/ca-certificates.crt` a 178,791-byte regular file with 118 certificates; SPDX lists the bundle and `spdxValidated: true`. |
| Real `build external-dns-0.21 0 --ca-bundle --entrypoint /usr/bin/external-dns --no-load` (the README example) | Succeeded. |
| Real `build busybox-static 1 --ca-bundle --no-load` and `build ca-certificates-bundle 20260909 --ca-bundle --no-load` | Both succeeded. busybox-static's lock is the same three-package set it has without the flag; the bundle build lists only `ca-certificates-bundle=20260909-r3` in apko's packages. |
| Real `build kubectl-1.34 1 --entrypoint /usr/bin/kubectl-1.34` with and without `--ca-bundle` (loaded into Docker), then `docker run … --server=https://packages.wolfi.dev --token=synthetic get --raw /os/x86_64/APKINDEX.tar.gz` | Without: `tls: failed to verify certificate: x509: certificate signed by unknown authority`. With: TLS verified and the server answered `You must be logged in to the server`, the expected reply to a synthetic token. (A first attempt with `--entrypoint /usr/bin/kubectl` failed the build with `/usr/bin/kubectl does not exist`; the package installs `/usr/bin/kubectl-1.34`.) |
| Loopback registry: `build external-dns-0.21 0 --no-load` published without the bundle | `status --exit-code` with the product: `current`, exit 0. After adding `caBundle: true`: `config-changed` with track `caBundle: true`, exit 3. |
| Explorer (`--enable-builds`) in Chrome | The Images page showed "Configuration changed" and "Rebuild" (screenshot inspected). Clicking Rebuild ran job 1 with `caBundle: true` from the products file; it loaded and published. The build page showed "CA bundle: added (ca-certificates-bundle)" in Inputs; the Images page then showed "Up to date", and `status --exit-code` reported `current` with annotation `lupetto.image.ca-bundle: true`, exit 0. No browser console errors. |

**Gates.** `gofmt -l .` empty; `go vet -composites=false ./...` passed; `go test ./...` passed.

Not exercised: an aarch64 bundle build, signing an image with the bundle, and a bundle whose file is missing in a real image (covered hermetically).

## v0.2.0 release readiness (2026-10-22)

Checks run on the `release-v0.2.0` branch after the [entrypoint](#image-entrypoint-v020), [selection](#exact-name-provider-precedence-v020), and [CA bundle](#ca-certificate-bundle-v020) changes, on darwin/amd64 with Go 1.27.1.

| Check | Observed result |
| --- | --- |
| `gofmt -l .`, `go vet -composites=false ./...`, `go test ./... -count=1` | Empty, passed, passed. |
| `go test -race ./... -count=1` | Passed. |
| `git diff --check v0.1.0` | No whitespace errors. |
| Relative links and anchors in `README.md`, `CHANGELOG.md`, `docs/*.md`, `docs/release-notes/*.md`, `AGENTS.md`, and the Explorer contract | All resolve. |
| `bash -n` on the 33 Bash-fenced blocks in `README.md`, `CHANGELOG.md`, `docs/registry-signing.md`, and the release notes | All pass (syntax only, not execution). The keyless `cosign verify` template in `docs/registry-signing.md`, which failed since v0.1.0 because of an unquoted `<…>` placeholder ending the line, now quotes its placeholders. |
| `lupetto help` | Both `build` lines and `sbom` show `[--entrypoint <element>]... [--ca-bundle]`; the status exit-code sentence lists `config-changed`. |

There is no version constant in the source; the release is the tag. The [release](#v020-release-2026-10-22) itself is recorded below.

## v0.2.0 release (2026-10-22)

With the maintainer's approval, `main` was fast-forwarded to `6adda2d` and pushed, and the annotated tag `v0.2.0` ("lupetto v0.2.0") was pushed on that commit. The checks below are read-only against the published image.

| Check | Observed result |
| --- | --- |
| Release workflow run `39812453440` (tag push `v0.2.0`) | Completed `success`; `docker/build-push-action` pushed the image and `cosign sign --yes ghcr.io/skel84/lupetto@sha256:46ba422e…b2a5` ran on the pushed digest. |
| `crane digest ghcr.io/skel84/lupetto:v0.2.0` | `sha256:46ba422e1cda5c9e49a12e85eb42aa6c1a44677490ebf680050af344926bb2a5`. |
| `lupetto verify --json --certificate-identity-regexp '^https://github.com/skel84/lupetto/' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/skel84/lupetto@sha256:46ba422e…b2a5` (CLI built from `6adda2d`) | Exit 0; transparency log `verified`; signature `signed` (1 artifact); signer `https://github.com/skel84/lupetto/.github/workflows/release.yml@refs/tags/v0.2.0`, issuer `https://token.actions.githubusercontent.com`; attestation `absent` (the workflow signs but does not attest). |
| `cosign verify` with the same identity policy | Claims, transparency-log inclusion, and certificate chain verified; certificate extensions show workflow ref `refs/tags/v0.2.0`, SHA `6adda2d1…f3a9`, trigger `push`. |
| `crane config` of the digest | `linux/amd64`; `Entrypoint` `/usr/local/bin/lupetto-explorer`, `Cmd` `--listen 0.0.0.0:8080 --products /etc/lupetto/products/products.yaml`. |
| `docker run --rm --entrypoint lupetto <digest> help` | The packaged CLI's usage lists `[--entrypoint <element>]... [--ca-bundle]` on `build` and `sbom`. |

`gh release create v0.2.0 --verify-tag --title "lupetto v0.2.0" --latest` published the [GitHub release](https://github.com/skel84/lupetto/releases/tag/v0.2.0) with `docs/release-notes/v0.2.0.md` at the tag as its body, its relative links rewritten to the tagged files. `gh release view v0.2.0` reports it as the latest, neither draft nor prerelease. v0.1.0 has no GitHub release object.
