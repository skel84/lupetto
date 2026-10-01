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

On darwin/amd64 targeting linux/amd64, with apko 1.4.5, `go run ./cmd/lupetto build postgresql 17` exited 0 after verifying the downloaded APKINDEX signature with the pinned Wolfi key. It selected `postgresql-17@17.10-r1` from APKINDEX SHA-256 `d296da0b216382d0e825cd1a71bebeaf0fb06e887f3e8b6b9ba15db544d5a27e`. The workspace was `/Users/skel/Library/Caches/lupetto/builds/postgresql-17-2725349457`, outside the repository. Independent inspection of the OCI manifest/layer, apko lock, and `usr/lib/apk/db/installed` found exactly `postgresql-17` `17.10-r1` on `x86_64`; the OCI layer digest matched its bytes. `go run ./cmd/lupetto build postgresql 17.10` and `go run ./cmd/lupetto build postgresql --apk-version 17.10-r1` also exited 0 with `17.10-r1` after signature verification. Each of `go run ./cmd/lupetto build postgresql 17.1`, `17.2`, and `17.3` exited 1 with an explicit unavailable-version error, without producing an image. This is not SBOM/lock consistency validation, historical version archival, Docker loading, or evidence of a runnable database image.

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

The last command selected `busybox-static@1.38.0-r2` for `x86_64` from verified APKINDEX SHA-256 `550f367b5eaaac0532ac767106d8223e68781494461d2513c3e7ee8d57d0cb91`. Workspace `/Users/skel/Library/Caches/lupetto/builds/image-974928037` retained validated architecture SPDX SHA-256 `a3087fbd0bbfe83b4a225cacca0b629a20eac8d8a5dc1d7291314482007b838c` and a private version-5 `result.json`. It recorded build `completed`, Docker load `loaded`, publication `published` with `verified: true`, signing `signed`, and attestation `attested`. Its unique published tag was `127.0.0.1:54355/tests/lupetto-test-01c1b8dd6fc2/signed/nested/images/busybox-static:1.38.0-r2-amd64-build-974928037`.

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

Observed 2026-10-01 on darwin/amd64 → linux/amd64 with Go 1.27.1, native apko 1.4.5, Docker client/server 27.4.0 (containerd store, used only for scenario C), and Cosign v3.1.3. The binary was built from commit `1671d04` with `go build -o <temporary>/lupetto ./cmd/lupetto`. The target was a disposable `registry:3` bound only to `127.0.0.1` over HTTP, with htpasswd authentication using a freshly generated synthetic password. Throwaway Cosign keys and an upstream no-service signing config were generated outside the repository. Passwords reached processes only through files and the process environment, never command arguments. `<temporary>` and `$REG` stand for the disposable binary directory and `127.0.0.1:<port>`. All runs selected `busybox-static@1.38.0-r2` (x86_64) from signed APKINDEX SHA-256 `f53bda2286a6edf801c5d2b5589c35a12b1069961bfe131d32030c64f63006fa`.

| Scenario | Command (plus environment) | Exit | Observed record |
| --- | --- | --- | --- |
| A. Publish, no Docker | `build busybox-static 1 --no-load --json --registry $REG --repository tests/final/publish`, `DOCKER_HOST` unreachable | 0 | v6 `succeeded`; load `skipped`; publication `published`, `verified: true`; digest `sha256:a3325f44…cf05` equal to `evidence.imageDigest`. |
| B. Publish + sign + attest, no Docker | as A plus `--cosign-key`, `--cosign-signing-config`, `--cosign-allow-http`; `COSIGN_PASSWORD` exported | 0 | publication `published`/verified; signing `signed`; attestation `attested`; digest `sha256:f2e7a0fe…1f82`. |
| C. Load + publish | `build busybox-static 1 --registry $REG --repository tests/final/loaded` | 0 | Human summary: Docker loaded with readable and build references, published, immutable `…@sha256:810e4a0f…f8fe`. |
| D. No credentials | as A with an empty `DOCKER_CONFIG` | 1 | v6 `failed`; `failure.stage` `publication`; error `publication push failed (HTTP 401)`; no digest; `result.json` absent; `failure.json` mode 0600 and byte-identical to stdout. |
| E. SBOM | `sbom busybox-static --apk-version 1.38.0-r2 --json`, `DOCKER_HOST` unreachable | 0 | v6 `command: sbom`; all optional stages `skipped`. |
| F. Credential helper | as A with `DOCKER_CONFIG` containing only `{"credsStore":"lupettoe2e"}`; a synthetic `docker-credential-lupettoe2e` on `PATH` returned the registry credentials and wrote a random canary to stderr | 0 | publication `published`/verified (scenario D shows anonymous access fails), so the helper's credentials were used; the canary appeared in neither Lupetto stdout nor stderr. |

For A, B, E, and F, `--json` stdout was byte-identical to the workspace `result.json` (mode 0600). Progress showed the four publication stages; scenario A/B/F workspaces contained no Docker archives, confirming that Docker was not used.

Independent checks:

- An authenticated `curl` (credentials from a mode-0600 netrc file) fetched scenario A's manifest by digest. Its SHA-256 equaled the recorded digest, and its bytes equaled both the retained `published-manifest.json` (mode 0600) and the local OCI layout's manifest blob, proving the manifest was pushed unchanged.
- `cosign verify` and `cosign verify-attestation --type spdxjson`, both with `--allow-http-registry --insecure-ignore-tlog`, against B's immutable reference: trusted key exit 0 and 0; wrong key exit 1 and 1. The decoded attestation had `predicateType` `https://spdx.dev/Document`, a predicate equal as JSON to the validated architecture SPDX, and a subject digest equal to the pushed digest.
- None of the outputs, records, or workspace JSON files contained the registry password, the Cosign password, or the helper canary.

Gates on the final tree: `gofmt -l cmd internal` empty; `go vet ./...` passed; `go test -count=1 ./...` and `go test -race -count=1 ./...` passed (`ok` for `cmd/lupetto`, `internal/build`, `internal/wolfi`). Hermetic tests use an in-process OCI registry for tampering (manifest, media type, tag body, config, layer), the loopback HTTP guard and token-realm requests, Docker-config-only authentication (Podman auth ignored), credential helpers in a re-executed subprocess with captured stderr, sanitization (including uppercase registry-supplied canary codes), cancellation, `--no-load` publication and signing, and version-6/`--json` records for every failure stage.

Limitations:

- A plain `docker pull` of the pushed reference was not exercised: the Docker Desktop daemon runs in a VM and cannot reach a registry bound to the host's loopback interface.
- `127.0.0.2` listener tests are skipped on macOS, which cannot bind that address; injected-dialer tests cover the HTTP fallback for that address instead.
- Production HTTPS/TUF/Rekor remains unexercised, as do non-loopback registries, other hosts and architectures, and other registry implementations.
- During an earlier intermediate run (before the final password rotation), the synthetic registry and Cosign passwords briefly appeared in local `htpasswd`, `curl`, and `env` process arguments in the test harness itself, not in Lupetto. Those disposable values were rotated before the final run, and the harness was corrected to use stdin, a netrc file, and shell `export`.

One `go test -race ./...` run during package extraction hung for 10 minutes in the pre-existing fake-`cosign` exec test and was not reproduced: an immediate rerun, 20 targeted race iterations, and three later full race runs all passed.

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

The production verification forms below are templates, not observed production interoperability. The [operator guide](registry-signing.md#verify-signature-and-spdx-attestation) documents both these forms and the separately labeled local variants exercised in [checkpoint 2](#local-cosign-signing-and-spdx-attestation-evidence):

```text
cosign verify --key /path/to/lupetto.pub registry.example.com/team/lupetto/<image>@sha256:<digest>
cosign verify-attestation --key /path/to/lupetto.pub --type spdxjson registry.example.com/team/lupetto/<image>@sha256:<digest>
```

The pinned Cosign v3.1.3 local HTTP/no-service forms were exercised above; production forms remain unexercised. Local HTTP access and verification without transparency-log evidence require separately labeled variants; never make them production defaults. Successful cryptographic verification does not prove absence of vulnerabilities, SBOM completeness, or policy compliance.

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

## Release evidence

Once code exists, run the following in each implemented Go module. A CLI release requires its applicable checks, not a completed Explorer:

```bash
go test ./...
```

Record the exact command and outcome, tool versions, exercised host/target architectures, CLI-help checks, real build/registry outcomes, and browser observations. Report unexercised scenarios explicitly.

Re-read all published flags and examples against parsing/help. Check relative documentation links and ensure no registry vendor is required. Never copy real credentials or secret-bearing command output into verification records.
