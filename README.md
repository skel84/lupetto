# Lupetto

Lupetto is a standalone CLI for discovering Wolfi APK versions, selecting an exact package revision, composing an OCI image with apko, and retaining validated SPDX and build evidence. `build` loads the image into Docker by default and can push the validated image directly to a compatible OCI registry. `status` compares tracked published images with the current signed Wolfi index and known security fixes. Optional Cosign signing and SPDX attestation extend that same build pipeline; see the [registry, signing, and verification guide](docs/registry-signing.md).

The CLI does not require Explorer or a database. Persistent SQLite catalog ingestion, historical snapshot queries, Explorer, and runnable service recipes are deferred, not implemented commands. These images contain packages; installing PostgreSQL or nginx does **not** establish a configured, runnable service.

This guide describes the current CLI/source contract. The [verification record](docs/verification.md) distinguishes observed interoperability from source behavior and unexercised scenarios. In particular, local HTTP/offline signing is not production HTTPS/transparency-log proof; production commands in the detailed guide are explicitly templates.

## Prerequisites and installation

Run from this checkout with **Go 1.27.1**. Install the CLI independently of Explorer:

```bash
go install ./cmd/lupetto
```

Go installs `lupetto` in `GOBIN`, or otherwise in the `bin` directory of `GOPATH` (normally `$HOME/go/bin`). Put that directory on `PATH`. This is a **local-checkout installation**, not a published module download path. You can instead substitute `go run ./cmd/lupetto` for `lupetto` in the commands below.

| Operation | Requirements |
| --- | --- |
| `help`, `doctor` | Installed CLI; `doctor` checks executable availability. |
| `discover` | Access to the public Wolfi index/key; no apko, Docker, or Cosign invocation. |
| `status` | Access to the public Wolfi index/key/security feed, a configured registry/repository and Docker client credentials when needed, writable user cache; no apko, Docker daemon, or Cosign invocation. |
| `build --no-load`, `sbom` | Native **apko 1.4.5**, access to the public Wolfi repository, writable user cache. |
| Default `build` | The above plus Docker on `PATH` and a running local Linux daemon (for loading). |
| Publication | An authorized compatible registry/repository and credentials in Docker's client configuration. Docker itself is not needed with `--no-load`. |
| Requested signing | Publication requirements plus exactly **Cosign v3.1.3** and the key/config inputs described in the [detailed guide](docs/registry-signing.md#sign-and-attest-the-verified-digest). |

```bash
lupetto help
lupetto doctor
```

`doctor` suggests OS-specific installation commands when tools are missing but never installs anything. It checks `PATH`, **not** versions, daemon health, authentication, or registry compatibility. Missing apko or Docker produces exit 1; missing optional Cosign does not. `--no-load` builds (including publication/signing) and `sbom` work without Docker even though `doctor` reports it missing. The build path checks apko's version; requested signing also checks Cosign's exact version before workspace/network/build/publication work.

Targets follow the host architecture: `amd64` → Wolfi `x86_64` / OCI `linux/amd64`, `arm64` → Wolfi `aarch64` / OCI `linux/arm64`. Other architectures fail. There is no target-architecture flag or multi-platform build. Recorded real interoperability is on **darwin/amd64 → linux/amd64**, using Docker 27.4.0 with its containerd image store for loading; arm64 and other host/store combinations are not thereby proven.

## Discover indexed versions

```bash
lupetto discover postgresql
lupetto discover nginx
lupetto discover valkey
lupetto discover cmd:curl
lupetto discover --json nginx
lupetto discover --json
```

`discover` verifies the live APKINDEX signature against the pinned Wolfi public key, prints the signed archive's SHA-256, and lists all matching exact APK names/versions for the host architecture, newest first. Names can match an actual package or a version-matched virtual provider (`cmd:curl` resolves to actual APK entries). Different packages advertising the same version are not silently collapsed.

**Indexed does not mean buildable.** apko must still lock the package/dependencies and fetch the needed APK bytes. Discovery creates no workspace, checks no APK contents, and does not browse imported or historical snapshots. A missing name exits unsuccessfully. The live index changes, so examples are not availability guarantees.

`discover --json <name>` returns those same exact entries and descriptions as one versioned document. `--json` can appear before or after the name. Without a name, `discover --json` lists **one latest APK per actual package name**, alphabetically by name, using APK version/revision ordering for the host architecture; virtual providers are not extra names. Descriptions come from the signed index's `T:` field and may be empty. Human discovery still requires a name and its output is unchanged.

```json
{
  "kind": "discover",
  "version": 1,
  "package": "nginx",
  "architecture": "x86_64",
  "indexSHA256": "…",
  "packages": [
    {"name": "nginx-stable", "version": "1.30.2-r0", "description": "…"}
  ]
}
```

The optional `package` field is the requested name/provider and is omitted for all-packages browsing. `indexSHA256` identifies the signed archive, not its decompressed contents. A successful empty all-packages result has `packages: []`; a missing named package or index/verification failure exits 1 with stderr diagnostics and **no JSON document**. Invalid arguments exit 2 with empty stdout. Discovery documents are separate from unchanged version-6 build/SBOM records.

## Compare published images with Wolfi

`status` is read-only: it never builds, loads, pushes, signs, or reports signature status. It compares explicitly tracked package/provider selectors against the current verified Wolfi index and the images in the configured registry repositories.

Create a products file (selectors must be quoted YAML strings):

```yaml
version: 1
products:
  - package: postgresql
    selectors: ["16", "17"]
  - package: nginx
    selectors: ["1.30"]
```

Unknown fields, duplicate tracks, unsupported versions, empty products/selectors, and malformed package names/selectors are rejected. Products are tracking groups, **not runtime recipes**. The file is limited to 1 MiB.

```bash
lupetto status --products products.yaml \
  --registry registry.example.invalid --repository team/lupetto/images

LUPETTO_REGISTRY=registry.example.invalid LUPETTO_REPOSITORY=team/lupetto/images \
  lupetto status --products products.yaml --json
```

These registry examples are templates requiring an authorized target. Both registry and repository are required. Each explicit flag independently overrides its matching `LUPETTO_REGISTRY` / `LUPETTO_REPOSITORY` input; duplicate/empty flags are errors. The same authority/prefix validation, Docker-config-only keychain, loopback-only HTTP guard, host TLS trust, and sanitized errors as publication apply. Signing environment inputs are ignored. See the [registry configuration guide](docs/registry-signing.md#configuration-and-upfront-errors).

For every track, status resolves the newest indexed APK, lists tags in `HOST/PREFIX/<actual-APK-component>`, and reads image identity from the six [manifest annotations](#image-identity-annotations), **never from tag text**. It deduplicates by manifest digest and orders matching images by APK version, then UTC creation time; digest order breaks exact ties deterministically. Non-image artifacts (including Cosign signatures/attestations/referrer manifests) and unidentified images are counted by unique digest, not inspected for package contents. Images built before annotation support are unidentified, not guessed.

The newest image's complete installed APK set is read by digest from its manifest/config/layers, with compressed and uncompressed hashes verified and layer-overlay/whiteout semantics applied. Its validated installed identities are cached by image digest under the OS user-cache `lupetto/status/installed/` directory, with private permissions. Registry tags and manifests are still read on every status run; security/index facts are fetched fresh. The cache is not a catalog or a vulnerability database.

| State | Meaning |
| --- | --- |
| `not-built` | No identified image matches this actual APK, architecture, and selector. |
| `update-available` | The selected index top-level APK is newer than the newest matching image. |
| `fixes-available` | Same top-level APK version, with reachable security fixes in installed dependencies available for a rebuild. |
| `current` | No newer top-level version or reachable fixes for this track; **not a clean vulnerability result**. |
| `error` | This track could not be compared (unavailable/ambiguous selector, registry/image/cache failure, or newest image newer than the current index selection). Other tracks still report. |

Every installed package with a newer same-name/same-architecture indexed version is listed in `outdated`. Missing fixes include CVE/GHSA/Go vulnerability IDs under fixed APK versions strictly newer than installed and available in the current index; secdb key `"0"` means not affected and is ignored. Supported IDs are `CVE-YYYY-NNNN`, `GHSA-xxxx-xxxx-xxxx`, and `GO-YYYY-NNNN`. Fixes outside a top-level numeric selector remain listed, with `reachableByTrack: false`, and do **not** trigger `fixes-available`. Dependency fixes use index availability (`reachableByTrack: true`). Thus `current` may still carry unreachable top-level fixes; consumers must show those as warnings. This is an index-based comparison, not a solved future dependency lock or proof that a particular rebuild will succeed.

### Status JSON contract and exits

`--json` prints one indented, newline-terminated document: `kind: "status"`, `version: 1`, `computedAt` (UTC RFC 3339), `architecture`, `registry`, `repository`, `indexSHA256`, `security`, and `tracks`. `security` has `url`, `sha256`, `unsigned`, `fixedOnly`, `wolfiOnly`, `unevaluatedFixCount`, and `unevaluatedFixes`. Each track has `package`, `selector`, `state`, optional `error`, optional `latest` (`name`, `version`, `architecture`), optional `repository`, `images`, optional `newest`, `installed`, `outdated`, `missingFixes`, `unevaluatedFixes`, `artifactCount`, and `unidentifiedCount`.

- Each image: `digest`, `tags`, `name`, `version`, `architecture`, `created`, `annotations`.
- Each installed identity: `name`, `version`, `architecture`.
- Each outdated package: `name`, `architecture`, `installedVersion`, `latestVersion`.
- Each missing fix: `name`, `architecture`, `installedVersion`, `fixedVersion`, `availableVersion`, `ids`, `reachableByTrack`.
- Each unevaluated fix: `name`, original `fixedVersion`, `ids`; track entries also include `installedVersion`, `architecture`.
- Empty fact lists are arrays, not `null`; unavailable facts (`latest`/`newest`) are omitted.

Exit **0** means the global comparison completed, even when tracks are outdated or have errors: inspect every track's state. Invalid invocation/configuration/products YAML exits **2**; global failures (including signed-index verification and security-feed fetch/parse failures) exit **1**. Exit 1/2 has stderr diagnostics and no partial JSON document.

### Security-data limitations

The feed at `https://packages.wolfi.dev/os/security.json` is fetched over HTTPS and its bytes are identified by SHA-256, but it is **not signed**. It lists **fixed vulnerabilities only**, covers Wolfi packages only, and is matched by exact installed APK name (no unproved origin/subpackage mapping). An empty result never means an image has no vulnerabilities. This is **not a vulnerability scan**, signature verification, or runtime-readiness assessment. Index and feed can change between independent requests; computed time/checksums identify the observations, not one atomic upstream snapshot. Real proof and the exercised bounds/cases are in [status verification](docs/verification.md#registry-status-checkpoint-2).

An unparseable secdb fixed-version key is never sorted heuristically or silently discarded. It is excluded from evaluated comparisons but reported in the security source's `unevaluatedFixCount` / `unevaluatedFixes`, and in any track that installs that exact package. Human output shows a warning and an `UNEVALUATED` count. For example, the observed feed included `opa-envoy` key `1.1.0-r1-r0`, which the pinned APK comparator rejects. Inspect these warnings even if a track says `current`; the vulnerability entries have **not been evaluated**. Other malformed feed structure, invalid package names, duplicate packages, and exceeded bounds remain global failures.

Fixed-version entries with **no recognised advisory IDs** are also reported as unevaluated, globally and on affected installed tracks, with their original unsupported IDs retained. They are never silently dropped just because their IDs have an unknown format. Mixed entries use their recognised CVE/GHSA/Go IDs for evaluated comparisons; consumers must inspect unevaluated warnings even when the fixed APK version parses.

## Build a local OCI image

For a local-only session, clear publication/signing environment settings described in the [configuration table](docs/registry-signing.md#configuration-and-upfront-errors). Otherwise environment configuration can request additional stages.

```bash
lupetto build nginx 1.30
lupetto build valkey 9.1
lupetto build postgresql 17
lupetto build nginx --apk-version 1.30.2-r0
lupetto build nginx --apk-version 1.30.2-r0 --no-load
lupetto build nginx 1.30 --no-load --json
```

These are examples, **not a package allowlist**. Lupetto resolves exact package names or version-matched providers from the signed Wolfi index. A numeric selector matches leading dotted upstream components and chooses the highest APK-compatible version/revision (`17`, `9.1`, or `9.1.2`); an exact request must include the packaging revision `-rN`. Selectors and `--apk-version` cannot be combined. Missing or ambiguous matches fail rather than substituting another package or version.

For example, exercised `nginx 1.30` and `valkey 9.1` selected actual APKs `nginx-stable@1.30.2-r0` and `valkey-9.1@9.1.2-r1`. Selection can change with a new index. Both forms enter **one** resolution/lock/composition/validation pipeline.

Stage progress and live apko lock/build diagnostics go to stderr; default builds also stream Docker load output. Interactive stderr has an ASCII spinner/elapsed time. Redirected stderr and `TERM=dumb` receive plain logs. Registry error bodies and Cosign diagnostics are suppressed to avoid credential/secret disclosure. Stdout contains the final summary **only after every requested stage and result recording succeeds**. For machine-readable output use `--json` ([below](#results-records-and---json)); never parse the human logs or summary.

### Image names and Docker loading

Success reports the actual APK/version, signed-index checksum, OCI layout, validated architecture SPDX path/checksum, workspace, and separate load/publication/signing/attestation outcomes.

The readable local reference is:

```text
lupetto/<resolved-actual-apk>:<exact-apk-version>-<oci-architecture>
```

For example, `lupetto/nginx-stable:1.30.2-r0-amd64`. Every build also retains a unique `lupetto/local:build-<workspace-suffix>` reference. The readable tag can move when rebuilding; **it is not immutable identity**. Docker-incompatible or oversized APK components use deterministic SHA-256 naming fallbacks without changing the displayed/recorded exact APK identity. Older images are not automatically renamed.

Loading exports the validated image once to `docker-image.tar`, imports/verifies the unique reference, then tags the **verified local image ID** with the readable name and inspects that name's ID/platform. If Docker reports a manifest ID instead of the OCI config digest, Lupetto saves the imported unique reference to `docker-loaded.tar` and checks its config digest before tagging.

```bash
docker image ls lupetto/nginx-stable
docker image ls lupetto/local
docker image inspect lupetto/nginx-stable:1.30.2-r0-amd64
```

Use the actual reference printed by your build. `--no-load` and `sbom` skip archive creation and all Docker commands; their reported references are **intended names**, not proof a tag exists or points to that build. `--no-load` can be combined with publication and signing, which push the validated OCI layout without Docker.

### Image identity annotations

Every `build` and `sbom` config supplies these manifest annotations through apko, independently of Docker loading or publication:

| Annotation | Value |
| --- | --- |
| `org.opencontainers.image.version` | Exact selected APK version, including `-rN`. |
| `org.opencontainers.image.created` | Actual build time, RFC 3339 UTC. |
| `lupetto.apk.name` | Actual resolved APK name, not the requested provider. |
| `lupetto.apk.version` | Exact selected APK version. |
| `lupetto.apk.architecture` | Wolfi APK architecture (`x86_64` or `aarch64`). |
| `lupetto.index.sha256` | SHA-256 of the signed APKINDEX archive used for selection. |

apko's build date and its subprocess-only `SOURCE_DATE_EPOCH` are pinned to the same current UTC timestamp so an inherited reproducibility epoch cannot replace the created annotation with a historical package date. Other subprocess environment settings remain inherited; Lupetto does not record the environment. Publication pushes that annotated manifest unchanged. Version-6 result records are unchanged.

Use annotations rather than parsing tags, which may contain naming fallbacks. Older images are not retrofitted; images without the required identity annotations remain unidentified. The provisional `lupetto.` prefix can change only with a status-document version bump.

## Generate validated SPDX

```bash
lupetto sbom valkey --apk-version 9.1.2-r1
```

`sbom` composes a **new OCI image and workspace** through the same exact-build path. It does not extract metadata from an existing image. It requires `--apk-version`, never loads/publishes/signs, rejects `--no-load` and all explicit publication/signing flags (including empty/false forms), and ignores all `LUPETTO_*` publication/signing environment inputs.

Lupetto checks the selected installed APK's name/version/architecture and requires the complete locked Wolfi APK identity set to match apko's architecture SPDX APK entries, including the supported `distro`/installed `origin` purl forms. Non-APK image, OS, and build-recipe entries are excluded. The supplemental index SPDX is **not** lock-validated. This validation does not independently compare every installed dependency against the image, prove SPDX completeness, or scan vulnerabilities.

## Retained evidence and failures

Each build uses a unique mode-0700 workspace under the OS user cache, `lupetto/builds/image-<suffix>`. It retains:

- `APKINDEX.tar.gz`, `APKINDEX.sha256`, and the pinned `wolfi-signing.rsa.pub`;
- `apko.yaml`, `lock.json`, and the local OCI layout `image/`;
- `sbom/sbom-<wolfi-architecture>.spdx.json` plus supplemental `sbom/sbom-index.spdx.json`;
- Docker archives when loading (`docker-image.tar`, and `docker-loaded.tar` for the identity fallback);
- `published-manifest.json`, the registry's manifest as read back by digest, when publishing;
- private mode-0600 `result.json` (success only) or `failure.json`.

Failures and cancellation exit nonzero, retain the workspace, and never print the success summary or write `result.json`. Build, load, publication, signing, and attestation are separate outcomes: images, tags, signatures, or attestations may already exist after a failure, cancellation is best-effort, and **there is no rollback**. See [partial outcomes](docs/registry-signing.md#partial-outcomes-and-failure-records).

Retaining an index and dependency lock does not preserve remote APK bytes or guarantee historical rebuildability. Keep needed workspaces deliberately; there is no persistent catalog or retention service.

## Results, records, and `--json`

Every `build` and `sbom` run that passes argument validation produces one **version-6** record. It is written as `result.json` when every requested stage succeeds, or as `failure.json` otherwise (when a workspace exists). With `--json`, the same bytes are printed to stdout instead of the human summary—on success (exit 0) and on failure (exit 1). Invocation errors (exit 2) print nothing to stdout.

```json
{
  "version": 6,
  "command": "build",
  "outcome": "succeeded",
  "workspace": "/home/user/.cache/lupetto/builds/image-123",
  "request": {"package": "nginx", "selector": "1.30", "apkVersion": "", "load": false, "publish": true, "sign": false},
  "selection": {"package": "nginx-stable", "version": "1.30.2-r0", "architecture": "x86_64", "indexSHA256": "…"},
  "evidence": {"apkoVersion": "1.4.5", "imageDirectory": "…/image", "imageDigest": "sha256:…", "lockPath": "…/lock.json",
               "spdxPath": "…/sbom/sbom-x86_64.spdx.json", "spdxSHA256": "…", "spdxValidated": true},
  "stages": {
    "build": {"status": "completed"},
    "load": {"status": "skipped", "imageReference": "lupetto/nginx-stable:1.30.2-r0-amd64",
             "buildReference": "lupetto/local:build-123", "readableReferenceConfirmed": false},
    "publication": {"status": "published", "reference": "registry.example.invalid/team/nginx-stable:1.30.2-r0-amd64-build-123",
                    "digest": "sha256:…", "immutableReference": "registry.example.invalid/team/nginx-stable@sha256:…", "verified": true},
    "signing": {"status": "skipped"},
    "attestation": {"status": "skipped"}
  }
}
```

(Reformatted for width; actual output is indented JSON.)

- `outcome` is `succeeded` or `failed`; a failed record adds `failure: {stage, error, sideEffectsPossible}`. Stages are `cosign-version`, `build`, `load`, `readable-tag`, `publication`, `signing`, `attestation`, or `record`.
- Stage statuses: build `completed|failed|not-attempted`; load `loaded|skipped|failed|not-attempted`; publication `published|skipped|failed|not-attempted`; signing `signed|…`; attestation `attested|…`. `skipped` means not requested; `not-attempted` means requested but an earlier stage failed.
- `selection` appears once an APK is selected, `evidence` once SPDX is validated, `workspace` once one exists. `evidence.imageDigest` is the local OCI manifest digest, which equals the published digest.
- Load references are intended names when loading is skipped; `readableReferenceConfirmed: false` with `loaded` means the readable tag could not be confirmed.
- Publication workflows keep `failure.error` to a sanitized stage message; local-only workflows record the detailed local error (capped at 8 KiB).

The schema changes only with a new `version`; version 3–5 records from earlier releases are not migrated. Explorer compatibility rules (supported versions, cancellation, concurrency) are still undecided.

## Publish, sign, and verify

Continue with the [registry, signing, and verification guide](docs/registry-signing.md) for nested repository prefixes, flag/environment precedence, Docker authentication, pushed-digest content verification, password-safe Cosign setup, production templates, and the explicitly local HTTP/offline exception. Signing and verification details live there rather than being duplicated here.

## Rebuild documentation map

| Document | Purpose |
| --- | --- |
| [Scope and behavior](docs/scope.md) | Current behavior, full compatibility targets, and exclusions. |
| [Architecture](docs/architecture.md) | CLI/Explorer boundaries, pipeline, and evidence ownership. |
| [Decisions](docs/decisions.md) | Resolved contracts, proposals, and open decisions. |
| [Implementation checklist](docs/implementation-plan.md) | Single progress record and CLI/Explorer release gates. |
| [Verification](docs/verification.md) | Recorded observations, limitations, and remaining checks. |
| [Registry, signing, and verification](docs/registry-signing.md) | Detailed operator instructions and security boundaries. |

The rebuild is based on the operator-documentation request for a lost implementation. The overwritten older checkout is excluded from evidence/design; no historical source or executable claims are inferred from it. [AGENTS.md](AGENTS.md) contains repository instructions for coding agents.

Explorer remains an optional separate application/consumer, not a second build engine or CLI prerequisite. Its approved dashboard design consumes the versioned CLI `status`, `discover`, and build JSON contracts; the dashboard and combined container are not implemented by these CLI checkpoints. Remote Konflux execution, unfixed-vulnerability scanning, production credential/key management, and invented service recipes remain deferred. Status is a bounded registry/security-fix comparison, not a general vulnerability scanner.
