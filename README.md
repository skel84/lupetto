# Lupetto

Lupetto is a standalone CLI for discovering Wolfi APK versions, selecting an exact package revision, composing an OCI image with apko, and retaining validated SPDX and build evidence. `build` loads the image into Docker by default and can push the validated image directly to a compatible OCI registry. `status` compares tracked published images with the current signed Wolfi index and known security fixes. Optional Cosign signing and SPDX attestation extend that same build pipeline; see the [registry, signing, and verification guide](docs/registry-signing.md).

The CLI does not require Explorer or a database. The optional `lupetto-explorer` backend, HTML dashboard, and combined non-root container are implemented and verified within the [recorded local scope](docs/verification.md#combined-container-checkpoint-5). Persistent SQLite catalog ingestion, historical snapshot queries, and runnable service recipes are deferred, not implemented commands. These images contain packages; installing PostgreSQL or nginx does **not** establish a configured, runnable service.

This guide describes the current CLI/source contract. The [verification record](docs/verification.md) distinguishes observed interoperability from source behavior and unexercised scenarios. In particular, local HTTP/offline signing is not production HTTPS/transparency-log proof; the production signing and verification forms in the detailed guide were exercised against one authorized Harbor registry with public Rekor ([evidence](docs/verification.md#production-harbor-registry-and-public-rekor-verification-2026-10-02)), and other registries remain unverified.

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
| `verify` | Exactly **Cosign v3.1.3**, a trusted Cosign public key, registry access with Docker client credentials when needed, and (outside the local HTTP exception) network access to upstream TUF/transparency-log services; no apko or Docker daemon. |

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

## Inspect immutable registry packages

```bash
lupetto inspect --json registry.example.invalid/team/curl@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Replace the example with a digest reference returned by a successful publication. Tags, implicit Docker Hub names, URLs, credentials in references, image indexes, and non-image artifacts are rejected. `inspect` reads only: no Docker daemon, build, signing, index, or security feed is required. It reuses status's Docker-config keychain, loopback-only HTTP guard, bounded digest-verified image reads, layer-overlay handling, and private digest-keyed installed-package cache. A cache hit avoids config/layer downloads; the manifest is still fetched by digest.

The newline-terminated JSON is `kind: "inspect"`, `version: 1`, with `reference`, `digest`, `unidentified`, optional `identity` (`name`, exact APK `version`, `architecture`), optional `created` (UTC RFC 3339), and `packages` (`name`, `version`, `architecture`). Identity is taken only from validated Lupetto annotations, never inferred from tags or installed package names. Older/unannotated images can still report their complete installed set with `unidentified: true`; creation time is omitted if unavailable. Unsupported platforms, missing/malformed APK databases, hash mismatches, bounds violations, and cache failures exit 1 without JSON. Invalid invocation exits 2 without JSON. This is package evidence, not an SPDX document, signature verification, or vulnerability scan.

## Verify signatures

```bash
lupetto verify --json --cosign-public-key /trusted/path/operator.pub \
  registry.example.invalid/team/curl@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

LUPETTO_COSIGN_PUBLIC_KEY=/trusted/path/operator.pub \
  lupetto verify --json --sbom-out ./curl.spdx.json \
  registry.example.invalid/team/curl@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Usage (as printed by `lupetto help`): `lupetto verify [--json] [--cosign-public-key <file>] [--cosign-allow-http[=true|false]] [--sbom-out <file>] <registry-repository@sha256:digest>`.

`verify` is read-only: it never builds, pushes, signs, or loads Docker. It reports whether one digest-addressed image carries a Cosign image signature and an SPDX attestation that verify against **exactly one trusted public key**. The reference follows `inspect`'s rules (tags, implicit Docker Hub names, URLs, and credentials are rejected). The key comes from `--cosign-public-key` or `LUPETTO_COSIGN_PUBLIC_KEY`; the flag overrides the environment, and an empty flag, duplicate flags, a missing key, private-key files, and anything other than one PEM `PUBLIC KEY` block (at most 64 KiB) are invocation errors. Exactly Cosign v3.1.3 is required.

Lupetto first lists the image's Sigstore artifacts itself, with the same Docker-config keychain, loopback-only HTTP guard, metadata bounds, and sanitized errors as `status`/`inspect`: OCI referrers (referrers API or referrers-tag fallback, at most 128) with artifact type `application/vnd.dev.sigstore.bundle.v0.N+json`, classified by their `dev.sigstore.bundle.predicateType` annotation (sign type → signature candidate, `https://spdx.dev/Document` → attestation candidate, absent → both; other predicate types are ignored), plus legacy `sha256-<hex>.sig` / `.att` tags. Only then does it run `cosign verify --key` and `cosign verify-attestation --key --type spdxjson` on the digest reference, with the validated key bytes staged in a private temporary file. Cosign stdout (verified claims and DSSE envelopes) is read up to 64 MiB. Stderr is never printed or retained; on failure it is only matched against fixed network/TLS, HTTP 5xx, registry-authorization, and TUF patterns to report an outage as `error` instead of `invalid`. `signed`/`attested` come only from parsed verified payloads and exit status; error text can only turn a failure into `error`, never into a positive or `unsigned` verdict.

| Section | State | Meaning |
| --- | --- | --- |
| `signature` | `unsigned` | No signature candidate; Cosign is not run. An attestation-only image is `unsigned`. |
| | `signed` | Cosign exited 0 **and** returned a verified claim with `critical.type` `https://sigstore.dev/cosign/sign/v1` (or legacy `cosign container image signature`) whose `docker-manifest-digest` is the image digest. |
| | `invalid` | A candidate exists but Cosign rejected it (non-zero exit not classified as an outage), or no verified sign claim names this digest. See the [limitations](docs/registry-signing.md#lupetto-verify). |
| | `error` | Artifact listing failed, Cosign could not run or produced unparseable output, or Cosign failed because the registry, transparency log, or trust root was unreachable or refused access. Never reported as `unsigned`. |
| `attestation` | `absent` | No SPDX attestation candidate; Cosign is not run. |
| | `attested` | Cosign exited 0 and a verified in-toto statement has predicate type `https://spdx.dev/Document`, a subject `digest.sha256` equal to the image digest, and a JSON-object predicate. The first such statement is used. |
| | `invalid` / `error` | As for `signature`. |

The legacy simple-signing claim type (`cosign container image signature`, written by non-bundle signing to a `.sig` tag) also satisfies `signed`: in that format Cosign `verify` returns only image-signature claims.

`--cosign-allow-http` (valueless means true; only `true`/`false`) is **required for, and restricted to,** literal localhost/loopback-IP registries. It adds `--allow-http-registry --insecure-ignore-tlog` and reports `transparencyLog: "skipped-local"`; otherwise Cosign keeps its defaults, including transparency-log verification, and the document reports `"verified"`. That field describes the verification mode, so a local result is never presented as production evidence. There is no environment input for this flag.

`--sbom-out <file>` must name a path that does not exist (checked at invocation and again with an exclusive create) in an existing directory. Only when the attestation is `attested` does Lupetto write the exact verified predicate bytes there as a new mode-0600 file and report its absolute `path`; for any other state, no file is written and the command still exits 0. Cosign re-serializes the predicate when attesting, so the bytes and SHA-256 differ from the retained `sbom-<arch>.spdx.json`; compare them as parsed JSON.

`--json` prints one indented, newline-terminated `kind: "verify"`, `version: 1` document: `reference`, `digest`, `checkedAt` (UTC RFC 3339), `trust.publicKeySHA256` (hex SHA-256 of the key's DER SubjectPublicKeyInfo), `transparencyLog`, `signature` (`state`, optional sanitized `error`, `artifacts` = candidate count), and `attestation` (`state`, optional `error`, `artifacts`, and, only when `attested`, `predicateType` and `sbom` with `sha256` of the exact predicate bytes, SPDX `packages` count, and `path` when written). Without `--json`, a short human summary is printed instead.

Exit **0** means the check completed, whatever the states: consumers must read them. Invalid invocation (including key, reference, loopback/HTTP, and `--sbom-out` path errors) exits **2**; global failures (Cosign missing or not v3.1.3, key staging, cancellation, or an `--sbom-out` write failure) exit **1**. Exit 1/2 have stderr diagnostics and no JSON document. Registry failures become that section's `error` state.

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

`--json` prints one indented, newline-terminated document: `kind: "status"`, **`version: 2`**, `computedAt` (UTC RFC 3339), `architecture`, `registry`, `repository`, `indexSHA256`, `security`, and `tracks`. `security` has `url`, `sha256`, `unsigned`, `fixedOnly`, `wolfiOnly`, `unevaluatedFixCount`, `unevaluatedFixes`, and `severity` (summary below). Each track has `package`, `selector`, `state`, optional `error`, optional `latest` (`name`, `version`, `architecture`), optional `repository`, `images`, optional `newest`, `installed`, `outdated`, `missingFixes`, `unevaluatedFixes`, `artifactCount`, and `unidentifiedCount`.

- Each image: `digest`, `tags`, `name`, `version`, `architecture`, `created`, `annotations`.
- Each installed identity: `name`, `version`, `architecture`.
- Each outdated package: `name`, `architecture`, `installedVersion`, `latestVersion`.
- Each missing fix: `name`, `architecture`, `installedVersion`, `fixedVersion`, `availableVersion`, `ids`, `reachableByTrack`, `advisories`, `maxSeverity`.
- Each unevaluated fix: `name`, original `fixedVersion`, `ids`, `advisories`, `maxSeverity`; track entries also include `installedVersion`, `architecture`.
- `ids` remains a string array for advisory links. `advisories` carries every ID as `{id, severity, severitySource}`; `maxSeverity` is the highest known severity in that fix group, or `unknown`. Valid severities are `critical`, `high`, `medium`, `low`, `unknown`.
- `security.severity` counts unique IDs across missing and global/track unevaluated fixes: `idCount`, `resolvedCount`, `unknownCount`, `pendingCount`, `fetchFailureCount`, and `sourceCounts` keyed by the exact source label. Pending IDs are a subset of unknown IDs.
- Empty fact lists are arrays, not `null`; unavailable facts (`latest`/`newest`) are omitted.

Exit **0** means the global comparison completed, even when tracks are outdated or have errors: inspect every track's state. Invalid invocation/configuration/products YAML exits **2**; global failures (including signed-index verification and security-feed fetch/parse failures) exit **1**. Exit 1/2 has stderr diagnostics and no partial JSON document.

### Advisory severity

Severity enrichment is best-effort metadata and **never changes track state, fix reachability, or APK version comparison**. Human output shows unique advisory counts by severity per track (including unevaluated warnings), plus an enrichment summary. `unknown` is not a clean-security result.

CVEs use the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities): prefer CVSS v4.0, then v3.1, v3.0, v2, choosing primary before secondary within each version; labels are `nvd-cvss-v4.0`, `nvd-cvss-v3.1`, `nvd-cvss-v3.0`, or `nvd-cvss-v2`. OSV database-provided severity is a fallback (`osv`). GHSA IDs prefer **their own** [OSV](https://google.github.io/osv.dev/api/) database severity (`osv`), then **their own** [GitHub advisory severity](https://docs.github.com/en/rest/security-advisories/global-advisories) (`ghsa`). Only when neither own severity is available may a true CVE alias from that advisory's OSV `aliases` or GitHub `cve_id` supply NVD severity, labelled `osv-alias:CVE-…` or `ghsa-alias:CVE-…`. GO IDs resolve true aliases from their own OSV record, preserving `osv-alias:<ID>` provenance. **IDs co-listed under a secdb fixed version are not aliases; no severity is transferred by fix grouping.** Raw CVSS vectors alone are deliberately skipped rather than assigning guessed scores. Unsupported IDs or complete sources without severity are `unknown` / `none`; unfinished or failed retrievals are `unknown` / `pending`. Upstream sources can disagree; advisory-own severity takes precedence over a CVE alias.

Results are stored by ID in private mode-0600 files under the mode-0700 OS user-cache `lupetto/status/severity/` directory, with fetch timestamps. Known results refresh after seven days; confirmed unknowns refresh after one hour. Pending results are not cached, allowing later runs to fill them. Cache failures only reduce severity coverage and never fail status.

```bash
lupetto status --products products.yaml --json --severity-budget 20s
lupetto status --products products.yaml --json --severity-budget 0
```

These commands inherit the configured registry/repository. The default severity budget is **20s**; `0` disables all severity network requests and uses fresh cached facts only. Other values are Go durations from 0 through 5m. The budget covers all advisory fetches, not the index/feed/registry comparison. Unauthenticated NVD requests are spaced at least 6.1s within the resolver; an optional **`NVD_API_KEY`** environment value reduces spacing to 0.6s and is sent only in the NVD request header, never printed, logged, or cached. Configure the variable through your secret-management mechanism, not a shell argument/example containing a real key. NVD 403/429 responses stop additional NVD requests for that run; GitHub's unauthenticated 60-request/hour allowance means it is used sparingly after OSV. HTTP failures, malformed or oversized responses and rate limits never fail status: remaining IDs stay honestly unknown/pending, with actual failed fetches counted in the summary. Independent CLI processes do not share an API quota lock; rapid repeated runs or other clients can still exhaust upstream limits.

### Security-data limitations

The feed at `https://packages.wolfi.dev/os/security.json` is fetched over HTTPS and its bytes are identified by SHA-256, but it is **not signed**. It lists **fixed vulnerabilities only**, covers Wolfi packages only, and is matched by exact installed APK name (no unproved origin/subpackage mapping). An empty result never means an image has no vulnerabilities. This is **not a vulnerability scan**, signature verification, or runtime-readiness assessment. Index and feed can change between independent requests; computed time/checksums identify the observations, not one atomic upstream snapshot. Real proof and the exercised bounds/cases are in [status verification](docs/verification.md#registry-status-checkpoint-2).

An unparseable secdb fixed-version key is never sorted heuristically or silently discarded. It is excluded from evaluated comparisons but reported in the security source's `unevaluatedFixCount` / `unevaluatedFixes`, and in any track that installs that exact package. Human output shows a warning and an `UNEVALUATED` count. For example, the observed feed included `opa-envoy` key `1.1.0-r1-r0`, which the pinned APK comparator rejects. Inspect these warnings even if a track says `current`; the vulnerability entries have **not been evaluated**. Other malformed feed structure, invalid package names, duplicate packages, and exceeded bounds remain global failures.

Fixed-version entries with **no recognised advisory IDs** are also reported as unevaluated, globally and on affected installed tracks, with their original unsupported IDs retained. They are never silently dropped just because their IDs have an unknown format. Mixed entries use their recognised CVE/GHSA/Go IDs for evaluated comparisons; consumers must inspect unevaluated warnings even when the fixed APK version parses.

## Manage tracked products

```bash
lupetto products list --products products.yaml --json
lupetto products add postgresql 16 17 --products products.yaml --create
lupetto products add nginx 1.30 --products products.yaml --json
lupetto products remove postgresql 16 --products products.yaml
lupetto products remove nginx --products products.yaml --json
```

These commands never contact the network. Names/providers and dotted numeric selectors use the same validation as build/status. `add` appends absent selectors or a new package, preserving existing ordering; adding an existing pair (including duplicate arguments) succeeds without rewriting the file and says `Already tracked; no changes`. `remove` removes only the supplied selectors, or the whole package when none are supplied; removing an absent pair is also a no-op. Removing the final selector removes that product. Management permits `products: []` after removing the last product, while `status` still requires at least one track.

A missing file is an error unless **`add --create`** explicitly permits creation (mode 0600). Edits use a same-directory temporary file, fsync, and atomic rename, preserving the existing file's permission mode. YAML node editing retains comments and ordering on surviving nodes, but formatting may be normalized and comments attached to removed nodes disappear. Symlinks are rejected. Read-only files/directories fail clearly; mount the **products directory writable**, not a single bind-mounted file, so atomic replacement can work. Concurrent editors are not serialized; the last atomic replacement wins.

`--json` returns one document with `kind: "products"`, `version: 1`, `products: [{package, selectors: [...]}, ...]`, `changed`, and `message`. Lists are arrays, including an empty products list. Human output is a compact package/selector table plus the message. Invalid invocation or products YAML exits **2**; filesystem failures exit **1**; both report stderr diagnostics without JSON. Successful no-ops exit **0**. See [products evidence](docs/verification.md#products-management-redesign-round).

## Inventory local images and build history

```bash
lupetto images
lupetto images --json
DOCKER_HOST=unix:///tmp/no-docker-daemon.sock lupetto images --json
```

`images` reads retained `result.json` **and** `failure.json` under the OS user cache's `lupetto/builds/`, newest record modification time first. Version-6 records preserve command, outcome/failure stage, request, exact selection, local OCI manifest digest, and separate load/publication/signing/attestation outcomes. Older/unknown versions are listed as `unsupported` without interpreting their fields; malformed/unreadable records are listed explicitly, not silently omitted. `buildTime` comes from the retained apko configuration's actual UTC creation annotation when available; `recordedAt` is the record file's modification time, not an invented build timestamp.

Validated local SPDX is reported with path/checksum and `present: true` only if the current regular file remains inside its workspace and its bytes still match the record's validated checksum. A deleted, changed, unreadable, oversized or outside-workspace document has `present: false` and a reason. This is retained, checksum-checked evidence, not a new SPDX validation or durable storage guarantee; deleting a workspace removes that history/evidence.

Docker access is optional and read-only: the command inherits the existing Docker environment/context and uses only `docker image ls` and `docker image inspect`, without starting a daemon or changing images/tags/contexts. Inventory includes `lupetto/` tags only, grouped by full image ID, with creation time and byte size. Exact APK identity is derived first from matching version-6 record image IDs; without such a record, one unambiguous literal readable tag can supply it. Conflicting identities, unique-only tags, and SHA-256 fallback names remain unknown. Readable tags are mutable names, not immutable build associations.

Missing/unreachable Docker returns **exit 0** with `docker.available: false` and a reason, while retaining build history. An available daemon with no Lupetto images returns `available: true, images: []`; these cases must not be conflated. A global history/cancellation failure exits **1**, invalid arguments exit **2**, both without JSON. Scans are bounded at 10,000 workspace directory entries, 1,000 retained records, 1 MiB per record/config, 32 MiB per SPDX, and 1,000 Docker images; Docker subprocess output is capped at 4 MiB per command and the inventory has a 10-second Docker deadline. Exceeded global history counts fail explicitly rather than return silently truncated history.

### Images JSON contract

The newline-terminated version-1 document has:

- `kind: "images"`, `version: 1`, `computedAt` (UTC RFC 3339), `builds`, `docker`.
- Each `builds` entry: `workspace`, `recordPath`, `recordVersion`, `status` (`supported|unsupported|invalid|unreadable`), optional `error`, `recordedAt`, optional `buildTime`, optional `record` (the **unchanged complete version-6 build document** described [below](#results-records-and---json)), `spdx`.
- `spdx`: `present`, optional `path`, `sha256`, `reason`. `path`/`sha256` retain validated record facts even when the current file is absent; only `present: true` confirms checksum-matching bytes now.
- `docker`: `available`, optional `reason`, `images`. Each image: `id`, `tags`, `created`, `size` (bytes), `identityKnown`, `identitySource` (`build-record|readable-tag|unknown`), optional `identity: {name, version, architecture}` (Wolfi architecture).
- Empty `builds`, `docker.images`, and `tags` are arrays, not `null`. Unsupported versions never include a parsed `record`.

For Explorer containers, local Docker inventory requires both the bundled Docker CLI and an explicitly mounted Docker socket. **The socket grants host-root-equivalent control** even though inventory is read-only; access is opt-in, not a requirement for retained build history. The default combined-container run has no socket and reports Docker unavailable. See the [container guide](#combined-container) and [inventory evidence](docs/verification.md#local-inventory-redesign-round).

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

The schema changes only with a new `version`; version 3–5 records from earlier releases are not migrated. Explorer accepts only version-6 build/SBOM records in inventory, kind `status` version-2 documents, and kind `discover`, `products`, `images`, and `inspect` version-1 documents; incompatible versions are explicit errors. Live build stdout must be a `build` record. Status version 2 preserves the original `ids` links and adds per-ID advisory severity, per-group maximum severity, and the enrichment summary; older Explorer binaries requiring status version 1 must be upgraded with the CLI.

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

Explorer remains an optional separate application/consumer, not a second build engine or CLI prerequisite. Its backend consumes only the versioned CLI `status`, `discover`, `products`, `images`, `inspect`, and build JSON contracts. Remote Konflux execution, unfixed-vulnerability scanning, production credential/key management, and invented service recipes remain deferred. Status is a bounded registry/security-fix comparison, not a general vulnerability scanner.

## Optional Explorer server

Install the separately runnable backend from this checkout:

```bash
go install ./cmd/lupetto-explorer
lupetto-explorer --help
lupetto-explorer --products products.yaml --lupetto-binary lupetto
```

| Flag | Default / behavior |
| --- | --- |
| `--listen` | `127.0.0.1:8080` |
| `--allowed-host` | Repeatable host or host:port allowlist, enforced for every listener. Without flags: `localhost`, `127.0.0.1`, `[::1]` at any port. Explicit flags replace defaults; a bare host permits any port, a host:port requires that exact port. |
| `--products` | Required path to the CLI products YAML file above. |
| `--lupetto-binary` | `lupetto`, resolved on `PATH`; an explicit executable path is accepted. |
| `--enable-builds` | `false`; enables one CLI build at a time, not a queue. |
| `--refresh-interval` | `15m`; positive Go duration for background status and package-catalog refresh. |

Explorer passes no registry, repository, credentials, keys, or passwords as arguments. Publication builds inherit the server process environment, including `LUPETTO_REGISTRY`, `LUPETTO_REPOSITORY`, `LUPETTO_COSIGN_KEY`, optional signing configuration/HTTP consent, `COSIGN_PASSWORD`, and `DOCKER_CONFIG`. Local-only builds exclude publication/signing settings while retaining Docker configuration. Use the existing [registry/signing configuration guide](docs/registry-signing.md#configuration-and-upfront-errors); Explorer performs no login and never logs the environment. Read-only operation needs no signing key. To publish UI-triggered builds, configure registry/repository before starting Explorer with `--enable-builds`.

**Signature status:** to show whether registry images are signed, start Explorer with `LUPETTO_COSIGN_PUBLIC_KEY=/trusted/path/operator.pub` in its environment (the trusted **public** key; no password or private key is needed). Explorer then runs [`lupetto verify --json`](#verify-signatures) in the background for registry images, at most two at a time and once per image reference; the key path reaches the CLI only through the inherited environment, never as an argument. `--cosign-allow-http` is added only when Explorer's environment has `LUPETTO_COSIGN_ALLOW_HTTP=true` **and** the image's registry is a literal loopback host. Without the key nothing is verified: every image shows **Not checked** with that reason. Otherwise each registry image in the image detail (and the newest image of each version on Images) shows:

| State | Meaning |
| --- | --- |
| Signed | A Cosign image signature verifies against the trusted key. |
| Unsigned | No signature was found for this digest. |
| Invalid | Signature artifacts exist but none verified against the trusted key with Cosign's default trust (rechecked after about five minutes; see [limitations](docs/registry-signing.md#lupetto-verify)). |
| Error | The check could not complete (for example registry or Cosign failure, or an incompatible CLI); the sanitized message is shown. |
| Checking… / Not checked yet | A check is queued or running, or has not started; pages never wait for it. |

The SPDX attestation state is shown beside it: SBOM attested (with package count), No SBOM attestation, Invalid SBOM attestation, or SBOM check error. "local only · no transparency log" marks a result verified with the loopback HTTP exception (`transparencyLog: skipped-local`), which is not production evidence. Signature results never change verdicts or track states. Results are cached in memory by key path and image reference for about an hour when signed and attested and about five minutes otherwise (including invalid); a changed key fingerprint discards all results; a finished build discards the results for the digests it published, signed or attested.

`GET /images/{package}/{selector}/sbom/{digest}` downloads a registry image's **signed** SPDX SBOM. It is offered only for an image in the current status whose cached result is attested. Each download re-runs `lupetto verify --json --sbom-out <new private temporary file>`, requires the fresh result to still be attested and the file's SHA-256 to equal the verified `attestation.sbom.sha256`, then serves it as an `application/spdx+json` attachment and deletes the temporary file. Unknown images return 404, malformed digests 400, unattested images 409, and verification failures or checksum mismatches 502; each download has 25 seconds and at most two run at once (503 when busy). The registry Packages list itself still comes from `inspect`, not from the attestation.

**Dashboard pages:** the B · Pista dashboard is server-rendered with Go `html/template`, embedded CSS and small progressive-enhancement JavaScript; no SPA or Node toolchain. Images (`/`, alias `/images`) groups tracked products and selectors, joining registry images with exact APK name/version/architecture matches from local Docker and retained builds. Search uses `?q=substring`; filters use `?filter=needs-action|current|not-in-registry|critical`. Image detail (`/images/{package}/{selector}`) has GET tabs `?tab=overview|vulnerabilities|packages|compare|builds`. Missing fixes are split into reachable rebuild fixes and fixes needing another version; one security-data note explains the unsigned fixed-only Wolfi feed. Packages use the newest registry image's status-installed list, digest-addressed inspect for older images, or validated retained SPDX for local builds. Compare selects two registry/build keys using `?from=…&to=…`, including sibling selectors of the same product, and shows added/removed/changed packages without inventing APK ordering.

Catalog (`/catalog?q=substring`, `/catalog/{name}`) searches the cached signed index and offers Track and exact-version Build actions. Builds (`/builds`, optionally `?package=name`, `/builds/{id}`) merges persistent CLI build/failure records with the last 50 in-memory jobs, deduplicated by workspace, and shows seven stages: resolve, build, validate, load, publish, sign, attest. Raw logs exist only for jobs started by the current server process, behind a toggle. Tracking (`/products/track?package=name&selector=major`) works as a dialog with JavaScript or as a plain page. `POST /products/add|remove` edits only through the CLI, is available even with builds disabled, reports read-only file/directory errors clearly, and refreshes status afterward. Mount the products **directory** writable for atomic replacement. Removing the last track yields an intentional empty state without asking status to compare an empty products file.

Build forms submit `package`, exactly one of `selector` (dotted numeric) or `apkVersion` (exact `-rN` revision), and `mode=local|publish` to `POST /builds`. Explorer invokes an argv array, never a shell: `lupetto build <package> (<selector> | --apk-version <revision>) --json`. Publish mode requires configured registry/repository and inherits signing settings. It also loads into local Docker when the latest inventory reports Docker available; otherwise it adds `--no-load` and shows the unavailable/unknown reason before and after submission. The job retains that loading decision even if inventory changes while it runs, and its running load stage follows the decision. Finished stages use the CLI record; a Docker load failure occurs before publication. Local mode always loads Docker and suppresses publication/signing even when the server has registry settings. Absent `mode` preserves the older no-load/environment-driven behavior. Builds disabled returns 403; another running job returns 409. Stdout must be a version-6 record, including partial failures; stderr polling at `/builds/{id}/logs?offset=<byte-position>` returns `{offset,nextOffset,text,truncated,done}`, capped at a 1 MiB retained tail. Job history is capped at the last 50 jobs. Restarting Explorer loses only in-memory jobs/logs; retained CLI history remains.

Status refreshes at startup, on the interval, after builds and tracking edits, and on `POST /status/refresh`. Refresh is single-flight; last good facts, computed time, latest error and in-progress state remain separate. A build finishing during an older refresh schedules another comparison. Inventory is cached for 15 seconds and invalidated after builds/tracking edits; inspected immutable package sets are cached by digest reference. Catalog search returns at most 200 entries; named discovery has a 25-second limit and at most four concurrent processes. Append `?format=json` to page GET routes for their view model. Old `/tracks`, `/packages`, and `/jobs` routes remain aliases. `/healthz` means process up, not healthy comparison data. The [rendering contract](internal/explorer/web/CONTRACT.md) specifies models, forms, states and polling.

`GET /builds/{record-id}/sbom` downloads only the local build's validated, checksum-matching SPDX as `application/spdx+json` with attachment disposition. Explorer rechecks the bytes, confines file access to the OS user-cache `lupetto/builds/` directory and that build's workspace, and rejects traversal, symlinks and non-regular/oversized files. The route never accepts a caller-supplied file path. Deleted or changed evidence is unavailable, not silently substituted. Signed SBOMs of registry images use the separate attested-download route above.

`POST /builds/{id}/cancel` sends SIGTERM, which the CLI handles through context cancellation; after five seconds Explorer kills an unresponsive CLI. SIGINT/SIGTERM cancels the active job/background work and gracefully drains HTTP. Cancellation is best-effort, can retain a failure record, and does not roll back images/tags/signatures; a CLI that completes successfully remains successful if cancel races its final record.

### Explorer HTTP security

**No login or user isolation.** Protect access with an operator-controlled network boundary (local connection, port-forward, or authenticating ingress). Builds are off by default and listening defaults to loopback; do not expose a build-enabled instance unauthenticated to an untrusted network.

Refresh/build/cancel/tracking edits are POST-only, require the per-process hidden form field `csrfToken` (not a query parameter), and check `Origin` or `Sec-Fetch-Site: same-origin`. An Origin must use `http` or `https` and its host and explicit port must exactly equal the request Host; either scheme is accepted to support TLS-terminating ingress forwarding plain HTTP. No `X-Forwarded-*` headers are trusted: an ingress must preserve the external Host and enforce authentication itself. Every request on every listener must also match `--allowed-host`, preventing DNS rebinding even when Explorer listens on `0.0.0.0` behind Docker/Kubernetes loopback port-forwarding. Defaults allow only `localhost`, `127.0.0.1`, and `[::1]` at any port. For ingress, explicitly list its external hostname, for example `--allowed-host explorer.example.invalid --allowed-host localhost`; explicit flags replace the defaults. IPv6 literals must be bracketed. Hostnames are case-insensitive; a configured port must match exactly. Host/CSRF/origin checks are not authentication.

Responses set CSP `default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: same-origin` (under `no-referrer`, browsers send `Origin: null` on form posts, which the same-origin check rejects); embedded `html/template` rendering escapes CLI metadata. Server read/header/write/idle timeouts and request/output limits are set. The dashboard must keep unsigned/fixed-only/Wolfi-only feed limitations and unreachable/unevaluated-fix warnings visible, including on `current` tracks. The server was exercised by curl and the dashboard in headless Chromium, both with real loopback publication/status runs; the combined container was verified separately with a non-root build/publication and dashboard JSON run. See [Explorer server evidence](docs/verification.md#explorer-server-checkpoint-3), [dashboard UI evidence](docs/verification.md#explorer-dashboard-ui-checkpoint-4), and [container evidence](docs/verification.md#combined-container-checkpoint-5).

### Combined container

Build the verified **linux/amd64** image from this checkout. The multi-stage `Containerfile` uses Go 1.27.1 with CGO disabled, a digest-pinned Wolfi base, exact Wolfi `apko=1.4.5-r0` and `docker-cli=28.5.0-r0`, upstream Cosign **v3.1.3** checked against a pinned SHA-256, and CA certificates. It embeds the Explorer templates/static assets present at build time; no image is published by this command.

```bash
docker build --platform linux/amd64 -f Containerfile -t lupetto-explorer:local .
docker run --rm --name lupetto-explorer \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  --mount type=volume,src=lupetto-cache,dst=/var/cache/lupetto \
  --mount "type=bind,src=$PWD/products,dst=/etc/lupetto/products" \
  --mount "type=bind,src=$HOME/.docker/config.json,dst=/etc/lupetto/docker/config.json,readonly" \
  -e DOCKER_CONFIG=/etc/lupetto/docker \
  -e LUPETTO_REGISTRY=registry.example.invalid \
  -e LUPETTO_REPOSITORY=team/lupetto/images \
  lupetto-explorer:local
```

This is an operator template: create a `products/` directory containing a [products file](#compare-published-images-with-wolfi) named `products.yaml`, replace the generic registry/repository with an authorized HTTPS target, and mount only the intended Docker config file. `DOCKER_CONFIG` names its **directory**, not the file. Credential helpers referenced by that file must also exist in the container; this image does not bundle vendor-specific helpers. Mounted files must be readable by UID/GID **65532:65532**. An empty new Docker named volume inherits the image's cache ownership; a pre-existing volume or bind-mounted cache must already be writable by that UID/GID.

For dashboard tracking edits, both `products/` and `products/products.yaml` must be writable by UID/GID 65532 (on Linux, for example, `sudo chown -R 65532:65532 products`, after placing the intended file there). Mount the **directory**, not a single file: `lupetto products` writes a temporary file alongside the original and atomically renames it. A single-file bind mount cannot be replaced by that rename. Add `,readonly` to the directory mount for deliberate read-only tracking; viewing still works and an attempted edit shows the dashboard's read-only/writable-directory message.

The entrypoint is `lupetto-explorer`, with default arguments `--listen 0.0.0.0:8080 --products /etc/lupetto/products/products.yaml`; **builds remain disabled**. Container arguments replace all default arguments, so to opt in supply all required defaults again:

```bash
# Append these arguments after the image name in the docker run command above:
--listen 0.0.0.0:8080 --products /etc/lupetto/products/products.yaml --enable-builds
```

The example exposes the port only on host loopback. Binding the server to `0.0.0.0` inside the container is necessary for port forwarding, **not authentication**; protect any other exposure with an operator-controlled network boundary/authenticating ingress. Configure `--allowed-host` for an ingress's external authority as described [above](#explorer-http-security), and preserve that Host through the proxy. Do not expose a build-enabled instance to an untrusted network. `/healthz` reports process liveness, not registry/status health.

No Docker daemon, socket, privileged mode, or extra capabilities are needed for registry publication: real non-root builds/push/readback succeeded with **all capabilities dropped** and `no-new-privileges`. Publish-mode dashboard builds use `--no-load`; local-mode builds require a reachable Docker daemon and load into it. The default run has **no socket**, so Images reports **Docker unavailable**, not an empty daemon. `docker run --rm --entrypoint lupetto lupetto-explorer:local doctor` now finds apko, Docker and Cosign and exits **0**; doctor checks executable availability, not daemon connectivity. For image-only CLI use, override the entrypoint and pass `--no-load`.

**Optional host Docker access is a host-root-equivalent grant**, not a harmless read-only inventory mount. Only opt in on a trusted instance: a socket client can create privileged containers or mount host filesystems, even when Explorer itself remains UID 65532 with no capabilities. On Linux, add these options **before the image name** to the run command above, replacing the group with the socket's numeric GID:

```bash
# Linux example: grant non-root UID 65532 access via the socket's group.
--mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
--group-add "$(stat -c '%g' /var/run/docker.sock)"
```

The socket must allow that group to read/write it; `--group-add` does not change socket permissions. Do not run the container as root or make the socket world-writable to work around access. Docker Desktop on macOS exposes the daemon through its Linux VM; the host CLI commonly uses `$HOME/.docker/run/docker.sock` (inspect `docker context inspect`) and `/var/run/docker.sock` may be an optional symlink. Desktop's `docker run --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock` exposes the **VM** socket, whose group/permissions need not match the macOS endpoint. Inspect its numeric GID in the VM/container and add that group if required; do not apply Linux `stat -c` to the macOS filesystem. Desktop socket mounting was exercised in the [redesign container check](docs/verification.md#combined-container-redesign-round).

Cache/evidence live below `XDG_CACHE_HOME=/var/cache/lupetto` on the declared volume; `HOME=/var/cache/lupetto/home` is on the same volume. Retained CLI build records persist there and populate history after restart; live jobs/logs are in-memory. For optional signing, additionally bind-mount the intended key file read-only (for example at `/etc/lupetto/cosign.key`), set `LUPETTO_COSIGN_KEY=/etc/lupetto/cosign.key`, and provide `COSIGN_PASSWORD` only through the process environment (`-e COSIGN_PASSWORD` passes an already-set host variable). Never put a password in image build arguments, the Containerfile, or command arguments. Signing requires the remaining [signing configuration](docs/registry-signing.md#sign-and-attest-the-verified-digest); the container check used no keys or credentials.

See [redesign-container verification](docs/verification.md#combined-container-redesign-round) for image size, Docker access, tracking edits and local/publish dashboard outcomes, and the [original container checkpoint](docs/verification.md#combined-container-checkpoint-5) for the pinned bases and earlier evidence. Exact APK/tool availability is fail-closed, but the live Wolfi index and unpinned APK dependency closure do not guarantee byte-identical historical rebuilds; arm64 is not supported by this recipe.
