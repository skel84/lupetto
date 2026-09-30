# Lupetto

Lupetto is a standalone CLI for discovering Wolfi APK versions, selecting an exact package revision, composing an OCI image with apko, and retaining validated SPDX and build evidence. `build` loads the image into Docker by default and can publish it to a compatible OCI registry. Optional Cosign signing and SPDX attestation extend that same build pipeline; see the [registry, signing, and verification guide](docs/registry-signing.md).

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
| `build --no-load`, `sbom` | Native **apko 1.4.5**, access to the public Wolfi repository, writable user cache. |
| Default `build` | The above plus Docker on `PATH` and a running configured local Linux Docker daemon. |
| Publication | Default build requirements, an authorized compatible registry/repository, and Docker's existing credential store. The supported push-summary grammar is Docker **27.4**. |
| Requested signing | Publication requirements plus exactly **Cosign v3.1.3** and the key/config inputs described in the [detailed guide](docs/registry-signing.md#sign-and-attest-the-verified-digest). |

```bash
lupetto help
lupetto doctor
```

`doctor` suggests OS-specific installation commands when tools are missing but never installs anything. It checks `PATH`, **not** versions, daemon health, authentication, or registry compatibility. Missing apko or Docker produces exit 1; missing optional Cosign does not. No-load and SBOM builds can work without Docker even though `doctor` reports it missing. The build path checks apko's version; requested signing also checks Cosign's exact version before workspace/network/build/publication work.

Targets follow the host architecture: `amd64` → Wolfi `x86_64` / OCI `linux/amd64`, `arm64` → Wolfi `aarch64` / OCI `linux/arm64`. Other architectures fail. There is no target-architecture flag or multi-platform build. Recorded real interoperability is on **darwin/amd64 → linux/amd64**, using Docker 27.4.0 with its containerd image store; arm64 and other host/store combinations are not thereby proven.

## Discover indexed versions

```bash
lupetto discover postgresql
lupetto discover nginx
lupetto discover valkey
lupetto discover cmd:curl
```

`discover` verifies the live APKINDEX signature against the pinned Wolfi public key, prints the signed archive's SHA-256, and lists all matching exact APK names/versions for the host architecture, newest first. Names can match an actual package or a version-matched virtual provider (`cmd:curl` resolves to actual APK entries). Different packages advertising the same version are not silently collapsed.

**Indexed does not mean buildable.** apko must still lock the package/dependencies and fetch the needed APK bytes. Discovery creates no workspace, checks no APK contents, and does not browse imported or historical snapshots. A missing name exits unsuccessfully. The live index changes, so examples are not availability guarantees.

## Build a local OCI image

For a local-only session, clear publication/signing environment settings described in the [configuration table](docs/registry-signing.md#configuration-and-upfront-errors). Otherwise environment configuration can request additional stages.

```bash
lupetto build nginx 1.30
lupetto build valkey 9.1
lupetto build postgresql 17
lupetto build nginx --apk-version 1.30.2-r0
lupetto build nginx --apk-version 1.30.2-r0 --no-load
```

These are examples, **not a package allowlist**. Lupetto resolves exact package names or version-matched providers from the signed Wolfi index. A numeric selector matches leading dotted upstream components and chooses the highest APK-compatible version/revision (`17`, `9.1`, or `9.1.2`); an exact request must include the packaging revision `-rN`. Selectors and `--apk-version` cannot be combined. Missing or ambiguous matches fail rather than substituting another package or version.

For example, exercised `nginx 1.30` and `valkey 9.1` selected actual APKs `nginx-stable@1.30.2-r0` and `valkey-9.1@9.1.2-r1`. Selection can change with a new index. Both forms enter **one** resolution/lock/composition/validation pipeline.

Stage progress and live apko lock/build diagnostics go to stderr; default builds also stream Docker load output. Interactive stderr has an ASCII spinner/elapsed time. Redirected stderr and `TERM=dumb` receive plain logs. Publication and signing tool diagnostics are suppressed to avoid credential/secret disclosure. Stdout contains the final summary **only after every requested stage and result recording succeeds**; these human-oriented logs are not an Explorer or machine-readable protocol.

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

Use the actual reference printed by your build. `--no-load` and `sbom` skip archive creation and all Docker commands; their reported references are **intended names**, not proof a tag exists or points to that build. Publication/signing cannot be combined with `--no-load`.

## Generate validated SPDX

```bash
lupetto sbom valkey --apk-version 9.1.2-r1
```

`sbom` composes a **new OCI image and workspace** through the same exact-build path. It does not extract metadata from an existing image. It requires `--apk-version`, never loads/publishes/signs, rejects `--no-load` and all explicit publication/signing flags (including empty/false forms), and ignores all `LUPETTO_*` publication/signing environment inputs.

Lupetto checks the selected installed APK's name/version/architecture and requires the complete locked Wolfi APK identity set to match apko's architecture SPDX APK entries, including the supported `distro`/installed `origin` purl forms. Non-APK image, OS, and build-recipe entries are excluded. The supplemental index SPDX is **not** lock-validated. This validation does not independently compare every installed dependency against the image, prove SPDX completeness, or scan vulnerabilities.

## Retained evidence and failures

Each build uses a unique mode-0700 workspace under the OS user cache, `lupetto/builds/image-<suffix>`. Success prints its location. It retains:

- `APKINDEX.tar.gz`, `APKINDEX.sha256`, and the pinned `wolfi-signing.rsa.pub`;
- `apko.yaml`, `lock.json`, and the local OCI layout `image/`;
- `sbom/sbom-<wolfi-architecture>.spdx.json` plus supplemental `sbom/sbom-index.spdx.json`;
- Docker archives when loading/publication requires them;
- private mode-0600 `result.json`, written only after all requested stages succeed.

Local-only/SBOM results use version 3; publication-only results use version 4; signing-requested results use version 5. These are private evidence formats, **not a supported Explorer integration contract**, and older records are not migrated. The local Docker image ID is never substituted for the pushed registry digest.

Failures/cancellation exit nonzero and retain partial workspaces. Publication/signing workflows additionally attempt a separate private `failure.json` when a workspace exists; they do not write success-only `result.json` or a complete-success summary. Build, load, publication/identity verification, signing, and attestation remain separate outcomes. Images, tags, signatures, or attestations may already exist after a failure; cancellation is best-effort and **there is no rollback**. Confirmed loading/publication/signing followed by final-record failure is partial success, not completed workflow success. See [failure handling](docs/registry-signing.md#partial-outcomes-and-failure-records).

Retaining an index and dependency lock does not preserve remote APK bytes or guarantee historical rebuildability. Keep needed workspaces/evidence deliberately; no persistent catalog/history or automatic retention service is implemented.

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

Explorer remains an optional separate application/consumer, not a second build engine or CLI prerequisite. Its product/repository/module packaging and a public CLI integration contract are undecided. Remote Konflux execution, registry inventory, vulnerability scanning, production credential/key management, and invented service recipes are not prerequisites or implemented features.
