# Lupetto

Lupetto is being rebuilt as a local tool for selecting Wolfi APK packages, composing OCI images with apko, and retaining verifiable build evidence. Optional registry publication extends the local build workflow; Cosign signing and signed SPDX attestation are the next checkpoint.

**Status: signed-index discovery, generic local OCI images with validated SPDX/lock package identities, local Docker loading, and registry-publication checkpoint implementation.** `lupetto discover <package-or-provider>` lists exact indexed versions; `lupetto build <package-or-provider> <numeric-selector>` and `--apk-version <exact-revision>` select an exact Wolfi APK, create a local OCI layout, validate apko-generated SPDX against the resolved lock, and load the image into Docker by default. `--no-load` skips Docker when publication is not configured. `lupetto sbom <package-or-provider> --apk-version <exact-revision>` uses that same build path without loading or publication. Publication source contracts are described below; real Lupetto publication interoperability has not yet been recorded. This is not a persistent catalog or runnable service recipe: signing, signed attestation, and Explorer are not implemented.

The source of the rebuild specification is the operator-documentation request supplied for the lost implementation. The overwritten older checkout is excluded from this project’s evidence and design. No claim about the lost implementation has been verified against its source or executable.

**Next priority:** exercise the registry-publication checkpoint, then implement Cosign image signing and a signed SPDX attestation bound to the verified pushed immutable digest. Persistent snapshot/catalog ingestion and historical queries are deferred, not removed from scope, and are not prerequisites for this workflow or the standalone CLI release. Continue using the live signed index and retained per-build evidence. See the [approved roadmap priority](docs/decisions.md#publication-first-roadmap-user-approved) and [single implementation checklist](docs/implementation-plan.md).

## Check external tools

```bash
go run ./cmd/lupetto doctor
```

The check reports whether `apko` and `docker` (required for default Docker loading and publication) and `cosign` (optional for future signing) are on `PATH`. It suggests OS-specific installation steps for missing tools. It does not install anything, verify tool versions, or check whether the Docker daemon is running. Exit status is 1 if a required tool is missing, 0 otherwise. `build --no-load` without publication settings and `sbom` do not use Docker or Cosign.

## Discover indexed versions

With Go 1.27.1 and access to the public Wolfi repository (no apko executable or Docker required):

```bash
go run ./cmd/lupetto discover postgresql
go run ./cmd/lupetto discover nginx
go run ./cmd/lupetto discover valkey
go run ./cmd/lupetto discover cmd:curl
```

`discover` verifies the current APKINDEX signature with the pinned Wolfi signing key and lists all matching exact APK names/versions for the host architecture, newest first, including version-matched virtual providers such as `cmd:curl` (which lists the actual `curl` APK). It prints the signed archive SHA-256 and does **not** silently collapse multiple packages advertising the same version. For the exercised x86_64 snapshot it listed PostgreSQL majors 13–18 and nginx series 1.26–1.31; index contents can change. An indexed version is **not confirmed buildable** until apko can lock its package/dependencies and compose an image. Discovery makes no workspace, checks no APK bytes, and does not ingest or browse historical snapshots. A missing name exits unsuccessfully.

## Build a local Wolfi OCI image

With Go 1.27.1, native apko 1.4.5, a Docker executable and running local daemon, and access to the public Wolfi package repository:

```bash
go run ./cmd/lupetto build nginx 1.30
go run ./cmd/lupetto build nginx 1.31
go run ./cmd/lupetto build valkey 9.0
go run ./cmd/lupetto build valkey 9.1
go run ./cmd/lupetto build postgresql 17
go run ./cmd/lupetto build nginx --apk-version 1.30.2-r0
go run ./cmd/lupetto build nginx --apk-version 1.30.2-r0 --no-load
```

`build` and `sbom` write stage progress and live apko lock/build diagnostics to stderr; default builds also stream Docker load output. Publication stages report progress but suppress Docker tool diagnostics because authentication failures can expose secrets. In an interactive stderr terminal, an ASCII spinner shows the active stage and elapsed time. Redirected stderr and `TERM=dumb` receive plain logs without animation. The final artifact/SPDX/load/publication summary remains on stdout and is printed only on complete success. Progress logs are not a persistent build-log artifact or machine-readable contract.

These names are **examples, not an allowlist**. Lupetto resolves any requested name that matches an exact package name or a version-matched provider in the signed Wolfi APKINDEX for the host architecture. Numeric selectors match leading dotted upstream components (`9`, `9.1`, or `9.1.2`) and choose the highest APK-compatible version and revision; an exact request must include `-rN`. Unavailable or ambiguous selections fail without substituting a package/version. Availability depends on the current index: the observed `nginx 1.30` and `1.31` selected `nginx-stable@1.30.2-r0` and `nginx-mainline@1.31.6-r2`; `valkey 9.0` and `9.1` selected `valkey-9.0@9.0.4-r0` and `valkey-9.1@9.1.2-r1`.

On success the command prints the selected **actual APK name and exact version**, the APKINDEX SHA-256, a local OCI layout, the validated architecture SPDX path/checksum, and a separate Docker loaded/skipped outcome. The primary image reference is `lupetto/<resolved-apk-name>:<exact-apk-version>-<architecture>`, for example `lupetto/busybox-static:1.38.0-r2-amd64` or `lupetto/nginx-stable:1.30.2-r0-amd64`. Architecture uses OCI spelling (`amd64` or `arm64`), not the APK spelling. Every build also retains `lupetto/local:build-<workspace-suffix>` as its unique reference. A later build can replace the readable version tag; it is not immutable identity. Older images are not automatically renamed.

Default builds export the already-validated image to `docker-image.tar`, load/verify it through the unique reference, then tag the verified local image ID with the readable name and inspect that name for the same ID/platform. When Docker's image store reports a manifest ID rather than the OCI config digest, Lupetto saves the unique imported reference to `docker-loaded.tar` and verifies its config digest against the built image before tagging. No-load and SBOM builds skip archive creation and all Docker commands; their reported references are intended names, not evidence that either tag was created or that an existing tag points to this new build.

New builds are discoverable by package name, for example `docker image ls lupetto/busybox-static` or `docker images | grep busybox`. Use the exact `Image reference:` or `Docker loaded:` value with `docker image inspect <reference>`. `docker image ls lupetto/local` still lists unique build tags, including older builds that have no readable alias. Docker-incompatible or oversized APK name/version components use deterministic SHA-256 fallback components; the exact APK identity is unchanged and remains displayed/recorded. See the [readable naming decisions](docs/decisions.md#readable-local-image-references-user-approved) and [observed evidence](docs/verification.md#readable-local-image-reference-evidence).

A unique workspace under the user's cache directory retains `APKINDEX.tar.gz`, its checksum, the pinned public key, `apko.yaml`, `lock.json`, `image/`, `sbom/sbom-x86_64.spdx.json`, supplemental `sbom/sbom-index.spdx.json`, and a version-3 local-only `result.json` written only after all requested stages succeed. The local-only result format is unchanged: it records the readable `imageReference`, unique `buildReference`, and separate Docker-load status/image ID; that local ID is **not** a pushed registry digest or Explorer contract. Existing records are not migrated. Publication success uses version 4, described below. The installed APK database is checked for the selected package/version/architecture. The complete lock APK identity set must match the architecture SPDX's Wolfi APK entries; non-APK image, OS, and build-recipe entries are excluded. This does not independently validate the index SPDX or every installed dependency against the image. Without publication settings nothing is pushed; nothing is signed in this checkpoint. These minimal images are not claimed to be runnable services.

To generate SPDX for an exact APK revision, use the same build/resolution/validation path:

```bash
go run ./cmd/lupetto sbom valkey --apk-version 9.1.2-r1
```

This composes a new local OCI image and workspace; it does not extract an SBOM from an existing image. `sbom` remains image-only, rejects `--no-load`, `--registry`, and `--repository`, and ignores `LUPETTO_REGISTRY` and `LUPETTO_REPOSITORY`. Signing flags are not implemented. A version listed by `discover` can still fail to lock or build. Failed builds retain partial workspaces but do not create a successful `result.json` or print validated-evidence success output. A load, tag, or inspect failure returns nonzero even after successful composition; once loading begins, an image may remain in Docker. A readable-tag failure reports the confirmed unique import separately from the uncertain readable tag, which may already have changed. Cancellation stops the client best-effort, not daemon work, and no image/tag rollback is attempted. Errors identify the stage/references/workspace; confirmed loading/tagging followed by result-record failure is partial local success. See [local-load evidence](docs/verification.md#local-docker-loading-evidence) and [readable-tag evidence and limitations](docs/verification.md#readable-local-image-reference-evidence).

## Publish the same built image

Only `build` accepts `--registry` / `LUPETTO_REGISTRY` and `--repository` / `LUPETTO_REPOSITORY`. Each flag independently overrides its corresponding environment value, so a registry flag can be combined with a repository environment input (or vice versa). An explicitly empty flag, including `--registry=` or `--repository=`, is an error, not a way to fall back to the environment or disable publication. Empty/unset environment values are absent. Both effective settings absent means local-only; exactly one present is an error. Duplicate/invalid flags and publication with `--no-load` are rejected before tool checks, workspace creation, or network/build side effects. Clear both environment inputs when you want a local-only build.

Registry is an authority such as `registry.example.invalid` or `registry.example.invalid:5443`, not a URL or image path. Repository is a lower-case nested prefix such as `team/lupetto/images`, without a tag, digest, empty component, or `.`/`..`. Lupetto requires an unambiguous registry authority and validates the complete eventual Docker reference; it does not silently normalize an ambiguous host or truncate an oversized operator-supplied prefix.

The following are **generic configuration examples, not exercised remote publication commands**. Replace the placeholder authority and prefix with an authorized compatible OCI registry/repository, and configure Docker's credential store separately:

```bash
go run ./cmd/lupetto build nginx 1.30 \
  --registry registry.example.invalid --repository team/lupetto/images

LUPETTO_REGISTRY=registry.example.invalid LUPETTO_REPOSITORY=team/lupetto/images \
  go run ./cmd/lupetto build nginx --apk-version 1.30.2-r0
```

Publication reuses the single validated composition and verified Docker load. The unique remote name is `HOST/PREFIX/<resolved-apk-component>:<local-readable-tag>-build-<workspace-suffix>`. It reuses the same literal-or-SHA-256-fallback APK component and exact-version/OCI-architecture tag as the readable local name; an overlong combined tag uses a deterministic SHA-256 fallback for the entire combined tag. The exact APK identity remains unchanged in output/evidence. Lupetto tags from the verified local image ID, **not** the mutable readable alias, and inspects the remote tag for that ID/platform before pushing. It uses Docker's existing credential store only: no Lupetto login, credential arguments, or copied Docker configuration.

Digest capture accepts exactly one supported Docker 27.4 summary for the expected unique tag. Missing, duplicate (even identical), conflicting, malformed, or wrong-tag summaries fail closed. The pushed immutable reference is `HOST/PREFIX/<resolved-apk-component>@sha256:<digest>`, never the local Docker ID. Lupetto then pulls that immutable reference, saves it to retained mode-0600 `docker-published.tar`, and verifies the saved config digest against the original OCI config plus the actual uncompressed saved layer bytes in manifest order against the source `rootfs.diff_ids`. A successful push or a matching claimed diffID array alone is not identity proof. Publication is reported successful only after these content/platform checks; registry manifest serialization need not match Docker's local image ID.

Authentication-bearing publication tool diagnostics are discarded rather than streamed, captured in errors, or retained. Push stdout is processed by a bounded streaming summary parser that retains only the validated digest; errors expose sanitized stage/status information. Stage progress remains visible, but there is no retained publication transcript or credential collection.

Successful publication writes a private version-4 `result.json` with separate build/load/publication outcomes, unique remote reference, captured pushed digest, immutable reference, and identity-verification status. Signing and attestation are explicitly `skipped`; **no image signature or signed SPDX attestation is implemented yet**. Local-only builds and SBOM retain version 3 unchanged. This is not an Explorer compatibility contract.

For publication-requested workflows, typed partial failures drive CLI reporting and a separate mode-0600 version-4 `failure.json` when a workspace exists. They distinguish build, Docker load, publication, identity verification, signing, and attestation outcomes; `result.json` remains success-only. A captured digest survives later verification failure but stays unverified, not a successful publication or authorization to sign. A final result-record failure can report confirmed publication without complete workflow success. Failed/canceled operations may already have changed local/remote tags, pushed an image, or pulled content; no rollback is attempted. Failure-record writing cannot hide the original stage failure. Real Lupetto registry interoperability remains to be exercised; these contracts are not a claim of observed remote publication.

## Documentation map

| Document | Purpose |
| --- | --- |
| [Scope and behavior](docs/scope.md) | What to rebuild, recovered command contracts, and explicit exclusions. |
| [Architecture](docs/architecture.md) | Recommended component boundaries, data flow, and evidence handling. |
| [Decisions](docs/decisions.md) | Distinguish specification constraints, design proposals, and open questions. |
| [Implementation checklist](docs/implementation-plan.md) | Single actionable checklist, with separate CLI and Explorer workstreams and release gates. |
| [Verification](docs/verification.md) | Observable checks required before claiming a feature works. |

Start with scope, then resolve the decisions needed for the next implementation milestone. Update these documents when a decision changes; do not turn proposed behavior into a claim of implemented behavior.

[AGENTS.md](AGENTS.md) defines repository instructions for coding agents, including evidence requirements and the CLI/Explorer boundary.

## Core workflow

```text
Wolfi snapshot → package selection → exact APK version
                                      │
                                      ▼
                              apko resolution/build
                                      │
                         lock + image + validated SPDX
                                      │
                               local Docker load
                                      │ optional
                               registry publication
                                      │
                              immutable image digest
                                      │ optional
                         image signature + SPDX attestation
```

Numeric selectors are implemented for the current signed index: they resolve to an exact package/version before entering the same build pipeline as explicit version requests. Persistent snapshot catalog ingestion and historical selections are deferred; retaining an index does not preserve APK bytes or guarantee historical rebuildability.

## CLI and Explorer separation

The CLI is a standalone application. Explorer is an optional application that consumes it for builds; the CLI never depends on Explorer. Explorer owns the web UI, not a second build engine.

Whether Explorer lives beside the CLI or becomes a separate product, repository, or Go module is intentionally undecided. [The application boundaries and integration contracts](docs/architecture.md#application-and-dependency-boundaries) must support either choice. CLI delivery does not wait for Explorer.

## Working principles

- Prefer a small coordinator of apko, Docker, and Cosign over a new build platform.
- Keep exact package selection and dependency resolution evidence explicit.
- Separate successful image creation, publication, signing, and attestation outcomes.
- Never store real passwords, tokens, private keys, or copied credentials in documentation or fixtures.
- Do not introduce remote Konflux execution, registry inventory, or vulnerability scanning as prerequisites for local builds.

## Operator documentation later

Once the build workflow is implemented and exercised, replace this landing page with the verified operator guide and add `docs/registry-signing.md` for detailed publication and verification instructions. Preserve links to the rebuild documents. Do not publish invented defaults or unexercised commands as current operator instructions.
