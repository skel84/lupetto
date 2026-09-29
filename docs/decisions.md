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

- The first standalone CLI uses Go 1.27.1 (the locally exercised toolchain), the temporary local module path `lupetto`, and the standard library only. A public module identity and older supported Go versions remain undecided.
- At CLI bootstrap, exact-request parsing required an APK revision (`-rN`) but did not perform catalog lookup or image builds. The PostgreSQL 17 first-image path below now resolves major/minor selectors; it does not establish generic package-family selection or validated SBOM evidence.
- apko was absent at CLI bootstrap and was subsequently installed locally through Homebrew as 1.4.5 on macOS/amd64. Installing a tool does not pin the version for Lupetto builds or settle repository/keyring, image configuration, and build-evidence decisions.
- The `doctor` command checks executable discovery on `PATH` for apko and Docker (needed by the planned default image-build/load path), with Cosign optional for signing. Missing required tools produce a nonzero status; missing optional Cosign is reported without blocking. Advice is OS-specific, but the command never installs tools or asserts version/daemon compatibility. The first-image decision below pins apko for this build path.

## Scoped first-image decisions: PostgreSQL 17

- Map the `postgresql` family only to the exact Wolfi APK name `postgresql-17`. For `17`, select the highest available numeric 17.x upstream version and packaging revision in the target-architecture APKINDEX; for `17.N`, select that upstream version's highest available revision. `--apk-version 17.N-rM` requests the exact revision. Other families/selector shapes remain unsupported. An unavailable match is an error, not a substitute or an archival fetch.
- Use the official Wolfi repository at `https://packages.wolfi.dev/os` and its [documented signing key](https://github.com/wolfi-dev/os#readme) at `https://packages.wolfi.dev/os/wolfi-signing.rsa.pub`; the key's observed SHA-256 is `f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc`. Verify the downloaded APKINDEX signature against that pinned key **before** major/minor selection or unavailable-version reporting, and retain the signed archive and its SHA-256. apko also uses the pinned key without signature bypass and locks the selected exact package/checksum before image creation; if the live repository changed in between, fail rather than substitute.
- Use native apko 1.4.5 with an `x86_64` target on the exercised darwin/amd64 host, emit a local OCI layout, and retain its input config, index, key, and apko dependency lock in a unique user-cache build workspace. No runnable PostgreSQL recipe, Docker load, publication, signing, or validated SBOM is implied. Other host/target pairs remain unverified.
- Probe evidence: `apko lock --arch x86_64 --output <lock> <config>` and `apko build --arch x86_64 --sbom=false --vcs=false --lockfile <lock> <config> <tag> <existing-output-directory>/` produced an OCI layout with `postgresql-17` version `17.10-r1` in `usr/lib/apk/db/installed`. At the observed amd64 index snapshot, `17.1`, `17.2`, and `17.3` were absent. These upstream apko probes preceded the separate Lupetto build recorded in [verification](verification.md#scoped-postgresql-17-image-evidence).

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

### Before the first exact build

- Go version/module identity and pinned apko version.
- Native or containerized apko invocation; supported host/target architecture pair.
- Repository/keyring trust inputs and resolution/lock procedure.
- Minimal image configuration versus runtime recipes: entrypoint, users, extra packages, and environment.
- Workspace ownership, output names, retention, and machine-readable result format.
- SPDX/lock comparison rules, including non-APK SPDX entries and architecture identity.
- Whether the SBOM-only command composes an image or can generate equivalent evidence without doing so.

### Before catalog selectors

- SQLite driver and schema; snapshot identity and duplicate-import semantics.
- Catalog ingest/query command names and database selection flags.
- Package-family mapping, definition of a major, and APK-compatible ordering implementation.
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
