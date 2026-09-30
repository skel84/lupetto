# Registry publication, signing, and verification

[CLI operator guide](../README.md) · [Scope](scope.md) · [Decisions](decisions.md) · [Verification record](verification.md)

Lupetto uses one signed-index selection, apko lock/composition, and architecture-SPDX validation path. Publication consumes that image's verified Docker load. Requested Cosign image signing and `spdxjson` attestation both bind to the **same verified pushed immutable reference**, not a mutable tag or local Docker ID.

This guide documents the CLI/source contract. Observed checks belong in the [verification record](verification.md), not in example commands. Authenticated loopback registry publication and the installed Lupetto CLI's **real local HTTP/offline signing and SPDX attestation proof** are recorded there, including trusted-key verification, predicate/subject agreement, and wrong-key/unrelated-digest rejection; see [completed local checkpoint 2 evidence and pending production verification](verification.md#local-cosign-signing-and-spdx-attestation-evidence). That evidence goes beyond the earlier synthetic-image prerequisite: scoped local signing/attestation acceptance and final tests have passed. Only production HTTPS/TUF/Rekor verification remains pending and has **not** been exercised. All production commands below are templates, not claims of production interoperability.

## Prerequisites

Use the [standalone CLI installation and architecture requirements](../README.md#prerequisites-and-installation): Go 1.27.1 for installation, native apko 1.4.5, Docker on `PATH`, and a running configured local Linux daemon. Publication's supported Docker push-summary grammar is 27.4; recorded runs use client/server 27.4.0 on darwin/amd64 → linux/amd64. Signing requires exactly upstream **Cosign v3.1.3**, checked before workspace/network/build/publication work when signing is requested. `doctor` checks executable presence only, not these versions or services.

Use an authorized compatible OCI registry and repository prefix. Lupetto reuses Docker's existing credential store: configure authentication outside Lupetto using your approved Docker tooling. There is no Lupetto login, credential flag, copied Docker configuration, credential/key store, or custom signing-config schema. Protect private keys and the registry account independently. Compatibility with every registry, keyless identity, or KMS backend is not established by upstream Cosign support.

Build workspaces live privately under the user's cache; keep signing keys/configuration outside the repository and do not put secrets in examples, shell command arguments/history, logs, or retained build evidence.

## Configuration and upfront errors

Only `build` accepts these inputs:

| Flag | Corresponding environment input | Meaning |
| --- | --- | --- |
| `--registry` | `LUPETTO_REGISTRY` | Registry authority, e.g. `registry.example.invalid:5443`. |
| `--repository` | `LUPETTO_REPOSITORY` | Lower-case nested prefix, e.g. `team/lupetto/images`. |
| `--cosign-key` | `LUPETTO_COSIGN_KEY` | Required effective key input to request signing. |
| `--cosign-signing-config` | `LUPETTO_COSIGN_SIGNING_CONFIG` | Optional upstream signing-config file; valid together with a key. |
| `--cosign-allow-http` | `LUPETTO_COSIGN_ALLOW_HTTP` | Explicit, literal-loopback-only HTTP consent. |

Each explicit flag overrides **only its corresponding** environment input. You can combine a registry flag with a repository environment value or a key flag with a signing-config environment value. Empty/unset environment inputs are absent. Explicitly empty string flags, including `--registry=` or `--cosign-key=`, are errors, not environment fallback or a way to disable a stage.

The HTTP boolean accepts only `true` or `false`. `--cosign-allow-http` means true; use `--cosign-allow-http=true` or `--cosign-allow-http=false` for an explicit value. `--cosign-allow-http=` is invalid. A separate following `false` is a positional argument, **not** the boolean value. Explicit false overrides environment true. Duplicate flags are errors.

Upfront configuration rejection occurs before external tool checks, workspace creation, network activity, or builds:

- Both registry/repository absent skips publication; exactly one present is an error.
- Publication or signing with `--no-load` is invalid; the Docker-loaded image is required.
- A key requires complete publication settings. A signing config or enabled HTTP consent requires a key. A key without a config is valid; there is no implicit keyless signing.
- HTTP consent is rejected for non-loopback authorities, even a DNS name resolving to loopback. Signing to a literal-loopback authority requires effective HTTP consent, even if that endpoint might support HTTPS (see the [local exception](#local-httpoffline-exception)).
- Invalid authorities/prefixes and duplicate/unknown flags are rejected rather than normalized into another target.

`sbom` ignores **all five** publication/signing environment inputs and rejects their explicit flags, including false/empty forms. It also rejects `--no-load` and requires `--apk-version`.

For an intentionally local-only build, clear all effective stage-requesting settings, for example:

```bash
unset LUPETTO_REGISTRY LUPETTO_REPOSITORY LUPETTO_COSIGN_KEY
unset LUPETTO_COSIGN_SIGNING_CONFIG LUPETTO_COSIGN_ALLOW_HTTP
lupetto build nginx 1.30
```

Registry is an authority, not a URL or image path: no scheme, user information, query, or fragment. Validated DNS names, IPv4, and bracketed IPv6 can have ports 1–65535. An unambiguous spelling has a dot, is `localhost`/an IP literal, or is a single-label DNS name with an explicit port. Repository is a lower-case nested OCI prefix with no leading/trailing/repeated slash, `.`/`..`, tag, or digest. The eventual complete reference is checked with the pinned Docker reference parser. Lupetto does not truncate an oversized operator-supplied prefix or silently change the intended authority.

## Publish the validated image

These are **generic templates, not exercised remote production commands**. Replace the placeholder authority/prefix with an authorized target and configure Docker authentication separately:

```bash
lupetto build nginx 1.30 \
  --registry registry.example.invalid --repository team/lupetto/images

LUPETTO_REGISTRY=registry.example.invalid LUPETTO_REPOSITORY=team/lupetto/images \
  lupetto build nginx --apk-version 1.30.2-r0

LUPETTO_REPOSITORY=team/lupetto/images \
  lupetto build nginx 1.30 --registry registry.example.invalid
```

Ensure signing environment inputs are absent if you want publication only. Each build derives a unique remote tag:

```text
HOST/PREFIX/<resolved-actual-apk-component>:<local-readable-tag>-build-<workspace-suffix>
```

The APK component and exact-version/OCI-architecture tag reuse the local literal-or-SHA-256-fallback naming. An overlong combined tag uses a deterministic hash of that entire tag; exact APK identity remains unchanged in evidence. Lupetto tags from the **verified local image ID**, not the mutable readable alias, and inspects the unique remote tag for the same ID/platform before pushing. There is no second apko build.

The bounded parser requires **exactly one** supported Docker 27.4 digest summary for the expected unique tag. Missing, duplicate (even identical), conflicting, wrong-tag, or malformed summaries fail closed. Lupetto constructs:

```text
HOST/PREFIX/<resolved-actual-apk-component>@sha256:<pushed-digest>
```

That digest comes from the push summary, **never** the local image ID (even if those happen to match in one Docker store). A successful push process alone is not verified publication. Lupetto pulls the immutable reference, saves it to private `docker-published.tar`, checks its config digest against the source OCI config, and hashes the actual uncompressed saved layers in manifest order against the source `rootfs.diff_ids`, with archive/platform checks. Claimed diffIDs alone are insufficient. Only then is publication reported `published` with identity verified; remote manifest serialization can differ from local identity.

Authentication-bearing Docker diagnostics are discarded, not streamed or attached to errors. Push stdout is processed by a bounded streaming parser retaining only the validated digest. Progress reports stages, not credentials or a retained publication transcript.

## Sign and attest the verified digest

Signing requires an effective key and exactly Cosign v3.1.3. An optional upstream signing-config file can be supplied **alongside** the key; it is service/signing configuration, not an identity or key store. Lupetto does not invent a file format, collect private-key contents, or provide keyless/KMS interoperability guarantees.

For encrypted keys, supply `COSIGN_PASSWORD` only through the process environment. In a Bash terminal, prompt without echoing or typing the secret into a command:

```bash
IFS= read -r -s -p 'Cosign key password: ' COSIGN_PASSWORD
printf '\n'
export COSIGN_PASSWORD
```

Do not use a literal password assignment in shell history, a password command argument, `set -x`, environment dumps, or secret-bearing log capture. Lupetto inherits the variable without adding its value to arguments, logs, or evidence; all signing/attestation stdout/stderr is discarded, so do not rely on an interactive upstream password prompt during the build. Unset `COSIGN_PASSWORD` when finished.

### Production signing template (not exercised)

Use a **non-loopback HTTPS** registry, an authorized protected key, and upstream default services:

```bash
unset LUPETTO_COSIGN_SIGNING_CONFIG LUPETTO_COSIGN_ALLOW_HTTP
lupetto build nginx 1.30 \
  --registry registry.example.invalid --repository team/lupetto/images \
  --cosign-key /protected/path/operator.key
unset COSIGN_PASSWORD
```

Paths/authority are placeholders. With no effective signing config (flag or environment), Lupetto leaves upstream HTTPS, TUF-provided signing/service configuration, and transparency-log defaults intact; it adds no insecure or log-bypass flags. A supplied signing config can change services and is **not** evidence of production transparency-log behavior. No production HTTPS/TUF/Rekor outcome has been recorded.

After verified publication, Lupetto invokes image signing with `--yes --key` and optional `--signing-config`/`--allow-http-registry`, then attestation with those same options plus `--type spdxjson --predicate <validated-architecture-SPDX>`. Both use the identical immutable registry reference. Immediately before attesting, Lupetto rereads the existing architecture document and compares its SHA-256 to the recorded validated checksum. It does not regenerate SPDX or attest the supplemental index document. A changed/unreadable document prevents attestation even after signing succeeds.

Cosign v3.1.3's default modern bundle/referrer registry behavior is preserved; Lupetto does not force deprecated legacy or experimental registry modes. The [observed Lupetto local `registry:3` run](verification.md#local-cosign-signing-and-spdx-attestation-evidence) exercised signing, attestation, and verification in that mode; it does not establish blanket registry compatibility.

## Local HTTP/offline exception

This is **local development only**, not a production default or public transparency-log/auditability proof. Use an isolated authorized registry bound to literal loopback; configuring or starting a registry is outside Lupetto. Docker must already be able to load, authenticate, push, and pull against that endpoint.

Literal loopback means `localhost` or an IP literal whose parsed address is loopback (including bracketed IPv6 with an optional port). A DNS name merely resolving to loopback does not qualify. Lupetto requires explicit effective `--cosign-allow-http` for loopback signing because upstream Cosign can automatically choose HTTP there even without `--allow-http-registry`. The option is not TLS-verification bypass or a generic insecure-registry switch. It governs Cosign, not Docker daemon transport configuration.

For a disposable local key/config, in Bash with the prompted/exported `COSIGN_PASSWORD` from above:

```bash
SIGNING_DIR=$(mktemp -d)
chmod 700 "$SIGNING_DIR"
cosign generate-key-pair --output-key-prefix "$SIGNING_DIR/local"
cosign signing-config create --out "$SIGNING_DIR/local-signing-config.json"
```

Keep this private directory outside the checkout. The config is generated by upstream v3.1.3 (Sigstore protobuf v0.2) **without services or `--with-default-services`**. Do not hand-author a replacement schema or use deprecated `--tlog-upload=false`/timestamp-service flags. This explicitly selected config removes configured signing services for the offline exception; the generic presence of a custom config does not necessarily mean offline mode.

The following is a **local target template**. Replace port `5000` and prefix with your isolated authorized target:

```bash
lupetto build busybox-static 1 \
  --registry 127.0.0.1:5000 --repository tests/lupetto/nested/images \
  --cosign-key "$SIGNING_DIR/local.key" \
  --cosign-signing-config "$SIGNING_DIR/local-signing-config.json" \
  --cosign-allow-http
unset COSIGN_PASSWORD
```

Success separates published, signed, and attested outcomes. It is not production HTTPS/TUF/Rekor proof. Protect the private key and distribute/trust the public key separately; fetching an arbitrary public key from the same registry would not establish the intended signer.

## Verify signature and SPDX attestation

Use exactly Cosign v3.1.3, a **trusted public key**, and the `Immutable reference:` from the successful build or confirmed publication outcome. Never replace it with the readable/local/remote tag or local image ID. Lupetto has no separate `verify` command; these are upstream Cosign commands.

### Production verification templates (not exercised)

Replace both placeholders with the expected immutable reference and trusted public-key path. No local HTTP or transparency-log bypass is included:

```bash
IMMUTABLE='registry.example.invalid/team/lupetto/images/actual-apk@sha256:REPLACE_WITH_PUSHED_DIGEST'
PUBLIC_KEY='/trusted/path/operator.pub'
cosign verify --key "$PUBLIC_KEY" "$IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --type spdxjson "$IMMUTABLE"
```

These forms preserve upstream production verification defaults, but they have **not** been exercised against a production registry/transparency log here. Do not describe template exit behavior as observed proof. A custom signing-services configuration or local no-service attestation cannot be promoted to production log-inclusion evidence by omitting an exception flag.

### Explicit local verification forms

For the isolated HTTP/no-service target above, replace the placeholder with its reported immutable reference. `--insecure-ignore-tlog` is a separately labeled **local-only** exception, not a production verification recommendation:

```bash
IMMUTABLE='127.0.0.1:5000/tests/lupetto/nested/images/actual-apk@sha256:REPLACE_WITH_PUSHED_DIGEST'
PUBLIC_KEY="$SIGNING_DIR/local.pub"
cosign verify --key "$PUBLIC_KEY" \
  --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --type spdxjson \
  --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
```

These upstream local forms were exercised successfully against the installed Lupetto CLI's signed/attested immutable image; see the [observed commands, claim inspection, negative checks, and limits](verification.md#local-cosign-signing-and-spdx-attestation-evidence). They authenticate signed claims with the trusted key while intentionally foregoing transparency-log verification. Upstream can autodetect loopback HTTP even without the HTTP flag; keep it explicit to communicate the local exception.

### Inspect the verified claims, not only the exit status

Successful cryptographic verification is necessary but **not sufficient**:

1. Inspect the verified image-signature claim and require its manifest digest to equal the expected pushed digest in `IMMUTABLE`.
2. Decode the returned verified attestation envelope's base64 `payload` as the in-toto statement. Check its `subject` identifies the intended repository/image and its `digest.sha256` equals the same expected pushed digest (without the `sha256:` prefix). Inspect the statement itself, not only a command exit code.
3. Require the SPDX predicate type corresponding to Cosign `--type spdxjson`. Compare the decoded `predicate` with the retained **validated architecture** `sbom/sbom-<wolfi-architecture>.spdx.json`, not the supplemental index SPDX. Parse both as JSON and require semantic agreement, including the selected exact APK revision, architecture, and full validated Wolfi APK identity set. Raw envelope bytes or JSON formatting can differ without predicate disagreement.
4. Recompute the retained local architecture document's checksum against `result.json`. Investigate any mismatch, unrelated digest/subject, unexpected signer, or missing/changed predicate; do not accept merely because Cosign returned 0.

Use trusted JSON/base64 tooling and retain inspection output privately if needed. Registry attestation, validated local SPDX, Explorer's future stored evidence, and registry-vendor scanner SBOMs are different artifacts. Neither signature validity nor lock/SPDX agreement proves completeness, absence of vulnerabilities, policy compliance, or runtime readiness.

## Partial outcomes and failure records

`result.json` is private, mode 0600, and success-only after every requested stage/finalization succeeds. Local-only/SBOM use version 3, publication-only version 4, and signing-requested version 5. These are not public Explorer schemas and old records are not migrated.

Publication/signing workflows use typed separate outcomes in stderr reporting and attempt a private mode-0600 `failure.json` when a workspace exists. Configuration/tool preflight failures may have no workspace. Failure-record writing cannot hide the original error. Requested but unreached signing/attestation is `not-attempted`; absent signing requests are `skipped`.

| Failure point | Confirmed outcome versus incomplete work |
| --- | --- |
| Push/digest/content verification | Build/load may be complete. A captured digest can remain recorded but unverified; it is not authorization to sign. |
| Image signing | Publication remains confirmed; signing is failed and attestation not attempted. A signature may still have been uploaded before tool failure/cancellation. |
| SPDX checksum/read or attestation | Publication and successful signing remain confirmed; attestation fails. An attempted attestation may already exist. |
| Final result recording | Published/signed/attested outcomes can already be confirmed, but the workflow is not complete success. |

Failures/cancellation return nonzero with no complete-success stdout. They may leave local/remote tags, a pushed image, pulled content, signatures, or attestations; **there is no rollback**. Cancellation stops clients best-effort, not necessarily daemon/server work. Inspect retained status/reference/workspace evidence before retrying; each new build has a different unique tag, and readable local tags can move.

No password, private-key/config contents, key/config path, environment dump, Docker credential configuration, or auth-bearing subprocess transcript is part of retained signing evidence. Sanitized errors expose stage/status/reference/workspace, not upstream secret-bearing diagnostics.
