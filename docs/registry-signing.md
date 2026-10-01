# Registry publication, signing, and verification

[CLI operator guide](../README.md) · [Scope](scope.md) · [Decisions](decisions.md) · [Verification record](verification.md)

This guide is the single operator reference for publication, signing, and verification. Lupetto pushes the **validated OCI layout** from its one exact-build pipeline directly to a registry, reads it back by digest, and only then signs and attests that **same verified immutable reference**—never a mutable tag or local Docker ID.

Observed runs are in the [verification record](verification.md#direct-oci-publication-and-version-6-record-evidence); they cover an isolated authenticated loopback HTTP registry with local/offline Cosign settings. **Production HTTPS/TUF/Rekor behavior has not been exercised**, so every production command below is a template.

## Prerequisites

- Lupetto installed as in the [operator guide](../README.md#prerequisites-and-installation), with native apko 1.4.5. Docker is needed only when loading (the default); publication itself does not use Docker.
- An authorized OCI registry and repository prefix. Lupetto authenticates with **Docker's client configuration only**: `$DOCKER_CONFIG/config.json` or `~/.docker/config.json`, including `credsStore`/`credHelpers`. Configure it with your approved Docker tooling (for example `docker login`). Podman/containers auth files are ignored. There is no Lupetto login, credential flag, or copied configuration.
- TLS trust and proxies come from the host and process environment (`HTTPS_PROXY` etc.), not the Docker daemon. Daemon-only `insecure-registries`, daemon `certs.d`, and daemon proxy settings do not apply.
- For signing: exactly upstream **Cosign v3.1.3** (checked before any workspace, network, or build work) and an operator-managed key. `doctor` checks only that executables are on `PATH`.

Keep keys, signing configuration, and passwords outside the repository, shell history, command arguments, and logs.

## Configuration and upfront errors

Only `build` accepts these inputs:

| Flag | Environment input | Meaning |
| --- | --- | --- |
| `--registry` | `LUPETTO_REGISTRY` | Registry authority, e.g. `registry.example.invalid:5443`. |
| `--repository` | `LUPETTO_REPOSITORY` | Lower-case nested prefix, e.g. `team/lupetto/images`. |
| `--cosign-key` | `LUPETTO_COSIGN_KEY` | Key that requests signing. |
| `--cosign-signing-config` | `LUPETTO_COSIGN_SIGNING_CONFIG` | Optional upstream signing-config file; requires a key. |
| `--cosign-allow-http` | `LUPETTO_COSIGN_ALLOW_HTTP` | Explicit HTTP consent for Cosign; literal loopback only. |

Each explicit flag overrides **only its own** environment input, so a registry flag can combine with a repository environment value. Unset or empty environment values are absent. Explicitly empty flags (`--registry=`, `--cosign-key=`) are errors, not a way to fall back or disable a stage. Duplicate flags are errors.

`--cosign-allow-http` alone means true; `--cosign-allow-http=true|false` sets it explicitly, and explicit false overrides environment true. A separate following `false` is a positional argument, not the value.

These are rejected before tool checks, workspace creation, network access, or building:

- Exactly one of registry/repository set. (Both absent skips publication.)
- A key without complete publication settings; a signing config or HTTP consent without a key. There is no implicit keyless signing.
- HTTP consent for a non-loopback authority (a DNS name that merely resolves to loopback does not count), or signing to a literal-loopback authority **without** HTTP consent.
- Invalid authorities or prefixes. Registry is an authority, not a URL: DNS name, IPv4, or bracketed IPv6, optional port 1–65535; a single-label name needs a port unless it is `localhost`. Repository has no leading/trailing/repeated slash, `.`/`..`, tag, or digest. Nothing is truncated or normalized into another target.

After the APK is selected (so after the workspace exists and the index is fetched) but before composition, loading, or publication, the complete reference is checked: it must parse to the same registry, repository, and tag in both `github.com/distribution/reference` and go-containerregistry (the only accepted difference is `docker.io` ↔ `index.docker.io`) and fit the length limits. A failure there is a `build`-stage failure with a `failure.json`.

`--no-load` is valid with publication and signing. `sbom` ignores all five environment inputs and rejects their flags (including false/empty forms).

For an intentionally local-only build, clear the stage-requesting settings:

```bash
unset LUPETTO_REGISTRY LUPETTO_REPOSITORY LUPETTO_COSIGN_KEY
unset LUPETTO_COSIGN_SIGNING_CONFIG LUPETTO_COSIGN_ALLOW_HTTP
lupetto build nginx 1.30
```

## Publish the validated image

**Templates, not exercised production commands.** Replace the authority/prefix with an authorized target:

```bash
lupetto build nginx 1.30 \
  --registry registry.example.invalid --repository team/lupetto/images

LUPETTO_REGISTRY=registry.example.invalid LUPETTO_REPOSITORY=team/lupetto/images \
  lupetto build nginx --apk-version 1.30.2-r0 --no-load --json
```

Each build pushes to a unique tag:

```text
HOST/PREFIX/<resolved-actual-apk-component>:<local-readable-tag>-build-<workspace-suffix>
```

The APK component and exact-version/architecture tag reuse the local literal-or-SHA-256-fallback naming; an overlong combined tag is replaced by a deterministic hash of the whole tag. Evidence keeps the unchanged APK name/version.

Publication then:

1. Confirms the layout's manifest is still the one validated earlier (`evidence.imageDigest`), then pushes it **unchanged**, so the pushed digest equals that validated digest.
2. Fetches the manifest **by digest** and requires its bytes to hash to that digest and equal the local manifest.
3. Fetches the unique **tag** and requires the same manifest bytes (the body is hashed; a `Docker-Content-Digest` header is not trusted).
4. Fetches the config by digest and requires it to equal the source config.
5. Fetches every layer by digest, hashing the compressed bytes against the manifest and the uncompressed stream against the source `rootfs.diff_ids`, in order.
6. Retains the fetched manifest as private `published-manifest.json`.

Only then is publication `published` with `verified: true`, and the immutable reference is:

```text
HOST/PREFIX/<resolved-actual-apk-component>@sha256:<pushed-digest>
```

A successful upload alone is not verification. If readback fails, the digest stays recorded as unverified and signing is blocked.

**Plain HTTP** is used only for `localhost` or a loopback IP literal (any `127.0.0.0/8` address or `::1`), where the client tries HTTPS first and may fall back to HTTP. Every other plain-HTTP request—including token-service requests and redirects—is refused before connecting. Publication needs no separate HTTP consent; signing does (see the [local exception](#local-httpoffline-exception)).

Errors report the stage plus, at most, a fixed classification: an HTTP status with any **known OCI distribution error codes** (such as `UNAUTHORIZED`, `DENIED`, `NAME_UNKNOWN`; unrecognized codes are dropped), `plain HTTP refused for non-loopback registry`, `TLS verification failed`, `registry unreachable`, `content mismatch`, or `unsupported layer compression`. Registry error bodies, messages, URLs, and credential-helper output are never printed or retained.

## Sign and attest the verified digest

Signing requires a key and exactly Cosign v3.1.3. An optional upstream signing-config file can accompany the key; it configures services, not identity. Lupetto has no key store, keyless mode, or KMS guarantee.

Supply `COSIGN_PASSWORD` only through the process environment. In Bash, prompt without echoing:

```bash
IFS= read -r -s -p 'Cosign key password: ' COSIGN_PASSWORD
printf '\n'
export COSIGN_PASSWORD
```

Never put the password in a command argument, history, `set -x`, environment dumps, or captured logs. Lupetto inherits the variable and discards all Cosign stdout/stderr, so an interactive upstream password prompt will not work during a build. Unset `COSIGN_PASSWORD` afterwards.

After verified publication Lupetto runs:

```text
cosign sign   --yes --key <key> [--signing-config <file>] [--allow-http-registry] <immutable-reference>
cosign attest --yes --key <key> [--signing-config <file>] [--allow-http-registry] \
  --type spdxjson --predicate <validated-architecture-SPDX> <immutable-reference>
```

Immediately before attesting, Lupetto re-hashes the validated architecture SPDX and compares it with the recorded checksum. It never regenerates SPDX or attests the supplemental index document. Cosign v3.1.3's default registry mode (modern bundle/referrers) is used unchanged.

### Production signing template (not exercised)

Use a non-loopback HTTPS registry, a protected key, and upstream default services:

```bash
unset LUPETTO_COSIGN_SIGNING_CONFIG LUPETTO_COSIGN_ALLOW_HTTP
lupetto build nginx 1.30 \
  --registry registry.example.invalid --repository team/lupetto/images \
  --cosign-key /protected/path/operator.key
unset COSIGN_PASSWORD
```

Without a signing config, upstream HTTPS, TUF-provided services, and transparency-log defaults stay intact; Lupetto adds no insecure or log-bypass flags. A supplied signing config can change services and is not evidence of production transparency-log behavior.

## Local HTTP/offline exception

**Local development only.** Use an isolated, authorized registry on literal loopback; starting it is outside Lupetto. Literal loopback is `localhost` or a loopback IP literal (bracketed IPv6 allowed); a DNS name resolving to loopback does not qualify. Signing there requires explicit `--cosign-allow-http`, because upstream Cosign may choose HTTP on loopback by itself. This is not a TLS-verification bypass.

Create disposable key material and a no-service signing config (Bash, with `COSIGN_PASSWORD` exported as above):

```bash
SIGNING_DIR=$(mktemp -d)
chmod 700 "$SIGNING_DIR"
cosign generate-key-pair --output-key-prefix "$SIGNING_DIR/local"
cosign signing-config create --out "$SIGNING_DIR/local-signing-config.json"
```

The config is generated by upstream v3.1.3 **without services or `--with-default-services`**; do not hand-author one or use deprecated `--tlog-upload=false`. Local target template (replace port and prefix):

```bash
lupetto build busybox-static 1 --no-load --json \
  --registry 127.0.0.1:5000 --repository tests/lupetto/nested/images \
  --cosign-key "$SIGNING_DIR/local.key" \
  --cosign-signing-config "$SIGNING_DIR/local-signing-config.json" \
  --cosign-allow-http
unset COSIGN_PASSWORD
```

Distribute and trust the public key separately; fetching a key from the same registry does not establish the signer.

## Verify signature and SPDX attestation

Use Cosign v3.1.3, a **trusted public key**, and the immutable reference from the build (`Immutable reference:` or `stages.publication.immutableReference`). Never substitute a tag or local image ID. Lupetto has no `verify` command.

### Production templates (not exercised)

```bash
IMMUTABLE='registry.example.invalid/team/lupetto/images/actual-apk@sha256:REPLACE_WITH_PUSHED_DIGEST'
PUBLIC_KEY='/trusted/path/operator.pub'
cosign verify --key "$PUBLIC_KEY" "$IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --type spdxjson "$IMMUTABLE"
```

### Local forms (exercised)

`--insecure-ignore-tlog` is a local-only exception, not a production recommendation:

```bash
IMMUTABLE='127.0.0.1:5000/tests/lupetto/nested/images/actual-apk@sha256:REPLACE_WITH_PUSHED_DIGEST'
PUBLIC_KEY="$SIGNING_DIR/local.pub"
cosign verify --key "$PUBLIC_KEY" \
  --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
cosign verify-attestation --key "$PUBLIC_KEY" --type spdxjson \
  --allow-http-registry --insecure-ignore-tlog "$IMMUTABLE"
```

### Inspect the verified claims, not only the exit status

1. Require the verified signature claim's manifest digest to equal the pushed digest.
2. Decode the attestation envelope's base64 `payload`; require the in-toto `subject` to name the intended image with `digest.sha256` equal to the pushed digest.
3. Require the SPDX predicate type and compare the decoded `predicate`, as parsed JSON, with the retained **architecture** SPDX (`sbom/sbom-<wolfi-architecture>.spdx.json`), not the supplemental index SPDX.
4. Recompute that file's SHA-256 against `evidence.spdxSHA256` in `result.json`.

Investigate any mismatch, unexpected signer, or missing predicate. Signature validity and lock/SPDX agreement do not prove completeness, absence of vulnerabilities, policy compliance, or runtime readiness.

## Partial outcomes and failure records

Every workflow uses the version-6 record described in the [operator guide](../README.md#results-records-and---json): private mode-0600 `result.json` only after every requested stage succeeds, otherwise `failure.json` (when a workspace exists) with the failed stage and each stage's status. Unrequested stages are `skipped`; requested stages not reached are `not-attempted`.

| Failure point | Confirmed versus incomplete |
| --- | --- |
| Push | Build (and load, if requested) complete; publication failed with no digest recorded. Some blobs may already be uploaded. |
| Readback | Digest recorded with `verified: false`; it does not authorize signing. The tag and image may already exist remotely. |
| Image signing | Publication confirmed; signing failed, attestation `not-attempted`. A signature may still have been uploaded. |
| Attestation (including the SPDX checksum check) | Publication and signing confirmed; attestation failed. An attestation may already exist. |
| Final result recording | Earlier stages can be confirmed, but the workflow is not complete success. |

Failures and cancellation exit nonzero with no success summary, may leave remote tags, images, signatures, or attestations, and are **never rolled back**. Publication/signing records contain only sanitized stage messages: no passwords, key or config contents or paths, environment, Docker credential configuration, or tool transcripts.
