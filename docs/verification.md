# Verification criteria

[Documentation home](../README.md) · [Scope](scope.md) · [Implementation checklist](implementation-plan.md)

**Current status: scoped local image only.** The standalone CLI has exercised PostgreSQL 17 exact-selector resolution, an apko OCI layout build, and installed-package identity checks. The full Wolfi snapshot catalog, SPDX validation, Docker load, registry, and Explorer scenarios below remain future acceptance criteria.

Use focused regression tests for uncertain behavior and real smoke runs for external-tool integration. Do not replace a real build or registry check with mocks that merely echo arguments.

Under the [approved publication-first roadmap](decisions.md#publication-first-roadmap-user-approved), registry publication, image signing, and signed SPDX attestation are the next CLI acceptance work. Persistent snapshot ingestion/history and Explorer checks remain deferred full-scope criteria, not prerequisites for that milestone or the standalone CLI release. Existing live-index selection, exact revision preservation, lock/SPDX validation, local loading, and per-build provenance checks still apply.

For this documentation-only reprioritization, relative links/heading anchors across the six required docs, checklist task/status preservation and milestone-order checks, `git diff --check`, and `go test ./...` passed (`ok lupetto/cmd/lupetto (cached)`). Independent read-only review found no concrete findings. Earlier source/untracked work was unchanged. No registry publication, signing, credentials, remote infrastructure changes, or new application behavior were exercised.

## Tool availability

On macOS/amd64, `go run ./cmd/lupetto doctor` initially reported missing apko (exit 1) with `brew install apko`, while Docker and Cosign were found. After `HOMEBREW_NO_AUTO_UPDATE=1 brew install apko`, `apko version` reported 1.4.5 and `go run ./cmd/lupetto doctor` reported all three present (exit 0). `docker --version` reported 27.4.0 and `cosign version` reported v3.1.3. These are executable checks, not build compatibility, Docker daemon availability, or signing verification.

## Scoped PostgreSQL 17 image evidence

On darwin/amd64 targeting linux/amd64, with apko 1.4.5, `go run ./cmd/lupetto build postgresql 17` exited 0 after verifying the downloaded APKINDEX signature with the pinned Wolfi key. It selected `postgresql-17@17.10-r1` from APKINDEX SHA-256 `d296da0b216382d0e825cd1a71bebeaf0fb06e887f3e8b6b9ba15db544d5a27e`. The workspace was `/Users/skel/Library/Caches/lupetto/builds/postgresql-17-2725349457`, outside the repository. Independent inspection of the OCI manifest/layer, apko lock, and `usr/lib/apk/db/installed` found exactly `postgresql-17` `17.10-r1` on `x86_64`; the OCI layer digest matched its bytes. `go run ./cmd/lupetto build postgresql 17.10` and `go run ./cmd/lupetto build postgresql --apk-version 17.10-r1` also exited 0 with `17.10-r1` after signature verification. Each of `go run ./cmd/lupetto build postgresql 17.1`, `17.2`, and `17.3` exited 1 with an explicit unavailable-version error, without producing an image. This is not SBOM/lock consistency validation, historical version archival, Docker loading, or evidence of a runnable database image.

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
- Reject publishing with `--no-load` before publication side effects.
- Sign and attest the same immutable digest, then verify both with the trusted public key.
- Inspect the verified attestation subject and SPDX predicate; compare the predicate with the validated local evidence.
- Verify that a wrong key or unrelated image digest cannot satisfy the expected signature/attestation checks.
- Exercise push failure and signing/attestation failure separately; report partial success accurately.
- Confirm secrets are not passed in password arguments or included in logs, result files, or downloaded evidence.

The target verification forms below are adapted to the Lupetto name. They are templates, not current runnable Lupetto instructions:

```text
cosign verify --key /path/to/lupetto.pub registry.example.com/team/lupetto/<image>@sha256:<digest>
cosign verify-attestation --key /path/to/lupetto.pub --type spdxjson registry.example.com/team/lupetto/<image>@sha256:<digest>
```

Exercise the pinned Cosign version before publishing operator examples. Local HTTP access and verification without transparency-log evidence require separately labeled variants; never make them production defaults. Successful cryptographic verification does not prove absence of vulnerabilities, SBOM completeness, or policy compliance.

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
