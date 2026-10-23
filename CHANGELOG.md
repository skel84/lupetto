# Changelog

User-visible changes to the `lupetto` CLI, `lupetto-explorer`, and the combined container. Releases are git tags `vX.Y.Z`; the [release workflow](.github/workflows/release.yml) publishes the combined Explorer image for each tag.

## v0.3.0 (2026-10-23)

Vulnerability scanners can now identify every Lupetto image as Wolfi. See the [release notes](docs/release-notes/v0.3.0.md) for upgrade guidance.

### Added

- **Wolfi base layout in every image.** Every build adds Wolfi's `wolfi-baselayout`, which installs `/etc/os-release`. Without it, Trivy detected no OS in images of packages such as `metrics-server` and reported no vulnerabilities at all, and Grype matched only Go modules, not APKs against Wolfi's feed. apko's retained lock records the exact version and SPDX is validated against it. The build fails unless the package is installed and `/etc/os-release` has `ID=wolfi` and a `VERSION_ID`. ([README](README.md#os-identity-and-base-layout))
- **`configChanges` status field.** Tracks list how their newest image differs from what a build would now produce: `entrypoint`, `caBundle`, or `baseLayout`. The status table prints one line per such track, and Explorer shows the list under "Configuration changed".

### Changed

- `status` reports a track as `config-changed` when its newest image's installed APKs lack `wolfi-baselayout`, so images built from packages that did not depend on it are rebuilt once.
- Every image now also contains `ca-certificates-bundle`, a dependency of the base layout, along with its `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, and `/bin` → `usr/bin` style links: about 146 KB compressed. `caBundle` and `--ca-bundle` keep their meaning, annotation, and file check.

### Compatibility

- v0.2.0's promise that builds without options give apko v0.1.0's configuration byte for byte no longer holds; every configuration lists `wolfi-baselayout`. Annotations and record version 6 are unchanged.
- Status document version 2 is unchanged; `configChanges` is optional. Consumers should show unknown `configChanges` values as a change. The v0.2.0 Explorer shows the new `config-changed` tracks as "Configuration changed" without the reason, and the v0.1.0 Explorer as "Unable to compare".
- Images whose closure already contained `wolfi-baselayout` (for example `busybox`) stay `current`.

## v0.2.0 (2026-10-22)

Lupetto images can now replace upstream images whose Helm charts pass only `args`. See the [release notes](docs/release-notes/v0.2.0.md) for upgrade guidance.

### Added

- **Image entrypoint.** `entrypoint: [...]` per product in the products file, and a repeatable `--entrypoint <element>` on `build` and `sbom`, set the OCI image `ENTRYPOINT`. The build fails clearly unless the executable resolves to an executable regular file in the selected package's closure. It is recorded as the `lupetto.image.entrypoint` annotation and the record's `request.entrypoint`. No `CMD` is set. ([README](README.md#image-entrypoint))
- **CA certificate bundle.** `caBundle: true` per product and `--ca-bundle` on `build` and `sbom` add Wolfi's `ca-certificates-bundle` for packages whose closure lacks system TLS roots (for example `external-dns`). apko's retained lock records the exact bundle version, and SPDX is validated against it. The build checks that `/etc/ssl/certs/ca-certificates.crt` exists. It is recorded as the `lupetto.image.ca-bundle` annotation and the record's `request.caBundle`. ([README](README.md#ca-certificate-bundle))
- **`config-changed` status state.** `status` reports it when a track's newest image was built with a different entrypoint or CA-bundle setting than the product now lists. It ranks between `update-available` and `fixes-available`, and `status --exit-code` exits 3 for it. Tracks also echo their requested `entrypoint` and `caBundle`.
- **Explorer** passes a tracked product's entrypoint and CA bundle to builds, taken from the products file and never from the form. It refuses a build (503) when the products file cannot be read, shows "Configuration changed" with a Rebuild action, and lists the options on the build page.

### Fixed

- **Exact-name provider precedence.** `busybox` with selector `1` (or `--apk-version 1.38.0-r3`) failed as ambiguous because `busybox-full` and `busybox-static` provide `busybox` at the same version. When distinct APKs tie at the selected version, the single APK named exactly as requested now wins. Other ties still fail as ambiguous, and version ranking is unchanged. ([decision](docs/decisions.md#exact-name-provider-precedence-2026-10-22))

### Compatibility

- Without the new options, builds give apko the same configuration as v0.1.0, byte for byte. Annotations and records are unchanged too, so existing tracks keep their status and need no rebuild. Image digests were never reproducible across separate builds: each build has a new creation time and a new workspace path inside `/etc/apko.json`. ([evidence](docs/verification.md#image-entrypoint-v020))
- Record version 6 and the status document version 2 are unchanged. The new fields are optional, and `config-changed` is an additional state value. Consumers that switch on `state` should treat unknown values as needing attention. The v0.1.0 Explorer shows them as "Unable to compare".
- A `busybox`-style request that used to fail as ambiguous now selects the exact-name APK.

### Documentation

- Recorded keyless identity verification of the v0.1.0 release image.

## v0.1.0 (2026-10-20)

First tagged release: the standalone CLI (`discover`, `build`, `sbom`, `status`, `products`, `images`, `inspect`, `verify`, `doctor`), with registry publication, Cosign signing and SPDX attestation (key or keyless), explicit target architecture, `status --exit-code`, and the optional `lupetto-explorer` dashboard and combined container.
