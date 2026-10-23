package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lupetto/internal/wolfi"
)

func TestValidateSPDXCompleteAPKSet(t *testing.T) {
	lock := `{"contents":{"packages":[{"name":"nginx-stable","version":"1.30.2-r0","architecture":"x86_64"},{"name":"wolfi-baselayout","version":"20230201-r30","architecture":"x86_64"}]}}`
	apk := func(name, version, arch string) map[string]any {
		return map[string]any{"SPDXID": "SPDXRef-Package-apk-" + name, "name": name, "versionInfo": version,
			"externalRefs": []any{map[string]string{"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/" + name + "@" + version + "?arch=" + arch + "&distro=wolfi"}}}
	}
	base := apk("wolfi-baselayout", "20230201-r30", "x86_64")
	nginx := apk("nginx-stable", "1.30.2-r0", "x86_64")
	origin := func(name, version string) map[string]any {
		return map[string]any{"SPDXID": "SPDXRef-Package-apk-" + name + "-installed", "name": name, "versionInfo": version,
			"externalRefs": []any{map[string]string{"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/" + name + "@" + version + "?arch=x86_64&origin=" + name}}}
	}
	container := map[string]any{"SPDXID": "SPDXRef-Package-Image", "name": "sha256:abc", "primaryPackagePurpose": "CONTAINER"}
	osEntry := map[string]any{"SPDXID": "SPDXRef-OperatingSystem-wolfi", "name": "wolfi"}
	melange := map[string]any{"SPDXID": "SPDXRef-Package-Melange-nginx", "name": "nginx.yaml", "externalRefs": []any{map[string]string{"referenceType": "purl", "referenceLocator": "pkg:github/example/recipe@123"}}}
	for _, tc := range []struct {
		name    string
		pkgs    []any
		lock    string
		valid   bool
		message string
	}{
		{"valid with non-APK and installed entries", []any{container, osEntry, melange, nginx, base, origin("nginx-stable", "1.30.2-r0"), origin("wolfi-baselayout", "20230201-r30")}, lock, true, ""},
		{"missing dependency", []any{container, nginx}, lock, false, "missing locked APK"},
		// Older package SBOMs carry only the distro entry, so origin entries are per package.
		{"origin entry for only some packages", []any{nginx, base, origin("wolfi-baselayout", "20230201-r30")}, lock, true, ""},
		{"origin entry without distro entry", []any{nginx, origin("wolfi-baselayout", "20230201-r30")}, lock, false, "missing locked APK"},
		{"extra origin entry", []any{nginx, base, origin("extra", "1-r0")}, lock, false, "extra or duplicate"},
		{"changed origin revision", []any{nginx, base, origin("nginx-stable", "1.30.2-r1")}, lock, false, "extra or duplicate"},
		{"duplicate origin entry", []any{nginx, base, origin("nginx-stable", "1.30.2-r0"), map[string]any{"SPDXID": "SPDXRef-Package-apk-nginx-copy", "name": "nginx-stable", "versionInfo": "1.30.2-r0", "externalRefs": origin("nginx-stable", "1.30.2-r0")["externalRefs"]}}, lock, false, "extra or duplicate"},
		{"extra dependency", []any{nginx, base, apk("extra", "1-r0", "x86_64")}, lock, false, "extra or duplicate"},
		{"changed revision", []any{apk("nginx-stable", "1.30.2-r1", "x86_64"), base}, lock, false, "extra or duplicate"},
		{"wrong architecture", []any{apk("nginx-stable", "1.30.2-r0", "aarch64"), base}, lock, false, "invalid SPDX APK"},
		{"duplicate APK", []any{nginx, base, map[string]any{"SPDXID": "SPDXRef-Package-apk-copy", "name": "nginx-stable", "versionInfo": "1.30.2-r0", "externalRefs": nginx["externalRefs"]}}, lock, false, "extra or duplicate"},
		{"APK without reference", []any{base, map[string]any{"SPDXID": "SPDXRef-Package-apk-nginx", "name": "nginx-stable", "versionInfo": "1.30.2-r0"}}, lock, false, "invalid SPDX APK"},
		{"APK purl disguised as non-APK", []any{base, map[string]any{"SPDXID": "SPDXRef-other", "name": "nginx-stable", "versionInfo": "1.30.2-r0", "externalRefs": nginx["externalRefs"]}}, lock, true, ""},
		{"duplicate lock", []any{nginx, base}, `{"contents":{"packages":[{"name":"nginx-stable","version":"1.30.2-r0","architecture":"x86_64"},{"name":"nginx-stable","version":"1.30.2-r0","architecture":"x86_64"}]}}`, false, "duplicate"},
		{"wrong lock architecture", []any{nginx, base}, strings.Replace(lock, `"architecture":"x86_64"`, `"architecture":"aarch64"`, 1), false, "wrong-architecture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lockPath := filepath.Join(dir, "lock.json")
			spdxPath := filepath.Join(dir, "sbom.spdx.json")
			doc, err := json.Marshal(map[string]any{"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "packages": tc.pkgs})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, []byte(tc.lock), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(spdxPath, doc, 0600); err != nil {
				t.Fatal(err)
			}
			digest, err := validateSPDX(lockPath, spdxPath, "x86_64")
			if tc.valid {
				if err != nil || digest != wolfi.SHA256Hex(doc) {
					t.Fatalf("digest=%q err=%v", digest, err)
				}
			} else if err == nil || digest != "" || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("digest=%q err=%v; want %q", digest, err, tc.message)
			}
		})
	}
}

func TestValidateSPDXRejectsMalformedReferences(t *testing.T) {
	for _, ref := range []string{
		"pkg:apk/other/pkg@1-r0?arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=aarch64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&distro=other",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&distro=wolfi&unknown=x",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&origin=source;other",
		"pkg:apk/wolf%/pkg@1-r0?arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/libstdc%2G%2B@1-r0?arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1%2-r0?arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86%ZZ64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&distro=wolf%",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&origin=source%",
		"pkg:apk/wolfi/pkg@1%40-r0?arch=x86_64&distro=wolfi",
		"pkg:apk/wolfi/pkg@1-r0?arch=x86_64&distro=%57olfi",
		"pkg:apk/wolfi/pkg@1-r0",
	} {
		if _, _, err := parseAPKRef(ref, "x86_64"); err == nil {
			t.Errorf("accepted %q", ref)
		}
	}
}

func TestParseAPKRefPercentEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, ref, arch, packageName, version, kind string
	}{
		{"encoded plus", "pkg:apk/wolfi/libstdc%2B%2b@15.2.0-r1?arch=x86_64&distro=wolfi", "x86_64", "libstdc++", "15.2.0-r1", "distro"},
		{"literal plus", "pkg:apk/wolfi/libstdc++@15.2.0-r1?arch=x86_64&origin=gcc++", "x86_64", "libstdc++", "15.2.0-r1", "origin"},
		{"encoded version", "pkg:apk/wolfi/pkg@1%2E2%2Btest%2Dr1?arch=x86_64&distro=wolfi", "x86_64", "pkg", "1.2+test-r1", "distro"},
		{"encoded namespace and qualifiers", "pkg:apk/%77olfi/pkg@1-r0?arch=x86%5F64&distro=%77olfi", "x86_64", "pkg", "1-r0", "distro"},
		{"encoded origin", "pkg:apk/wolfi/pkg@1-r0?arch=x86_64&origin=gcc%2B%2B", "x86_64", "pkg", "1-r0", "origin"},
		{"literal qualifier plus", "pkg:apk/wolfi/pkg@1-r0?arch=x86+64&distro=wolfi", "x86+64", "pkg", "1-r0", "distro"},
		{"decode once", "pkg:apk/wolfi/pkg@1%252B-r0?arch=x86_64&distro=wolfi", "x86_64", "pkg", "1%2B-r0", "distro"},
		{"preserve name case", "pkg:apk/wolfi/Libstdc%2B%2B@1-r0?arch=x86_64&distro=wolfi", "x86_64", "Libstdc++", "1-r0", "distro"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, kind, err := parseAPKRef(tc.ref, tc.arch)
			want := apkIdentity{tc.packageName, tc.version, tc.arch}
			if err != nil || id != want || kind != tc.kind {
				t.Fatalf("identity=%+v kind=%q err=%v; want %+v kind=%q", id, kind, err, want, tc.kind)
			}
		})
	}
}

func TestValidateSPDXPercentEncodedIdentities(t *testing.T) {
	for _, tc := range []struct {
		name, packageName, version, refName, refVersion string
		valid                                           bool
	}{
		{"encoded plus", "libstdc++", "15.2.0-r1", "libstdc%2B%2B", "15.2.0-r1", true},
		{"encoded version", "pkg", "1.2+test-r1", "pkg", "1%2E2%2Btest%2Dr1", true},
		{"mismatched decoded name", "libstdc++", "15.2.0-r1", "libstdc%2B", "15.2.0-r1", false},
		{"case mismatch", "libstdc++", "15.2.0-r1", "Libstdc%2B%2B", "15.2.0-r1", false},
		{"malformed name", "libstdc++", "15.2.0-r1", "libstdc%2G%2B", "15.2.0-r1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			lockPath := filepath.Join(dir, "lock.json")
			spdxPath := filepath.Join(dir, "sbom.spdx.json")
			lock, err := json.Marshal(map[string]any{"contents": map[string]any{"packages": []any{
				map[string]string{"name": tc.packageName, "version": tc.version, "architecture": "x86_64"},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			var packages []any
			for _, qualifier := range []string{"distro=%77olfi", "origin=source%2B%2B"} {
				packages = append(packages, map[string]any{
					"SPDXID": "SPDXRef-Package-apk-" + qualifier, "name": tc.packageName, "versionInfo": tc.version,
					"externalRefs": []any{map[string]string{
						"referenceType": "purl", "referenceLocator": "pkg:apk/%77olfi/" + tc.refName + "@" + tc.refVersion + "?arch=x86%5F64&" + qualifier,
					}},
				})
			}
			doc, err := json.Marshal(map[string]any{"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "packages": packages})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, lock, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(spdxPath, doc, 0600); err != nil {
				t.Fatal(err)
			}
			digest, err := validateSPDX(lockPath, spdxPath, "x86_64")
			if tc.valid {
				if err != nil || digest != wolfi.SHA256Hex(doc) {
					t.Fatalf("digest=%q err=%v", digest, err)
				}
			} else if err == nil || digest != "" {
				t.Fatalf("accepted mismatched or malformed identity: digest=%q", digest)
			}
		})
	}
}

// apko 1.4.5's real SPDX for kubectl-1.33 1.33.4-r3: kubectl's package SBOM
// has only a distro entry, while wolfi-baselayout and ca-certificates-bundle
// also have origin entries. v0.3.0 rejected it.
func TestValidateSPDXKubectlWithoutOriginEntry(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock.json")
	lock := `{"contents":{"packages":[{"name":"kubectl-1.33","version":"1.33.4-r3","architecture":"x86_64"},{"name":"wolfi-baselayout","version":"20230201-r30","architecture":"x86_64"},{"name":"ca-certificates-bundle","version":"20260909-r3","architecture":"x86_64"}]}}`
	if err := os.WriteFile(lockPath, []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	spdxPath := filepath.Join("testdata", "kubectl-1.33-x86_64.spdx.json")
	data, err := os.ReadFile(spdxPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := validateSPDX(lockPath, spdxPath, "x86_64")
	if err != nil || digest != wolfi.SHA256Hex(data) {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	// The same document must still fail when the lock names an APK it lacks.
	if err := os.WriteFile(lockPath, []byte(strings.Replace(lock, `]}}`, `,{"name":"glibc","version":"2.44-r8","architecture":"x86_64"}]}}`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSPDX(lockPath, spdxPath, "x86_64"); err == nil || !strings.Contains(err.Error(), "missing locked APK glibc@2.44-r8") {
		t.Fatalf("missing APK accepted: %v", err)
	}
}
