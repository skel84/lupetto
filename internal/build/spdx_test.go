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
		{"missing installed dependency", []any{nginx, base, origin("nginx-stable", "1.30.2-r0")}, lock, false, "missing installed APK"},
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
		"pkg:apk/wolfi/pkg@1-r0",
	} {
		if _, _, err := parseAPKRef(ref, "x86_64"); err == nil {
			t.Errorf("accepted %q", ref)
		}
	}
}
