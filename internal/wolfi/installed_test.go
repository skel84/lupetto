package wolfi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func installedLayer(t *testing.T, name, data string, size int64) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: size}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	// Oversize/truncated fixtures deliberately have incomplete tar entries.
	_ = tw.Close()
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestReadInstalledPackagesFullSet(t *testing.T) {
	data := "P:nginx-stable\nV:1.30.2-r0\nA:x86_64\no:nginx\n\nP:musl\nV:1.2.5-r10\nA:x86_64\n\nP:ca-certificates\nV:20260601-r0\nA:noarch"
	packages, err := ReadInstalledPackages(bytes.NewReader(installedLayer(t, "usr/lib/apk/db/installed", data, int64(len(data)))))
	if err != nil || len(packages) != 3 {
		t.Fatalf("packages=%+v err=%v", packages, err)
	}
	want := []InstalledPackage{{"nginx-stable", "1.30.2-r0", "x86_64"}, {"musl", "1.2.5-r10", "x86_64"}, {"ca-certificates", "20260601-r0", "noarch"}}
	for i := range want {
		if packages[i] != want[i] {
			t.Fatalf("package %d=%+v want=%+v", i, packages[i], want[i])
		}
	}
}

func TestReadInstalledPackagesFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"bad gzip", []byte("bad"), "open OCI layer gzip"},
		{"missing", installedLayer(t, "other", "", 0), "database missing"},
		{"oversize", installedLayer(t, "usr/lib/apk/db/installed", "", MaxInstalledDatabaseBytes+1), "exceeds 8 MiB"},
		{"truncated", installedLayer(t, "usr/lib/apk/db/installed", "P:nginx", 100), "read installed APK database"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadInstalledPackages(bytes.NewReader(tc.data)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want=%q", err, tc.want)
			}
		})
	}
}

func TestParseInstalledPackagesPreservesOrderAndDuplicateRecords(t *testing.T) {
	packages := ParseInstalledPackages([]byte("P:a\nV:1-r0\nA:x86_64\n\nP:a\nV:2-r0\nA:x86_64\n\nP:incomplete\n\n"))
	if len(packages) != 3 || packages[0].Version != "1-r0" || packages[1].Version != "2-r0" || packages[2].Name != "incomplete" || packages[2].Version != "" {
		t.Fatalf("packages=%+v", packages)
	}
}
