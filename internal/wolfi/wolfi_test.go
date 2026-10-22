package wolfi

import (
	"strings"
	"testing"

	"lupetto/internal/wolfi/wolfitest"
)

// selection is the request subset that package selection consumes.
type selection struct{ packageName, selector, version string }

func selectFor(packages []Package, request selection, arch string) (Package, error) {
	return SelectPackage(packages, request.packageName, request.selector, request.version, arch)
}

func TestSelectPackageUsesAPKVersionOrderAndExactRevision(t *testing.T) {
	fixture := "P:postgresql-17\nV:17.9-r9\nA:x86_64\nC:checksum-9\np:postgresql=17.9-r9\n\n" +
		"P:postgresql-17\nV:17.10-r1\nA:x86_64\nC:checksum-10\np:postgresql=17.10-r1\n\n" +
		"P:postgresql-17\nV:17.2-r11\nA:x86_64\nC:checksum-11\np:postgresql=17.2-r11\n\n" +
		"P:postgresql-17\nV:17.2-r2\nA:x86_64\nC:checksum-2\np:postgresql=17.2-r2\n\n" +
		"P:postgresql-17\nV:17.99-r0\nA:aarch64\nC:other-arch\np:postgresql=17.99-r0\n\n" +
		"P:postgresql-17-client\nV:17.99-r0\nA:x86_64\nC:other-package\n\n"
	packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), "postgresql")
	if err != nil || len(packages) != 5 {
		t.Fatalf("ParseAPKINDEX: %d packages, error %v", len(packages), err)
	}
	for _, tc := range []struct{ selector, version string }{
		{"17", "17.10-r1"},
		{"17.2", "17.2-r11"},
	} {
		selected, err := selectFor(packages, selection{packageName: "postgresql", selector: tc.selector}, "x86_64")
		if err != nil || selected.Name != "postgresql-17" || selected.Version != tc.version {
			t.Fatalf("selector %s: %+v, %v; want %s", tc.selector, selected, err, tc.version)
		}
	}
	selected, err := selectFor(packages, selection{packageName: "postgresql", version: "17.2-r2"}, "x86_64")
	if err != nil || selected.Version != "17.2-r2" {
		t.Fatalf("exact selector: %+v, %v", selected, err)
	}
}

func TestSelectPackageResolvesIndexNamesAndDeclaredProviders(t *testing.T) {
	fixture := "P:nginx-stable\nV:1.30.2-r0\nA:x86_64\nC:one\np:nginx=1.30.2-r0\n\n" +
		"P:nginx-mainline\nV:1.31.6-r2\nA:x86_64\nC:two\np:nginx=1.31.6-r2\n\n" +
		"P:valkey-9.0\nV:9.0.4-r0\nA:x86_64\nC:three\np:valkey=9.0.4-r0\n\n" +
		"P:valkey-9.1\nV:9.1.2-r1\nA:x86_64\nC:four\np:valkey=9.1.2-r1\n\n" +
		"P:fake-valkey\nV:9.9-r0\nA:x86_64\nC:five\np:valkey=8.0-r0\n\n"
	for _, tc := range []struct{ name, selector, want string }{
		{"nginx", "1.30", "nginx-stable"},
		{"nginx", "1.31", "nginx-mainline"},
		{"nginx-mainline", "1.31", "nginx-mainline"},
		{"valkey", "9.0", "valkey-9.0"},
		{"valkey", "9.1", "valkey-9.1"},
	} {
		packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), tc.name)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := selectFor(packages, selection{packageName: tc.name, selector: tc.selector}, "x86_64")
		if err != nil || selected.Name != tc.want {
			t.Fatalf("%s %s: selected %+v, error %v; want %s", tc.name, tc.selector, selected, err, tc.want)
		}
	}
}

func TestSelectPackageDoesNotSubstituteUnavailableVersion(t *testing.T) {
	packages := []Package{{Name: "postgresql-17", Provides: "postgresql=17.10-r1", Version: "17.10-r1", Arch: "x86_64", Checksum: "checksum"}}
	for _, request := range []selection{
		{packageName: "postgresql", selector: "17.1"},
		{packageName: "postgresql", selector: "17.2"},
		{packageName: "postgresql", version: "17.10-r0"},
		{packageName: "valkey", selector: "17"},
	} {
		selected, err := selectFor(packages, request, "x86_64")
		if err == nil || !strings.Contains(err.Error(), "unavailable version") || selected.Version != "" {
			t.Fatalf("request %+v unexpectedly resolved %+v: %v", request, selected, err)
		}
	}
}

func TestSelectPackageRejectsAmbiguousRevisionAndProvider(t *testing.T) {
	for _, packages := range [][]Package{
		{
			{Name: "valkey", Version: "9.1-r1", Arch: "x86_64", Checksum: "one"},
			{Name: "valkey", Version: "9.1-r1", Arch: "x86_64", Checksum: "two"},
		},
		{
			{Name: "valkey-9.1", Provides: "valkey=9.1-r1", Version: "9.1-r1", Arch: "x86_64", Checksum: "one"},
			{Name: "valkey-full", Provides: "valkey=9.1-r1", Version: "9.1-r1", Arch: "x86_64", Checksum: "two"},
		},
		// An exact-name APK does not settle a tie among its own distinct builds.
		{
			{Name: "valkey", Version: "9.1-r1", Arch: "x86_64", Checksum: "one"},
			{Name: "valkey", Version: "9.1-r1", Arch: "x86_64", Checksum: "two"},
			{Name: "valkey-full", Provides: "valkey=9.1-r1", Version: "9.1-r1", Arch: "x86_64", Checksum: "three"},
		},
	} {
		for _, req := range []selection{{packageName: "valkey", selector: "9"}, {packageName: "valkey", version: "9.1-r1"}} {
			if _, err := selectFor(packages, req, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("expected ambiguous revision for %+v, got %v", req, err)
			}
		}
	}
}

// Wolfi's busybox-full and busybox-static provide busybox at busybox's own
// version; asking for busybox means the busybox APK.
func TestSelectPackagePrefersExactNameAmongEqualProviders(t *testing.T) {
	packages := []Package{
		{Name: "busybox-full", Provides: "busybox=1.38.0-r3 cmd:busybox=1.38.0-r3", Version: "1.38.0-r3", Arch: "x86_64", Checksum: "full"},
		{Name: "busybox", Version: "1.38.0-r3", Arch: "x86_64", Checksum: "exact"},
		{Name: "busybox", Version: "1.38.0-r3", Arch: "x86_64", Checksum: "exact"},
		{Name: "busybox-static", Provides: "busybox=1.38.0-r3", Version: "1.38.0-r3", Arch: "x86_64", Checksum: "static"},
		{Name: "busybox", Version: "1.38.0-r2", Arch: "x86_64", Checksum: "older"},
		{Name: "busybox", Version: "1.38.0-r3", Arch: "aarch64", Checksum: "arm"},
	}
	for _, request := range []selection{
		{packageName: "busybox", selector: "1"},
		{packageName: "busybox", selector: "1.38.0"},
		{packageName: "busybox", version: "1.38.0-r3"},
	} {
		selected, err := selectFor(packages, request, "x86_64")
		if err != nil || selected.Name != "busybox" || selected.Checksum != "exact" {
			t.Fatalf("%+v: selected %+v, error %v", request, selected, err)
		}
	}
	// Exact names still never pick a lower version over a newer provider.
	newerProvider := Package{Name: "busybox-full", Provides: "busybox=1.38.1-r0", Version: "1.38.1-r0", Arch: "x86_64", Checksum: "newer"}
	for _, newer := range [][]Package{append([]Package{newerProvider}, packages...), append(packages[1:2:2], newerProvider)} {
		if selected, err := selectFor(newer, selection{packageName: "busybox", selector: "1"}, "x86_64"); err != nil || selected.Name != "busybox-full" || selected.Version != "1.38.1-r0" {
			t.Fatalf("newer provider: selected %+v, error %v", selected, err)
		}
	}
	// One provider is still selected; several without the exact APK stay ambiguous.
	if _, err := selectFor(packages, selection{packageName: "cmd:busybox", selector: "1"}, "x86_64"); err != nil {
		t.Fatalf("single provider: %v", err)
	}
	for _, request := range []selection{{packageName: "busybox", selector: "1"}, {packageName: "busybox", version: "1.38.0-r3"}} {
		if _, err := selectFor(packages[3:4:4], request, "x86_64"); err != nil {
			t.Fatalf("lone provider %+v: %v", request, err)
		}
		if _, err := selectFor([]Package{packages[0], packages[3]}, request, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("two providers without the exact APK %+v: %v", request, err)
		}
	}
}

func TestSelectPackageIgnoresAmbiguousLowerRankedProviders(t *testing.T) {
	packages := []Package{
		{Name: "nginx-stable", Provides: "nginx=1.30-r0", Version: "1.30-r0", Arch: "x86_64", Checksum: "one"},
		{Name: "nginx-other", Provides: "nginx=1.30-r0", Version: "1.30-r0", Arch: "x86_64", Checksum: "two"},
		{Name: "nginx-mainline", Provides: "nginx=1.31-r0", Version: "1.31-r0", Arch: "x86_64", Checksum: "three"},
	}
	selected, err := selectFor(packages, selection{packageName: "nginx", selector: "1"}, "x86_64")
	if err != nil || selected.Name != "nginx-mainline" {
		t.Fatalf("highest unambiguous provider: %+v, %v", selected, err)
	}
	if _, err := selectFor(packages, selection{packageName: "nginx", selector: "1.30"}, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous highest version accepted: %v", err)
	}
}

func TestSelectPackageRejectsInvalidActualAPKNameForProvider(t *testing.T) {
	packages := []Package{{
		Name: "cmd:curl", Provides: "cmd:curl=8.22.0-r3",
		Version: "8.22.0-r3", Arch: "x86_64", Checksum: "checksum",
	}}
	for _, request := range []selection{
		{packageName: "cmd:curl", selector: "8.22"},
		{packageName: "cmd:curl", version: "8.22.0-r3"},
	} {
		if _, err := selectFor(packages, request, "x86_64"); err == nil || !strings.Contains(err.Error(), "invalid APKINDEX package name") {
			t.Fatalf("accepted malformed actual APK name for %+v: %v", request, err)
		}
	}
}

func TestParseAPKINDEXRejectsInvalidArchive(t *testing.T) {
	if _, err := ParseAPKINDEX([]byte("not gzip"), "valkey"); err == nil {
		t.Fatal("invalid gzip accepted")
	}
}
