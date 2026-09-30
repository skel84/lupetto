package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func makeIndex(t *testing.T, records string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "APKINDEX", Mode: 0600, Size: int64(len(records))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(records)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestSelectPackageUsesAPKVersionOrderAndExactRevision(t *testing.T) {
	fixture := "P:postgresql-17\nV:17.9-r9\nA:x86_64\nC:checksum-9\np:postgresql=17.9-r9\n\n" +
		"P:postgresql-17\nV:17.10-r1\nA:x86_64\nC:checksum-10\np:postgresql=17.10-r1\n\n" +
		"P:postgresql-17\nV:17.2-r11\nA:x86_64\nC:checksum-11\np:postgresql=17.2-r11\n\n" +
		"P:postgresql-17\nV:17.2-r2\nA:x86_64\nC:checksum-2\np:postgresql=17.2-r2\n\n" +
		"P:postgresql-17\nV:17.99-r0\nA:aarch64\nC:other-arch\np:postgresql=17.99-r0\n\n" +
		"P:postgresql-17-client\nV:17.99-r0\nA:x86_64\nC:other-package\n\n"
	packages, err := parseAPKINDEX(makeIndex(t, fixture), "postgresql")
	if err != nil || len(packages) != 5 {
		t.Fatalf("parseAPKINDEX: %d packages, error %v", len(packages), err)
	}
	for _, tc := range []struct{ selector, version string }{
		{"17", "17.10-r1"},
		{"17.2", "17.2-r11"},
	} {
		selected, err := selectPackage(packages, buildRequest{packageName: "postgresql", selector: tc.selector}, "x86_64")
		if err != nil || selected.name != "postgresql-17" || selected.version != tc.version {
			t.Fatalf("selector %s: %+v, %v; want %s", tc.selector, selected, err, tc.version)
		}
	}
	selected, err := selectPackage(packages, buildRequest{packageName: "postgresql", version: "17.2-r2"}, "x86_64")
	if err != nil || selected.version != "17.2-r2" {
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
		packages, err := parseAPKINDEX(makeIndex(t, fixture), tc.name)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := selectPackage(packages, buildRequest{packageName: tc.name, selector: tc.selector}, "x86_64")
		if err != nil || selected.name != tc.want {
			t.Fatalf("%s %s: selected %+v, error %v; want %s", tc.name, tc.selector, selected, err, tc.want)
		}
	}
}

func TestSelectPackageDoesNotSubstituteUnavailableVersion(t *testing.T) {
	packages := []indexedPackage{{name: "postgresql-17", provides: "postgresql=17.10-r1", version: "17.10-r1", arch: "x86_64", checksum: "checksum"}}
	for _, request := range []buildRequest{
		{packageName: "postgresql", selector: "17.1"},
		{packageName: "postgresql", selector: "17.2"},
		{packageName: "postgresql", version: "17.10-r0"},
		{packageName: "valkey", selector: "17"},
	} {
		selected, err := selectPackage(packages, request, "x86_64")
		if err == nil || !strings.Contains(err.Error(), "unavailable version") || selected.version != "" {
			t.Fatalf("request %+v unexpectedly resolved %+v: %v", request, selected, err)
		}
	}
}

func TestSelectPackageRejectsAmbiguousRevisionAndProvider(t *testing.T) {
	for _, packages := range [][]indexedPackage{
		{
			{name: "valkey", version: "9.1-r1", arch: "x86_64", checksum: "one"},
			{name: "valkey", version: "9.1-r1", arch: "x86_64", checksum: "two"},
		},
		{
			{name: "valkey", version: "9.1-r1", arch: "x86_64", checksum: "one"},
			{name: "valkey-9.1", provides: "valkey=9.1-r1", version: "9.1-r1", arch: "x86_64", checksum: "two"},
		},
	} {
		for _, req := range []buildRequest{{packageName: "valkey", selector: "9"}, {packageName: "valkey", version: "9.1-r1"}} {
			if _, err := selectPackage(packages, req, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("expected ambiguous revision for %+v, got %v", req, err)
			}
		}
	}
}

func TestSelectPackageIgnoresAmbiguousLowerRankedProviders(t *testing.T) {
	packages := []indexedPackage{
		{name: "nginx-stable", provides: "nginx=1.30-r0", version: "1.30-r0", arch: "x86_64", checksum: "one"},
		{name: "nginx-other", provides: "nginx=1.30-r0", version: "1.30-r0", arch: "x86_64", checksum: "two"},
		{name: "nginx-mainline", provides: "nginx=1.31-r0", version: "1.31-r0", arch: "x86_64", checksum: "three"},
	}
	selected, err := selectPackage(packages, buildRequest{packageName: "nginx", selector: "1"}, "x86_64")
	if err != nil || selected.name != "nginx-mainline" {
		t.Fatalf("highest unambiguous provider: %+v, %v", selected, err)
	}
	if _, err := selectPackage(packages, buildRequest{packageName: "nginx", selector: "1.30"}, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous highest version accepted: %v", err)
	}
}

func TestSelectPackageRejectsInvalidActualAPKNameForProvider(t *testing.T) {
	packages := []indexedPackage{{
		name: "cmd:curl", provides: "cmd:curl=8.22.0-r3",
		version: "8.22.0-r3", arch: "x86_64", checksum: "checksum",
	}}
	for _, request := range []buildRequest{
		{packageName: "cmd:curl", selector: "8.22"},
		{packageName: "cmd:curl", version: "8.22.0-r3"},
	} {
		if _, err := selectPackage(packages, request, "x86_64"); err == nil || !strings.Contains(err.Error(), "invalid APKINDEX package name") {
			t.Fatalf("accepted malformed actual APK name for %+v: %v", request, err)
		}
	}
}

func TestParseAPKINDEXRejectsInvalidArchive(t *testing.T) {
	if _, err := parseAPKINDEX([]byte("not gzip"), "valkey"); err == nil {
		t.Fatal("invalid gzip accepted")
	}
}
