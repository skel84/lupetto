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

func TestSelectPostgresUsesNumericMinorAndRevision(t *testing.T) {
	fixture := "P:postgresql-17\nV:17.9-r9\nA:x86_64\nC:checksum-9\n\n" +
		"P:postgresql-17\nV:17.10-r1\nA:x86_64\nC:checksum-10\n\n" +
		"P:postgresql-17\nV:17.2-r11\nA:x86_64\nC:checksum-11\n\n" +
		"P:postgresql-17\nV:17.2-r2\nA:x86_64\nC:checksum-2\n\n" +
		"P:postgresql-17\nV:17.99-r0\nA:aarch64\nC:other-arch\n\n" +
		"P:postgresql-17-client\nV:17.99-r0\nA:x86_64\nC:other-package\n\n"
	packages, err := parseAPKINDEX(makeIndex(t, fixture))
	if err != nil || len(packages) != 5 {
		t.Fatalf("parseAPKINDEX: %d packages, error %v", len(packages), err)
	}
	for _, tc := range []struct{ selector, version string }{
		{"17", "17.10-r1"},
		{"17.2", "17.2-r11"},
	} {
		selected, err := selectPostgres(packages, buildRequest{selector: tc.selector}, "x86_64")
		if err != nil || selected.version != tc.version {
			t.Fatalf("selector %s: %+v, %v; want %s", tc.selector, selected, err, tc.version)
		}
	}
	selected, err := selectPostgres(packages, buildRequest{version: "17.2-r2"}, "x86_64")
	if err != nil || selected.version != "17.2-r2" {
		t.Fatalf("exact selector: %+v, %v", selected, err)
	}
}

func TestSelectPostgresDoesNotSubstituteUnavailableVersion(t *testing.T) {
	packages := []indexedPackage{{name: postgresAPK, version: "17.10-r1", arch: "x86_64", checksum: "checksum"}}
	for _, request := range []buildRequest{{selector: "17.1"}, {selector: "17.2"}, {selector: "17.3"}, {version: "17.10-r0"}} {
		selected, err := selectPostgres(packages, request, "x86_64")
		if err == nil || !strings.Contains(err.Error(), "unavailable version") || selected.version != "" {
			t.Fatalf("request %+v unexpectedly resolved %+v: %v", request, selected, err)
		}
	}
}

func TestSelectPostgresRejectsAmbiguousRevision(t *testing.T) {
	packages := []indexedPackage{
		{name: postgresAPK, version: "17.2-r1", arch: "x86_64", checksum: "one"},
		{name: postgresAPK, version: "17.2-r1", arch: "x86_64", checksum: "two"},
	}
	if _, err := selectPostgres(packages, buildRequest{selector: "17"}, "x86_64"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous revision failure, got %v", err)
	}
}

func TestParseAPKINDEXRejectsInvalidArchive(t *testing.T) {
	if _, err := parseAPKINDEX([]byte("not gzip")); err == nil {
		t.Fatal("invalid gzip accepted")
	}
}
