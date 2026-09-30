package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestReadableImageReferenceLiteralIdentities(t *testing.T) {
	for _, tc := range []struct{ pkg, version string }{
		{"busybox-static", "1.38.0-r2"},
		{"postgresql-17", "17.10-r1"},
		{"nginx-stable", "1.30.2-r0"},
		{"package.with__separators---ok", "1.2_RC1-r12"},
	} {
		for _, arch := range []struct{ apk, oci string }{{"x86_64", "amd64"}, {"aarch64", "arm64"}} {
			t.Run(tc.pkg+"/"+arch.apk, func(t *testing.T) {
				got, err := readableImageReference(indexedPackage{name: tc.pkg, version: tc.version}, arch.apk)
				want := "lupetto/" + tc.pkg + ":" + tc.version + "-" + arch.oci
				if err != nil || got != want {
					t.Fatalf("reference=%q want=%q err=%v", got, want, err)
				}
			})
		}
	}
	if _, err := readableImageReference(indexedPackage{name: "busybox-static", version: "1.38.0-r2"}, "unsupported"); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
}

func TestReadableImageReferenceUsesResolvedProviderIdentity(t *testing.T) {
	for _, tc := range []struct{ provider, pkg, version string }{
		{"postgresql", "postgresql-17", "17.10-r1"},
		{"nginx", "nginx-stable", "1.30.2-r0"},
		{"cmd:busybox", "busybox-static", "1.38.0-r2"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			index := makeIndex(t, "P:"+tc.pkg+"\nV:"+tc.version+"\nA:x86_64\nC:Q1checksum\np:"+tc.provider+"="+tc.version+"\n\n")
			packages, err := parseAPKINDEX(index, tc.provider)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := selectPackage(packages, buildRequest{packageName: tc.provider, version: tc.version}, "x86_64")
			if err != nil {
				t.Fatal(err)
			}
			got, err := readableImageReference(selected, "x86_64")
			if err != nil || got != "lupetto/"+tc.pkg+":"+tc.version+"-amd64" {
				t.Fatalf("reference=%q selected=%+v err=%v", got, selected, err)
			}
		})
	}
}

func referenceTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestReadableImageReferenceComponentFallbacks(t *testing.T) {
	for _, pkg := range []string{"Package", "package+extra", "package..extra", "package___extra", "package.-extra", "package-", "package/extra", "apk-sha256-literal", strings.Repeat("p", 238), strings.Repeat("p", 248)} {
		got, err := readableImageReference(indexedPackage{name: pkg, version: "1.2.3-r4"}, "x86_64")
		want := "lupetto/apk-sha256-" + referenceTestHash(pkg) + ":1.2.3-r4-amd64"
		if err != nil || got != want {
			t.Fatalf("package=%q reference=%q want=%q err=%v", pkg, got, want, err)
		}
	}
	for _, version := range []string{"1.2+extra-r1", "1.2~rc-r1", "1:2-r1", "_apk-sha256-literal-r1", "-1-r1", strings.Repeat("1", 120) + "-r1"} {
		for _, arch := range []struct{ apk, oci string }{{"x86_64", "amd64"}, {"aarch64", "arm64"}} {
			got, err := readableImageReference(indexedPackage{name: "package", version: version}, arch.apk)
			want := "lupetto/package:_apk-sha256-" + referenceTestHash(version) + "-" + arch.oci
			if err != nil || got != want {
				t.Fatalf("version=%q reference=%q want=%q err=%v", version, got, want, err)
			}
			if _, err := name.NewTag(got); err != nil {
				t.Fatalf("fallback failed upstream validation: %v", err)
			}
		}
	}
	// Exact boundary lengths remain literal rather than being truncated or hashed.
	pkg, version := strings.Repeat("p", 237), strings.Repeat("1", 119)+"-r1"
	got, err := readableImageReference(indexedPackage{name: pkg, version: version}, "x86_64")
	if err != nil || got != "lupetto/"+pkg+":"+version+"-amd64" {
		t.Fatalf("boundary reference=%q err=%v", got, err)
	}
}

func TestReadableImageReferenceFallbacksAvoidLossyAndReservedCollisions(t *testing.T) {
	identities := []indexedPackage{
		{name: "Package", version: "1+2-r1"},
		{name: "package", version: "1+2-r1"},
		{name: "Package", version: "1~2-r1"},
		{name: "Package", version: "1-2-r1"},
		{name: "apk-sha256-" + referenceTestHash("Package"), version: "1+2-r1"},
		{name: "Package", version: "_apk-sha256-" + referenceTestHash("1+2-r1")},
	}
	seen := make(map[string]bool)
	for _, identity := range identities {
		got, err := readableImageReference(identity, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		if seen[got] {
			t.Fatalf("colliding reference %q for %+v", got, identity)
		}
		seen[got] = true
		again, err := readableImageReference(identity, "x86_64")
		if err != nil || got != again {
			t.Fatalf("nondeterministic reference: %q then %q (%v)", got, again, err)
		}
	}
}
