package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDiscoverListsExactNamesAndMatchingProvidersInAPKOrder(t *testing.T) {
	fixture := "P:postgresql-17\nV:17.9-r3\nA:x86_64\nC:one\np:postgresql=17.9-r3\n\n" +
		"P:postgresql-17\nV:17.10-r2\nA:x86_64\nC:two\np:postgresql=17.10-r2\n\n" +
		"P:postgresql-17\nV:17.10-r10\nA:x86_64\nC:three\np:postgresql=17.10-r10\n\n" +
		"P:postgresql-17\nV:17.10-r0\nA:x86_64\nC:four\np:postgresql=17.10-r0\n\n" +
		"P:postgresql-16\nV:16.14-r1\nA:x86_64\nC:five\np:postgresql=16.14-r1\n\n" +
		"P:postgresql-17\nV:17.99-r0\nA:aarch64\nC:six\np:postgresql=17.99-r0\n\n" +
		"P:postgresql-17-client\nV:17.99-r0\nA:x86_64\nC:seven\n\n" +
		"P:other\nV:99-r0\nA:x86_64\nC:eight\np:postgresql=98-r0\n\n"
	packages, err := parseAPKINDEX(makeIndex(t, fixture), "postgresql")
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := orderedIndexedPackages(packages, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"postgresql-17@17.10-r10", "postgresql-17@17.10-r2", "postgresql-17@17.10-r0", "postgresql-17@17.9-r3", "postgresql-16@16.14-r1"}
	if len(ordered) != len(want) {
		t.Fatalf("got %d indexed versions, want %d: %+v", len(ordered), len(want), ordered)
	}
	for i, pkg := range ordered {
		if got := pkg.name + "@" + pkg.version; got != want[i] {
			t.Fatalf("entry %d = %q; want %q", i, got, want[i])
		}
	}
}

func TestDiscoverIncludesDistinctEqualVersionProviders(t *testing.T) {
	fixture := "P:nginx-stable\nV:1.30-r0\nA:x86_64\nC:one\np:nginx=1.30-r0\n\n" +
		"P:nginx-mainline\nV:1.30-r0\nA:x86_64\nC:two\np:nginx=1.30-r0\n\n"
	packages, err := parseAPKINDEX(makeIndex(t, fixture), "nginx")
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := orderedIndexedPackages(packages, "x86_64")
	if err != nil || len(ordered) != 2 || ordered[0].name != "nginx-mainline" || ordered[1].name != "nginx-stable" {
		t.Fatalf("equal-version providers: %+v, %v", ordered, err)
	}
}

func TestDiscoverMatchesNamespacedProvider(t *testing.T) {
	fixture := "P:curl\nV:8.19.0-r0\nA:x86_64\nC:one\np:cmd:curl=8.19.0-r0\n\n" +
		"P:other\nV:8.19.0-r0\nA:x86_64\nC:two\np:cmd:curl=8.18.0-r0\n\n"
	packages, err := parseAPKINDEX(makeIndex(t, fixture), "cmd:curl")
	if err != nil || len(packages) != 1 || packages[0].name != "curl" {
		t.Fatalf("namespaced provider entries: %+v, %v", packages, err)
	}
	selected, err := selectPackage(packages, buildRequest{packageName: "cmd:curl", selector: "8.19"}, "x86_64")
	if err != nil || selected.name != "curl" || selected.version != "8.19.0-r0" {
		t.Fatalf("selected namespaced provider: %+v, %v", selected, err)
	}
}

func TestDiscoverRejectsInvalidArgsBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{nil, {"nginx", "extra"}, {"../../nginx"}, {"--help"}, {"cmd:"}, {":curl"}, {"cmd::curl"}} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), append([]string{"discover"}, args...), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "discover requires one valid") {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q", args, code, stdout.String(), stderr.String())
		}
	}
}
