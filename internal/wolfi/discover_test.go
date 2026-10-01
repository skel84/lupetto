package wolfi

import (
	"testing"

	"lupetto/internal/wolfi/wolfitest"
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
	packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), "postgresql")
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
		if got := pkg.Name + "@" + pkg.Version; got != want[i] {
			t.Fatalf("entry %d = %q; want %q", i, got, want[i])
		}
	}
}

func TestDiscoverIncludesDistinctEqualVersionProviders(t *testing.T) {
	fixture := "P:nginx-stable\nV:1.30-r0\nA:x86_64\nC:one\np:nginx=1.30-r0\n\n" +
		"P:nginx-mainline\nV:1.30-r0\nA:x86_64\nC:two\np:nginx=1.30-r0\n\n"
	packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), "nginx")
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := orderedIndexedPackages(packages, "x86_64")
	if err != nil || len(ordered) != 2 || ordered[0].Name != "nginx-mainline" || ordered[1].Name != "nginx-stable" {
		t.Fatalf("equal-version providers: %+v, %v", ordered, err)
	}
}

func TestDiscoverMatchesNamespacedProvider(t *testing.T) {
	fixture := "P:curl\nV:8.19.0-r0\nA:x86_64\nC:one\np:cmd:curl=8.19.0-r0\n\n" +
		"P:other\nV:8.19.0-r0\nA:x86_64\nC:two\np:cmd:curl=8.18.0-r0\n\n"
	packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), "cmd:curl")
	if err != nil || len(packages) != 1 || packages[0].Name != "curl" {
		t.Fatalf("namespaced provider entries: %+v, %v", packages, err)
	}
	selected, err := selectFor(packages, selection{packageName: "cmd:curl", selector: "8.19"}, "x86_64")
	if err != nil || selected.Name != "curl" || selected.Version != "8.19.0-r0" {
		t.Fatalf("selected namespaced provider: %+v, %v", selected, err)
	}
}

func TestDiscoverAllPackagesLatestDescriptions(t *testing.T) {
	fixture := "P:zeta\nV:1.9-r0\nA:x86_64\nC:one\nT:old description\np:virtual=1.9-r0\n\n" +
		"P:zeta\nV:1.10-r2\nA:x86_64\nC:two\nT:new description: with colon\n\n" +
		"P:zeta\nV:1.10-r10\nA:x86_64\nC:three\nT:latest description\n\n" +
		"P:alpha\nV:2-r0\nA:x86_64\nC:four\n\n" +
		"P:zeta\nV:99-r0\nA:aarch64\nC:five\nT:other architecture\n\n" +
		"P:incomplete\nV:1-r0\nA:x86_64\n\n" +
		"P:last\nV:3-r0\nA:x86_64\nC:six\nT:last without separator"
	packages, err := ParseAPKINDEX(wolfitest.MakeIndex(t, fixture), "")
	if err != nil || len(packages) != 6 {
		t.Fatalf("full entries=%+v err=%v", packages, err)
	}
	latest, err := LatestIndexedPackages(packages, "x86_64")
	if err != nil || len(latest) != 3 {
		t.Fatalf("latest=%+v err=%v", latest, err)
	}
	if latest[0].Name != "alpha" || latest[0].Description != "" || latest[1].Name != "last" || latest[1].Description != "last without separator" || latest[2].Name != "zeta" || latest[2].Version != "1.10-r10" || latest[2].Description != "latest description" {
		t.Fatalf("latest entries=%+v", latest)
	}
	if packages[1].Description != "new description: with colon" {
		t.Fatalf("description parsing=%q", packages[1].Description)
	}
}
