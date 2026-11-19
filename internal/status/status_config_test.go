package status

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lupetto/internal/imageconfig"
	"lupetto/internal/wolfi"
)

func TestRunImageConfigurationState(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	index := signedIndexReader(t, "P:curl\nV:8.2.0-r1\nA:x86_64\nC:Q1a\n\nP:dependency\nV:1.2.0-r2\nA:x86_64\nC:Q1c\n\n")
	security := func(context.Context) (SecurityFeed, string, error) {
		return SecurityFeed{"dependency": {"1.2.0-r2": {"CVE-2024-0002"}}}, strings.Repeat("a", 64), nil
	}
	entrypoint := []string{"/usr/bin/curl", "--fail"}
	built := imageconfig.Options{Entrypoint: entrypoint}.Annotations()
	for _, scenario := range []struct {
		name        string
		version     string
		dependency  string
		annotations map[string]string
		desired     []string
		want        string
	}{
		{"none requested none built", "8.2.0-r1", "1.2.0-r2", nil, nil, Current},
		{"requested and built", "8.2.0-r1", "1.2.0-r2", built, entrypoint, Current},
		{"added", "8.2.0-r1", "1.2.0-r2", nil, entrypoint, ConfigChanged},
		{"removed", "8.2.0-r1", "1.2.0-r2", built, nil, ConfigChanged},
		{"changed argument", "8.2.0-r1", "1.2.0-r2", built, []string{"/usr/bin/curl"}, ConfigChanged},
		{"config change outranks fixes", "8.2.0-r1", "1.2.0-r1", nil, entrypoint, ConfigChanged},
		{"fixes with matching config", "8.2.0-r1", "1.2.0-r1", built, entrypoint, FixesAvailable},
		{"update outranks config change", "8.1.0-r0", "1.2.0-r2", nil, entrypoint, UpdateAvailable},
		{"malformed annotation", "8.2.0-r1", "1.2.0-r2", map[string]string{imageconfig.EntrypointAnnotation: "/usr/bin/curl"}, nil, Error},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			image := testImage(scenario.version, "a", now)
			image.Annotations = scenario.annotations
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: scenario.version, Arch: "x86_64"}, {Name: "dependency", Version: scenario.dependency, Arch: "x86_64"}, baseLayout}}}
			products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}, Entrypoint: scenario.desired}}}
			services := Services{Architecture: "x86_64", ReadIndex: index, ReadSecurity: security, Registry: registry, Cache: &testCache{sets: map[string][]wolfi.InstalledPackage{}}, Now: func() time.Time { return now }}
			document, err := RunWith(context.Background(), products, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services)
			if err != nil || len(document.Tracks) != 1 {
				t.Fatalf("document=%+v err=%v", document, err)
			}
			track := document.Tracks[0]
			if track.State != scenario.want || (scenario.want == Error) != strings.Contains(track.Error, "invalid image configuration annotation") {
				t.Fatalf("state=%s error=%q want %s", track.State, track.Error, scenario.want)
			}
			data, _ := json.Marshal(track)
			if strings.Contains(string(data), `"entrypoint":[`) != (scenario.desired != nil) {
				t.Fatalf("track entrypoint presence: %s", data)
			}
		})
	}
}

func TestParseProductsEntrypoint(t *testing.T) {
	products, err := ParseProducts(strings.NewReader("version: 1\nproducts:\n  - package: kyverno\n    selectors: [\"1\"]\n    entrypoint: [/usr/bin/kyverno, \"--v=2\"]\n  - package: curl\n    selectors: [\"8\"]\n"))
	if err != nil || strings.Join(products.Products[0].Entrypoint, " ") != "/usr/bin/kyverno --v=2" || products.Products[1].Entrypoint != nil {
		t.Fatalf("products=%+v err=%v", products, err)
	}
	for _, invalid := range []string{
		"entrypoint: /usr/bin/kyverno",
		"entrypoint: []",
		"entrypoint: null",
		"entrypoint: [kyverno]",
		"entrypoint: [/usr/bin/kyverno, 2]",
		"entrypoint: [/usr/bin/kyverno, true]",
		"entrypoint: [/usr/bin/kyverno, [a]]",
		"entrypoint: [/usr/bin/kyverno, \"it's\"]",
	} {
		document := "version: 1\nproducts:\n  - package: kyverno\n    selectors: [\"1\"]\n    " + invalid + "\n"
		if _, err := ParseProducts(strings.NewReader(document)); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

func TestRunCABundleState(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	index := signedIndexReader(t, "P:curl\nV:8.2.0-r1\nA:x86_64\nC:Q1a\n\n")
	security := func(context.Context) (SecurityFeed, string, error) {
		return SecurityFeed{}, strings.Repeat("a", 64), nil
	}
	built := imageconfig.Options{CABundle: true}.Annotations()
	for _, scenario := range []struct {
		name        string
		annotations map[string]string
		desired     bool
		want        string
	}{
		{"requested and built", built, true, Current},
		{"added", nil, true, ConfigChanged},
		{"removed", built, false, ConfigChanged},
		{"malformed annotation", map[string]string{imageconfig.CABundleAnnotation: "yes"}, true, Error},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			image := testImage("8.2.0-r1", "a", now)
			image.Annotations = scenario.annotations
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: "8.2.0-r1", Arch: "x86_64"}, baseLayout}}}
			products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}, CABundle: scenario.desired}}}
			services := Services{Architecture: "x86_64", ReadIndex: index, ReadSecurity: security, Registry: registry, Cache: &testCache{sets: map[string][]wolfi.InstalledPackage{}}, Now: func() time.Time { return now }}
			document, err := RunWith(context.Background(), products, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services)
			if err != nil || len(document.Tracks) != 1 {
				t.Fatalf("document=%+v err=%v", document, err)
			}
			track := document.Tracks[0]
			if track.State != scenario.want {
				t.Fatalf("state=%s error=%q want %s", track.State, track.Error, scenario.want)
			}
			data, _ := json.Marshal(track)
			if strings.Contains(string(data), `"caBundle":true`) != scenario.desired {
				t.Fatalf("track caBundle presence: %s", data)
			}
		})
	}
}

func TestParseProductsCABundle(t *testing.T) {
	products, err := ParseProducts(strings.NewReader("version: 1\nproducts:\n  - package: external-dns-0.21\n    selectors: [\"0\"]\n    caBundle: true\n  - package: curl\n    selectors: [\"8\"]\n    caBundle: false\n"))
	if err != nil || !products.Products[0].CABundle || products.Products[1].CABundle || !products.Products[0].Image().CABundle {
		t.Fatalf("products=%+v err=%v", products, err)
	}
	for _, invalid := range []string{`caBundle: "true"`, "caBundle: yes", "caBundle: 1", "caBundle: null", "caBundle: [true]"} {
		document := "version: 1\nproducts:\n  - package: curl\n    selectors: [\"8\"]\n    " + invalid + "\n"
		if _, err := ParseProducts(strings.NewReader(document)); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

func TestRunBaseLayoutState(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	index := signedIndexReader(t, "P:curl\nV:8.2.0-r1\nA:x86_64\nC:Q1a\n\nP:dependency\nV:1.2.0-r2\nA:x86_64\nC:Q1c\n\n")
	security := func(context.Context) (SecurityFeed, string, error) {
		return SecurityFeed{"dependency": {"1.2.0-r2": {"CVE-2024-0002"}}}, strings.Repeat("a", 64), nil
	}
	entrypoint := []string{"/usr/bin/curl"}
	curl := wolfi.InstalledPackage{Name: "curl", Version: "8.2.0-r1", Arch: "x86_64"}
	for _, scenario := range []struct {
		name      string
		version   string
		installed []wolfi.InstalledPackage
		product   Product
		cached    bool
		want      string
		changes   []string
	}{
		{"built with the base layout", "8.2.0-r1", []wolfi.InstalledPackage{curl, baseLayout}, Product{}, false, Current, nil},
		{"built before the base layout", "8.2.0-r1", []wolfi.InstalledPackage{curl}, Product{}, false, ConfigChanged, []string{ChangeBaseLayout}},
		{"cached installed set without it", "8.2.0-r1", []wolfi.InstalledPackage{curl}, Product{}, true, ConfigChanged, []string{ChangeBaseLayout}},
		{"missing base layout outranks fixes", "8.2.0-r1", []wolfi.InstalledPackage{curl, {Name: "dependency", Version: "1.2.0-r1", Arch: "x86_64"}}, Product{}, false, ConfigChanged, []string{ChangeBaseLayout}},
		{"fixes with the base layout", "8.2.0-r1", []wolfi.InstalledPackage{curl, {Name: "dependency", Version: "1.2.0-r1", Arch: "x86_64"}, baseLayout}, Product{}, false, FixesAvailable, nil},
		{"update outranks it and still lists it", "8.1.0-r0", []wolfi.InstalledPackage{{Name: "curl", Version: "8.1.0-r0", Arch: "x86_64"}}, Product{}, false, UpdateAvailable, []string{ChangeBaseLayout}},
		{"every change in order", "8.2.0-r1", []wolfi.InstalledPackage{curl}, Product{Entrypoint: entrypoint, CABundle: true}, false, ConfigChanged, []string{ChangeEntrypoint, ChangeCABundle, ChangeBaseLayout}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			image := testImage(scenario.version, "a", now)
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: scenario.installed}}
			cache := &testCache{sets: map[string][]wolfi.InstalledPackage{}}
			if scenario.cached {
				registry.installed = nil
				cache.sets[image.Digest] = scenario.installed
			}
			product := scenario.product
			product.Package, product.Selectors = "curl", []string{"8"}
			services := Services{Architecture: "x86_64", ReadIndex: index, ReadSecurity: security, Registry: registry, Cache: cache, Now: func() time.Time { return now }}
			document, err := RunWith(context.Background(), Products{Version: 1, Products: []Product{product}}, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services)
			if err != nil || len(document.Tracks) != 1 {
				t.Fatalf("document=%+v err=%v", document, err)
			}
			track := document.Tracks[0]
			if track.State != scenario.want || strings.Join(track.ConfigChanges, ",") != strings.Join(scenario.changes, ",") {
				t.Fatalf("state=%s changes=%q error=%q; want %s %q", track.State, track.ConfigChanges, track.Error, scenario.want, scenario.changes)
			}
			data, _ := json.Marshal(track)
			if strings.Contains(string(data), `"configChanges"`) != (scenario.changes != nil) {
				t.Fatalf("configChanges presence: %s", data)
			}
		})
	}
}

func TestRunPackagesAndUserState(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	index := signedIndexReader(t, "P:postgresql-18\nV:18.1-r0\nA:x86_64\nC:Q1a\n\nP:postgresql-18-contrib\nV:18.1-r0\nA:x86_64\nC:Q1b\n\nP:libxml2\nV:2.15.1-r1\nA:x86_64\nC:Q1c\n\n")
	// The feed names the origin, so a fix applies to the installed subpackage.
	security := func(context.Context) (SecurityFeed, string, error) {
		return SecurityFeed{"libxml2-src": {"2.15.1-r1": {"CVE-2025-0001"}}}, strings.Repeat("a", 64), nil
	}
	packages := []string{"postgresql-18-contrib"}
	built := imageconfig.Options{Packages: packages, User: "26"}.Annotations()
	for _, scenario := range []struct {
		name        string
		annotations map[string]string
		packages    []string
		user        string
		libxml2     string
		contrib     string
		want        string
		changes     string
	}{
		{"requested and built", built, packages, "26", "2.15.1-r1", "18.1-r0", Current, ""},
		{"packages added", map[string]string{imageconfig.UserAnnotation: "26"}, packages, "26", "2.15.1-r1", "18.1-r0", ConfigChanged, ChangePackages},
		{"packages removed", built, nil, "26", "2.15.1-r1", "18.1-r0", ConfigChanged, ChangePackages},
		{"user changed", built, packages, "26:26", "2.15.1-r1", "18.1-r0", ConfigChanged, ChangeUser},
		{"user removed", built, packages, "", "2.15.1-r1", "18.1-r0", ConfigChanged, ChangeUser},
		{"newer additional package alone", built, packages, "26", "2.15.1-r1", "18.0-r0", Current, ""},
		{"fix in an additional package's dependency", built, packages, "26", "2.15.1-r0", "18.1-r0", FixesAvailable, ""},
		{"malformed packages annotation", map[string]string{imageconfig.PackagesAnnotation: "postgresql-18-contrib"}, packages, "", "2.15.1-r1", "18.1-r0", Error, ""},
		{"malformed user annotation", map[string]string{imageconfig.UserAnnotation: "0"}, nil, "", "2.15.1-r1", "18.1-r0", Error, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			image := testImage("18.1-r0", "a", now)
			image.Name = "postgresql-18"
			image.Annotations = scenario.annotations
			installed := []wolfi.InstalledPackage{{Name: "postgresql-18", Version: "18.1-r0", Arch: "x86_64"}, {Name: "postgresql-18-contrib", Version: scenario.contrib, Arch: "x86_64", Origin: "postgresql-18"}, {Name: "libxml2", Version: scenario.libxml2, Arch: "x86_64", Origin: "libxml2-src"}, baseLayout}
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/postgresql-18": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: installed}}
			products := Products{Version: 1, Products: []Product{{Package: "postgresql-18", Selectors: []string{"18"}, Packages: scenario.packages, User: scenario.user}}}
			services := Services{Architecture: "x86_64", ReadIndex: index, ReadSecurity: security, Registry: registry, Cache: &testCache{sets: map[string][]wolfi.InstalledPackage{}}, Now: func() time.Time { return now }}
			document, err := RunWith(context.Background(), products, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services)
			if err != nil || len(document.Tracks) != 1 {
				t.Fatalf("document=%+v err=%v", document, err)
			}
			track := document.Tracks[0]
			if track.State != scenario.want || strings.Join(track.ConfigChanges, ",") != scenario.changes {
				t.Fatalf("state=%s changes=%v error=%q want %s %s", track.State, track.ConfigChanges, track.Error, scenario.want, scenario.changes)
			}
			data, _ := json.Marshal(track)
			if strings.Contains(string(data), `"packages":[`) != (scenario.packages != nil) || strings.Contains(string(data), `"user":`) != (scenario.user != "") {
				t.Fatalf("track packages/user presence: %s", data)
			}
		})
	}
}

func TestParseProductsPackagesAndUser(t *testing.T) {
	products, err := ParseProducts(strings.NewReader("version: 1\nproducts:\n  - package: postgresql-18\n    selectors: [\"18\"]\n    packages: [postgresql-18-contrib, \"cmd:psql\"]\n    user: 26:26\n  - package: curl\n    selectors: [\"8\"]\n"))
	if err != nil || strings.Join(products.Products[0].Packages, " ") != "postgresql-18-contrib cmd:psql" || products.Products[0].Image().User != "26:26" || products.Products[1].Packages != nil || products.Products[1].User != "" {
		t.Fatalf("products=%+v err=%v", products, err)
	}
	for _, invalid := range []string{
		"packages: postgresql-18-contrib",
		"packages: []",
		"packages: [postgresql-18]",
		"packages: [a, a]",
		"packages: [\"--flag\"]",
		"packages: [1]",
		"user: 26",
		"user: \"0\"",
		"user: \"root\"",
		"user: \"26:\"",
		"user: \"026\"",
		"user: \"4294967296\"",
		"user: \"\"",
	} {
		document := "version: 1\nproducts:\n  - package: postgresql-18\n    selectors: [\"18\"]\n    " + invalid + "\n"
		if _, err := ParseProducts(strings.NewReader(document)); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}
