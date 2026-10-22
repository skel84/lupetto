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
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: scenario.version, Arch: "x86_64"}, {Name: "dependency", Version: scenario.dependency, Arch: "x86_64"}}}}
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
			if strings.Contains(string(data), `"entrypoint"`) != (scenario.desired != nil) {
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
