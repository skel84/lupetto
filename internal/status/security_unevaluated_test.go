package status

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lupetto/internal/wolfi"
)

func TestMalformedSecdbFixedVersionIsReportedWithoutGuessingOrGlobalFailure(t *testing.T) {
	// This malformed exact key was observed in Wolfi's unsigned secdb. It is
	// deliberately retained verbatim, never repaired into an invented version.
	data := []byte(`{"packages":[{"pkg":{"name":"opa-envoy","secfixes":{"0":["CVE-2025-0000"],"1.1.0-r1-r0":["GHSA-aaaa-bbbb-cccc","CVE-2025-0001","CVE-2025-0001","GO-2025-1234","secretcanary"]}}},{"pkg":{"name":"unrelated","secfixes":{"not a version":[]}}}]}`)
	feed, err := ParseSecurity(data)
	if err != nil {
		t.Fatalf("one malformed key aborted feed: %v", err)
	}
	if _, retained := feed["opa-envoy"]["1.1.0-r1-r0"]; !retained {
		t.Fatal("malformed fixed-version evidence silently discarded")
	}
	if _, retained := feed["unrelated"]["not a version"]; !retained {
		t.Fatal("malformed fixed-version entry without supported IDs disappeared")
	}
	issues := unevaluatedSecurity(feed)
	if len(issues) != 2 || issues[0].Name != "opa-envoy" || issues[0].FixedVersion != "1.1.0-r1-r0" || strings.Join(issues[0].IDs, ",") != "CVE-2025-0001,GHSA-aaaa-bbbb-cccc" || len(issues[1].IDs) != 0 {
		t.Fatalf("unevaluated feed evidence: %+v", issues)
	}

	opa := testImage("1.1.0-r1", "a", time.Now().UTC())
	opa.Name = "opa-envoy"
	curl := testImage("8.1-r0", "b", time.Now().UTC())
	reader := &testRegistry{
		listings: map[string]RegistryListing{
			"images/opa-envoy": {Images: []Image{opa}},
			"images/curl":      {Images: []Image{curl}},
		},
		installed: map[string][]wolfi.InstalledPackage{
			opa.Digest:  {{Name: "opa-envoy", Version: opa.Version, Arch: "x86_64"}},
			curl.Digest: {{Name: "curl", Version: curl.Version, Arch: "x86_64"}, {Name: "opa-envoy", Version: opa.Version, Arch: "x86_64"}},
		},
	}
	packages := []wolfi.Package{
		{Name: "opa-envoy", Version: opa.Version, Arch: "x86_64", Checksum: "Q1a"},
		{Name: "curl", Version: curl.Version, Arch: "x86_64", Checksum: "Q1b"},
		{Name: "unrelated", Version: "1.0-r0", Arch: "x86_64", Checksum: "Q1c"},
	}
	products := Products{Version: 1, Products: []Product{
		{Package: "opa-envoy", Selectors: []string{"1.1"}},
		{Package: "curl", Selectors: []string{"8"}},
		{Package: "unrelated", Selectors: []string{"1"}},
	}}
	services := simpleServices(reader, &testCache{sets: map[string][]wolfi.InstalledPackage{}}, packages, feed)
	services.ReadSecurity = func(context.Context) (SecurityFeed, string, error) {
		return feed, wolfi.SHA256Hex(data), nil
	}
	document, err := RunWith(context.Background(), products, Options{Registry: "r.invalid", Repository: "images"}, services)
	if err != nil || document.Version != 1 || document.Security.SHA256 != wolfi.SHA256Hex(data) || document.Security.UnevaluatedFixCount != 2 || len(document.Security.UnevaluatedFixes) != 2 {
		t.Fatalf("computed document unavailable or missing issues: %+v %v", document, err)
	}
	for _, track := range document.Tracks[:2] {
		if track.State != Current || track.Error != "" || len(track.MissingFixes) != 0 || len(track.UnevaluatedFixes) != 1 {
			t.Fatalf("malformed key guessed into fix/state, or omitted from installed track: %+v", track)
		}
		issue := track.UnevaluatedFixes[0]
		if issue.Name != "opa-envoy" || issue.FixedVersion != "1.1.0-r1-r0" || issue.InstalledVersion != opa.Version || issue.Architecture != "x86_64" || len(issue.IDs) != 2 {
			t.Fatalf("installed issue identity: %+v", issue)
		}
	}
	if document.Tracks[2].State != NotBuilt || len(document.Tracks[2].UnevaluatedFixes) != 0 {
		t.Fatalf("uninstalled package incorrectly given installed issue: %+v", document.Tracks[2])
	}
	for _, issue := range document.Security.UnevaluatedFixes {
		if issue.InstalledVersion != "" || issue.Architecture != "" {
			t.Fatalf("global issue invented installed identity: %+v", issue)
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || !strings.Contains(string(encoded), `"unevaluatedFixCount":2`) || !strings.Contains(string(encoded), `"fixedVersion":"1.1.0-r1-r0"`) || strings.Contains(string(encoded), "secretcanary") {
		t.Fatalf("unevaluated JSON contract: %s %v", encoded, err)
	}
}

func TestMalformedFixedKeyDoesNotSuppressValidFixComparison(t *testing.T) {
	data := []byte(`{"packages":[{"pkg":{"name":"opa-envoy","secfixes":{"1.1.0-r1-r0":["CVE-2025-0001"],"1.1.0-r2":["CVE-2025-0002"]}}}]}`)
	feed, err := ParseSecurity(data)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := latestPackages([]wolfi.Package{{Name: "opa-envoy", Version: "1.1.0-r2", Arch: "x86_64"}})
	if err != nil {
		t.Fatal(err)
	}
	outdated, fixes := compareInstalled([]wolfi.InstalledPackage{{Name: "opa-envoy", Version: "1.1.0-r1", Arch: "x86_64"}}, latest, feed)
	if len(outdated) != 1 || len(fixes) != 1 || fixes[0].FixedVersion != "1.1.0-r2" || strings.Join(fixes[0].IDs, ",") != "CVE-2025-0002" {
		t.Fatalf("valid fixed entry suppressed or malformed entry guessed: %+v %+v", outdated, fixes)
	}
	issues := unevaluatedSecurity(feed)
	if len(issues) != 1 || issues[0].FixedVersion != "1.1.0-r1-r0" {
		t.Fatalf("malformed evidence disappeared: %+v", issues)
	}
}
