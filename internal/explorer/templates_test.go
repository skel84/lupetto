package explorer

import (
	"bytes"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every embedded template must execute against representative models,
// including nil pointers, zero times and hostile strings, and must stay
// compatible with the CSP (no inline script/style/handlers).
func TestEmbeddedTemplatesRenderRepresentativeModels(t *testing.T) {
	renderer, err := embeddedRenderer()
	if err != nil {
		t.Fatal(err)
	}
	evil := `<script>alert(1)</script>"'`
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ended := created.Add(time.Minute)
	zero, failed := 0, 1
	image := Image{Digest: "sha256:" + strings.Repeat("a", 64), Tags: []string{"1", "1.38.0-r2"}, Name: "busybox-static", Version: "1.38.0-r2", Architecture: "x86_64", Created: created, Annotations: map[string]string{"lupetto.apk.name": "busybox-static", "x": evil}}
	fullTrack := Track{
		Package: "openssl", Selector: "3.6", State: "fixes-available", Error: evil, Repository: "127.0.0.1:5000/x/openssl",
		Latest: &PackageIdentity{Name: "openssl", Version: "3.6.0-r2", Architecture: "x86_64"},
		Images: []Image{image, {Digest: "short"}}, Newest: &image,
		Installed:        []PackageIdentity{{Name: "libcrypto3", Version: "3.6.0-r1", Architecture: "x86_64"}},
		Outdated:         []OutdatedPackage{{Name: "libcrypto3", Architecture: "x86_64", InstalledVersion: "3.6.0-r1", LatestVersion: "3.6.0-r2"}},
		MissingFixes:     []MissingFix{{Name: "libcrypto3", IDs: []string{"CVE-2026-0001", "GHSA-aaaa-bbbb-cccc", "GO-2026-0001", evil, "CVE"}, ReachableByTrack: true}, {Name: "openssl", IDs: nil}},
		UnevaluatedFixes: []UnevaluatedFix{{Name: "libcrypto3", FixedVersion: "1.1.0-r1-r0", IDs: []string{"CVE-2026-0002"}}},
		ArtifactCount:    2, UnidentifiedCount: 1,
	}
	security := SecuritySource{URL: "https://packages.wolfi.dev/os/security.json", SHA256: "abc", Unsigned: true, FixedOnly: true, WolfiOnly: true, UnevaluatedFixCount: 1, UnevaluatedFixes: []UnevaluatedFix{{Name: "opa-envoy", FixedVersion: "1.1.0-r1-r0"}}}
	document := &StatusDocument{Kind: "status", Version: 1, ComputedAt: created, Architecture: "x86_64", Registry: "127.0.0.1:5000", Repository: "x", IndexSHA256: "def", Security: security, Tracks: []Track{fullTrack}}
	emptyTrack := Track{Package: "valkey", Selector: "9.1", State: "not-built"}
	record := &BuildRecord{Version: 6, Command: "build", Outcome: "failed", Workspace: "/tmp/ws",
		Failure:   &RecordFailure{Stage: "signing", Error: evil, SideEffectsPossible: true},
		Request:   RecordRequest{BuildRequest: BuildRequest{Package: "openssl", Selector: "3.6"}, Publish: true, Sign: true},
		Selection: &RecordSelection{Package: "openssl", Version: "3.6.0-r2", Architecture: "x86_64", IndexSHA256: "def"},
		Evidence:  &RecordEvidence{ApkoVersion: "1.4.5", ImageDigest: "sha256:b", SPDXValidated: true},
		Stages: RecordStages{Build: StageOutcome{Status: "completed"}, Load: StageOutcome{Status: "skipped"},
			Publication: StageOutcome{Status: "published", Digest: "sha256:c", ImmutableReference: "r@sha256:c"},
			Signing:     StageOutcome{Status: "failed"}, Attestation: StageOutcome{Status: "not-attempted"}},
	}
	base := BaseView{CSRFToken: "tok-123", BuildsEnabled: true}
	disabled := BaseView{CSRFToken: "tok-123"}
	running := JobView{ID: "2", Request: BuildRequest{Package: "openssl", APKVersion: "3.6.0-r1"}, State: "running", StartedAt: created, CancelRequested: true}
	finished := JobView{ID: "1", Request: BuildRequest{Package: "busybox-static", Selector: "1"}, State: "failed", StartedAt: created, EndedAt: &ended, ExitCode: &failed, Record: record, Error: evil}
	succeeded := JobView{ID: "3", State: "succeeded", EndedAt: &ended, ExitCode: &zero}

	cases := []struct {
		name, template string
		model          any
		want           []string
	}{
		{"overview full", "overview", OverviewView{BaseView: base, Status: StatusView{Document: document, LastError: evil, Refreshing: true}, Tracks: []TrackSummary{{Track: fullTrack, DetailURL: "/tracks/openssl/3.6", OutdatedCount: 1, ReachableFixCount: 1, UnreachableFixCount: 1, UnevaluatedFixCount: 1}, {Track: emptyTrack, DetailURL: "/tracks/valkey/9.1"}}}, []string{`name="csrfToken" value="tok-123"`, `name="selector" value="3.6"`, "not signed", "fixed vulnerabilities only", "Wolfi packages only", "opa-envoy", "1 outside selector", "data-poll-url"}},
		{"overview empty disabled", "overview", OverviewView{BaseView: disabled, Tracks: []TrackSummary{}}, []string{"Builds disabled", "No status comparison"}},
		{"track full", "track", TrackView{BaseView: base, Status: StatusView{Document: document}, Track: fullTrack}, []string{`href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001" rel="noopener noreferrer"`, `href="https://github.com/advisories/GHSA-aaaa-bbbb-cccc"`, `href="https://pkg.go.dev/vuln/GO-2026-0001"`, "Outside this track", "not “no vulnerabilities”", "Unevaluated advisories", "1 unidentified image manifest"}},
		{"track empty", "track", TrackView{BaseView: disabled, Track: emptyTrack}, []string{"No image of this track exists", "Builds disabled"}},
		{"packages loading", "packages", PackagesView{BaseView: base, Query: "a&b", Packages: []PackageItem{}, Limit: 200, Refreshing: true, LastError: evil}, []string{`data-poll-url="/packages?format=json&amp;q=a%26b"`}},
		{"packages truncated", "packages", PackagesView{BaseView: base, Query: "s", Packages: []PackageItem{{DiscoveredPackage: DiscoveredPackage{Name: "busybox", Version: "1", Description: evil}, DetailURL: "/packages/busybox"}}, TotalMatches: 201, Limit: 200, Document: &DiscoverDocument{Architecture: "x86_64"}}, []string{"Results are truncated", `href="/packages/busybox"`}},
		{"package", "package", PackageView{BaseView: base, Name: "cmd:curl", Document: &DiscoverDocument{Packages: []DiscoveredPackage{{Name: "curl", Version: "8.0-r1", Description: evil}}}}, []string{`name="package" value="cmd:curl"`, `name="apkVersion" value="8.0-r1"`}},
		{"package error", "package", PackageView{BaseView: disabled, Name: "x", Error: evil}, []string{"Discovery failed"}},
		{"jobs", "jobs", JobsView{BaseView: base, Jobs: []JobView{running, finished, succeeded}, Running: true, HistoryLimit: 50}, []string{"in memory only", "cancellation requested", `<td class="num">0</td>`, `<td class="num">1</td>`}},
		{"jobs empty", "jobs", JobsView{BaseView: disabled, Jobs: []JobView{}, HistoryLimit: 50}, []string{"No builds have run"}},
		{"job running", "job", JobDetailView{BaseView: base, Job: JobView{ID: "2", State: "running", StartedAt: created}, Log: LogChunk{NextOffset: 10, Text: evil, Truncated: true}}, []string{`action="/jobs/2/cancel"`, `data-log-url="/jobs/2/logs" data-log-offset="10"`, "earlier output discarded"}},
		{"job partial failure", "job", JobDetailView{BaseView: base, Job: finished, Log: LogChunk{Done: true}}, []string{"Partial result", "Failed at stage: signing", "side effects may remain", "skipped (not requested)", "not attempted (earlier stage failed)", "not verified"}},
		{"job canceled no record", "job", JobDetailView{BaseView: disabled, Job: JobView{ID: "4", State: "canceled", CancelRequested: true}, Log: LogChunk{Done: true}}, []string{"Build canceled; external side effects may remain", "No CLI build record"}},
	}
	inline := regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>[^<]|<style|\sstyle=|\son[a-z]+=|javascript:`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderer.Render(&out, tc.template, tc.model); err != nil {
				t.Fatal(err)
			}
			html := out.String()
			if strings.Contains(html, "<script>alert") {
				t.Fatalf("unescaped hostile string:\n%s", html)
			}
			if match := inline.FindString(html); match != "" {
				t.Fatalf("CSP-incompatible markup %q", match)
			}
			if !strings.Contains(html, `<link rel="stylesheet" href="/static/app.css">`) || !strings.Contains(html, `<script src="/static/app.js" defer></script>`) {
				t.Fatal("missing static assets")
			}
			for _, want := range tc.want {
				if !strings.Contains(html, want) {
					t.Errorf("missing %q in:\n%s", want, html)
				}
			}
			if !tc.model.(interface{ testBase() BaseView }).testBase().BuildsEnabled && (strings.Contains(html, `action="/builds"`) || strings.Contains(html, "/cancel")) {
				t.Error("build/cancel controls shown while builds are disabled")
			}
		})
	}
}

func (b BaseView) testBase() BaseView { return b }

func TestEmbeddedStaticAssetsServed(t *testing.T) {
	for _, name := range []string{"app.css", "app.js"} {
		if _, err := fs.Stat(embeddedStatic(), name); err != nil {
			t.Fatal(err)
		}
	}
	server, _, _ := testServer(t, goodFake(), false)
	w := request(server, http.MethodGet, "/static/app.js", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "textContent") || strings.Contains(w.Body.String(), "innerHTML") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// A failed comparison must not be presented as an empty (clean) result.
func TestEmbeddedTemplatesDistinguishTrackErrorsFromEmptyResults(t *testing.T) {
	renderer, err := embeddedRenderer()
	if err != nil {
		t.Fatal(err)
	}
	image := Image{Digest: "sha256:" + strings.Repeat("b", 64), Version: "1.0-r0"}
	cases := []struct {
		name, template string
		model          any
		want, absent   []string
	}{
		{"track error with newest image", "track", TrackView{Track: Track{Package: "p", Selector: "1", State: "error", Error: "registry read failed", Newest: &image, Images: []Image{image}}},
			[]string{"missing fixes could not be determined", "outdated packages could not be determined", "prevented reading the installed package set"},
			[]string{"No known fixed-version advisories", "No installed package has a newer version", "No installed package set (no image"}},
		{"track error without images", "track", TrackView{Track: Track{Package: "p", Selector: "1", State: "error", Error: "index unavailable"}},
			[]string{"does not establish that no image exists", "unknown (track error)"},
			[]string{"No image of this track exists", "No identified images for this track", "No image to compare"}},
		{"overview error row", "overview", OverviewView{Status: StatusView{Document: &StatusDocument{}}, Tracks: []TrackSummary{{Track: Track{Package: "p", Selector: "1", State: "error", Error: "boom"}, DetailURL: "/tracks/p/1"}}},
			[]string{"unknown (track error)", `<span class="warn-text">unknown</span>`},
			[]string{"no image to compare", "> reachable"}},
		{"packages initial failure polling stops", "packages", PackagesView{Packages: []PackageItem{}, Limit: 200, Refreshing: true, LastError: "discover failed"},
			[]string{`data-poll-error-field="lastError" data-poll-unless-field="document"`, "discover failed"}, nil},
		{"packages background refresh with document", "packages", PackagesView{Packages: []PackageItem{}, Limit: 200, Refreshing: true, Document: &DiscoverDocument{}},
			nil, []string{"data-poll-url", "Loading the package index"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderer.Render(&out, tc.template, tc.model); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q", want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(out.String(), absent) {
					t.Errorf("unexpected %q", absent)
				}
			}
		})
	}
}
