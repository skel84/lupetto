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

type templateCase struct {
	name, template string
	model          any
	want, absent   []string
}

func renderCases(t *testing.T, cases []templateCase) {
	t.Helper()
	renderer, err := embeddedRenderer()
	if err != nil {
		t.Fatal(err)
	}
	inline := regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>[^<]|<style|\sstyle=|\son[a-z]+=|javascript:`)
	postForm := regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*>.*?</form>`)
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
			if !strings.HasPrefix(html, "<!doctype html>") || !strings.Contains(html, "</html>") {
				t.Fatal("incomplete document")
			}
			for _, form := range postForm.FindAllString(html, -1) {
				if !strings.Contains(form, `name="csrfToken" value="tok-123"`) {
					t.Errorf("POST form without CSRF token: %s", form)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(html, want) {
					t.Errorf("missing %q in:\n%s", want, html)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(html, absent) {
					t.Errorf("unexpected %q", absent)
				}
			}
			if base, ok := tc.model.(interface{ testBase() BaseView }); ok && !base.testBase().BuildsEnabled {
				if strings.Contains(html, `action="/builds"`) || strings.Contains(html, "/cancel\"") {
					t.Error("build/cancel controls shown while builds are disabled")
				}
			}
		})
	}
}

func (b BaseView) testBase() BaseView { return b }

// Every embedded template must execute against representative models,
// including nil pointers, zero times and hostile strings, and must stay
// compatible with the CSP (no inline script/style/handlers).
func TestEmbeddedTemplatesRenderRepresentativeModels(t *testing.T) {
	evil := `<script>alert(1)</script>"'`
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ended := created.Add(time.Minute)
	failed := 1
	digest := "sha256:" + strings.Repeat("a", 64)
	image := Image{Digest: digest, Tags: []string{"3.6.0-r1", evil}, Name: "openssl", Version: "3.6.0-r1", Architecture: "x86_64", Created: created}
	fix := MissingFix{Name: "libcrypto3", Architecture: "x86_64", InstalledVersion: "3.6.0-r1", FixedVersion: "3.6.0-r2", AvailableVersion: "3.6.0-r3", IDs: []string{"CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"}, ReachableByTrack: true,
		Advisories: []Advisory{{ID: "CVE-2026-0001", Severity: "critical", SeveritySource: "nvd:cvss-v3.1"}, {ID: "GHSA-aaaa-bbbb-cccc", Severity: "", SeveritySource: evil}}, MaxSeverity: "critical"}
	unreach := MissingFix{Name: "openssl", Architecture: "x86_64", InstalledVersion: "3.6.0-r1", FixedVersion: "3.7.0-r0", IDs: []string{"GO-2026-0001", evil}, MaxSeverity: "bogus"}
	track := Track{
		Package: "openssl", Selector: "3.6", State: "fixes-available", Error: evil, Repository: "127.0.0.1:5000/x/openssl",
		Latest: &PackageIdentity{Name: "openssl", Version: "3.6.0-r2", Architecture: "x86_64"},
		Images: []Image{image, {Digest: "short"}}, Newest: &image,
		Installed:        []PackageIdentity{{Name: "libcrypto3", Version: "3.6.0-r1", Architecture: "x86_64"}},
		Outdated:         []OutdatedPackage{{Name: "libcrypto3", Architecture: "x86_64", InstalledVersion: "3.6.0-r1", LatestVersion: "3.6.0-r2"}},
		MissingFixes:     []MissingFix{fix, unreach},
		UnevaluatedFixes: []UnevaluatedFix{{Name: "libcrypto3", FixedVersion: "1.1.0-r1-r0", IDs: []string{"CVE-2026-0002"}}},
		ArtifactCount:    2, UnidentifiedCount: 1,
	}
	security := SecuritySource{URL: "https://packages.wolfi.dev/os/security.json", SHA256: "abc", Unsigned: true, FixedOnly: true, WolfiOnly: true, UnevaluatedFixCount: 1, UnevaluatedFixes: []UnevaluatedFix{{Name: "opa-envoy", FixedVersion: "1.1.0-r1-r0"}}, Severity: SeveritySummary{PendingCount: 2}}
	document := &StatusDocument{Kind: "status", Version: 2, ComputedAt: created, Architecture: "x86_64", Registry: "127.0.0.1:5000", Repository: "x", IndexSHA256: "def", Security: security, Tracks: []Track{track}}
	record := &BuildRecord{Version: 6, Command: "build", Outcome: "failed", Workspace: "/tmp/ws",
		Failure:   &RecordFailure{Stage: "signing", Error: evil, SideEffectsPossible: true},
		Request:   RecordRequest{BuildRequest: BuildRequest{Package: "openssl", Selector: "3.6"}, Publish: true, Sign: true},
		Selection: &RecordSelection{Package: "openssl", Version: "3.6.0-r2", Architecture: "x86_64", IndexSHA256: "def"},
		Evidence:  &RecordEvidence{ApkoVersion: "1.4.5", ImageDigest: "sha256:b", SPDXValidated: true},
		Stages: RecordStages{Build: StageOutcome{Status: "completed"}, Load: StageOutcome{Status: "skipped"},
			Publication: StageOutcome{Status: "published", Digest: "sha256:c", ImmutableReference: "r@sha256:c", Reference: "r:3.6.0-r2"},
			Signing:     StageOutcome{Status: "failed"}, Attestation: StageOutcome{Status: "not-attempted"}},
	}
	stages := func(statuses ...string) []BuildStage {
		names := []string{"resolve", "build", "validate", "load", "publish", "sign", "attest"}
		out := make([]BuildStage, len(names))
		for i, name := range names {
			out[i] = BuildStage{Name: name, Status: statuses[i]}
		}
		return out
	}
	failedItem := BuildItem{ID: "20260930-184410", DetailURL: "/builds/20260930-184410", Package: "openssl", Version: "3.6.0-r2", State: "failed", StartedAt: created, Record: record, Error: evil,
		Stages: stages("completed", "completed", "completed", "skipped", "published", "failed", "not-attempted"), SPDXURL: "/builds/20260930-184410/spdx"}
	runningItem := BuildItem{ID: "7", DetailURL: "/builds/7", Package: "nginx-stable", Version: "1.30.2-r0", State: "running", StartedAt: created, Live: true,
		Stages: stages("completed", "running", "pending", "pending", "pending", "pending", "pending")}
	succeededItem := BuildItem{ID: "3", DetailURL: "/builds/3", Package: "valkey-9.1", Version: "9.1.2-r2", State: "succeeded", StartedAt: created,
		Stages: stages("completed", "completed", "completed", "loaded", "skipped", "skipped", "skipped")}
	invalidItem := BuildItem{ID: "x", DetailURL: "/builds/x", State: "unreadable", Error: evil}

	shell := ShellView{Registry: "127.0.0.1:5000/x", RegistryState: "ready", DockerState: "available", PublishLoad: true, StatusComputedAt: created, IndexSHA256: strings.Repeat("d", 64), FeedSHA256: strings.Repeat("e", 64), Architecture: "x86_64"}
	base := BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: shell}
	disabled := BaseView{CSRFToken: "tok-123", Shell: ShellView{Registry: "127.0.0.1:1/x", RegistryState: "error", DockerState: "unavailable", DockerReason: evil}}
	busyShell := shell
	busyShell.RunningBuild = &runningItem
	busy := BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: busyShell}

	versions := []VersionRow{
		{Identity: PackageIdentity{Name: "openssl", Version: "3.6.0-r2"}, Key: "3.6.0-r2", Latest: true},
		{Identity: PackageIdentity{Name: "openssl", Version: "3.6.0-r1"}, Key: digest, Registry: []Image{image},
			LocalImages: []DockerImage{{ID: "sha256:" + strings.Repeat("f", 64), Tags: []string{"lupetto/openssl:3.6.0-r1-amd64"}, Created: created, IdentityKnown: true, Identity: &PackageIdentity{Name: "openssl", Version: "3.6.0-r1"}}},
			Builds:      []BuildItem{failedItem}},
	}
	row := ProductRow{Package: "openssl", Selector: "3.6", Track: track, DetailURL: "/images/openssl/3.6", Versions: versions,
		Verdict: "Fixes available", VerdictKind: "rebuild", VerdictDetail: "3.6.0-r1 · 1 fix", UnreachableCount: 1, NeedsAction: true,
		Severity: SeverityCounts{Critical: 1, Unknown: 1, Total: 2}, Action: PrimaryAction{Label: "Rebuild", Kind: "build", Package: "openssl", Selector: "3.6", Mode: "publish"}}
	notBuilt := ProductRow{Package: "valkey", Selector: "9.2", Track: Track{Package: "valkey", Selector: "9.2", State: "error", Error: "no match"}, DetailURL: "/images/valkey/9.2",
		Verdict: "Unable to compare", VerdictKind: "error", Action: PrimaryAction{Label: "Edit tracking", Kind: "tracking", URL: "/products/track?package=valkey"}}
	fresh := ProductRow{Package: "busybox-static", Selector: "1", Track: Track{Package: "busybox-static", Selector: "1", State: "not-built", Latest: &PackageIdentity{Name: "busybox-static", Version: "1.38.0-r2"}},
		DetailURL: "/images/busybox-static/1", Verdict: "Not in registry", VerdictKind: "notbuilt", Action: PrimaryAction{Label: "Build 1.38.0-r2", Kind: "build", Package: "busybox-static", Selector: "1", Mode: "publish"}}
	groups := []ProductGroup{{Package: "openssl", DetailURL: "/images/openssl/3.6", Rows: []ProductRow{row}}, {Package: "valkey", DetailURL: "/images/valkey/9.2", Rows: []ProductRow{notBuilt}}, {Package: "busybox-static", DetailURL: "/images/busybox-static/1", Rows: []ProductRow{fresh}}}
	summary := ImagesSummary{All: 3, NeedsAction: 3, NotInRegistry: 1, MissingCritical: 1}
	status := StatusView{Document: document}

	sets := []PackageSet{
		{Key: digest, Label: "3.6.0-r1 · registry", Source: "registry", Packages: []PackageIdentity{{Name: "libcrypto3", Version: "3.6.0-r1", Architecture: "x86_64"}, {Name: evil, Version: "1", Architecture: "x86_64"}}},
		{Key: "20260930-184410", Label: "3.6.0-r2 · local build", Source: "local", SPDXURL: "/builds/20260930-184410/spdx", Packages: []PackageIdentity{{Name: "libcrypto3", Version: "3.6.0-r2", Architecture: "x86_64"}}},
	}
	imageView := func(tab string) ImageView {
		return ImageView{BaseView: base, Status: status, Product: row, Tab: tab, Versions: sets, Packages: sets[0],
			Compare: CompareView{From: sets[0].Key, To: sets[1].Key, Before: sets[0], After: sets[1], Added: 1, Removed: 1, Changed: 1, Unchanged: 9,
				Changes: []PackageChange{{Name: "libcrypto3", Architecture: "x86_64", Before: "3.6.0-r1", After: "3.6.0-r2", Kind: "changed"}, {Name: evil, Kind: "added", After: "1"}, {Name: "zlib", Kind: "removed", Before: "1.3"}}},
			FixedByRebuilding: []MissingFix{fix}, NeedsAnotherVersion: []MissingFix{unreach}, Builds: []BuildItem{failedItem, succeededItem},
			Siblings: []ImageSibling{{Selector: "3.6", URL: "/images/openssl/3.6", Current: true}, {Selector: "3.5", URL: "/images/openssl/3.5"}}}
	}
	localPackages := imageView("packages")
	localPackages.Packages = sets[1]
	emptyImage := ImageView{BaseView: disabled, Product: fresh, Tab: "vulnerabilities"}
	errorImage := ImageView{BaseView: base, Status: status, Product: notBuilt, Tab: "overview"}

	renderCases(t, []templateCase{
		{"images full", "images", ImagesView{BaseView: base, Status: status, Groups: groups, Summary: summary, Notice: ImagesNotice{Tracked: evil}},
			[]string{`name="mode" value="publish"`, `name="selector" value="3.6"`, `action="/builds"`, "Now tracking", "1 need another version", "Unknown (track error)", "Not in registry",
				`class="verdict v-rebuild"`, "not signed", "opa-envoy", "2 advisory IDs are still waiting", `id="track-dialog"`, `href="/products/track"`, `data-opens="track-dialog"`, "&nbsp;Crit"},
			[]string{"secure", "No vulnerabilities"}},
		{"images empty", "images", ImagesView{BaseView: base, Status: status, Summary: ImagesSummary{}}, []string{"No products tracked yet", "Browse the catalog"}, nil},
		{"images nothing tracked", "images", ImagesView{BaseView: base, Empty: true, Status: StatusView{Empty: true}}, []string{"No products tracked yet", "Nothing tracked yet."}, []string{"Checking your images", "No status yet"}},
		{"images no match", "images", ImagesView{BaseView: base, Status: status, Query: evil, Filter: "current", Summary: ImagesSummary{}}, []string{"No images match", "Clear filters"}, []string{"No products tracked yet"}},
		{"images first check", "images", ImagesView{BaseView: base, Status: StatusView{Refreshing: true}}, []string{"Checking your images", `data-poll-field="status.refreshing"`}, nil},
		{"images error read-only", "images", ImagesView{BaseView: disabled, Status: StatusView{LastError: evil}, Inventory: InventoryView{Error: evil}}, []string{"couldn’t check your images", "Last comparison had errors", "Docker isn’t available", "Read-only server", "Local inventory couldn’t be read"}, nil},
		{"images building", "images", ImagesView{BaseView: busy, Status: status, Groups: groups, Summary: summary}, []string{"Another build is running", "View progress", `data-build-running`, `<span class="count"`}, []string{`action="/builds"`}},
		{"images disabled", "images", ImagesView{BaseView: disabled, Status: status, Groups: groups, Summary: summary}, []string{"Builds are disabled on this server", "Docker unavailable"}, nil},
		{"image overview", "image", imageView("overview"), []string{`id="about-data"`, "Overview &amp; versions", `aria-current="page">Overview`, "lupetto/openssl:3.6.0-r1-amd64", "1 image without Lupetto labels", "2 other artifacts", `class="mark latest"`, "Recent openssl builds", "/images/openssl/3.5?tab=overview"}, nil},
		{"image vulnerabilities", "image", imageView("vulnerabilities"), []string{"Fixed by rebuilding", "Needs another version", `href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"`, `href="https://github.com/advisories/GHSA-aaaa-bbbb-cccc"`, `href="https://pkg.go.dev/vuln/GO-2026-0001"`, "nvd:cvss-v3.1", "Couldn’t be evaluated", "index has 3.6.0-r3", "sev sev-unknown", "Any new build"}, []string{"No missing fixes found"}},
		{"image packages registry", "image", imageView("packages"), []string{"Packages read from the registry image", `<span class="ver newer">3.6.0-r2</span>`, "?tab=packages&amp;version=20260930-184410"}, []string{"Download SPDX"}},
		{"image packages local", "image", localPackages, []string{`href="/builds/20260930-184410/spdx" download`, "Download SPDX (JSON)"}, nil},
		{"image compare", "image", imageView("compare"), []string{`name="from"`, `<option value="20260930-184410" selected>`, "+ Added", "− Removed", "↕ Changed", "<strong>9</strong> unchanged"}, nil},
		{"image builds", "image", imageView("builds"), []string{"/builds/20260930-184410", "published; failed at Sign", "loaded into Docker"}, nil},
		{"image never built disabled", "image", emptyImage, []string{"No registry image to check"}, nil},
		{"image error", "image", errorImage, []string{"can’t compare valkey 9.2", "no match"}, []string{"No missing fixes found"}},
		{"image docker state unknown", "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Product: fresh, Tab: "overview"},
			[]string{"Local Docker state unknown or unavailable."}, []string{"No images in local Docker"}},
		{"image docker unavailable", "image", ImageView{BaseView: disabled, Product: fresh, Tab: "overview"},
			[]string{"Local Docker state unknown or unavailable: &lt;script&gt;"}, []string{"No images in local Docker"}},
		{"image docker available empty", "image", ImageView{BaseView: base, Product: fresh, Tab: "overview"},
			[]string{"No images in local Docker."}, []string{"state unknown"}},
		{"images docker state unknown", "images", ImagesView{BaseView: BaseView{CSRFToken: "tok-123"}, Status: status, Groups: groups, Summary: summary},
			[]string{"Docker state unknown"}, nil},
		{"image error vulns", "image", ImageView{BaseView: base, Status: status, Product: ProductRow{Package: "p", Selector: "1", DetailURL: "/images/p/1", Track: Track{State: "error", Error: "registry read failed", Newest: &image}}, Tab: "vulnerabilities"},
			[]string{"Missing fixes could not be determined", "registry read failed"}, []string{"No missing fixes found", "No registry image to check"}},
		{"catalog", "packages", PackagesView{BaseView: base, Query: "s", Packages: []PackageItem{{DiscoveredPackage: DiscoveredPackage{Name: "busybox", Version: "1", Description: evil}, DetailURL: "/catalog/busybox", Tracked: true}, {DiscoveredPackage: DiscoveredPackage{Name: "curl", Version: "8"}, DetailURL: "/catalog/curl"}}, TotalMatches: 201, Limit: 200, Document: &DiscoverDocument{Architecture: "x86_64", IndexSHA256: "abc"}},
			[]string{"Showing the first 200 of 201", `href="/catalog/busybox"`, "Tracked", `data-package="curl"`, `id="track-dialog"`}, nil},
		{"catalog loading", "packages", PackagesView{BaseView: base, Packages: []PackageItem{}, Limit: 200, Refreshing: true, LastError: evil}, []string{"Loading the Wolfi index", `data-poll-url="/catalog?format=json" data-poll-field="refreshing" data-poll-error-field="lastError" data-poll-unless-field="document"`, "couldn’t be loaded"}, nil},
		{"catalog none", "packages", PackagesView{BaseView: base, Query: "zz", Packages: []PackageItem{}, Limit: 200, Document: &DiscoverDocument{}}, []string{"No packages match"}, nil},
		{"catalog package", "package", PackageView{BaseView: base, Name: "cmd:curl", Document: &DiscoverDocument{Packages: []DiscoveredPackage{{Name: "curl", Version: "8.0-r1", Description: evil}}}},
			[]string{`name="package" value="cmd:curl"`, `name="apkVersion" value="8.0-r1"`, `name="mode" value="local"`, `name="mode" value="publish"`}, nil},
		{"catalog package disabled", "package", PackageView{BaseView: disabled, Name: "x", Error: evil}, []string{"Versions couldn’t be listed", "Builds are disabled"}, nil},
		{"builds", "jobs", JobsView{BaseView: busy, Items: []BuildItem{runningItem, failedItem, succeededItem, invalidItem}, Running: true, HistoryLimit: 50}, []string{"Running now", `action="/builds/7/cancel"`, `data-live-url="/builds/7?format=json"`, "Unreadable record", "This server", "Build record"}, nil},
		{"builds empty", "jobs", JobsView{BaseView: disabled, Items: []BuildItem{}, HistoryLimit: 50}, []string{"No builds yet", "Read-only server"}, nil},
		{"build running", "job", JobDetailView{BaseView: busy, Item: runningItem, HasLog: true, Job: JobView{ID: "7", State: "running", StartedAt: created, Request: BuildRequest{Package: "nginx", Selector: "1.30"}}, Log: LogChunk{NextOffset: 10, Text: evil, Truncated: true}},
			[]string{`action="/builds/7/cancel"`, `data-log-url="/builds/7/logs" data-log-offset="10"`, "Earlier output was discarded", `data-live-url="/builds/7?format=json"`, "Waiting", "In progress"}, nil},
		{"build partial failure", "job", JobDetailView{BaseView: base, Item: failedItem, HasLog: true, Log: LogChunk{Done: true}},
			[]string{"Failed at Sign.", "Side effects may remain", "Skipped · not requested", "Not attempted · earlier stage failed", "SPDX JSON", "validated against lock", "r@sha256:c", "Explorer diagnostic", "Raw log"},
			[]string{"data-log-url", `class="banner ok"`, "<dt>Entrypoint</dt>", "<dt>CA bundle</dt>"}},
		{"build entrypoint", "job", JobDetailView{BaseView: base, Item: BuildItem{ID: "8", DetailURL: "/builds/8", State: "succeeded", Record: &BuildRecord{Outcome: "succeeded", Request: RecordRequest{BuildRequest: BuildRequest{Package: "kyverno", Selector: "1", Entrypoint: []string{"/usr/bin/kyverno", "two words", evil}, CABundle: true}}}}},
			[]string{"<dt>Entrypoint</dt>", "&#34;/usr/bin/kyverno&#34; &#34;two words&#34; &#34;&lt;script&gt;", "<dt>CA bundle</dt>"}, nil},
		{"build unverified digest", "job", JobDetailView{BaseView: base, Item: BuildItem{ID: "9", DetailURL: "/builds/9", State: "failed", Record: &BuildRecord{Stages: RecordStages{Publication: StageOutcome{Status: "failed", Digest: "sha256:d"}}}}},
			[]string{"Digest not verified", "kept only for builds started from this server"}, nil},
		{"build canceled", "job", JobDetailView{BaseView: disabled, Item: BuildItem{ID: "4", DetailURL: "/builds/4", State: "canceled", Live: true}, Job: JobView{ID: "4", State: "canceled", CancelRequested: true, EndedAt: &ended, ExitCode: &failed}},
			[]string{"Build canceled.", "External side effects may remain", "exit code 1"}, nil},
		{"build unreadable record", "job", JobDetailView{BaseView: base, Item: invalidItem}, []string{"can’t be fully read", "No readable record"}, nil},
		{"tracking", "tracking", TrackingView{BaseView: base, Package: evil, Selector: "17", Products: &ProductsDocument{Products: []Product{{Package: "postgresql", Selectors: []string{"17", "16"}}}}, Message: "Saved"},
			[]string{`action="/products/add"`, `action="/products/remove"`, `name="selector" value="16"`, "Stop tracking postgresql 16", `value="17"`}, nil},
		{"tracking error read-only", "tracking", TrackingView{BaseView: disabled, Error: evil}, []string{"couldn’t be changed", "products file couldn’t be read"}, nil},
	})
}

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
	css := request(server, http.MethodGet, "/static/app.css", nil)
	if css.Code != 200 || !strings.Contains(css.Body.String(), "prefers-color-scheme: dark") || strings.Contains(css.Body.String(), "data-theme") {
		t.Fatalf("%d stylesheet is not the single Pista theme", css.Code)
	}
	// Collapsed nav labels and repeated table headers must stay in the accessibility tree.
	for _, hidden := range []string{".navtext { display: none", "tracks thead { display: none", "stackable thead { display: none"} {
		if strings.Contains(css.Body.String(), hidden) {
			t.Errorf("stylesheet removes accessible text with %q", hidden)
		}
	}
}

// A failed comparison must not be presented as an empty (clean) result, and
// the UI must never claim a clean security result.
func TestEmbeddedTemplatesDistinguishTrackErrorsFromEmptyResults(t *testing.T) {
	image := Image{Digest: "sha256:" + strings.Repeat("b", 64), Version: "1.0-r0"}
	errorRow := ProductRow{Package: "p", Selector: "1", DetailURL: "/images/p/1", Track: Track{Package: "p", Selector: "1", State: "error", Error: "registry read failed", Newest: &image, Images: []Image{image}}, Verdict: "Unable to compare", VerdictKind: "error"}
	cleanRow := ProductRow{Package: "q", Selector: "1", DetailURL: "/images/q/1", Track: Track{Package: "q", Selector: "1", State: "current", Newest: &image, Images: []Image{image}}, Verdict: "Up to date", VerdictKind: "ok"}
	doc := &StatusDocument{Security: SecuritySource{Unsigned: true, FixedOnly: true, WolfiOnly: true}}
	renderer, err := embeddedRenderer()
	if err != nil {
		t.Fatal(err)
	}
	for _, tab := range []string{"overview", "vulnerabilities"} {
		var out bytes.Buffer
		if err := renderer.Render(&out, "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Status: StatusView{Document: doc}, Product: cleanRow, Tab: tab}); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(out.String(), `id="about-data"`); n != 1 {
			t.Errorf("%s tab renders the security-data note %d times, want 1", tab, n)
		}
	}
	renderCases(t, []templateCase{
		{"images error row", "images", ImagesView{BaseView: BaseView{CSRFToken: "tok-123"}, Status: StatusView{Document: doc}, Groups: []ProductGroup{{Package: "p", Rows: []ProductRow{errorRow}}}, Summary: ImagesSummary{All: 1}},
			[]string{"Unknown (track error)", "registry read failed"}, []string{"None found"}},
		{"image error overview", "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Product: errorRow, Tab: "overview"},
			[]string{"could not be determined"}, []string{"None found", "Nothing published yet"}},
		{"image error overview without images", "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Product: ProductRow{Package: "p", Selector: "1", DetailURL: "/images/p/1", Track: Track{State: "error", Error: "registry unreachable"}}, Tab: "overview"},
			[]string{"Registry contents could not be determined"}, []string{"Nothing published yet"}},
		{"clean overview carries the data note", "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Status: StatusView{Document: doc}, Product: cleanRow, Tab: "overview"},
			[]string{"None found", `id="about-data"`, "isn’t a full vulnerability scan"}, nil},
		{"clean track still qualified", "image", ImageView{BaseView: BaseView{CSRFToken: "tok-123"}, Status: StatusView{Document: doc}, Product: cleanRow, Tab: "vulnerabilities"},
			[]string{"No missing fixes found", "What this does and doesn’t cover", "isn’t a full vulnerability scan", "The feed is not signed", "Fixed issues only", "Wolfi packages only"}, []string{"secure", "No vulnerabilities"}},
	})
}
