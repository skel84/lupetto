package explorer

import (
	"strings"
	"testing"
	"time"
)

// Publish builds also load into local Docker when the latest inventory reports
// Docker as available; otherwise every publish control and the build detail say
// that the build publishes only, and why.
func TestEmbeddedTemplatesShowPublishLoadDecision(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	available := BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: ShellView{DockerState: "available", PublishLoad: true}}
	unavailable := BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: ShellView{DockerState: "unavailable", DockerReason: "Docker CLI is not available on PATH", PublishLoadReason: "Docker CLI is not available on PATH"}}
	unknown := BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: ShellView{PublishLoadReason: "Docker availability is unknown"}}

	publishRow := ProductRow{Package: "busybox-static", Selector: "1", Track: Track{Package: "busybox-static", Selector: "1", State: "not-built"}, DetailURL: "/images/busybox-static/1",
		Verdict: "Not in registry", VerdictKind: "notbuilt", Action: PrimaryAction{Label: "Build 1.38.0-r2", Kind: "build", Package: "busybox-static", Selector: "1", Mode: "publish"}}
	localRow := publishRow
	localRow.Action.Mode = "local"
	images := func(base BaseView, row ProductRow) ImagesView {
		return ImagesView{BaseView: base, Status: StatusView{Document: &StatusDocument{ComputedAt: created}}, Groups: []ProductGroup{{Package: row.Package, DetailURL: row.DetailURL, Rows: []ProductRow{row}}}, Summary: ImagesSummary{All: 1}}
	}
	image := func(base BaseView) ImageView {
		return ImageView{BaseView: base, Product: publishRow, Tab: "vulnerabilities"}
	}
	catalog := func(base BaseView) PackageView {
		return PackageView{BaseView: base, Name: "curl", Document: &DiscoverDocument{Packages: []DiscoveredPackage{{Name: "curl", Version: "8.0-r1"}}}}
	}

	stages := func(load string) []BuildStage {
		return []BuildStage{{"resolve", "completed"}, {"build", "completed"}, {"validate", "completed"}, {"load", load}, {"publish", "published"}, {"sign", "skipped"}, {"attest", "skipped"}}
	}
	record := func(load bool, loadStatus string) *BuildRecord {
		return &BuildRecord{Version: 6, Command: "build", Outcome: "succeeded",
			Request: RecordRequest{BuildRequest: BuildRequest{Package: "curl", Selector: "8", Load: load}, Publish: true},
			Stages:  RecordStages{Build: StageOutcome{Status: "completed"}, Load: StageOutcome{Status: loadStatus}, Publication: StageOutcome{Status: "published"}}}
	}
	publishOnly := BuildItem{ID: "5", DetailURL: "/builds/5", Package: "curl", Version: "8.0-r1", State: "succeeded", StartedAt: created, Live: true,
		Mode: "publish", LoadReason: "Docker CLI is not available on PATH", Record: record(false, "skipped"), Stages: stages("skipped")}
	publishLoaded := BuildItem{ID: "6", DetailURL: "/builds/6", Package: "curl", Version: "8.0-r1", State: "succeeded", StartedAt: created, Live: true,
		Mode: "publish", Load: true, Record: record(true, "loaded"), Stages: stages("loaded")}
	historyPublishOnly := BuildItem{ID: "h", DetailURL: "/builds/h", Package: "curl", Version: "8.0-r1", State: "succeeded", StartedAt: created,
		Mode: "publish", Record: record(false, "skipped"), Stages: stages("skipped")}
	running := func(load bool, reason, loadStatus string) BuildItem {
		item := BuildItem{ID: "7", DetailURL: "/builds/7", Package: "curl", State: "running", StartedAt: created, Live: true, Mode: "publish", Load: load, LoadReason: reason,
			Stages: []BuildStage{{"resolve", "completed"}, {"build", "running"}, {"validate", "pending"}, {"load", loadStatus}, {"publish", "pending"}, {"sign", "pending"}, {"attest", "pending"}}}
		return item
	}
	runningView := func(item BuildItem) JobDetailView {
		return JobDetailView{BaseView: available, Item: item, Job: JobView{ID: "7", State: "running", StartedAt: created, Request: BuildRequest{Package: "curl", Selector: "8", Mode: "publish", Load: item.Load, LoadReason: item.LoadReason}}}
	}

	const loadNotRequested = "Load into Docker</span>\n<span class=\"state\" data-stage-state>Skipped · not requested"
	renderCases(t, []templateCase{
		{"images publish docker available", "images", images(available, publishRow),
			[]string{`<span class="btn-note">also loads into local Docker</span>`}, []string{"publish only"}},
		{"images publish docker unavailable", "images", images(unavailable, publishRow),
			[]string{`<span class="btn-note">publish only: Docker unavailable</span>`, "publishes without loading into Docker until Docker is available again"}, []string{"also loads into local Docker"}},
		{"images publish docker unknown", "images", images(unknown, publishRow),
			[]string{`<span class="btn-note">publish only: Docker state unknown</span>`}, []string{"also loads into local Docker"}},
		{"images local action has no publish note", "images", images(unavailable, localRow), nil, []string{"publish only:", "also loads into local Docker"}},
		{"image publish docker available", "image", image(available), []string{`<span class="btn-note">also loads into local Docker</span>`}, []string{"publish only"}},
		{"image publish docker unavailable", "image", image(unavailable), []string{`<span class="btn-note">publish only: Docker unavailable</span>`}, []string{"also loads into local Docker"}},
		{"catalog publish docker available", "package", catalog(available),
			[]string{"and signs when a key is configured) and also loads the image into local Docker."}, []string{"without loading into Docker"}},
		{"catalog publish docker unavailable", "package", catalog(unavailable),
			[]string{"it publishes only, without loading into Docker (Docker CLI is not available on PATH)."}, []string{"also loads the image"}},
		{"catalog publish docker unknown", "package", catalog(unknown),
			[]string{"it publishes only, without loading into Docker (Docker availability is unknown)."}, []string{"also loads the image"}},
		{"build publish-only shows skip reason", "job", JobDetailView{BaseView: available, Item: publishOnly, Job: JobView{ID: "5", State: "succeeded", StartedAt: created}},
			[]string{"Skipped · Docker CLI is not available on PATH", "no Docker load: Docker CLI is not available on PATH"}, []string{loadNotRequested}},
		{"build publish loaded", "job", JobDetailView{BaseView: available, Item: publishLoaded, Job: JobView{ID: "6", State: "succeeded", StartedAt: created}},
			[]string{`data-stage="load"`, "Loaded", "Docker load requested"}, []string{"no Docker load"}},
		{"build history publish-only without reason", "job", JobDetailView{BaseView: available, Item: historyPublishOnly},
			[]string{loadNotRequested}, []string{"no Docker load:"}},
		{"build running publish with load", "job", runningView(running(true, "", "pending")),
			[]string{"publish · also loads into local Docker", `data-live-url="/builds/7?format=json"`}, []string{"Skipped · "}},
		{"build running publish only", "job", runningView(running(false, "Docker availability is unknown", "skipped")),
			[]string{"publish only · Docker availability is unknown", "Skipped · Docker availability is unknown"}, []string{loadNotRequested}},
		{"builds list running publish only", "jobs", JobsView{BaseView: BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: ShellView{DockerState: "unavailable", RunningBuild: new(running(false, "Docker is unavailable", "skipped"))}}, HistoryLimit: 50},
			[]string{"Running now", "Skipped · Docker is unavailable"}, nil},
	})

	// The live stage updater must keep the reason rather than reverting to "not requested".
	js, err := embeddedWeb.ReadFile("web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`item.mode === "publish" && !item.load && item.loadReason`, "applyStages(container, item)"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}
