package explorer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fixtureInventory places one validated build in the durable data builds
// root; callers must isolate the environment with isolatedCache first.
func fixtureInventory(t *testing.T) (ImagesDocument, InventoryBuild) {
	t.Helper()
	roots, err := buildsRoots()
	if err != nil {
		t.Fatal(err)
	}
	return fixtureInventoryAt(t, roots[0], "image-fixture")
}
func fixtureInventoryAt(t *testing.T, builds, name string) (ImagesDocument, InventoryBuild) {
	t.Helper()
	if home := os.Getenv("HOME"); home == "" || !strings.HasPrefix(builds, home+string(filepath.Separator)) {
		t.Fatalf("fixture root %q is outside the isolated HOME %q", builds, home)
	}
	workspace := filepath.Join(builds, name)
	if err := os.MkdirAll(filepath.Join(workspace, "sbom"), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/wolfi/curl@1.2-r0?arch=x86_64&distro=wolfi"}]}]}`)
	path := filepath.Join(workspace, "sbom", "sbom-x86_64.spdx.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	b := InventoryBuild{Workspace: workspace, RecordPath: filepath.Join(workspace, "result.json"), RecordVersion: 6, Status: "supported", RecordedAt: time.Now(), SPDX: SPDXArtifact{Present: true, Path: path, SHA256: hash}, Record: &BuildRecord{Version: 6, Command: "build", Outcome: "succeeded", Workspace: workspace, Request: RecordRequest{BuildRequest: BuildRequest{Package: "cmd:curl", Selector: "1"}}, Selection: &RecordSelection{Package: "curl", Version: "1.2-r0", Architecture: "x86_64"}, Evidence: &RecordEvidence{SPDXValidated: true, SPDXPath: path, SPDXSHA256: hash}, Stages: RecordStages{Build: StageOutcome{Status: "completed"}, Load: StageOutcome{Status: "loaded"}, Publication: StageOutcome{Status: "skipped"}, Signing: StageOutcome{Status: "skipped"}, Attestation: StageOutcome{Status: "skipped"}}}}
	d := ImagesDocument{Kind: "images", Version: 1, Builds: []InventoryBuild{b}, Docker: DockerInventory{Available: true, Images: []DockerImage{{ID: "sha256:local", IdentityKnown: true, Identity: &PackageIdentity{Name: "curl", Version: "1.2-r0", Architecture: "x86_64"}}}}}
	return d, b
}

// isolatedCache points every user cache/data input at a fresh temporary
// HOME, so tests never touch the real cache or data directories. It returns
// the durable data and legacy cache builds roots.
func isolatedCache(t *testing.T) (data, legacy string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "xdg-data"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "cache"))
	t.Setenv("LUPETTO_DATA_DIR", filepath.Join(home, "data"))
	roots, err := buildsRoots()
	if err != nil || len(roots) != 2 {
		t.Fatalf("isolated roots: %q %v", roots, err)
	}
	return roots[0], roots[1]
}
func fixtureTrack() Track {
	newest := Image{Digest: "sha256:" + strings.Repeat("a", 64), Name: "curl", Version: "1.2-r0", Architecture: "x86_64"}
	older := Image{Digest: "sha256:" + strings.Repeat("b", 64), Name: "curl", Version: "1.1-r0", Architecture: "x86_64"}
	return Track{Package: "cmd:curl", Selector: "1", State: "current", Repository: "127.0.0.1:5000/team/curl", Latest: &PackageIdentity{Name: "curl", Version: "1.2-r0", Architecture: "x86_64"}, Newest: &newest, Images: []Image{newest, older}, Installed: []PackageIdentity{{Name: "curl", Version: "1.2-r0", Architecture: "x86_64"}}}
}
func encodeFixture(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestDashboardRoutesAndEvidence(t *testing.T) {
	isolatedCache(t)
	inventory, build := fixtureInventory(t)
	track := fixtureTrack()
	config := goodFake()
	config.Images = encodeFixture(t, inventory)
	ref := track.Repository + "@" + track.Images[1].Digest
	config.Inspect = encodeFixture(t, InspectDocument{Kind: "inspect", Version: 1, Reference: ref, Digest: track.Images[1].Digest, Packages: []PackageIdentity{{Name: "curl", Version: "1.1-r0", Architecture: "x86_64"}, {Name: "removed", Version: "1-r0", Architecture: "x86_64"}}})
	config.Products = `{"kind":"products","version":1,"products":[{"package":"cmd:curl","selectors":["1"]}],"changed":true,"message":"Added"}`
	server, _, calls := testServer(t, config, true)
	server.status.finish(&StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}, nil)
	server.discovery.finish(&DiscoverDocument{Kind: "discover", Version: 1, Packages: []DiscoveredPackage{{Name: "curl", Version: "1.2-r0"}}}, nil)
	id := buildID(build)
	for _, path := range []string{"/?format=json", "/images?format=json", "/catalog?format=json", "/catalog/curl?format=json", "/products/track?format=json", "/builds?format=json", "/builds/" + id + "?format=json", "/images/cmd:curl/1?format=json", "/images/cmd:curl/1?tab=vulnerabilities&format=json", "/images/cmd:curl/1?tab=builds&format=json", "/images/cmd:curl/1?tab=packages&version=" + id + "&format=json", "/images/cmd:curl/1?tab=packages&version=" + track.Images[1].Digest + "&format=json"} {
		w := request(server, "GET", path, nil)
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := request(server, "GET", "/?format=json", nil)
	var home ImagesView
	if err := json.Unmarshal(w.Body.Bytes(), &home); err != nil {
		t.Fatal(err)
	}
	if len(home.Groups) != 1 || len(home.Products) != 1 || len(home.Products[0].Versions[0].LocalImages) != 1 || len(home.Products[0].Versions[0].Builds) != 1 {
		t.Fatalf("join: %+v", home.Products)
	}
	comparePath := "/images/cmd:curl/1?tab=compare&format=json&from=" + track.Images[1].Digest + "&to=" + id
	for range 2 {
		w = request(server, "GET", comparePath, nil)
		var view ImageView
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.Compare.Error != "" || view.Compare.Changed != 1 || view.Compare.Removed != 1 {
			t.Fatalf("compare: %+v", view.Compare)
		}
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "inspect|") != 1 {
		t.Fatalf("inspect not cached: %s", data)
	}
	w = request(server, "GET", "/builds/"+id+"/sbom", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/spdx+json" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d %s", w.Code, w.Body.String())
	}
	sum := sha256.Sum256(w.Body.Bytes())
	if hex.EncodeToString(sum[:]) != build.SPDX.SHA256 {
		t.Fatal("download checksum differs")
	}
	for _, path := range []string{"/images?filter=invalid&format=json", "/images/cmd:curl/1?tab=invalid&format=json"} {
		if w := request(server, "GET", path, nil); w.Code != 400 {
			t.Fatalf("accepted %s", path)
		}
	}
	for _, path := range []string{"/images/absent/1?format=json", "/builds/absent?format=json", "/builds/absent/sbom"} {
		if w := request(server, "GET", path, nil); w.Code != 404 {
			t.Fatalf("%s=%d", path, w.Code)
		}
	}
	if w := request(server, "GET", "/builds/"+id+"/logs", nil); w.Code != 404 {
		t.Fatal("persistent history exposed raw logs")
	}
}
func TestDashboardVerdictsJoinFiltersAndDiff(t *testing.T) {
	track := fixtureTrack()
	inventory := ImagesDocument{Docker: DockerInventory{Images: []DockerImage{{IdentityKnown: true, Identity: &PackageIdentity{Name: "curl", Version: "1.2-r0", Architecture: "aarch64"}}, {IdentityKnown: true, Identity: &PackageIdentity{Name: "other", Version: "1.2-r0", Architecture: "x86_64"}}, {IdentityKnown: true, Identity: &PackageIdentity{Name: "curl", Version: "11.2-r0", Architecture: "x86_64"}}}}}
	for _, test := range []struct {
		state, kind, label string
		action             bool
	}{{"current", "ok", "Build locally", false}, {"update-available", "update", "Update", true}, {"fixes-available", "rebuild", "Rebuild for fixes", true}, {"not-built", "notbuilt", "Build & publish", true}, {"error", "error", "Edit tracking", true}} {
		track.State = test.state
		row := joinTrack(track, &inventory)
		if row.VerdictKind != test.kind || row.Action.Label != test.label || row.NeedsAction != test.action {
			t.Fatalf("verdict %s: %+v", test.state, row)
		}
		for _, version := range row.Versions {
			if len(version.LocalImages) != 0 {
				t.Fatal("joined wrong APK name/version/arch")
			}
		}
	}
	track = fixtureTrack()
	track.MissingFixes = []MissingFix{{IDs: []string{"CVE-2026-1234"}, Advisories: []Advisory{{ID: "CVE-2026-1234", Severity: "critical"}}}, {IDs: []string{"CVE-2026-1234"}, ReachableByTrack: false}}
	track.UnevaluatedFixes = []UnevaluatedFix{{IDs: []string{"GO-2026-1234"}}}
	row := joinTrack(track, nil)
	if row.Severity.Total != 2 || row.Severity.Critical != 1 || row.Severity.Unknown != 1 || row.UnreachableCount != 2 {
		t.Fatalf("severity: %+v", row)
	}
	config := goodFake()
	server, _, _ := testServer(t, config, false)
	server.status.finish(&StatusDocument{Tracks: []Track{track, {Package: "nginx", Selector: "1", State: "not-built"}}}, nil)
	for _, test := range []struct {
		query string
		count int
	}{{"q=curl", 1}, {"filter=critical", 1}, {"filter=needs-action", 1}, {"filter=current", 1}, {"filter=not-in-registry", 1}, {"q=absent", 0}} {
		w := request(server, "GET", "/?format=json&"+test.query, nil)
		var view ImagesView
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if len(view.Products) != test.count {
			t.Fatalf("%s=%d", test.query, len(view.Products))
		}
	}
}
func TestDashboardSPDXPathSafety(t *testing.T) {
	isolatedCache(t)
	_, build := fixtureInventory(t)
	if _, err := readValidatedSPDX(build); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"outside", "traversal", "symlink-file", "symlink-directory", "changed", "unvalidated", "inventory-mismatch"} {
		t.Run(name, func(t *testing.T) {
			copy := build
			record := *build.Record
			evidence := *record.Evidence
			record.Evidence = &evidence
			copy.Record = &record
			switch name {
			case "outside":
				copy.SPDX.Path = filepath.Join(t.TempDir(), "outside.json")
				copy.Record.Evidence.SPDXPath = copy.SPDX.Path
			case "traversal":
				copy.SPDX.Path = filepath.Join(build.Workspace, "..", "..", "outside.json")
				copy.Record.Evidence.SPDXPath = copy.SPDX.Path
			case "symlink-file":
				link := filepath.Join(build.Workspace, "link.json")
				if err := os.Symlink(build.SPDX.Path, link); err != nil {
					t.Fatal(err)
				}
				copy.SPDX.Path = link
				copy.Record.Evidence.SPDXPath = link
			case "symlink-directory":
				link := filepath.Join(build.Workspace, "linked")
				if err := os.Symlink(filepath.Dir(build.SPDX.Path), link); err != nil {
					t.Fatal(err)
				}
				copy.SPDX.Path = filepath.Join(link, filepath.Base(build.SPDX.Path))
				copy.Record.Evidence.SPDXPath = copy.SPDX.Path
			case "changed":
				copy.SPDX.SHA256 = strings.Repeat("0", 64)
				copy.Record.Evidence.SPDXSHA256 = copy.SPDX.SHA256
			case "unvalidated":
				copy.Record.Evidence.SPDXValidated = false
			case "inventory-mismatch":
				copy.SPDX.SHA256 = "wrong"
			}
			if _, err := readValidatedSPDX(copy); err == nil {
				t.Fatal("unsafe SPDX accepted")
			}
		})
	}
}
func TestDashboardProductsEditsAndVersions(t *testing.T) {
	config := goodFake()
	server, update, calls := testServer(t, config, false)
	for _, action := range []string{"add", "remove"} {
		form := url.Values{"csrfToken": {server.token}, "package": {"cmd:curl"}, "selectors": {"1 2.0"}}
		w := request(server, "POST", "/products/"+action, form)
		if w.Code != 303 {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
	}
	eventually(t, func() bool { return !server.status.snapshot().Refreshing })
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "products|add|cmd:curl|1|2.0|--products|products.yaml|--json") || !strings.Contains(string(data), "status|--products") {
		t.Fatalf("argv/refresh: %s", data)
	}
	config.ProductsExit = 1
	update(config)
	w := request(server, "POST", "/products/add", url.Values{"csrfToken": {server.token}, "package": {"curl"}, "selector": {"1"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "writable") {
		t.Fatalf("read-only: %d %s", w.Code, w.Body.String())
	}
	if w := request(server, "POST", "/products/remove", url.Values{"package": {"curl"}}); w.Code != 403 {
		t.Fatal("products bypassed CSRF")
	}
	for _, kind := range []string{"products", "images", "inspect"} {
		for _, doc := range []string{`{"kind":"wrong","version":1}`, `{"kind":"` + kind + `","version":2}`} {
			c := goodFake()
			c.Products = doc
			c.Images = doc
			c.Inspect = doc
			binary, _, _ := fakeCLI(t, c)
			cli, err := NewCLI(binary)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "products":
				_, err = cli.Products(context.Background(), "p", "list", "", nil)
			case "images":
				_, err = cli.Images(context.Background())
			case "inspect":
				_, err = cli.Inspect(context.Background(), "127.0.0.1:5000/team/curl@sha256:"+strings.Repeat("a", 64))
			}
			if err == nil || !strings.Contains(err.Error(), "incompatible") {
				t.Fatalf("accepted %s %s: %v", kind, doc, err)
			}
		}
	}
}
func TestDashboardBuildModesStagesAndMerge(t *testing.T) {
	if err := ValidateBuild(BuildRequest{Package: "curl", Selector: "1", Mode: "shell"}); err == nil {
		t.Fatal("invalid mode")
	}
	for _, mode := range []string{"local", "publish"} {
		args := buildArgs(BuildRequest{Package: "curl", Selector: "1", Mode: mode})
		hasNoLoad := strings.Contains(strings.Join(args, " "), "--no-load")
		if hasNoLoad != (mode == "publish") {
			t.Fatalf("mode %s: %v", mode, args)
		}
	}
	for _, test := range []struct {
		log, mode string
		active    int
	}{{"", "publish", 0}, {"lupetto: Composing OCI image with apko", "publish", 1}, {"lupetto: Validating SPDX against apko lock", "local", 2}, {"lupetto: Pushing OCI image to registry", "publish", 4}, {"lupetto: Verifying registry manifest by digest", "publish", 4}, {"lupetto: Verifying registry tag", "publish", 4}, {"lupetto: Verifying registry config and layers", "publish", 4}} {
		stages := liveStages(test.log, BuildRequest{Mode: test.mode, Load: test.mode == "local"})
		if len(stages) != 7 || stages[test.active].Status != "running" {
			t.Fatalf("stages: %+v", stages)
		}
	}
	inventory := ImagesDocument{Builds: []InventoryBuild{{Workspace: "same", RecordPath: "record", Record: &BuildRecord{Version: 6, Outcome: "succeeded"}}, {Workspace: "other", RecordPath: "other"}}}
	items := mergeBuilds(&inventory, []JobView{{ID: "1", Record: &BuildRecord{Workspace: "same"}}})
	if len(items) != 2 || len(items[0].Stages) != 7 {
		t.Fatalf("merge: %+v", items)
	}
	config := goodFake()
	server, _, calls := testServer(t, config, true)
	form := buildForm(server)
	form.Set("mode", "local")
	w := request(server, "POST", "/builds", form)
	if w.Code != http.StatusSeeOther {
		t.Fatal(w.Body.String())
	}
	eventually(t, func() bool { _, running := server.jobs.list(); return !running })
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "build|cmd:curl|1.2|--json") || strings.Contains(string(data), "build|cmd:curl|1.2|--no-load") {
		t.Fatalf("local argv: %s", data)
	}
	for _, path := range []string{"/builds/1?format=json", "/builds/1/logs?offset=0"} {
		w := request(server, "GET", path, nil)
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestDashboardLocalEnvironmentAndDuplicateForms(t *testing.T) {
	for _, key := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP", "LUPETTO_REQUIRE_SIGNING", "DOCKER_HOST", "DOCKER_CONFIG"} {
		t.Setenv(key, "synthetic")
	}
	config := goodFake()
	config.BuildEnvironment = filepath.Join(t.TempDir(), "environment.json")
	server, _, _ := testServer(t, config, true)
	form := buildForm(server)
	form.Set("mode", "local")
	if w := request(server, "POST", "/builds", form); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	eventually(t, func() bool { _, running := server.jobs.list(); return !running })
	data, err := os.ReadFile(config.BuildEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	var present map[string]bool
	if err := json.Unmarshal(data, &present); err != nil {
		t.Fatal(err)
	}
	for key, available := range present {
		want := key == "DOCKER_HOST" || key == "DOCKER_CONFIG"
		if available != want {
			t.Fatalf("local environment %s=%t", key, available)
		}
	}
	for _, path := range []string{"/builds", "/products/remove"} {
		duplicate := buildForm(server)
		duplicate["selector"] = []string{"1", "2"}
		if w := request(server, "POST", path, duplicate); w.Code != 400 {
			t.Fatalf("duplicate field accepted: %s %d", path, w.Code)
		}
	}
}

func TestDashboardEmptyTrackingAndLiveStagesRetained(t *testing.T) {
	config := goodFake()
	config.Products = `{"kind":"products","version":1,"products":[]}`
	server, _, calls := testServer(t, config, false)
	server.RefreshStatus()
	eventually(t, func() bool { return !server.status.snapshot().Refreshing })
	w := request(server, "GET", "/?format=json", nil)
	var view ImagesView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Empty || view.Status.LastError != "" {
		t.Fatalf("empty: %+v", view.Status)
	}
	data, _ := os.ReadFile(calls)
	if strings.Contains(string(data), "status|") {
		t.Fatal("empty tracking invoked status")
	}
	buffer := newLogBuffer(32)
	_, _ = buffer.Write([]byte("lupetto: Composing OCI image with apko\n"))
	_, _ = buffer.Write([]byte(strings.Repeat("x", 128)))
	if stages := buffer.stages(BuildRequest{Mode: "local", Load: true}); stages[1].Status != "running" || stages[2].Status != "pending" {
		t.Fatalf("truncation reset stages: %+v", stages)
	}
}

func TestDashboardSiblingCompareAndRootSymlink(t *testing.T) {
	isolatedCache(t)
	inventory, build := fixtureInventory(t)
	config := goodFake()
	config.Images = encodeFixture(t, inventory)
	server, _, _ := testServer(t, config, false)
	first := fixtureTrack()
	second := fixtureTrack()
	second.Selector = "2"
	second.Latest = &PackageIdentity{Name: "curl", Version: "2.0-r0", Architecture: "x86_64"}
	second.Images = []Image{{Digest: "sha256:" + strings.Repeat("c", 64), Name: "curl", Version: "2.0-r0", Architecture: "x86_64"}}
	second.Newest = &second.Images[0]
	second.Installed = []PackageIdentity{{Name: "curl", Version: "2.0-r0", Architecture: "x86_64"}}
	server.status.finish(&StatusDocument{Tracks: []Track{first, second}}, nil)
	w := request(server, "GET", "/images/cmd:curl/1?tab=compare&format=json&from="+first.Newest.Digest+"&to="+second.Newest.Digest, nil)
	var view ImageView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Compare.Error != "" || view.Compare.Changed != 1 {
		t.Fatalf("sibling compare: %+v", view.Compare)
	}
	roots, err := buildsRoots()
	if err != nil {
		t.Fatal(err)
	}
	root := roots[0]
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, root); err != nil {
		t.Fatal(err)
	}
	if _, err := readValidatedSPDX(build); err == nil {
		t.Fatal("symlink data builds root accepted")
	}
}

func TestDashboardErrorsAreNotRegistryAbsence(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	track := fixtureTrack()
	track.MissingFixes = []MissingFix{{IDs: []string{"CVE-2026-1234", "CVE-2026-5678"}, Advisories: []Advisory{{ID: "CVE-2026-1234", Severity: "critical"}, {ID: "CVE-2026-5678", Severity: "critical"}}}}
	server.status.finish(&StatusDocument{Tracks: []Track{track, {Package: "unreachable", Selector: "1", State: "error", Error: "registry unavailable"}}}, nil)
	w := request(server, "GET", "/?format=json&filter=not-in-registry", nil)
	var view ImagesView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Products) != 0 || view.Summary.NotInRegistry != 0 || view.Summary.MissingCritical != 1 || view.Shell.RegistryState != "error" {
		t.Fatalf("error/absence/critical state: %+v", view)
	}
	server.status.finish(&StatusDocument{Tracks: []Track{track}}, nil)
	if server.shell().RegistryState != "ready" {
		t.Fatal("successful comparison not ready")
	}
	server.status.finish(nil, context.DeadlineExceeded)
	if server.shell().RegistryState != "error" {
		t.Fatal("last error claimed successful comparison")
	}
}

func TestDashboardSPDXFromDataAndLegacyRoots(t *testing.T) {
	data, legacy := isolatedCache(t)
	inventory, durable := fixtureInventoryAt(t, data, "image-durable")
	_, old := fixtureInventoryAt(t, legacy, "image-legacy")
	inventory.Builds = append(inventory.Builds, old)
	config := goodFake()
	config.Images = encodeFixture(t, inventory)
	server, _, _ := testServer(t, config, false)
	for _, build := range []InventoryBuild{durable, old} {
		w := request(server, "GET", "/builds/"+buildID(build)+"/sbom", nil)
		sum := sha256.Sum256(w.Body.Bytes())
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/spdx+json" || hex.EncodeToString(sum[:]) != build.SPDX.SHA256 {
			t.Fatalf("%s download: %d %s", build.Workspace, w.Code, w.Body.String())
		}
	}

	// A workspace outside both roots, and SPDX evidence that crosses from one
	// root's workspace into the other's, are refused.
	_, outside := fixtureInventoryAt(t, filepath.Join(os.Getenv("HOME"), "elsewhere", "lupetto", "builds"), "image-outside")
	if _, err := readValidatedSPDX(outside); err == nil || !strings.Contains(err.Error(), "outside the Lupetto builds directories") {
		t.Fatalf("workspace outside both roots: %v", err)
	}
	crossed := old
	record, evidence := *old.Record, *old.Record.Evidence
	record.Evidence = &evidence
	crossed.Record = &record
	crossed.SPDX.Path, crossed.Record.Evidence.SPDXPath = durable.SPDX.Path, durable.SPDX.Path
	crossed.SPDX.SHA256, crossed.Record.Evidence.SPDXSHA256 = durable.SPDX.SHA256, durable.SPDX.SHA256
	if _, err := readValidatedSPDX(crossed); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("cross-root SPDX accepted: %v", err)
	}

	// A symlinked legacy root is refused without affecting the data root.
	moved := legacy + "-moved"
	if err := os.Rename(legacy, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := readValidatedSPDX(old); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked legacy root accepted: %v", err)
	}
	if _, err := readValidatedSPDX(durable); err != nil {
		t.Fatalf("data root affected by legacy symlink: %v", err)
	}

	t.Setenv("LUPETTO_DATA_DIR", "relative/data")
	if _, err := readValidatedSPDX(durable); err == nil || !strings.Contains(err.Error(), "LUPETTO_DATA_DIR must be an absolute path") {
		t.Fatalf("relative LUPETTO_DATA_DIR: %v", err)
	}
}

func TestExplorerDataDirMatchesCLIRule(t *testing.T) {
	for _, test := range []struct {
		goos string
		env  map[string]string
		want string
	}{
		{"linux", map[string]string{"LUPETTO_DATA_DIR": "/srv/data/", "XDG_DATA_HOME": "/xdg"}, "/srv/data"},
		{"darwin", map[string]string{"HOME": "/Users/u", "XDG_DATA_HOME": "/ignored"}, "/Users/u/Library/Application Support"},
		{"windows", map[string]string{"LocalAppData": "/appdata"}, "/appdata"},
		{"linux", map[string]string{"XDG_DATA_HOME": "/xdg", "HOME": "/home/u"}, "/xdg"},
		{"linux", map[string]string{"XDG_DATA_HOME": "relative", "HOME": "/home/u"}, "/home/u/.local/share"},
	} {
		got, err := dataDir(test.goos, func(key string) string { return test.env[key] })
		if err != nil || got != test.want {
			t.Fatalf("%s %v: %q %v; want %q", test.goos, test.env, got, err, test.want)
		}
	}
	for _, env := range []map[string]string{{"LUPETTO_DATA_DIR": "data", "HOME": "/home/u"}, {"HOME": "relative"}, {}} {
		if got, err := dataDir("linux", func(key string) string { return env[key] }); err == nil {
			t.Fatalf("%v accepted: %q", env, got)
		}
	}
}

func TestDashboardSPDXRejectsFIFO(t *testing.T) {
	isolatedCache(t)
	_, build := fixtureInventory(t)
	fifo := filepath.Join(build.Workspace, "fifo.spdx.json")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	build.SPDX.Path = fifo
	build.Record.Evidence.SPDXPath = fifo
	if _, err := readValidatedSPDX(build); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO must be rejected without opening or reading it: %v", err)
	}
}

func TestDashboardUnreadableInventoryTimestamp(t *testing.T) {
	config := goodFake()
	config.Images = `{"kind":"images","version":1,"builds":[{"workspace":"/unknown","recordPath":"/unknown/result.json","recordVersion":0,"status":"unreadable","error":"permission denied","recordedAt":""},{"recordPath":"/known/result.json","status":"unsupported","recordVersion":5,"recordedAt":"2026-10-01T00:00:00Z"}],"docker":{"available":true,"images":[{"id":"sha256:known","tags":[]}]}}`
	binary, _, _ := fakeCLI(t, config)
	cli, err := NewCLI(binary)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := cli.Images(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Builds) != 2 || !inventory.Builds[0].RecordedAt.IsZero() || inventory.Builds[1].RecordedAt.IsZero() || len(inventory.Docker.Images) != 1 {
		t.Fatalf("lost inventory: %+v", inventory)
	}
	item := buildItem(inventory.Builds[0])
	if item.State != "unreadable" || item.Error != "permission denied" || !item.StartedAt.IsZero() {
		t.Fatalf("unreadable history item: %+v", item)
	}
}

func TestDashboardRecordFailureStageMapping(t *testing.T) {
	for _, test := range []struct {
		stage  string
		failed int
	}{{"cosign-version", 5}, {"publication", 4}, {"future-unknown-stage", -1}, {"record", -1}} {
		stages := buildStages(&BuildRecord{Failure: &RecordFailure{Stage: test.stage}}, false)
		for i, stage := range stages {
			if (stage.Status == "failed") != (i == test.failed) {
				t.Fatalf("failure %s: %+v", test.stage, stages)
			}
		}
	}
}

func TestDashboardSharedReadsDoNotBlockShellOrPoisonCache(t *testing.T) {
	config := goodFake()
	config.ImagesDelay = 600
	config.InspectDelay = 600
	reference := "127.0.0.1:5000/team/curl@sha256:" + strings.Repeat("a", 64)
	config.Inspect = encodeFixture(t, InspectDocument{Kind: "inspect", Version: 1, Reference: reference, Digest: "sha256:" + strings.Repeat("a", 64), Packages: []PackageIdentity{{Name: "curl", Version: "1-r0", Architecture: "x86_64"}}})
	server, _, calls := testServer(t, config, false)
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan InventoryView, 1)
	go func() { first <- server.inventory(requestCtx) }()
	eventually(t, func() bool { data, _ := os.ReadFile(calls); return strings.Contains(string(data), "images|") })
	assertShellFast := func() {
		t.Helper()
		done := make(chan ShellView, 1)
		go func() { done <- server.shell() }()
		select {
		case <-done:
		case <-time.After(250 * time.Millisecond):
			t.Fatal("shell blocked on shared CLI read")
		}
	}
	assertShellFast()
	second := make(chan InventoryView, 1)
	go func() { second <- server.inventory(context.Background()) }()
	cancel()
	select {
	case view := <-first:
		if !strings.Contains(view.Error, "canceled") {
			t.Fatalf("caller cancellation: %+v", view)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnected inventory caller blocked")
	}
	select {
	case view := <-second:
		if view.Document == nil || view.Error != "" {
			t.Fatalf("client cancellation poisoned shared inventory: %+v", view)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inventory refresh stalled")
	}
	if view := server.inventory(context.Background()); view.Document == nil || view.Error != "" {
		t.Fatal("bad cached inventory")
	}
	type inspectResult struct {
		document *InspectDocument
		err      error
	}
	one := make(chan inspectResult, 1)
	two := make(chan inspectResult, 1)
	go func() { d, err := server.inspect(context.Background(), reference); one <- inspectResult{d, err} }()
	eventually(t, func() bool { data, _ := os.ReadFile(calls); return strings.Contains(string(data), "inspect|") })
	assertShellFast()
	// The inventory snapshot must remain immediately usable during inspect.
	if view := server.inventory(context.Background()); view.Document == nil {
		t.Fatal("inspect blocked or hid inventory")
	}
	go func() { d, err := server.inspect(context.Background(), reference); two <- inspectResult{d, err} }()
	for _, channel := range []chan inspectResult{one, two} {
		select {
		case result := <-channel:
			if result.err != nil || result.document == nil {
				t.Fatalf("inspect: %+v", result)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("inspect refresh stalled")
		}
	}
	data, _ := os.ReadFile(calls)
	if strings.Count(string(data), "images|") != 1 || strings.Count(string(data), "inspect|") != 1 {
		t.Fatalf("reads not single-flight: %s", data)
	}
}

func TestDashboardInventoryInvalidationDuringSharedRead(t *testing.T) {
	config := goodFake()
	config.ImagesDelay = 200
	server, _, calls := testServer(t, config, false)
	done := make(chan InventoryView, 1)
	go func() { done <- server.inventory(context.Background()) }()
	eventually(t, func() bool { data, _ := os.ReadFile(calls); return strings.Contains(string(data), "images|") })
	server.invalidateInventory()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shared read stalled")
	}
	server.dashboard.mu.Lock()
	fresh := !server.dashboard.inventoryAt.IsZero()
	server.dashboard.mu.Unlock()
	if fresh {
		t.Fatal("in-flight old inventory became fresh after invalidation")
	}
	if view := server.inventory(context.Background()); view.Document == nil {
		t.Fatal("replacement inventory read failed")
	}
	data, _ := os.ReadFile(calls)
	if strings.Count(string(data), "images|") != 2 {
		t.Fatalf("did not refresh after invalidation: %s", data)
	}
}

func TestDashboardCloseCancelsSharedInventoryRead(t *testing.T) {
	config := goodFake()
	config.ImagesDelay = 5000
	server, _, calls := testServer(t, config, false)
	done := make(chan InventoryView, 1)
	go func() { done <- server.inventory(context.Background()) }()
	eventually(t, func() bool { data, _ := os.ReadFile(calls); return strings.Contains(string(data), "images|") })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case view := <-done:
		if view.Error == "" {
			t.Fatal("shutdown returned successful shared read")
		}
	case <-ctx.Done():
		t.Fatal("shared read survived Close")
	}
}

func TestDashboardProductsMutationsSerialized(t *testing.T) {
	config := goodFake()
	config.ProductsDelay = 150
	config.ProductsGuard = filepath.Join(t.TempDir(), "mutation.lock")
	server, _, _ := testServer(t, config, false)
	start := make(chan struct{})
	results := make(chan int, 2)
	for _, name := range []string{"curl", "openssl"} {
		go func() {
			<-start
			w := request(server, "POST", "/products/add", url.Values{"csrfToken": {server.token}, "package": {name}, "selector": {"1"}})
			results <- w.Code
		}()
	}
	close(start)
	for range 2 {
		select {
		case code := <-results:
			if code != http.StatusSeeOther {
				t.Fatalf("overlapping mutation rejected/lost: HTTP%d", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("serialized products edit stalled")
		}
	}
}

func TestDashboardPublishLoadDecisionAndArgs(t *testing.T) {
	for _, test := range []struct {
		name      string
		inventory InventoryView
		load      bool
		reason    string
	}{
		{"available", InventoryView{Document: &ImagesDocument{Docker: DockerInventory{Available: true}}}, true, ""},
		{"unavailable", InventoryView{Document: &ImagesDocument{Docker: DockerInventory{Reason: "Docker daemon unreachable"}}}, false, "Docker daemon unreachable"},
		{"unknown", InventoryView{}, false, "Docker availability is unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("LUPETTO_REGISTRY", "127.0.0.1:5000")
			t.Setenv("LUPETTO_REPOSITORY", "tests/images")
			for _, key := range []string{"LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP", "DOCKER_HOST", "DOCKER_CONFIG"} {
				t.Setenv(key, "synthetic")
			}
			// Publish builds inherit the signing requirement unchanged.
			t.Setenv("LUPETTO_REQUIRE_SIGNING", "true")
			config := goodFake()
			record, err := parseRecord([]byte(config.Build))
			if err != nil {
				t.Fatal(err)
			}
			record.Request.Load = test.load
			if test.load {
				record.Stages.Load.Status = "loaded"
			}
			config.Build = encodeFixture(t, record)
			config.BuildDelay = 200
			config.BuildEnvironment = filepath.Join(t.TempDir(), "environment.json")
			server, _, calls := testServer(t, config, true)
			server.dashboard.inventory = test.inventory
			shell := server.shell()
			if shell.PublishLoad != test.load || shell.PublishLoadReason != test.reason {
				t.Fatalf("shell decision: %+v", shell)
			}
			if test.name == "unknown" && shell.DockerState != "unknown" {
				t.Fatalf("unknown Docker state: %s", shell.DockerState)
			}
			form := buildForm(server)
			form.Set("mode", "publish")
			// Client fields must not override the inventory-derived decision.
			form.Set("load", "true")
			form.Set("loadReason", "caller input")
			if w := request(server, "POST", "/builds", form); w.Code != 303 {
				t.Fatal(w.Body.String())
			}
			view, _, ok := server.jobs.detail("1", 0)
			if !ok || view.Request.Load != test.load || view.Request.LoadReason != test.reason {
				t.Fatalf("job decision: %+v", view)
			}
			if got := view.Progress[3].Status; (got == "skipped") == test.load {
				t.Fatalf("running load status: %s", got)
			}
			// A later inventory update must not alter a running job's decision.
			server.dashboard.mu.Lock()
			server.dashboard.inventory = InventoryView{Document: &ImagesDocument{Docker: DockerInventory{Available: !test.load}}}
			server.dashboard.mu.Unlock()
			view, _, _ = server.jobs.detail("1", 0)
			if view.Request.Load != test.load {
				t.Fatal("inventory update changed the job's decision")
			}
			eventually(t, func() bool { _, running := server.jobs.list(); return !running })
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "images|") {
				t.Fatalf("POST refreshed inventory instead of reading its snapshot: %s", data)
			}
			argv := "build|cmd:curl|1.2|"
			if !test.load {
				argv += "--no-load|"
			}
			if !strings.Contains(string(data), argv+"--json\n") {
				t.Fatalf("argv: %s", data)
			}
			data, err = os.ReadFile(config.BuildEnvironment)
			if err != nil {
				t.Fatal(err)
			}
			var present map[string]bool
			if err := json.Unmarshal(data, &present); err != nil {
				t.Fatal(err)
			}
			for key, available := range present {
				if !available {
					t.Errorf("publish mode suppressed %s", key)
				}
			}
			w := request(server, "GET", "/builds/1?format=json", nil)
			var detail JobDetailView
			if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Job.Request.Load != test.load || detail.Item.Load != test.load || detail.Item.LoadReason != test.reason || detail.Item.Mode != "publish" {
				t.Fatalf("JSON decision: %+v", detail)
			}
		})
	}
}

func TestDashboardPublishLoadRunningStagesAndRecords(t *testing.T) {
	job := JobView{State: "running", Request: BuildRequest{Mode: "publish", Load: true}}
	if item := liveItem(job); item.Stages[3].Status != "pending" || item.Stages[4].Status != "pending" {
		t.Fatalf("publish+load pending stages: %+v", item.Stages)
	}
	for _, test := range []struct {
		log    string
		status string
	}{
		{"lupetto: Loading image into Docker", "running"},
		{"lupetto: Pushing OCI image to registry", "completed"},
	} {
		job.Progress = liveStages(test.log, job.Request)
		if item := liveItem(job); item.Stages[3].Status != test.status {
			t.Fatalf("publish+load stages: %+v", item.Stages)
		}
	}
	if stages := liveStages("lupetto: Loading image into Docker", BuildRequest{Mode: "publish"}); stages[3].Status != "skipped" {
		t.Fatalf("log marker overrode the stored no-load decision: %+v", stages)
	}
	record, err := parseRecord([]byte(`{"version":6,"command":"build","outcome":"succeeded","request":{"package":"busybox-static","selector":"1","load":true,"publish":true,"sign":true},"selection":{"package":"busybox-static","version":"1.38.0-r2","architecture":"x86_64"},"evidence":{"spdxValidated":true},"stages":{"build":{"status":"completed"},"load":{"status":"loaded","dockerImageID":"sha256:local"},"publication":{"status":"published","verified":true,"immutableReference":"127.0.0.1:5000/tests/busybox-static@sha256:remote"},"signing":{"status":"signed"},"attestation":{"status":"attested"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !record.Request.Load || !record.Request.Publish || !record.Request.Sign || record.Stages.Load.DockerImageID != "sha256:local" || !record.Stages.Publication.Verified {
		t.Fatalf("load+publish+sign record: %+v", record)
	}
	// Finished records override live progress, including a differing request.
	job.State, job.Record = "succeeded", record
	job.Request.Load = false
	item := liveItem(job)
	want := []string{"completed", "completed", "completed", "loaded", "published", "signed", "attested"}
	for i, stage := range item.Stages {
		if stage.Status != want[i] {
			t.Fatalf("record stages: %+v", item.Stages)
		}
	}
	historical := buildItem(InventoryBuild{Record: record})
	if !historical.Load || historical.Mode != "publish" {
		t.Fatalf("historical decision: %+v", historical)
	}
	record.Outcome = "failed"
	record.Failure = &RecordFailure{Stage: "Docker load"}
	record.Stages.Load.Status = "failed"
	record.Stages.Publication.Status = "not-attempted"
	job.State = "failed"
	item = liveItem(job)
	if item.Stages[3].Status != "failed" || item.Stages[4].Status != "not-attempted" {
		t.Fatalf("load failure mislabeled as publication: %+v", item.Stages)
	}
}

func TestDashboardPublishLoadInvalidatesInventory(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "127.0.0.1:5000")
	t.Setenv("LUPETTO_REPOSITORY", "tests/images")
	config := goodFake()
	record, err := parseRecord([]byte(config.Build))
	if err != nil {
		t.Fatal(err)
	}
	record.Request.Load = true
	record.Stages.Load.Status = "loaded"
	config.Build = encodeFixture(t, record)
	config.Images = `{"kind":"images","version":1,"builds":[],"docker":{"available":true,"images":[]}}`
	server, update, calls := testServer(t, config, true)
	if view := server.inventory(context.Background()); view.Document == nil || !view.Document.Docker.Available {
		t.Fatal("initial inventory unavailable")
	}
	form := buildForm(server)
	form.Set("mode", "publish")
	if w := request(server, "POST", "/builds", form); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	eventually(t, func() bool {
		server.dashboard.mu.Lock()
		defer server.dashboard.mu.Unlock()
		return server.dashboard.inventoryGeneration > 0 && server.dashboard.inventoryAt.IsZero()
	})
	config.Images = `{"kind":"images","version":1,"builds":[],"docker":{"available":true,"images":[{"id":"sha256:new","tags":["lupetto/busybox-static:1.38.0-r2-amd64"]}]}}`
	update(config)
	view := server.inventory(context.Background())
	if view.Document == nil || len(view.Document.Docker.Images) != 1 || view.Document.Docker.Images[0].ID != "sha256:new" {
		t.Fatalf("newly loaded image absent after invalidation: %+v", view)
	}
	data, _ := os.ReadFile(calls)
	if strings.Count(string(data), "images|") != 2 {
		t.Fatalf("inventory not re-read: %s", data)
	}
}
