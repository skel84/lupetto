package explorer

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lupetto/internal/explorer/vulnscan"
)

const (
	vulnDigest     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	vulnDigestNext = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	vulnRepository = "registry.example.invalid/lupetto/curl"
	vulnLupetto    = vulnRepository + "@" + vulnDigest
	vulnUpstream   = "docker.io/curlimages/curl:8.17.0"
)

func vulnStatus(digest string) string {
	return `{"kind":"status","version":2,"computedAt":"2026-10-01T00:00:00Z","architecture":"x86_64","tracks":[{"package":"cmd:curl","selector":"1","state":"current","repository":"` + vulnRepository + `","newest":{"digest":"` + digest + `"},"images":[],"installed":[],"outdated":[],"missingFixes":[],"unevaluatedFixes":[]}]}`
}

const vulnProducts = `{"kind":"products","version":1,"products":[{"package":"cmd:curl","selectors":["1"],"upstream":{"1":"` + vulnUpstream + `"}}],"changed":false,"message":"synthetic"}`

var vulnDB = vulnscan.DBInfo{Built: time.Date(2026, 10, 22, 4, 0, 0, 0, time.UTC), Schema: "v6.1.4"}

// fakeScanEngine returns canned findings per reference, or failures.
type fakeScanEngine struct {
	mu        sync.Mutex
	findings  map[string][]vulnscan.Finding
	scanErr   error
	updateErr error
	openErr   error
	block     bool
	opens     []bool
	scans     []string
	open      int
}

func (e *fakeScanEngine) Open(update bool) (scanSession, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opens = append(e.opens, update)
	if update && e.updateErr != nil {
		return nil, e.updateErr
	}
	if e.openErr != nil {
		return nil, e.openErr
	}
	e.open++
	return fakeScanSession{e}, nil
}

func (e *fakeScanEngine) set(change func(*fakeScanEngine)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	change(e)
}

func (e *fakeScanEngine) scanned() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.scans...)
}

type fakeScanSession struct{ engine *fakeScanEngine }

func (s fakeScanSession) Database() vulnscan.DBInfo { return vulnDB }
func (s fakeScanSession) Close() error {
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	s.engine.open--
	return nil
}
func (s fakeScanSession) Scan(ctx context.Context, reference, platform string) (vulnscan.Scan, error) {
	e := s.engine
	e.mu.Lock()
	e.scans = append(e.scans, reference+" "+platform)
	block, err, findings := e.block, e.scanErr, e.findings[reference]
	e.mu.Unlock()
	if block {
		<-ctx.Done()
		return vulnscan.Scan{}, ctx.Err()
	}
	if err != nil {
		return vulnscan.Scan{}, err
	}
	issues, counts := vulnscan.Summarize(findings)
	return vulnscan.Scan{Image: vulnscan.ImageInfo{Reference: reference, Digest: vulnDigest, Platform: platform}, ScannedAt: time.Now().UTC(), DB: vulnDB, Counts: counts, Issues: issues}, nil
}

func finding(id, severity, pkg string, related ...string) vulnscan.Finding {
	f := vulnscan.Finding{ID: id, Severity: severity, Package: vulnscan.Package{Name: pkg, Version: "1.0", Type: "apk"}, FixState: "fixed", FixVersions: []string{"1.1"}}
	for _, r := range related {
		f.Related = append(f.Related, vulnscan.Related{ID: r, Severity: severity})
	}
	return f
}

func defaultFindings() map[string][]vulnscan.Finding {
	return map[string][]vulnscan.Finding{
		vulnLupetto: {finding("CVE-2026-0001", "high", "libcurl")},
		vulnUpstream: {
			// A GHSA and its CVE are one issue, however many packages.
			finding("GHSA-aaaa-bbbb-cccc", "critical", "openssl", "CVE-2026-0002"),
			finding("CVE-2026-0002", "high", "libssl"),
			finding("CVE-2026-0001", "high", "libcurl"),
			finding("CVE-2026-0003", "low", "zlib"),
		},
	}
}

type vulnFixture struct {
	server  *Server
	engine  *fakeScanEngine
	update  func(fakeConfig)
	results string
}

func vulnServer(t *testing.T, engine *fakeScanEngine) vulnFixture {
	t.Helper()
	fake := goodFake()
	fake.Status, fake.Products = vulnStatus(vulnDigest), vulnProducts
	binary, update, _ := fakeCLI(t, fake)
	dir := t.TempDir()
	config := DefaultConfig()
	config.Products = "products.yaml"
	config.LupettoBinary = binary
	config.ScanInterval = time.Hour
	config.ScanResults = filepath.Join(dir, "vulnerabilities.json")
	config.ScanCache = filepath.Join(dir, "cache")
	config.scanEngine = engine
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	server.cli.grace = 100 * time.Millisecond
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return vulnFixture{server, engine, func(c fakeConfig) {
		c.Products = vulnProducts
		update(c)
	}, config.ScanResults}
}

func (f vulnFixture) side(source string) *vulnscan.Side {
	state := f.server.vulns.store.Snapshot()
	track := state.Track("cmd:curl", "1")
	if track == nil {
		return nil
	}
	return track.Side(source)
}

func (f vulnFixture) idle() bool {
	f.server.vulns.mu.Lock()
	defer f.server.vulns.mu.Unlock()
	return !f.server.vulns.running
}

func (f vulnFixture) refreshed(t *testing.T) {
	t.Helper()
	if w := request(f.server, "POST", "/status/refresh", url.Values{"csrfToken": {f.server.token}}); w.Code >= 400 {
		t.Fatalf("refresh = %d %s", w.Code, w.Body)
	}
}

func get(t *testing.T, server *Server, path string, code int) string {
	t.Helper()
	w := request(server, "GET", path, nil)
	if w.Code != code {
		t.Fatalf("GET %s = %d, want %d: %s", path, w.Code, code, w.Body)
	}
	return w.Body.String()
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestVulnScanComparesBothImages(t *testing.T) {
	f := vulnServer(t, &fakeScanEngine{findings: defaultFindings()})
	f.server.Start()
	eventually(t, func() bool { return f.side("upstream") != nil && f.side("upstream").Success && f.idle() })
	if got := f.engine.scanned(); len(got) != 2 || got[0] != vulnLupetto+" linux/amd64" || got[1] != vulnUpstream+" linux/amd64" {
		t.Fatalf("scans = %q", got)
	}
	if f.engine.open != 0 {
		t.Fatal("database left open after the pass")
	}
	// Three unique upstream issues: the GHSA/CVE pair counts once, at critical.
	if c := f.side("upstream").Result.Counts; c.Critical != 1 || c.High != 1 || c.Low != 1 || c.Total != 3 {
		t.Fatalf("upstream counts = %+v", c)
	}

	body := get(t, f.server, "/vulnerabilities", 200)
	mustContain(t, body, `href="/vulnerabilities/cmd:curl/1"`, "2 fewer than upstream", "(67%)", vulnUpstream, `name="csrfToken" value="`+f.server.token+`"`, "How these counts are made")
	if strings.Contains(body, "Stale</span>") {
		t.Error("fresh result marked stale")
	}
	detail := get(t, f.server, "/vulnerabilities/cmd:curl/1", 200)
	mustContain(t, detail, "GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "openssl 1.0", "libssl 1.0", "1 issue in both images", "2 upstream issues not found", "0 Lupetto issues not found")
	get(t, f.server, "/vulnerabilities/cmd:curl/2", 404)
	images := get(t, f.server, "/", 200)
	mustContain(t, images, `<a class="vuln-link" href="/vulnerabilities/cmd:curl/1"`, "1 vs 3 upstream", `<a href="/vulnerabilities">`)

	metrics := get(t, f.server, "/metrics", 200)
	mustContain(t, metrics,
		`lupetto_vulnerabilities{package="cmd:curl",selector="1",severity="critical",source="upstream"} 1`,
		`lupetto_vulnerabilities{package="cmd:curl",selector="1",severity="high",source="lupetto"} 1`,
		`lupetto_vulnerability_scan_success{package="cmd:curl",selector="1",source="lupetto"} 1`,
		`lupetto_vulnerability_result_stale{package="cmd:curl",selector="1",source="upstream"} 0`,
		`lupetto_vulnerability_db_built_timestamp_seconds 1.7926416e+09`,
		`lupetto_track_state{package="cmd:curl",selector="1",state="current"} 1`,
		`lupetto_track_state{package="cmd:curl",selector="1",state="error"} 0`,
		`lupetto_status_timestamp_seconds 1.7908128e+09`)
	if strings.Contains(metrics, "CVE-") || strings.Contains(metrics, "sha256:") {
		t.Error("metrics expose issue IDs or digests")
	}

	// Nothing is due on the next status check, so the database stays closed.
	opens := len(f.engine.opens)
	f.refreshed(t)
	eventually(t, func() bool { return !f.server.status.snapshot().Refreshing && f.idle() })
	if len(f.engine.opens) != opens {
		t.Fatal("opened the database with nothing due")
	}
	// A new Lupetto image is scanned; the upstream result stays.
	f.update(fakeConfig{Status: vulnStatus(vulnDigestNext)})
	f.refreshed(t)
	next := vulnRepository + "@" + vulnDigestNext
	eventually(t, func() bool { s := f.side("lupetto"); return s.Reference == next && s.Success && f.idle() })
	if got := f.engine.scanned(); len(got) != 3 || got[2] != next+" linux/amd64" {
		t.Fatalf("scans = %q", got)
	}
}

func TestVulnFailedScanKeepsResultMarkedStale(t *testing.T) {
	f := vulnServer(t, &fakeScanEngine{findings: defaultFindings()})
	f.server.Start()
	eventually(t, func() bool { return f.side("upstream") != nil && f.side("upstream").Success && f.idle() })
	f.engine.set(func(e *fakeScanEngine) {
		e.scanErr = errors.New("GET https://registry.example.invalid/v2/token?scope=repository:x&secret=abc: 503")
	})
	if w := request(f.server, "POST", "/vulnerabilities/scan", url.Values{"csrfToken": {f.server.token}}); w.Code != 303 {
		t.Fatalf("rescan = %d %s", w.Code, w.Body)
	}
	eventually(t, func() bool { return !f.side("upstream").Success && f.idle() })
	side := f.side("lupetto")
	if side.Result == nil || side.Result.Counts.High != 1 {
		t.Fatalf("previous result dropped: %+v", side)
	}
	if strings.Contains(side.Error, "secret") || !strings.Contains(side.Error, "token?…") {
		t.Fatalf("error = %q", side.Error)
	}
	body := get(t, f.server, "/vulnerabilities", 200)
	mustContain(t, body, "Stale</span>", "2 fewer than upstream", "503")
	metrics := get(t, f.server, "/metrics", 200)
	mustContain(t, metrics,
		`lupetto_vulnerability_scan_success{package="cmd:curl",selector="1",source="lupetto"} 0`,
		`lupetto_vulnerability_result_stale{package="cmd:curl",selector="1",source="lupetto"} 1`,
		`lupetto_vulnerabilities{package="cmd:curl",selector="1",severity="high",source="lupetto"} 1`)

	// A failed save keeps results in memory and says so.
	if err := os.Chmod(filepath.Dir(f.results), 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Dir(f.results), 0o700)
	if w := request(f.server, "POST", "/vulnerabilities/scan", url.Values{"csrfToken": {f.server.token}}); w.Code != 303 {
		t.Fatalf("rescan = %d", w.Code)
	}
	eventually(t, func() bool { return f.idle() && f.server.vulnScanView().SaveError != "" })
	mustContain(t, get(t, f.server, "/vulnerabilities", 200), "Scan results couldn’t be saved")
	if err := os.Chmod(filepath.Dir(f.results), 0o700); err != nil {
		t.Fatal(err)
	}

	// Results survive a restart.
	store, err := vulnscan.OpenStore(f.results)
	if err != nil {
		t.Fatal(err)
	}
	stored := store.Snapshot()
	if track := stored.Track("cmd:curl", "1"); track == nil || track.Lupetto.Result == nil || track.Lupetto.Success {
		t.Fatalf("stored track = %+v", track)
	}
}

func TestVulnFailureWithoutResultIsNeverZero(t *testing.T) {
	f := vulnServer(t, &fakeScanEngine{scanErr: errors.New("image is larger than --scan-max-image-size")})
	f.server.Start()
	eventually(t, func() bool { return f.side("upstream") != nil && !f.side("upstream").LastAttempt.IsZero() && f.idle() })
	body := get(t, f.server, "/vulnerabilities", 200)
	mustContain(t, body, "No result: the scan failed", "larger than --scan-max-image-size")
	if strings.Contains(body, `data-label="Total"`) {
		t.Error("failed scans rendered as counts")
	}
	metrics := get(t, f.server, "/metrics", 200)
	mustContain(t, metrics, `lupetto_vulnerability_scan_success{package="cmd:curl",selector="1",source="upstream"} 0`)
	if strings.Contains(metrics, "lupetto_vulnerabilities{") || strings.Contains(metrics, "lupetto_vulnerability_result_stale{") {
		t.Error("metrics report counts without a successful scan")
	}
	mustContain(t, get(t, f.server, "/", 200), "– vs – upstream")
}

func TestVulnDatabaseUpdateFailure(t *testing.T) {
	t.Run("installed database", func(t *testing.T) {
		f := vulnServer(t, &fakeScanEngine{findings: defaultFindings(), updateErr: errors.New("listing: connection refused")})
		f.server.Start()
		eventually(t, func() bool { return f.side("upstream") != nil && f.side("upstream").Success && f.idle() })
		if got := f.engine.opens; len(got) != 2 || !got[0] || got[1] {
			t.Fatalf("opens = %v", got)
		}
		mustContain(t, get(t, f.server, "/vulnerabilities", 200), "couldn’t be updated", "Scans use the installed database", "connection refused")
	})
	t.Run("no database", func(t *testing.T) {
		f := vulnServer(t, &fakeScanEngine{updateErr: errors.New("listing: connection refused"), openErr: errors.New("no database installed")})
		f.server.Start()
		eventually(t, func() bool { return f.side("upstream") != nil && !f.side("upstream").LastAttempt.IsZero() && f.idle() })
		if len(f.engine.scanned()) != 0 {
			t.Fatal("scanned without a database")
		}
		for _, source := range []string{"lupetto", "upstream"} {
			if side := f.side(source); side.Success || !strings.Contains(side.Error, "vulnerability database unavailable") {
				t.Fatalf("%s = %+v", source, side)
			}
		}
		mustContain(t, get(t, f.server, "/vulnerabilities", 200), "No database is installed")
		if side := f.side("upstream"); !strings.Contains(side.Error, "no database installed") || !strings.Contains(side.Error, "connection refused") {
			t.Fatalf("error = %q", side.Error)
		}
	})
}

func TestVulnShutdownIsNotAFailedScan(t *testing.T) {
	f := vulnServer(t, &fakeScanEngine{block: true})
	f.server.Start()
	eventually(t, func() bool { return len(f.engine.scanned()) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.server.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if side := f.side("lupetto"); side != nil && !side.LastAttempt.IsZero() {
		t.Fatalf("shutdown recorded as an attempt: %+v", side)
	}
	if f.engine.open != 0 {
		t.Fatal("database left open after shutdown")
	}
}

func TestVulnRescanNeedsCSRFAndQueues(t *testing.T) {
	f := vulnServer(t, &fakeScanEngine{findings: defaultFindings()})
	if w := request(f.server, "POST", "/vulnerabilities/scan", url.Values{}); w.Code != 403 {
		t.Fatalf("rescan without token = %d", w.Code)
	}
	// Without status there is nothing to scan yet.
	if w := request(f.server, "POST", "/vulnerabilities/scan", url.Values{"csrfToken": {f.server.token}}); w.Code != 303 {
		t.Fatalf("rescan = %d", w.Code)
	}
	eventually(t, f.idle)
	if len(f.engine.opens) != 0 {
		t.Fatal("opened the database without status")
	}
	mustContain(t, get(t, f.server, "/vulnerabilities", 200), "Status hasn’t been checked yet")
}

func TestVulnScanningOff(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	server.Start()
	eventually(t, func() bool { return server.status.snapshot().Document != nil })
	get(t, server, "/vulnerabilities", 404)
	get(t, server, "/vulnerabilities/cmd:curl/1", 404)
	if w := request(server, "POST", "/vulnerabilities/scan", url.Values{"csrfToken": {server.token}}); w.Code != 503 {
		t.Fatalf("rescan = %d", w.Code)
	}
	if strings.Contains(get(t, server, "/", 200), `href="/vulnerabilities"`) {
		t.Error("navigation links to the disabled page")
	}
	metrics := get(t, server, "/metrics", 200)
	if strings.Contains(metrics, "lupetto_vulnerabilit") {
		t.Error("vulnerability metrics while scanning is off")
	}
	mustContain(t, metrics, "# TYPE lupetto_track_state gauge", "go_goroutines")
}

func TestMetricsSkipHostCheck(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	for path, code := range map[string]int{"/metrics": 200, "/healthz": 403, "/metrics/x": 403} {
		r := httptest.NewRequest("GET", "http://10.0.0.7:8080"+path, nil)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != code && !(path == "/metrics/x" && w.Code == 404) {
			t.Errorf("%s from a pod address = %d, want %d", path, w.Code, code)
		}
	}
	r := httptest.NewRequest("POST", "http://10.0.0.7:8080/metrics", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("POST /metrics from a pod address = %d", w.Code)
	}
}

func TestNewRejectsNegativeScanInterval(t *testing.T) {
	binary, _, _ := fakeCLI(t, goodFake())
	config := DefaultConfig()
	config.Products = "products.yaml"
	config.LupettoBinary = binary
	config.ScanInterval = -time.Second
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "--scan-interval") {
		t.Fatalf("err = %v", err)
	}
}

func TestVulnDelta(t *testing.T) {
	for _, test := range []struct {
		lupetto, upstream int
		want              VulnDelta
	}{
		{1, 3, VulnDelta{Total: 2, Magnitude: 2, Percent: "67%"}},
		{4, 2, VulnDelta{Total: -2, Magnitude: 2, Percent: "100%"}},
		{0, 0, VulnDelta{}},
		{3, 0, VulnDelta{Total: -3, Magnitude: 3}},
	} {
		if got := vulnDelta(vulnscan.Counts{Total: test.lupetto}, vulnscan.Counts{Total: test.upstream}); got != test.want {
			t.Errorf("delta(%d, %d) = %+v, want %+v", test.lupetto, test.upstream, got, test.want)
		}
	}
}
