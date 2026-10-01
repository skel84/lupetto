package explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeConfig struct {
	Status           string
	Discover         string
	Build            string
	Images           string
	Inspect          string
	Products         string
	ProductsExit     int
	BuildEnvironment string
	StatusExit       int
	BuildExit        int
	StatusDelay      int
	DiscoverDelay    int
	BuildDelay       int
	ImagesDelay      int
	InspectDelay     int
	ProductsDelay    int
	ProductsGuard    string
	LogBytes         int
	OutputBytes      int
	IgnoreTERM       bool
	Calls            string
}

const goodStatus = `{"kind":"status","version":2,"computedAt":"2026-10-01T00:00:00Z","security":{"severity":{"idCount":1,"resolvedCount":1,"sourceCounts":{"nvd-cvss-v3.1":1}}},"tracks":[{"package":"cmd:curl","selector":"1","state":"current","outdated":[{"name":"dep"}],"missingFixes":[{"reachableByTrack":true,"maxSeverity":"high","advisories":[{"id":"CVE-2026-1234","severity":"high","severitySource":"nvd-cvss-v3.1"}]},{"reachableByTrack":false}],"unevaluatedFixes":[{"name":"dep","fixedVersion":"invalid"}]}]}`
const goodDiscover = `{"kind":"discover","version":1,"architecture":"x86_64","indexSHA256":"fixture","packages":[{"name":"busybox-static","version":"1.38.0-r2","description":"synthetic"}]}`
const goodRecord = `{"version":6,"command":"build","outcome":"succeeded","request":{"package":"busybox-static","selector":"1","load":false,"publish":true},"selection":{"package":"busybox-static","version":"1.38.0-r2","architecture":"x86_64"},"evidence":{"imageDigest":"sha256:fixture"},"stages":{"build":{"status":"completed"},"load":{"status":"skipped"},"publication":{"status":"published","digest":"sha256:fixture","verified":true},"signing":{"status":"skipped"},"attestation":{"status":"skipped"}}}`

// Executed in a subprocess, not an argument-echo substitute for real smoke.
func TestCLIHelper(t *testing.T) {
	path := os.Getenv("EXPLORER_TEST_FIXTURE")
	if path == "" {
		return
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i + 1
			break
		}
	}
	if separator == 0 {
		return
	}
	args := os.Args[separator:]
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(3)
	}
	var config fakeConfig
	if json.Unmarshal(data, &config) != nil {
		os.Exit(3)
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	if config.Calls != "" {
		file, err := os.OpenFile(config.Calls, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(3)
		}
		_, _ = fmt.Fprintln(file, strings.Join(args, "|"))
		_ = file.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if config.IgnoreTERM {
		stop()
		ctx = context.Background()
		signal.Ignore(syscall.SIGTERM)
	}
	pause := func(milliseconds int) bool {
		select {
		case <-time.After(time.Duration(milliseconds) * time.Millisecond):
			return true
		case <-ctx.Done():
			return false
		}
	}
	if config.OutputBytes > 0 {
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", config.OutputBytes))
		os.Exit(0)
	}
	switch args[0] {
	case "status":
		if !pause(config.StatusDelay) {
			os.Exit(1)
		}
		if config.StatusExit != 0 {
			_, _ = fmt.Fprint(os.Stderr, strings.Repeat("e", maxErrorBytes+50))
			os.Exit(config.StatusExit)
		}
		_, _ = fmt.Fprint(os.Stdout, config.Status)
	case "discover":
		if !pause(config.DiscoverDelay) {
			os.Exit(1)
		}
		_, _ = fmt.Fprint(os.Stdout, config.Discover)
	case "images":
		if !pause(config.ImagesDelay) {
			os.Exit(1)
		}
		_, _ = fmt.Fprint(os.Stdout, config.Images)
	case "inspect":
		if !pause(config.InspectDelay) {
			os.Exit(1)
		}
		_, _ = fmt.Fprint(os.Stdout, config.Inspect)
	case "products":
		if config.ProductsExit != 0 {
			_, _ = fmt.Fprint(os.Stderr, "products file is read-only")
			os.Exit(config.ProductsExit)
		}
		if len(args) > 1 && args[1] != "list" {
			if config.ProductsGuard != "" {
				guard, err := os.OpenFile(config.ProductsGuard, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					_, _ = fmt.Fprint(os.Stderr, "concurrent products mutation")
					os.Exit(1)
				}
				_ = guard.Close()
			}
			completed := pause(config.ProductsDelay)
			if config.ProductsGuard != "" {
				_ = os.Remove(config.ProductsGuard)
			}
			if !completed {
				os.Exit(1)
			}
		}
		_, _ = fmt.Fprint(os.Stdout, config.Products)
	case "build":
		if config.BuildEnvironment != "" {
			present := map[string]bool{}
			for _, key := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP", "DOCKER_HOST", "DOCKER_CONFIG"} {
				_, present[key] = os.LookupEnv(key)
			}
			data, _ := json.Marshal(present)
			if os.WriteFile(config.BuildEnvironment, data, 0600) != nil {
				os.Exit(3)
			}
		}
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("x", config.LogBytes)+"live stderr tail\n")
		if !pause(config.BuildDelay) {
			_, _ = fmt.Fprint(os.Stdout, `{"version":6,"command":"build","outcome":"failed","failure":{"stage":"build","error":"context canceled","sideEffectsPossible":true}}`)
			os.Exit(1)
		}
		_, _ = fmt.Fprint(os.Stdout, config.Build)
		os.Exit(config.BuildExit)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}
func fakeCLI(t *testing.T, config fakeConfig) (string, func(fakeConfig), string) {
	t.Helper()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "fixture.json")
	calls := filepath.Join(dir, "calls")
	update := func(config fakeConfig) {
		config.Calls = calls
		data, _ := json.Marshal(config)
		if err := os.WriteFile(fixture+".next", data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(fixture+".next", fixture); err != nil {
			t.Fatal(err)
		}
	}
	update(config)
	t.Setenv("EXPLORER_TEST_FIXTURE", fixture)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "lupetto")
	// Shell executes the test binary only; CLI invocation itself is always argv.
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec '"+strings.ReplaceAll(binary, "'", "'\\''")+"' -test.run=^TestCLIHelper$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return wrapper, update, calls
}
func goodFake() fakeConfig {
	return fakeConfig{Status: goodStatus, Discover: goodDiscover, Build: goodRecord, Images: `{"kind":"images","version":1,"builds":[],"docker":{"available":false,"reason":"Docker unavailable","images":[]}}`, Products: `{"kind":"products","version":1,"products":[{"package":"cmd:curl","selectors":["1"]}],"changed":false,"message":"synthetic"}`}
}
func testServer(t *testing.T, config fakeConfig, builds bool) (*Server, func(fakeConfig), string) {
	t.Helper()
	binary, update, calls := fakeCLI(t, config)
	options := DefaultConfig()
	options.Products = "products.yaml"
	options.LupettoBinary = binary
	options.EnableBuilds = builds
	server, err := New(options)
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
	return server, update, calls
}
func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
func request(server *Server, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, body)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://127.0.0.1:8080")
	}
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	return w
}
func buildForm(server *Server) url.Values {
	return url.Values{"csrfToken": {server.token}, "package": {"cmd:curl"}, "selector": {"1.2"}}
}

func TestCompatibilityAndRecordParsing(t *testing.T) {
	for _, test := range []struct{ name, status, discover string }{
		{"status-version", `{"kind":"status","version":1}`, goodDiscover},
		{"status-kind", `{"kind":"discover","version":1}`, goodDiscover},
		{"discover-version", goodStatus, `{"kind":"discover","version":2}`},
		{"discover-kind", goodStatus, `{"kind":"status","version":1}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary, _, _ := fakeCLI(t, fakeConfig{Status: test.status, Discover: test.discover})
			cli, err := NewCLI(binary)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(test.name, "status") {
				_, err = cli.Status(context.Background(), "p")
			} else {
				_, err = cli.Discover(context.Background(), "")
			}
			if err == nil || !strings.Contains(err.Error(), "incompatible lupetto CLI") {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, data := range []string{`{"version":5}`, `{"kind":"status","version":6}`, goodRecord + goodRecord, `{"version":6,"command":"sbom","outcome":"succeeded"}`, `not json`} {
		if _, err := parseRecord([]byte(data)); err == nil {
			t.Errorf("accepted incompatible record: %s", data)
		}
	}
	record, err := parseRecord([]byte(goodRecord))
	if err != nil {
		t.Fatal(err)
	}
	if record.Selection.Package != "busybox-static" || record.Evidence.ImageDigest != "sha256:fixture" || record.Stages.Publication.Status != "published" || !record.Request.Publish {
		t.Fatalf("record = %#v", record)
	}
}

func TestStatusVersionTwoSeverityDecoding(t *testing.T) {
	binary, _, _ := fakeCLI(t, goodFake())
	cli, err := NewCLI(binary)
	if err != nil {
		t.Fatal(err)
	}
	document, err := cli.Status(context.Background(), "products.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fix := document.Tracks[0].MissingFixes[0]
	if document.Version != 2 || document.Security.Severity.ResolvedCount != 1 || fix.MaxSeverity != "high" || len(fix.Advisories) != 1 || fix.Advisories[0].SeveritySource != "nvd-cvss-v3.1" {
		t.Fatalf("severity facts lost: %+v", document)
	}
}
func TestStatusCacheSingleFlightAndLastGood(t *testing.T) {
	config := goodFake()
	config.StatusDelay = 150
	server, update, calls := testServer(t, config, false)
	if !server.RefreshStatus() || server.RefreshStatus() {
		t.Fatal("refresh was not single-flight")
	}
	eventually(t, func() bool { return !server.status.snapshot().Refreshing })
	view := server.status.snapshot()
	if view.Document == nil || view.LastError != "" {
		t.Fatalf("view = %#v", view)
	}
	data, _ := os.ReadFile(calls)
	if strings.Count(string(data), "status|") != 1 {
		t.Fatalf("calls: %s", data)
	}
	config.StatusExit = 1
	config.StatusDelay = 0
	update(config)
	server.RefreshStatus()
	eventually(t, func() bool { return !server.status.snapshot().Refreshing })
	view = server.status.snapshot()
	if view.Document == nil || !strings.Contains(view.LastError, "stderr truncated") || len(view.LastError) > maxErrorBytes+150 {
		t.Fatalf("bad last-good/error (length %d)", len(view.LastError))
	}
	config.StatusExit = 0
	update(config)
	server.RefreshStatus()
	eventually(t, func() bool { v := server.status.snapshot(); return !v.Refreshing && v.LastError == "" })
}
func TestStartupIntervalAndPostBuildRefresh(t *testing.T) {
	server, _, calls := testServer(t, goodFake(), true)
	server.config.RefreshInterval = 40 * time.Millisecond
	server.Start()
	server.Start()
	eventually(t, func() bool {
		data, _ := os.ReadFile(calls)
		return strings.Count(string(data), "status|") >= 2 && strings.Contains(string(data), "discover|--json")
	})
	if _, err := server.jobs.start(BuildRequest{Package: "busybox-static", Selector: "1"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { views, active := server.jobs.list(); return len(views) == 1 && !active })
}
func TestBuildFinishQueuesFreshStatusWhenRefreshActive(t *testing.T) {
	config := goodFake()
	config.StatusDelay = 200
	server, _, calls := testServer(t, config, true)
	server.RefreshStatus()
	if _, err := server.jobs.start(BuildRequest{Package: "busybox-static", Selector: "1"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { data, _ := os.ReadFile(calls); return strings.Count(string(data), "status|") == 2 })
	eventually(t, func() bool { return !server.status.snapshot().Refreshing })
}
func TestBuildValidation(t *testing.T) {
	for _, request := range []BuildRequest{
		{Package: "-x", Selector: "1"}, {Package: "a;touch", Selector: "1"}, {Package: "a/b", Selector: "1"}, {Package: "cmd:", Selector: "1"},
		{Package: "a", Selector: "1.2x"}, {Package: "a", Selector: "-1"}, {Package: "a"}, {Package: "a", APKVersion: "1.2"}, {Package: "a", APKVersion: "-r1"}, {Package: "a", Selector: "1", APKVersion: "1-r1"},
	} {
		if ValidateBuild(request) == nil {
			t.Errorf("accepted %#v", request)
		}
	}
	for _, request := range []BuildRequest{{Package: "cmd:curl", Selector: "1.2"}, {Package: "libstdc++", APKVersion: "14.2.0-r4"}, {Package: "name._-+", Selector: "1"}} {
		if err := ValidateBuild(request); err != nil {
			t.Errorf("rejected %#v: %v", request, err)
		}
	}
}
func TestHTTPBuildDisabledAndConcurrentAndArgs(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		server, _, _ := testServer(t, goodFake(), false)
		w := request(server, "POST", "/builds", buildForm(server))
		if w.Code != 403 {
			t.Fatalf("code = %d", w.Code)
		}
		w = request(server, "GET", "/?format=json", nil)
		if !strings.Contains(w.Body.String(), `"buildsEnabled":false`) {
			t.Fatal(w.Body.String())
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		config := goodFake()
		config.BuildDelay = 250
		server, _, calls := testServer(t, config, true)
		w := request(server, "POST", "/builds", buildForm(server))
		if w.Code != 303 || w.Header().Get("Location") != "/builds/1" {
			t.Fatalf("response = %d %s", w.Code, w.Body.String())
		}
		w = request(server, "POST", "/builds", buildForm(server))
		if w.Code != 409 || !strings.Contains(w.Body.String(), "already running") {
			t.Fatalf("response = %d %s", w.Code, w.Body.String())
		}
		eventually(t, func() bool { _, log, ok := server.jobs.detail("1", 0); return ok && log.Done })
		view, _, _ := server.jobs.detail("1", 0)
		if view.State != "succeeded" || view.ExitCode == nil || *view.ExitCode != 0 || view.Record == nil {
			t.Fatalf("job = %#v", view)
		}
		data, _ := os.ReadFile(calls)
		if !strings.Contains(string(data), "build|cmd:curl|1.2|--no-load|--json\n") {
			t.Fatal(string(data))
		}
		form := buildForm(server)
		form.Del("selector")
		form.Set("apkVersion", "1.2-r3")
		w = request(server, "POST", "/builds", form)
		if w.Code != 303 {
			t.Fatal(w.Body.String())
		}
		eventually(t, func() bool { _, log, _ := server.jobs.detail("2", 0); return log.Done })
		data, _ = os.ReadFile(calls)
		if !strings.Contains(string(data), "build|cmd:curl|--apk-version|1.2-r3|--no-load|--json\n") {
			t.Fatal(string(data))
		}
	})
}
func TestRequestSafety(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), true)
	for _, route := range []string{"/builds", "/status/refresh", "/jobs/1/cancel"} {
		for _, test := range []struct {
			name, origin, site, host, token string
			method                          string
			expected                        int
		}{
			{"missing-token", "http://127.0.0.1:8080", "", "127.0.0.1:8080", "", "POST", 403},
			{"query-token", "http://127.0.0.1:8080", "", "127.0.0.1:8080", "query", "POST", 403},
			{"wrong-origin", "https://evil.invalid", "", "127.0.0.1:8080", server.token, "POST", 403},
			{"null-origin", "null", "", "127.0.0.1:8080", server.token, "POST", 403},
			// Browsers send "Origin: null" on form POSTs under no-referrer; it stays rejected.
			{"null-origin-same-origin-site", "null", "same-origin", "127.0.0.1:8080", server.token, "POST", 403},
			{"missing-origin", "", "", "127.0.0.1:8080", server.token, "POST", 403},
			{"cross-site", "http://127.0.0.1:8080", "cross-site", "127.0.0.1:8080", server.token, "POST", 403},
			{"rebind", "http://evil.invalid:8080", "same-origin", "evil.invalid:8080", server.token, "POST", 403},
			{"get", "", "", "127.0.0.1:8080", server.token, "GET", 405},
		} {
			t.Run(route+test.name, func(t *testing.T) {
				if test.name == "get" && route == "/builds" {
					test.expected = 200
				}
				form := buildForm(server)
				form.Set("csrfToken", test.token)
				target := route
				if test.token == "query" {
					target += "?csrfToken=" + server.token
					form.Del("csrfToken")
				}
				r := httptest.NewRequest(test.method, "http://127.0.0.1:8080"+target, strings.NewReader(form.Encode()))
				r.Host = test.host
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Origin", test.origin)
				r.Header.Set("Sec-Fetch-Site", test.site)
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, r)
				if w.Code != test.expected {
					t.Fatalf("response=%d %s", w.Code, w.Body.String())
				}
			})
		}
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080"} {
		if !server.hostAllowed(host) {
			t.Errorf("default host %q rejected", host)
		}
	}
	for _, host := range []string{"localhost.evil:8080", "127.0.0.1.evil:8080", "example.invalid", "192.168.1.2:8080", "127.0.0.2:8080"} {
		if server.hostAllowed(host) {
			t.Errorf("host %q allowed", host)
		}
	}
	w := request(server, "GET", "/healthz", nil)
	// same-origin (not no-referrer): under no-referrer browsers send "Origin: null" on
	// same-origin form POSTs, which authorize rejects, breaking every HTML form.
	if w.Code != 200 || w.Body.String() != "ok\n" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("health response=%#v", w)
	}
	form := buildForm(server)
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/status/refresh", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
}
func TestLiveLogsTruncationCancellationAndHistory(t *testing.T) {
	config := goodFake()
	config.LogBytes = defaultLogBytes + 100
	config.BuildDelay = 3000
	server, update, _ := testServer(t, config, true)
	if _, err := server.jobs.start(BuildRequest{Package: "busybox-static", Selector: "1"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		_, chunk, _ := server.jobs.detail("1", 0)
		return strings.Contains(chunk.Text, "live stderr tail")
	})
	w := request(server, "GET", "/jobs/1/logs?offset=0", nil)
	var chunk LogChunk
	if json.Unmarshal(w.Body.Bytes(), &chunk) != nil || !chunk.Truncated || chunk.Done || len(chunk.Text) > defaultLogBytes || chunk.Offset == 0 {
		t.Fatalf("chunk=%#v", chunk)
	}
	w = request(server, "GET", "/jobs/1/logs?offset="+strconv.FormatInt(chunk.NextOffset, 10), nil)
	if !strings.Contains(w.Body.String(), `"text":""`) {
		t.Fatal(w.Body.String())
	}
	w = request(server, "POST", "/jobs/1/cancel", url.Values{"csrfToken": {server.token}})
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	eventually(t, func() bool { view, _, _ := server.jobs.detail("1", 0); return view.State == "canceled" })
	view, _, _ := server.jobs.detail("1", 0)
	if view.Record == nil || view.Record.Outcome != "failed" || !view.CancelRequested || view.EndedAt == nil || *view.ExitCode != 1 {
		t.Fatalf("view=%#v", view)
	}
	config.BuildDelay = 0
	config.LogBytes = 0
	update(config)
	server.jobs.limit = 2
	for range 3 {
		if _, err := server.jobs.start(BuildRequest{Package: "busybox-static", Selector: "1"}); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool { _, running := server.jobs.list(); return !running })
	}
	jobs, _ := server.jobs.list()
	if len(jobs) != 2 || jobs[0].ID != "4" {
		t.Fatalf("jobs=%#v", jobs)
	}
	if _, _, ok := server.jobs.detail("1", 0); ok {
		t.Fatal("evicted job still present")
	}
}
func TestFailureRecordsAndEmptyInvocationOutput(t *testing.T) {
	for _, test := range []struct {
		name, record string
		exit         int
		wantRecord   bool
		wantError    string
	}{
		{"post-validation", `{"version":6,"command":"build","outcome":"failed","failure":{"stage":"publication","error":"failed","sideEffectsPossible":true},"stages":{"publication":{"status":"failed"}}}`, 1, true, "exit 1"},
		{"invocation", "", 2, false, "exit 2"},
		{"incompatible", `{"version":7,"command":"build","outcome":"succeeded"}`, 0, false, "incompatible"},
		{"success-empty", "", 0, false, "no version-6 record"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := goodFake()
			config.Build = test.record
			config.BuildExit = test.exit
			server, _, _ := testServer(t, config, true)
			_, err := server.jobs.start(BuildRequest{Package: "a", Selector: "1"})
			if err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool { _, running := server.jobs.list(); return !running })
			view, _, _ := server.jobs.detail("1", 0)
			if view.State != "failed" || (view.Record != nil) != test.wantRecord || !strings.Contains(view.Error, test.wantError) {
				t.Fatalf("view=%#v", view)
			}
		})
	}
}
func TestShutdownAndForcedKill(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run(fmt.Sprint(ignore), func(t *testing.T) {
			config := goodFake()
			config.BuildDelay = 10000
			config.IgnoreTERM = ignore
			server, _, _ := testServer(t, config, true)
			_, err := server.jobs.start(BuildRequest{Package: "a", Selector: "1"})
			if err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				_, log, _ := server.jobs.detail("1", 0)
				return strings.Contains(log.Text, "live stderr tail")
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			if err := server.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("shutdown did not bound grace")
			}
			view, log, _ := server.jobs.detail("1", 0)
			if view.State != "canceled" || !log.Done {
				t.Fatalf("view=%#v", view)
			}
			if _, err := server.jobs.start(BuildRequest{Package: "a", Selector: "1"}); err != ErrShuttingDown {
				t.Fatalf("new job error=%v", err)
			}
			if server.RefreshStatus() {
				t.Fatal("refresh after close")
			}
		})
	}
}
func TestHTTPRunGracefulShutdown(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.config.Listen = listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	client := &http.Client{Timeout: time.Second}
	eventually(t, func() bool {
		response, err := client.Get("http://" + server.config.Listen + "/healthz")
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == 200
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not shut down")
	}
	if _, err := client.Get("http://" + server.config.Listen + "/healthz"); err == nil {
		t.Fatal("HTTP listener remained open")
	}
}
func TestViewModelsPackageBoundAndEscaping(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	server.status.finish(&StatusDocument{Tracks: []Track{{Package: "cmd:curl", Selector: "1", State: "current", Outdated: []OutdatedPackage{{Name: "dep"}}, MissingFixes: []MissingFix{{ReachableByTrack: true}, {ReachableByTrack: false}}, UnevaluatedFixes: []UnevaluatedFix{{Name: "dep"}}}}}, nil)
	w := request(server, "GET", "/?format=json", nil)
	var overview ImagesView
	if json.Unmarshal(w.Body.Bytes(), &overview) != nil || len(overview.Products) != 1 || overview.Products[0].UnreachableCount != 1 || len(overview.Products[0].Track.Outdated) != 1 || len(overview.Products[0].Track.UnevaluatedFixes) != 1 || overview.CSRFToken == "" {
		t.Fatal(w.Body.String())
	}
	w = request(server, "GET", "/tracks/cmd:curl/1?format=json", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"package":"cmd:curl"`) {
		t.Fatal(w.Body.String())
	}
	packages := make([]DiscoveredPackage, PackageResultLimit+3)
	for i := range packages {
		packages[i] = DiscoveredPackage{Name: fmt.Sprintf("pkg-%03d", i), Description: "<script>evil</script>"}
	}
	server.discovery.finish(&DiscoverDocument{Kind: "discover", Version: 1, Packages: packages}, nil)
	w = request(server, "GET", "/packages?q=pkg&format=json", nil)
	var view PackagesView
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Packages) != PackageResultLimit || view.TotalMatches != PackageResultLimit+3 || len(view.Document.Packages) != 0 {
		t.Fatal(w.Body.String())
	}
	w = request(server, "GET", "/packages?q=PKG-001&format=json", nil)
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Packages) != 1 {
		t.Fatal(w.Body.String())
	}
	server.renderer = NewTemplateRenderer(template.Must(template.New("test").Parse(`{{define "packages"}}{{range .Packages}}{{.Description}}{{end}}{{end}}`)))
	w = request(server, "GET", "/packages?q=pkg-001", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
	w = request(server, "GET", "/", nil)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "template") {
		t.Fatal(w.Body.String())
	}
	w = request(server, "GET", "/packages/busybox-static?format=json", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "1.38.0-r2") {
		t.Fatal(w.Body.String())
	}
}
func TestImportBoundary(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "lupetto/internal/explorer/...", "lupetto/cmd/lupetto-explorer")
	data, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range strings.Fields(string(data)) {
		for _, forbidden := range []string{"lupetto/internal/build", "lupetto/internal/wolfi", "lupetto/internal/status", "lupetto/internal/registry", "lupetto/cmd/lupetto"} {
			if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
				t.Errorf("Explorer imported forbidden package %s", path)
			}
		}
	}
	command = exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "lupetto/cmd/lupetto")
	data, err = command.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range strings.Fields(string(data)) {
		if strings.HasPrefix(path, "lupetto/internal/explorer") {
			t.Errorf("CLI depends on Explorer: %s", path)
		}
	}
}
func TestIngressOriginAndNoProxyHeaderTrust(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	for _, test := range []struct {
		origin string
		want   int
	}{
		{"https://127.0.0.1:8080", 303}, {"http://127.0.0.1:8080", 303},
		{"https://127.0.0.1:9090", 403}, {"https://other.invalid:8080", 403},
		{"ftp://127.0.0.1:8080", 403},
	} {
		form := url.Values{"csrfToken": {server.token}}
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/status/refresh", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-Forwarded-Host", "other.invalid:8080")
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("origin=%s code=%d body=%s", test.origin, w.Code, w.Body.String())
		}
	}
}
func TestPackageDiscoveryConcurrencyBound(t *testing.T) {
	server, _, _ := testServer(t, goodFake(), false)
	for range cap(server.discoverSlots) {
		server.discoverSlots <- struct{}{}
	}
	w := request(server, "GET", "/packages/busybox-static?format=json", nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "busy") {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
	for range cap(server.discoverSlots) {
		<-server.discoverSlots
	}
	w = request(server, "GET", "/packages/busybox-static?format=json", nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
func TestCancellationCannotUndoSuccessfulRecord(t *testing.T) {
	config := goodFake()
	config.IgnoreTERM = true
	config.BuildDelay = 150
	server, _, _ := testServer(t, config, true)
	server.cli.grace = time.Second
	if _, err := server.jobs.start(BuildRequest{Package: "a", Selector: "1"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		_, log, _ := server.jobs.detail("1", 0)
		return strings.Contains(log.Text, "live stderr tail")
	})
	_, err := server.jobs.cancelJob("1")
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { _, running := server.jobs.list(); return !running })
	view, _, _ := server.jobs.detail("1", 0)
	if view.State != "succeeded" || view.Record == nil || view.Record.Outcome != "succeeded" || !view.CancelRequested || view.Error != "" {
		t.Fatalf("view=%#v", view)
	}
}
func TestCLIOutputLimitDiagnostic(t *testing.T) {
	config := goodFake()
	config.OutputBytes = maxDocumentBytes + 1
	server, _, _ := testServer(t, config, true)
	if _, err := server.cli.Status(context.Background(), "p"); err == nil || !strings.Contains(err.Error(), "32 MiB limit") {
		t.Fatalf("status error=%v", err)
	}
	if _, err := server.cli.Discover(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "32 MiB limit") {
		t.Fatalf("discover error=%v", err)
	}
	if _, err := server.jobs.start(BuildRequest{Package: "a", Selector: "1"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { _, running := server.jobs.list(); return !running })
	view, _, _ := server.jobs.detail("1", 0)
	if view.State != "failed" || !strings.Contains(view.Error, "32 MiB limit") {
		t.Fatalf("view=%#v", view)
	}
}
