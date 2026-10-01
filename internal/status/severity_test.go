package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const severityTestCVE = "CVE-2026-1234"
const severityTestGHSA = "GHSA-abcd-1234-efgh"
const severityTestGO = "GO-2026-1234"

func severityFixture(t *testing.T, handler http.HandlerFunc) (*SeverityResolver, string) {
	t.Helper()
	t.Setenv("NVD_API_KEY", "")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	directory := filepath.Join(t.TempDir(), "severity")
	return NewSeverityResolverWithOptions(SeverityResolverOptions{HTTPClient: server.Client(),
		NVDURL: server.URL + "/nvd", OSVURL: server.URL + "/osv", GitHubURL: server.URL + "/ghsa",
		CacheDirectory: directory, NVDInterval: -1}), directory
}

func severityNVDJSON(id, metrics string) string {
	return `{"vulnerabilities":[{"cve":{"id":"` + id + `","metrics":` + metrics + `}}]}`
}

func severityAssert(t *testing.T, got SeverityResult, severity, source string) {
	t.Helper()
	if got != (SeverityResult{severity, source}) {
		t.Fatalf("got %+v, want %s/%s", got, severity, source)
	}
}

func TestSeverityNVDPrecedence(t *testing.T) {
	cases := []struct{ name, metrics, severity, source string }{
		{"v4-before-v31-primary", `{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseSeverity":"LOW"}}],"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"CRITICAL"}}]}`, "low", "nvd-cvss-v4.0"},
		{"v31-primary-before-secondary", `{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseSeverity":"LOW"}},{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}],"cvssMetricV30":[{"type":"Primary","cvssData":{"baseSeverity":"CRITICAL"}}]}`, "high", "nvd-cvss-v3.1"},
		{"v4-primary", `{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseSeverity":"HIGH"}},{"type":"Primary","cvssData":{"baseSeverity":"MEDIUM"}}]}`, "medium", "nvd-cvss-v4.0"},
		{"v30-before-v2", `{"cvssMetricV30":[{"type":"Secondary","cvssData":{"baseSeverity":"MEDIUM"}}],"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH"}]}`, "medium", "nvd-cvss-v3.0"},
		{"v2-metric-field-primary", `{"cvssMetricV2":[{"type":"Secondary","baseSeverity":"LOW"},{"type":"Primary","baseSeverity":"HIGH","cvssData":{"baseSeverity":"CRITICAL"}}]}`, "high", "nvd-cvss-v2"},
		{"invalid-v4-falls-back", `{"cvssMetricV40":[{"type":"Primary","cvssData":{"baseSeverity":"untrusted-secret"}}],"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"LOW"}}]}`, "low", "nvd-cvss-v3.1"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/nvd" || req.URL.Query().Get("cveId") != severityTestCVE {
					t.Errorf("unexpected fallback %s", req.URL)
					w.WriteHeader(500)
					return
				}
				fmt.Fprint(w, severityNVDJSON(severityTestCVE, test.metrics))
			})
			severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], test.severity, test.source)
		})
	}
}

func TestSeverityCVEOFallbackAndVectorsNotGuessed(t *testing.T) {
	for _, test := range []struct{ name, nvd, osv, severity, source string }{
		{"osv-database-severity", severityNVDJSON(severityTestCVE, `{}`), `{"database_specific":{"severity":"MODERATE"}}`, "medium", "osv"},
		{"v2-wrong-field-not-used", severityNVDJSON(severityTestCVE, `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}`), `{}`, "unknown", "none"},
		{"vectors-not-guessed", severityNVDJSON(severityTestCVE, `{}`), `{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`, "unknown", "none"},
		{"mismatched-nvd-id", severityNVDJSON("CVE-2026-9999", `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}`), `{}`, "unknown", "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/nvd" {
					fmt.Fprint(w, test.nvd)
				} else {
					fmt.Fprint(w, test.osv)
				}
			})
			severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], test.severity, test.source)
		})
	}
}

func TestSeverityGroupedIDsAreIndependentAndOrdering(t *testing.T) {
	var requests []string
	resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.URL.Path+":"+req.URL.Query().Get("cveId"))
		switch req.URL.Path {
		case "/osv/" + severityTestGHSA:
			fmt.Fprint(w, `{"database_specific":{"severity":"MEDIUM"}}`)
		case "/osv/" + severityTestGO:
			fmt.Fprint(w, `{"database_specific":{"severity":"HIGH"}}`)
		case "/nvd":
			fmt.Fprint(w, severityNVDJSON(req.URL.Query().Get("cveId"), `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}`))
		default:
			t.Errorf("unexpected request %s", req.URL)
		}
	})
	groups := [][]string{{severityTestGO, severityTestGHSA, "CVE-2026-2222", severityTestCVE}, {"CVE-2026-0001"}, {"UNSUPPORTED", severityTestCVE}}
	result := resolver.Resolve(context.Background(), groups, time.Second)
	severityAssert(t, result[severityTestGHSA], "medium", "osv")
	severityAssert(t, result[severityTestGO], "unknown", "none")
	severityAssert(t, result[severityTestCVE], "high", "nvd-cvss-v3.1")
	severityAssert(t, result["UNSUPPORTED"], "unknown", "none")
	if len(result) != 6 {
		t.Fatalf("not exactly supplied IDs: %+v", result)
	}
	want := []string{"/osv/" + severityTestGHSA + ":", "/osv/" + severityTestGO + ":", "/nvd:CVE-2026-0001", "/nvd:" + severityTestCVE, "/nvd:CVE-2026-2222"}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("order %v, want %v", requests, want)
	}
	cached := NewSeverityResolverWithOptions(SeverityResolverOptions{CacheDirectory: directory})
	severityAssert(t, cached.Resolve(context.Background(), [][]string{{severityTestGHSA}}, 0)[severityTestGHSA], "medium", "osv")
}

func TestSeverityOSVAliasesAndGitHubFallback(t *testing.T) {
	cases := []struct {
		name, id, osv, cveOSV, githubBody, severity, source string
		nvdStatus                                           int
		github                                              bool
	}{
		{"ghsa-own-osv-before-alias", severityTestGHSA, `{"aliases":["CVE-2026-1234"],"database_specific":{"severity":"LOW"}}`, `{}`, `{"severity":"high"}`, "low", "osv", 200, false},
		{"ghsa-own-github-before-osv-alias", severityTestGHSA, `{"aliases":["CVE-2026-1234"]}`, `{}`, `{"severity":"medium"}`, "medium", "ghsa", 200, true},
		{"ghsa-true-osv-cve-alias", severityTestGHSA, `{"aliases":["CVE-2026-1234"]}`, `{}`, `{}`, "critical", "osv-alias:" + severityTestCVE, 200, true},
		{"ghsa-true-github-cve-alias", severityTestGHSA, `{}`, `{}`, `{"cve_id":"CVE-2026-1234"}`, "critical", "ghsa-alias:" + severityTestCVE, 200, true},
		{"go-cve-alias-does-not-inherit-osv-fallback", severityTestGO, `{"aliases":["CVE-2026-1234"],"database_specific":{"severity":"LOW"}}`, `{"database_specific":{"severity":"HIGH"}}`, `{}`, "unknown", "none", 404, false},
		{"osv-before-github", severityTestGHSA, `{"database_specific":{"severity":"MODERATE"}}`, `{}`, `{"severity":"low"}`, "medium", "osv", 200, false},
		{"github-fallback", severityTestGHSA, `{}`, `{}`, `{"severity":"low"}`, "low", "ghsa", 200, true},
		{"go-true-ghsa-alias", severityTestGO, `{"aliases":["GHSA-abcd-1234-efgh"]}`, `{}`, `{"severity":"low"}`, "low", "osv-alias:" + severityTestGHSA, 200, true},
		{"go-direct-severity-is-not-used", severityTestGO, `{"database_specific":{"severity":"HIGH"}}`, `{}`, `{}`, "unknown", "none", 200, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			githubRequests := 0
			resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.URL.Path == "/nvd":
					w.WriteHeader(test.nvdStatus)
					if test.nvdStatus == 200 {
						fmt.Fprint(w, severityNVDJSON(severityTestCVE, `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"CRITICAL"}}]}`))
					}
				case req.URL.Path == "/osv/"+severityTestCVE:
					fmt.Fprint(w, test.cveOSV)
				case req.URL.Path == "/osv/"+test.id:
					fmt.Fprint(w, test.osv)
				case req.URL.Path == "/osv/"+severityTestGHSA:
					fmt.Fprint(w, `{}`)
				case req.URL.Path == "/ghsa/"+severityTestGHSA:
					githubRequests++
					fmt.Fprint(w, test.githubBody)
				default:
					t.Errorf("unexpected request %s", req.URL)
					w.WriteHeader(500)
				}
			})
			result := resolver.Resolve(context.Background(), [][]string{{test.id}}, time.Second)
			severityAssert(t, result[test.id], test.severity, test.source)
			if len(result) != 1 {
				t.Fatalf("internal alias leaked into output: %+v", result)
			}
			if (githubRequests > 0) != test.github {
				t.Fatalf("github requests %d", githubRequests)
			}
		})
	}
}

func TestSeverityBudgetCacheOnlyAndCancellation(t *testing.T) {
	var calls atomic.Int64
	resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		<-req.Context().Done()
	})
	groups := [][]string{{severityTestCVE, severityTestGO, "unsupported"}}
	result := resolver.Resolve(context.Background(), groups, 0)
	severityAssert(t, result[severityTestCVE], "unknown", "pending")
	severityAssert(t, result[severityTestGO], "unknown", "pending")
	severityAssert(t, result["unsupported"], "unknown", "none")
	if calls.Load() != 0 {
		t.Fatal("cache-only made a request")
	}
	start := time.Now()
	result = resolver.Resolve(context.Background(), groups, 30*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("budget exceeded: %s", elapsed)
	}
	severityAssert(t, result[severityTestCVE], "unknown", "pending")
	severityAssert(t, result[severityTestGO], "unknown", "pending")
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
	files, _ := os.ReadDir(directory)
	if len(files) != 0 {
		t.Fatal("pending cached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver.Resolve(ctx, groups, time.Second)
	if calls.Load() != 1 {
		t.Fatal("cancelled context made request")
	}
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, resolver.now())
	severityAssert(t, resolver.Resolve(ctx, [][]string{{severityTestGO, severityTestCVE}}, 0)[severityTestGO], "unknown", "pending")
}

func TestSeverityCacheTTLPermissionsAndAtomicRecords(t *testing.T) {
	now := time.Date(2026, 10, 1, 1, 2, 3, 0, time.UTC)
	cache := severityCache{directory: filepath.Join(t.TempDir(), "private")}
	known := SeverityResult{"critical", "nvd-cvss-v4.0"}
	cache.store(severityTestCVE, known, now)
	cache.store(severityTestGO, unknownSeverity(), now)
	cache.store(severityTestGHSA, pendingSeverity(), now)
	info, err := os.Stat(cache.directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory permissions: %v %v", info, err)
	}
	files, err := os.ReadDir(cache.directory)
	if err != nil || len(files) != 2 {
		t.Fatalf("files %v %v", files, err)
	}
	for _, file := range files {
		info, _ := file.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatalf("file mode %v", info.Mode())
		}
		data, _ := os.ReadFile(filepath.Join(cache.directory, file.Name()))
		var record cachedSeverity
		if json.Unmarshal(data, &record) != nil || !record.FetchedAt.Equal(now) {
			t.Fatalf("invalid record: %s", data)
		}
	}
	for _, test := range []struct {
		id  string
		age time.Duration
		hit bool
	}{
		{severityTestCVE, 7*24*time.Hour - time.Nanosecond, true}, {severityTestCVE, 7 * 24 * time.Hour, false},
		{severityTestGO, time.Hour - time.Nanosecond, true}, {severityTestGO, time.Hour, false}, {severityTestCVE, -time.Second, false},
	} {
		_, hit := cache.load(test.id, now.Add(test.age))
		if hit != test.hit {
			t.Errorf("%s age %s hit=%t", test.id, test.age, hit)
		}
	}
	// Replacement remains one complete record and leaves no temporary files.
	cache.store(severityTestCVE, SeverityResult{"low", "osv"}, now.Add(time.Minute))
	got, ok := cache.load(severityTestCVE, now.Add(time.Minute))
	if !ok {
		t.Fatal("replacement unavailable")
	}
	severityAssert(t, got, "low", "osv")
	files, _ = os.ReadDir(cache.directory)
	if len(files) != 2 {
		t.Fatal("temporary files leaked")
	}
	if err := os.Chmod(cache.file(severityTestCVE), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.load(severityTestCVE, now.Add(time.Minute)); ok {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(cache.directory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.load(severityTestGO, now); ok {
		t.Fatal("public directory accepted")
	}
}

func TestSeverityCacheInvalidAndFailuresAreHarmless(t *testing.T) {
	resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, `{}`) })
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, resolver.now())
	path := resolver.cache.file(severityTestCVE)
	for _, content := range []string{`{`, strings.Repeat("x", 4097), `{"version":1,"id":"CVE-2026-1234","fetchedAt":"2026-10-01T00:00:00Z","severity":"high","severitySource":"secret-canary"}`} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, 0)[severityTestCVE], "unknown", "pending")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, ok := resolver.cache.load(severityTestCVE, resolver.now()); ok {
		t.Fatal("symlink accepted")
	}
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, resolver.now())
	data, _ := os.ReadFile(outside)
	if string(data) != "untouched" {
		t.Fatal("followed cache symlink")
	}
	// A regular file where the cache directory should be does not fail resolution.
	resolver.cache.directory = outside
	severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], "unknown", "none")
	if _, err := os.Stat(directory); err != nil {
		t.Fatal(err)
	}
}

func TestSeverityRateLimitStopsOnlyNVD(t *testing.T) {
	for _, code := range []int{403, 429} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			nvdCalls := 0
			resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/nvd" {
					nvdCalls++
					w.WriteHeader(code)
					fmt.Fprint(w, "secret-canary")
					return
				}
				if strings.HasSuffix(req.URL.Path, "2222") {
					fmt.Fprint(w, `{"database_specific":{"severity":"HIGH"}}`)
				} else {
					w.WriteHeader(404)
				}
			})
			groups := [][]string{{severityTestCVE, "CVE-2026-2222", "CVE-2026-3333"}}
			result := resolver.Resolve(context.Background(), groups, time.Second)
			severityAssert(t, result[severityTestCVE], "unknown", "pending")
			severityAssert(t, result["CVE-2026-2222"], "high", "osv")
			severityAssert(t, result["CVE-2026-3333"], "unknown", "pending")
			if nvdCalls != 1 {
				t.Fatalf("NVD calls %d", nvdCalls)
			}
			files, _ := os.ReadDir(directory)
			if len(files) != 1 {
				t.Fatalf("cached failed requests: %v", files)
			}
			data, _ := os.ReadFile(filepath.Join(directory, files[0].Name()))
			if strings.Contains(string(data), "secret-canary") {
				t.Fatal("error body retained")
			}
			resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)
			if nvdCalls != 2 {
				t.Fatal("NVD did not resume next run")
			}
		})
	}
}

func TestSeverityHTTPBoundsErrorsAndIdentity(t *testing.T) {
	for _, test := range []struct {
		name, body string
		code       int
	}{
		{"oversize", strings.Repeat("x", maxSeverityResponseBytes+1), 200}, {"malformed", `{`, 200}, {"server-error", "secret-canary", 500},
		{"mismatched-osv", `{"id":"CVE-2026-9999","database_specific":{"severity":"HIGH"}}`, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(test.code); fmt.Fprint(w, test.body) })
			severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], "unknown", "pending")
		})
	}
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(404) })
	resolver.client.Transport = severityFailingTransport{}
	severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], "unknown", "pending")
}

type severityFailingTransport struct{}

func (severityFailingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("secret transport canary")
}

func TestSeveritySpacingKeyAndRedirectSafety(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		keys = append(keys, req.Header.Get("apiKey"))
		mu.Unlock()
		fmt.Fprint(w, severityNVDJSON(req.URL.Query().Get("cveId"), `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"LOW"}}]}`))
	})
	now := time.Now()
	waits := []time.Duration{}
	resolver.now = func() time.Time { return now }
	resolver.interval = 6100 * time.Millisecond
	resolver.wait = func(ctx context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		now = now.Add(duration)
		return nil
	}
	resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)
	resolver.Resolve(context.Background(), [][]string{{"CVE-2026-2222"}}, time.Second)
	if !reflect.DeepEqual(waits, []time.Duration{6100 * time.Millisecond}) {
		t.Fatalf("spacing %v", waits)
	}
	// Cache reads do not renew fetchedAt.
	before, _ := os.ReadFile(filepath.Join(directory, filepath.Base(resolver.cache.file(severityTestCVE))))
	resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, 0)
	after, _ := os.ReadFile(resolver.cache.file(severityTestCVE))
	if string(before) != string(after) {
		t.Fatal("cache read renewed TTL")
	}
	t.Setenv("NVD_API_KEY", "synthetic-key")
	keyed := NewSeverityResolverWithOptions(SeverityResolverOptions{CacheDirectory: t.TempDir()})
	if keyed.interval != 600*time.Millisecond {
		t.Fatalf("keyed spacing %s", keyed.interval)
	}
	keyed.apiKey = ""
	keyless := NewSeverityResolverWithOptions(SeverityResolverOptions{NVDInterval: time.Nanosecond, CacheDirectory: t.TempDir()})
	if keyless.interval != 600*time.Millisecond {
		t.Fatal("production minimum overridden")
	}
	resolver.apiKey = "synthetic-key"
	resolver.Resolve(context.Background(), [][]string{{"CVE-2026-3333"}}, time.Second)
	mu.Lock()
	if keys[len(keys)-1] != "synthetic-key" {
		t.Error("NVD key header missing")
	}
	mu.Unlock()
	data, _ := os.ReadFile(resolver.cache.file("CVE-2026-3333"))
	if strings.Contains(string(data), "synthetic-key") {
		t.Fatal("key cached")
	}
	redirectCalls := 0
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { redirectCalls++; t.Error("redirect followed") }))
	defer redirect.Close()
	resolver2, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { http.Redirect(w, req, redirect.URL, http.StatusFound) })
	resolver2.apiKey = "synthetic-key"
	severityAssert(t, resolver2.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], "unknown", "pending")
	if redirectCalls != 0 {
		t.Fatal("redirect key leak")
	}
}

func TestSeverityRateWaitHonorsBudget(t *testing.T) {
	calls := 0
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/nvd" {
			w.WriteHeader(404)
			return
		}
		calls++
		fmt.Fprint(w, severityNVDJSON(req.URL.Query().Get("cveId"), `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}`))
	})
	resolver.interval = 6100 * time.Millisecond
	start := time.Now()
	result := resolver.Resolve(context.Background(), [][]string{{severityTestCVE, "CVE-2026-2222", severityTestGO}}, 30*time.Millisecond)
	severityAssert(t, result[severityTestCVE], "high", "nvd-cvss-v3.1")
	severityAssert(t, result["CVE-2026-2222"], "unknown", "pending")
	severityAssert(t, result[severityTestGO], "unknown", "none")
	if calls != 1 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("rate/budget calls=%d elapsed=%s", calls, time.Since(start))
	}
}

func TestSeverityFailureStatsResetAndBudgetExclusion(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(500) })
	resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)
	if resolver.Stats().FetchFailureCount != 2 {
		t.Fatalf("stats %+v", resolver.Stats())
	}
	resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, 0)
	if resolver.Stats().FetchFailureCount != 0 {
		t.Fatal("stats not reset")
	}
	resolver, _ = severityFixture(t, func(w http.ResponseWriter, req *http.Request) { <-req.Context().Done() })
	resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, 20*time.Millisecond)
	if resolver.Stats().FetchFailureCount != 0 {
		t.Fatal("budget cancellation reported as HTTP failure")
	}
}

func TestSeverityUnknownRefreshAndKnownCacheReuse(t *testing.T) {
	var calls atomic.Int64
	resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.URL.Path == "/nvd" {
			fmt.Fprint(w, severityNVDJSON(severityTestCVE, `{}`))
		} else {
			fmt.Fprint(w, `{}`)
		}
	})
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	resolver.now = func() time.Time { return now }
	groups := [][]string{{severityTestCVE}}
	severityAssert(t, resolver.Resolve(context.Background(), groups, time.Second)[severityTestCVE], "unknown", "none")
	if calls.Load() != 2 {
		t.Fatal("initial lookups missing")
	}
	now = now.Add(time.Hour - time.Second)
	resolver.Resolve(context.Background(), groups, time.Second)
	if calls.Load() != 2 {
		t.Fatal("fresh unknown fetched again")
	}
	now = now.Add(time.Second)
	resolver.Resolve(context.Background(), groups, time.Second)
	if calls.Load() != 4 {
		t.Fatal("expired unknown not refreshed")
	}
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, now)
	cached := NewSeverityResolverWithOptions(SeverityResolverOptions{CacheDirectory: directory, Now: func() time.Time { return now.Add(6 * 24 * time.Hour) }})
	severityAssert(t, cached.Resolve(context.Background(), groups, time.Second)[severityTestCVE], "high", "osv")
}

func TestSeverityPartialOSVJSONDoesNotSupplySeverity(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"database_specific":{"severity":"HIGH"},"aliases":17}`)
	})
	severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestGO}}, time.Second)[severityTestGO], "unknown", "pending")
}

func TestSeverityDefaultsEnforceHTTPSAndTimeout(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	resolver := NewSeverityResolver()
	for _, endpoint := range []string{resolver.nvdURL, resolver.osvURL, resolver.githubURL} {
		if !strings.HasPrefix(endpoint, "https://") {
			t.Fatalf("insecure default %s", endpoint)
		}
	}
	if resolver.interval < 6100*time.Millisecond || resolver.client.Timeout != 10*time.Second {
		t.Fatal("unsafe defaults")
	}
	custom := NewSeverityResolverWithOptions(SeverityResolverOptions{HTTPClient: &http.Client{Timeout: time.Minute}, CacheDirectory: t.TempDir()})
	if custom.client.Timeout != 10*time.Second {
		t.Fatal("custom timeout not bounded")
	}
	resolver, _ = severityFixture(t, func(w http.ResponseWriter, req *http.Request) { t.Error("unsafe URL fetched") })
	resolver.nvdURL = "http://remote.example.invalid/nvd"
	resolver.osvURL = "http://remote.example.invalid/osv"
	severityAssert(t, resolver.Resolve(context.Background(), [][]string{{severityTestCVE}}, time.Second)[severityTestCVE], "unknown", "pending")
}

func TestSeverityFailedGoAliasRemainsPendingEvenWithOwnSeverity(t *testing.T) {
	for _, ownSeverity := range []string{"", "HIGH"} {
		t.Run("own-"+ownSeverity, func(t *testing.T) {
			resolver, directory := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/nvd" {
					w.WriteHeader(500)
					return
				}
				if req.URL.Path == "/osv/"+severityTestGO {
					fmt.Fprintf(w, `{"aliases":["CVE-2026-1234"],"database_specific":{"severity":%q}}`, ownSeverity)
					return
				}
				w.WriteHeader(404)
			})
			result := resolver.Resolve(context.Background(), [][]string{{severityTestGO}}, time.Second)[severityTestGO]
			severityAssert(t, result, "unknown", "pending")
			files, _ := os.ReadDir(directory)
			if len(files) != 0 {
				t.Fatal("incomplete alias persisted as unknown")
			}
		})
	}
}

func TestSeverityKeyNeverSentToFallbacks(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/nvd" {
			if req.Header.Get("apiKey") != "synthetic-key" {
				t.Error("missing NVD header")
			}
			fmt.Fprint(w, severityNVDJSON(severityTestCVE, `{}`))
			return
		}
		if req.Header.Get("apiKey") != "" || req.Header.Get("Authorization") != "" {
			t.Error("key forwarded to fallback")
		}
		if strings.HasPrefix(req.URL.Path, "/ghsa/") {
			fmt.Fprint(w, `{"severity":"medium"}`)
		} else {
			fmt.Fprint(w, `{}`)
		}
	})
	resolver.apiKey = "synthetic-key"
	result := resolver.Resolve(context.Background(), [][]string{{severityTestCVE}, {severityTestGHSA}}, time.Second)
	severityAssert(t, result[severityTestCVE], "unknown", "none")
	severityAssert(t, result[severityTestGHSA], "medium", "ghsa")
}

func TestSeverityCachedTrueAliasDoesNotRenewTTL(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { t.Error("cache-only fetched") })
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	resolver.now = func() time.Time { return now }
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, now)
	resolver.cache.store(severityTestGO, SeverityResult{"high", "osv-alias:" + severityTestCVE}, now)
	path := resolver.cache.file(severityTestGO)
	before, _ := os.ReadFile(path)
	now = now.Add(time.Hour)
	result := resolver.Resolve(context.Background(), [][]string{{severityTestGO, severityTestCVE}}, 0)
	severityAssert(t, result[severityTestGO], "high", "osv-alias:"+severityTestCVE)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("true alias cache hit renewed fetchedAt")
	}
	now = now.Add(7*24*time.Hour - time.Hour)
	result = resolver.Resolve(context.Background(), [][]string{{severityTestGO, severityTestCVE}}, 0)
	severityAssert(t, result[severityTestGO], "unknown", "pending")
	severityAssert(t, result[severityTestCVE], "unknown", "pending")
}

func TestSeverityLegacyGroupedAliasesAndDirectGoCacheAreRejected(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) { t.Error("cache-only fetched") })
	now := resolver.now()
	for _, test := range []struct{ id, source string }{
		{severityTestGHSA, "alias:" + severityTestCVE},
		{severityTestGO, "alias:" + severityTestCVE},
		{severityTestGO, "osv"},
	} {
		if !resolver.cache.privateDirectory() {
			t.Fatal("cache unavailable")
		}
		data, err := json.Marshal(cachedSeverity{Version: 1, ID: test.id, FetchedAt: now, SeverityResult: SeverityResult{"high", test.source}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(resolver.cache.file(test.id), data, 0600); err != nil {
			t.Fatal(err)
		}
		severityAssert(t, resolver.Resolve(context.Background(), [][]string{{test.id, severityTestCVE}}, 0)[test.id], "unknown", "pending")
	}
}

func TestSeverityTrueCVEAliasUsesNVDNotCachedOSVSeverity(t *testing.T) {
	nvdCalls := 0
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/osv/" + severityTestGHSA:
			fmt.Fprint(w, `{"aliases":["CVE-2026-1234"]}`)
		case "/ghsa/" + severityTestGHSA:
			fmt.Fprint(w, `{}`)
		case "/nvd":
			nvdCalls++
			fmt.Fprint(w, severityNVDJSON(severityTestCVE, `{}`))
		default:
			t.Errorf("unexpected alias fallback request %s", req.URL)
		}
	})
	resolver.cache.store(severityTestCVE, SeverityResult{"high", "osv"}, resolver.now())
	result := resolver.Resolve(context.Background(), [][]string{{severityTestGHSA, severityTestCVE}}, time.Second)
	severityAssert(t, result[severityTestGHSA], "unknown", "none")
	severityAssert(t, result[severityTestCVE], "high", "osv")
	if nvdCalls != 1 {
		t.Fatal("true CVE alias did not query NVD")
	}
}

func TestSeverityGHSAOwnSourceBeforeNVDConsumesBudget(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/osv/" + severityTestGHSA:
			fmt.Fprint(w, `{"database_specific":{"severity":"MEDIUM"}}`)
		case "/nvd":
			<-req.Context().Done()
		default:
			t.Errorf("unexpected request %s", req.URL)
		}
	})
	result := resolver.Resolve(context.Background(), [][]string{{severityTestCVE, severityTestGHSA}}, 30*time.Millisecond)
	severityAssert(t, result[severityTestGHSA], "medium", "osv")
	severityAssert(t, result[severityTestCVE], "unknown", "pending")
}

func TestSeverityGoTrueGHSAUsesOwnOSVAndIgnoresAliasCycles(t *testing.T) {
	resolver, _ := severityFixture(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/osv/" + severityTestGO:
			fmt.Fprint(w, `{"aliases":["GO-2026-1234","GHSA-abcd-1234-efgh"],"database_specific":{"severity":"HIGH"}}`)
		case "/osv/" + severityTestGHSA:
			fmt.Fprint(w, `{"aliases":["GO-2026-1234","GHSA-abcd-1234-efgh"],"database_specific":{"severity":"LOW"}}`)
		default:
			t.Errorf("unexpected cyclic alias request %s", req.URL)
		}
	})
	result := resolver.Resolve(context.Background(), [][]string{{severityTestGO}}, time.Second)
	severityAssert(t, result[severityTestGO], "low", "osv-alias:"+severityTestGHSA)
	if len(result) != 1 {
		t.Fatal("internal alias leaked into output")
	}
}
