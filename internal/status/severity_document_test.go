package status

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSeverityEnrichmentNeverChangesStates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nvd" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-1234","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}}}]}`))
			return
		}
		if r.URL.Path == "/osv/GHSA-aaaa-bbbb-cccc" {
			w.Write([]byte(`{"id":"GHSA-aaaa-bbbb-cccc","database_specific":{"severity":"MODERATE"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	resolver := NewSeverityResolverWithOptions(SeverityResolverOptions{NVDURL: server.URL + "/nvd", OSVURL: server.URL + "/osv", GitHubURL: server.URL + "/github", CacheDirectory: filepath.Join(t.TempDir(), "severity"), NVDInterval: -1})
	document := Document{Version: Version, Kind: "status", Security: SecuritySource{UnevaluatedFixes: []UnevaluatedFix{{Name: "malformed", IDs: []string{"CVE-2026-1234", "unsupported"}}}}, Tracks: []Track{
		{State: Current, MissingFixes: []MissingFix{{IDs: []string{"CVE-2026-1234", "GHSA-aaaa-bbbb-cccc"}, ReachableByTrack: false}}, UnevaluatedFixes: []UnevaluatedFix{{Name: "malformed", IDs: []string{"CVE-2026-1234", "unsupported"}}}},
		{State: FixesAvailable}, {State: UpdateAvailable}, {State: NotBuilt}, {State: Error, Error: "unchanged"},
	}}
	beforeStates := []string{Current, FixesAvailable, UpdateAvailable, NotBuilt, Error}
	enrichSeverity(context.Background(), &document, resolver, time.Second)
	afterStates := []string{}
	for _, track := range document.Tracks {
		afterStates = append(afterStates, track.State)
	}
	if !reflect.DeepEqual(beforeStates, afterStates) || document.Tracks[4].Error != "unchanged" || document.Tracks[0].MissingFixes[0].ReachableByTrack {
		t.Fatal("severity changed comparison state")
	}
	fix := document.Tracks[0].MissingFixes[0]
	if fix.MaxSeverity != "high" || len(fix.Advisories) != 2 || fix.Advisories[1].SeveritySource != "osv" || fix.Advisories[1].Severity != "medium" {
		t.Fatalf("fix %+v", fix)
	}
	global := document.Security.UnevaluatedFixes[0]
	if len(global.Advisories) != 2 || global.MaxSeverity != "high" || global.Advisories[1].Severity != "unknown" || global.Advisories[1].SeveritySource != "none" {
		t.Fatalf("global %+v", global)
	}
	summary := document.Security.Severity
	if summary.IDCount != 3 || summary.ResolvedCount != 2 || summary.UnknownCount != 1 || summary.PendingCount != 0 || summary.SourceCounts["nvd-cvss-v3.1"] != 1 || summary.SourceCounts["osv"] != 1 {
		t.Fatalf("summary %+v", summary)
	}
	if document.Version != 2 {
		t.Fatal("wrong status schema")
	}
	// Cache-only enrichment preserves the same severities without HTTP.
	server.Close()
	enrichSeverity(context.Background(), &document, resolver, 0)
	if document.Security.Severity.ResolvedCount != 2 || document.Security.Severity.FetchFailureCount != 0 {
		t.Fatalf("cache-only %+v", document.Security.Severity)
	}
}

func TestSeverityAdvisoriesMaxAndEmptyArrays(t *testing.T) {
	advisories, max := severityAdvisories([]string{"a", "b", "c", "d", "e"}, map[string]SeverityResult{"a": {"low", "osv"}, "b": {"medium", "osv"}, "c": {"high", "ghsa"}, "d": {"critical", "nvd-cvss-v4.0"}})
	if max != "critical" || len(advisories) != 5 || advisories[4].Severity != "unknown" {
		t.Fatalf("%+v %s", advisories, max)
	}
	advisories, max = severityAdvisories(nil, nil)
	if advisories == nil || max != "unknown" {
		t.Fatalf("empty %+v %s", advisories, max)
	}
}
