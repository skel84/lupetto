package vulnscan

import (
	"reflect"
	"testing"
)

func TestSummarizeDedupesAliases(t *testing.T) {
	stdlib := Package{Name: "stdlib", Version: "go1.24.1", Type: "go-module"}
	openssl := Package{Name: "openssl", Version: "3.5.0-r0", Type: "apk"}
	findings := []Finding{
		// One Go advisory, reported as a GHSA and as its CVE, against two binaries' stdlib.
		{ID: "GHSA-aaaa-bbbb-cccc", Severity: "High", Related: []Related{{ID: "CVE-2025-0001", Severity: "Medium"}}, Package: stdlib, FixState: "fixed", FixVersions: []string{"1.24.2"}},
		{ID: "CVE-2025-0001", Severity: "Medium", Package: Package{Name: "stdlib", Version: "go1.23.0", Type: "go-module"}, FixState: "fixed", FixVersions: []string{"1.23.8"}},
		// Transitive: a second GHSA linked only through the shared CVE.
		{ID: "GHSA-dddd-eeee-ffff", Severity: "Unknown", Related: []Related{{ID: "CVE-2025-0001"}}, Package: stdlib},
		// A distro record whose own severity is unknown takes its related NVD severity.
		{ID: "CVE-2025-0002", Severity: "Unknown", Related: []Related{{ID: "CVE-2025-0002", Severity: "Critical"}}, Package: openssl, FixState: "not-fixed"},
		// The same distro record matched twice counts once.
		{ID: "CVE-2025-0002", Severity: "", Package: openssl, FixState: "not-fixed"},
		{ID: "GHSA-1111-2222-3333", Severity: "Low", Package: stdlib, FixState: "wont-fix"},
		{ID: "", Severity: "Critical"},
	}
	issues, counts := Summarize(findings)
	want := Counts{Critical: 1, High: 1, Low: 1, Total: 3}
	if counts != want {
		t.Fatalf("counts = %+v, want %+v", counts, want)
	}
	if len(issues) != 3 {
		t.Fatalf("issues = %+v", issues)
	}
	critical, high, low := issues[0], issues[1], issues[2]
	if critical.ID != "CVE-2025-0002" || critical.Severity != Critical || critical.Aliases != nil || len(critical.Packages) != 1 || critical.FixState != "not-fixed" {
		t.Fatalf("critical issue = %+v", critical)
	}
	if high.ID != "CVE-2025-0001" || high.Severity != High || !reflect.DeepEqual(high.Aliases, []string{"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}) {
		t.Fatalf("aliased issue = %+v", high)
	}
	if len(high.Packages) != 2 || high.FixState != "fixed" || high.Packages[0].Version != "go1.23.0" || !reflect.DeepEqual(high.Packages[0].FixVersions, []string{"1.23.8"}) || !reflect.DeepEqual(high.Packages[1].FixVersions, []string{"1.24.2"}) {
		t.Fatalf("aliased issue packages/fixes = %+v", high)
	}
	if low.ID != "GHSA-1111-2222-3333" || low.Severity != Low {
		t.Fatalf("GHSA-only issue = %+v", low)
	}
}

func TestSummarizeKnownSeverityIsNotRaisedByRelated(t *testing.T) {
	issues, counts := Summarize([]Finding{{ID: "CVE-2025-0003", Severity: "Low", Related: []Related{{ID: "CVE-2025-0003", Severity: "Critical"}}}})
	if counts.Low != 1 || counts.Total != 1 || issues[0].Severity != Low || issues[0].FixState != "unknown" {
		t.Fatalf("issues=%+v counts=%+v", issues, counts)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	issues, counts := Summarize(nil)
	if len(issues) != 0 || counts != (Counts{}) || issues == nil {
		t.Fatalf("issues=%#v counts=%+v", issues, counts)
	}
}

func TestCompareMatchesByAlias(t *testing.T) {
	upstream, _ := Summarize([]Finding{
		{ID: "GHSA-aaaa-bbbb-cccc", Severity: "High", Related: []Related{{ID: "CVE-2025-0001"}}},
		{ID: "CVE-2025-0004", Severity: "Critical"},
	})
	lupetto, _ := Summarize([]Finding{
		// Reported under the CVE alone on the Lupetto side.
		{ID: "CVE-2025-0001", Severity: "High"},
		{ID: "CVE-2025-0005", Severity: "Medium"},
	})
	comparison := Compare(lupetto, upstream)
	if len(comparison.Removed) != 1 || comparison.Removed[0].ID != "CVE-2025-0004" {
		t.Fatalf("removed = %+v", comparison.Removed)
	}
	if len(comparison.Remaining) != 1 || comparison.Remaining[0].Lupetto.ID != "CVE-2025-0001" || comparison.Remaining[0].Upstream.ID != "CVE-2025-0001" {
		t.Fatalf("remaining = %+v", comparison.Remaining)
	}
	if len(comparison.New) != 1 || comparison.New[0].ID != "CVE-2025-0005" {
		t.Fatalf("new = %+v", comparison.New)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	for in, want := range map[string]string{"Critical": Critical, " HIGH ": High, "Negligible": Negligible, "": Unknown, "Unknown": Unknown, "severe": Unknown} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
