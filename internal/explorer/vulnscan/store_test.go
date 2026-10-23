package vulnscan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func scanOf(reference string, at time.Time, counts Counts) Scan {
	return Scan{Image: ImageInfo{Reference: reference, Digest: "sha256:" + reference}, ScannedAt: at, DB: DBInfo{Built: at.Add(-time.Hour), Schema: "v6.1.10"}, Counts: counts, Issues: []Issue{}}
}

func TestFailureKeepsPreviousResultAndMarksItStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lupetto", "explorer", "vulnerabilities.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	start := time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC)
	ref := "registry.k8s.io/metrics-server/metrics-server:v0.8.0"
	if err := store.Update(func(s *State) {
		s.RecordSuccess("metrics-server", "0", SourceUpstream, scanOf(ref, start, Counts{High: 3, Total: 3}))
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if side := snapshot.Track("metrics-server", "0").Upstream; side.Stale(ref, start.Add(time.Hour), day) {
		t.Fatalf("fresh result reported stale: %+v", side)
	}
	if err := store.Update(func(s *State) {
		s.RecordFailure("metrics-server", "0", SourceUpstream, ref, start.Add(day), errors.New("registry unavailable"))
	}); err != nil {
		t.Fatal(err)
	}
	// A restart reads the same file.
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reopenedState := reopened.Snapshot()
	side := reopenedState.Track("metrics-server", "0").Upstream
	if side.Success || side.Error != "registry unavailable" || !side.LastAttempt.Equal(start.Add(day)) {
		t.Fatalf("failed attempt not recorded: %+v", side)
	}
	if side.Result == nil || side.Result.Counts.Total != 3 || side.Result.Counts.High != 3 {
		t.Fatalf("failure replaced the previous result: %+v", side.Result)
	}
	if !side.Stale(ref, start.Add(day), day) {
		t.Fatal("result after a failed attempt is not stale")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("results file mode: %v %v", info, err)
	}
}

func TestFailureWithoutResultHasNoCounts(t *testing.T) {
	var state State
	state.RecordFailure("kyverno", "1", SourceLupetto, "registry.example/kyverno@sha256:abc", time.Now(), errors.New("image exceeds the size limit"))
	side := state.Track("kyverno", "1").Lupetto
	if side.Result != nil || side.Success {
		t.Fatalf("a failed first scan produced a result: %+v", side)
	}
	if side.Stale(side.Reference, time.Now(), time.Hour) {
		t.Fatal("no result cannot be stale")
	}
}

func TestStaleWhenReferenceChangesOrResultIsOld(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	var state State
	state.RecordSuccess("kyverno", "1", SourceLupetto, scanOf("registry.example/kyverno@sha256:old", now, Counts{}))
	side := state.Track("kyverno", "1").Lupetto
	if !side.Stale("registry.example/kyverno@sha256:new", now, time.Hour) {
		t.Fatal("result for an older image is not stale")
	}
	if side.Stale("registry.example/kyverno@sha256:old", now.Add(2*time.Hour), time.Hour) {
		t.Fatal("result within twice the interval reported stale")
	}
	if !side.Stale("registry.example/kyverno@sha256:old", now.Add(2*time.Hour+time.Second), time.Hour) {
		t.Fatal("result older than twice the interval is not stale")
	}
}

func TestPruneDropsUntrackedTracksAndUpstreams(t *testing.T) {
	now := time.Now()
	var state State
	state.RecordSuccess("a", "1", SourceLupetto, scanOf("a", now, Counts{}))
	state.RecordSuccess("a", "1", SourceUpstream, scanOf("up", now, Counts{}))
	state.RecordSuccess("b", "1", SourceLupetto, scanOf("b", now, Counts{}))
	state.Prune(func(pkg, selector string) (bool, bool) { return pkg == "a", false })
	if len(state.Tracks) != 1 || state.Tracks[0].Package != "a" || state.Tracks[0].Upstream != nil || state.Tracks[0].Lupetto == nil {
		t.Fatalf("pruned state = %+v", state.Tracks)
	}
}

func TestOpenStoreRejectsUnknownVersionsAndCorruptFiles(t *testing.T) {
	for name, data := range map[string]string{
		"version": `{"version":2,"kind":"vulnerability-scans","tracks":[]}`,
		"kind":    `{"version":1,"kind":"other","tracks":[]}`,
		"corrupt": `{"version":1,`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vulnerabilities.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := OpenStore(path)
			if err == nil {
				t.Fatal("incompatible results file accepted")
			}
			if state := store.Snapshot(); len(state.Tracks) != 0 || state.Version != StoreVersion {
				t.Fatalf("state = %+v", state)
			}
		})
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	store, _ := OpenStore(filepath.Join(t.TempDir(), "v.json"))
	if err := store.Update(func(s *State) { s.RecordSuccess("a", "1", SourceLupetto, scanOf("a", time.Now(), Counts{Total: 1})) }); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	snapshot.Tracks[0].Lupetto.Result.Counts.Total = 99
	if store.Snapshot().Tracks[0].Lupetto.Result.Counts.Total != 1 {
		t.Fatal("snapshot shares memory with the store")
	}
}

func TestErrorTextDropsQueriesAndIsBounded(t *testing.T) {
	if got := ErrorText(nil); got != "scan failed" {
		t.Fatalf("nil = %q", got)
	}
	got := ErrorText(errors.New("GET https://auth.example.invalid/token?scope=repo&access_token=abc: 401\nretry"))
	if strings.Contains(got, "access_token") || strings.Contains(got, "\n") || !strings.Contains(got, "/token?… 401 retry") {
		t.Fatalf("got %q", got)
	}
	long := ErrorText(errors.New(strings.Repeat("é", 1000)))
	if len(long) > MaxErrorBytes || !strings.HasSuffix(long, "…") || !utf8.ValidString(long) {
		t.Fatalf("long = %d bytes, valid %v", len(long), utf8.ValidString(long))
	}
}
