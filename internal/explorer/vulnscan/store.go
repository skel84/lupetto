package vulnscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Sources of a track's two scans.
const (
	SourceLupetto  = "lupetto"
	SourceUpstream = "upstream"
)

// StoreVersion is the version of the results file. Files with another
// version are not read; the Explorer starts with no results instead.
const StoreVersion = 1

const maxStoreBytes = 64 << 20

// DBInfo identifies the Grype vulnerability database a scan used.
type DBInfo struct {
	Built  time.Time `json:"built"`
	Schema string    `json:"schema"`
}

// ImageInfo identifies what one scan read.
type ImageInfo struct {
	// Reference is the reference requested: the configured upstream
	// reference, or the Lupetto repository with the newest image's digest.
	Reference string `json:"reference"`
	// Digest is what Reference resolved to (an index or a manifest);
	// ManifestDigest is the platform manifest scanned.
	Digest          string `json:"digest"`
	ManifestDigest  string `json:"manifestDigest"`
	Platform        string `json:"platform"`
	CompressedBytes int64  `json:"compressedBytes"`
	Distro          string `json:"distro,omitempty"`
}

// Scan is one successful scan.
type Scan struct {
	Image     ImageInfo `json:"image"`
	ScannedAt time.Time `json:"scannedAt"`
	DB        DBInfo    `json:"db"`
	Packages  int       `json:"packages"`
	// Matches counts Grype's matches before deduplication. Suppressed counts
	// matches Grype found and set aside: distro advisories saying a package
	// is not affected or fixed (including for files an OS package owns), and
	// its default ignore rules. Neither is part of Counts.
	Matches    int     `json:"matches"`
	Suppressed int     `json:"suppressed"`
	Counts     Counts  `json:"counts"`
	Issues     []Issue `json:"issues"`
}

// Side is the scan history of one image of a track.
type Side struct {
	// Reference, LastAttempt, Success and Error describe the last attempt.
	Reference   string    `json:"reference"`
	LastAttempt time.Time `json:"lastAttempt"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	// Result is the last successful scan, kept when later attempts fail. It
	// can be of an older reference.
	Result *Scan `json:"result,omitempty"`
}

// Stale reports whether Result no longer stands for reference: the last
// attempt failed, the reference changed, or the result is older than twice
// the scan interval. A side without a result is not stale; it has no result.
func (s *Side) Stale(reference string, now time.Time, interval time.Duration) bool {
	if s == nil || s.Result == nil {
		return false
	}
	return !s.Success || s.Result.Image.Reference != reference || (interval > 0 && now.Sub(s.Result.ScannedAt) > 2*interval)
}

// Track holds both sides of one tracked package and selector. Upstream is
// nil when none is configured.
type Track struct {
	Package  string `json:"package"`
	Selector string `json:"selector"`
	Lupetto  *Side  `json:"lupetto,omitempty"`
	Upstream *Side  `json:"upstream,omitempty"`
}

// Side returns the side for source, or nil.
func (t *Track) Side(source string) *Side {
	if source == SourceUpstream {
		return t.Upstream
	}
	return t.Lupetto
}

// State is the results file's content.
type State struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	// DB is the last vulnerability database loaded successfully.
	DB          *DBInfo   `json:"db,omitempty"`
	DBCheckedAt time.Time `json:"dbCheckedAt"`
	DBError     string    `json:"dbError,omitempty"`
	Tracks      []Track   `json:"tracks"`
}

// Track returns the stored track, or nil.
func (s *State) Track(pkg, selector string) *Track {
	for i := range s.Tracks {
		if s.Tracks[i].Package == pkg && s.Tracks[i].Selector == selector {
			return &s.Tracks[i]
		}
	}
	return nil
}

func (s *State) side(pkg, selector, source string) *Side {
	track := s.Track(pkg, selector)
	if track == nil {
		s.Tracks = append(s.Tracks, Track{Package: pkg, Selector: selector})
		track = &s.Tracks[len(s.Tracks)-1]
	}
	if source == SourceUpstream {
		if track.Upstream == nil {
			track.Upstream = &Side{}
		}
		return track.Upstream
	}
	if track.Lupetto == nil {
		track.Lupetto = &Side{}
	}
	return track.Lupetto
}

// RecordSuccess stores a successful scan as the side's result.
func (s *State) RecordSuccess(pkg, selector, source string, scan Scan) {
	side := s.side(pkg, selector, source)
	*side = Side{Reference: scan.Image.Reference, LastAttempt: scan.ScannedAt, Success: true, Result: &scan}
}

// RecordFailure records a failed attempt and keeps the previous result.
func (s *State) RecordFailure(pkg, selector, source, reference string, at time.Time, err error) {
	side := s.side(pkg, selector, source)
	side.Reference, side.LastAttempt, side.Success = reference, at, false
	side.Error = ErrorText(err)
}

// MaxErrorBytes bounds a stored scan or database error.
const MaxErrorBytes = 512

var urlQuery = regexp.MustCompile(`(https?://[^\s?"']+)\?[^\s"']*`)

// ErrorText is err's message without URL query strings (registry blob
// redirects carry signed, short-lived ones) or control characters, cut to
// MaxErrorBytes.
func ErrorText(err error) string {
	if err == nil {
		return "scan failed"
	}
	text := urlQuery.ReplaceAllString(err.Error(), "$1?…")
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, text)
	if len(text) > MaxErrorBytes {
		text = text[:MaxErrorBytes-len("…")]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		text += "…"
	}
	return text
}

// Prune drops tracks, and upstream sides, that are no longer configured.
// keep reports whether a track is tracked and whether it has an upstream.
func (s *State) Prune(keep func(pkg, selector string) (tracked, upstream bool)) {
	kept := s.Tracks[:0]
	for _, track := range s.Tracks {
		tracked, upstream := keep(track.Package, track.Selector)
		if !tracked {
			continue
		}
		if !upstream {
			track.Upstream = nil
		}
		kept = append(kept, track)
	}
	s.Tracks = kept
}

// Store keeps State in one JSON file, replaced atomically on every change.
type Store struct {
	path  string
	mu    sync.Mutex
	state State
}

// OpenStore reads path when it exists. An unreadable or incompatible file
// yields an empty store and an error describing it; the next save replaces it.
func OpenStore(path string) (*Store, error) {
	store := &Store{path: path, state: State{Version: StoreVersion, Kind: "vulnerability-scans", Tracks: []Track{}}}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, fmt.Errorf("read vulnerability results: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxStoreBytes+1))
	if err != nil {
		return store, fmt.Errorf("read vulnerability results: %w", err)
	}
	if len(data) > maxStoreBytes {
		return store, errors.New("vulnerability results file exceeds 64 MiB; starting without results")
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return store, fmt.Errorf("vulnerability results file is not valid JSON; starting without results: %w", err)
	}
	if state.Version != StoreVersion || state.Kind != "vulnerability-scans" {
		return store, fmt.Errorf("vulnerability results file has version %d; starting without results", state.Version)
	}
	if state.Tracks == nil {
		state.Tracks = []Track{}
	}
	store.state = state
	return store, nil
}

// Snapshot returns a copy of the state that later updates do not change.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.state)
}

// Update applies change and saves the result. When saving fails, the change
// is kept in memory and the error is returned.
func (s *Store) Update(change func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(&s.state)
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return writeAtomic(s.path, data)
}

func clone(state State) State {
	data, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	var copied State
	if err := json.Unmarshal(data, &copied); err != nil {
		panic(err)
	}
	return copied
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".vulnerabilities-*.json")
	if err != nil {
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("save vulnerability results: %w", err)
	}
	return nil
}
