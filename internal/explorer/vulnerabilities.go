package explorer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"lupetto/internal/explorer/vulnscan"
)

// DefaultScanInterval and DefaultScanMaxImageSize are the --scan-interval and
// --scan-max-image-size defaults.
const (
	DefaultScanInterval     = 24 * time.Hour
	DefaultScanMaxImageSize = 2 << 30
	// scanTimeout bounds one image's pull, catalog and match.
	scanTimeout = 30 * time.Minute
)

// scanEngine and scanSession are the Grype boundary, replaced in tests.
type scanEngine interface {
	Open(update bool) (scanSession, error)
}
type scanSession interface {
	Scan(ctx context.Context, reference, platform string) (vulnscan.Scan, error)
	Database() vulnscan.DBInfo
	Close() error
}

type grypeEngine struct{ engine *vulnscan.Engine }

func (e grypeEngine) Open(update bool) (scanSession, error) {
	session, err := e.engine.Open(update)
	if err != nil {
		return nil, err
	}
	return grypeSession{session}, nil
}

type grypeSession struct{ *vulnscan.Session }

func (s grypeSession) Database() vulnscan.DBInfo { return s.DB }

// vulnScanner runs one scan pass at a time; a request during a pass runs
// another pass after it.
type vulnScanner struct {
	engine   scanEngine
	store    *vulnscan.Store
	storeErr string
	interval time.Duration

	mu        sync.Mutex
	saveErr   string
	running   bool
	queued    bool
	queuedAll bool
	current   string
}

func newVulnScanner(config Config) (*vulnScanner, error) {
	if config.ScanInterval == 0 {
		return nil, nil
	}
	storePath := config.ScanResults
	if storePath == "" {
		data, err := dataDir(runtime.GOOS, os.Getenv)
		if err != nil {
			return nil, err
		}
		storePath = filepath.Join(data, "lupetto", "explorer", "vulnerabilities.json")
	}
	engine := config.scanEngine
	if engine == nil {
		cache := config.ScanCache
		if cache == "" {
			dir, err := os.UserCacheDir()
			if err != nil {
				return nil, fmt.Errorf("find the cache directory for the vulnerability database: %w", err)
			}
			cache = filepath.Join(dir, "lupetto", "grype")
		}
		grype, err := vulnscan.NewEngine(vulnscan.Config{CacheDir: cache, MaxCompressedBytes: config.ScanMaxImageSize, Timeout: scanTimeout, Version: config.Version})
		if err != nil {
			return nil, err
		}
		engine = grypeEngine{grype}
	}
	store, err := vulnscan.OpenStore(storePath)
	scanner := &vulnScanner{engine: engine, store: store, interval: config.ScanInterval}
	if err != nil {
		scanner.storeErr = err.Error()
	}
	return scanner, nil
}

// update changes the stored results; a failed save keeps the change in
// memory and is shown on the page until a save succeeds.
func (v *vulnScanner) update(change func(*vulnscan.State)) {
	err := v.store.Update(change)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.saveErr = ""
	if err != nil {
		v.saveErr = err.Error()
	}
}

// vulnTarget is one image to scan.
type vulnTarget struct {
	Package, Selector, Source, Reference, Platform string
}

func (t vulnTarget) label() string { return t.Package + " " + t.Selector + " " + t.Source }

// vulnTracks pairs every tracked selector with its newest published image
// (from status) and its configured upstream image (from the products file).
type vulnTrack struct {
	Package, Selector string
	Lupetto, Upstream string
}

func vulnTracks(status *StatusDocument, products []Product) []vulnTrack {
	newest := map[string]string{}
	if status != nil {
		for _, track := range status.Tracks {
			if track.Newest == nil || track.Repository == "" {
				continue
			}
			reference := track.Repository + "@" + track.Newest.Digest
			if len(reference) <= 1024 && digestReferencePattern.MatchString(reference) {
				newest[track.Package+"\x00"+track.Selector] = reference
			}
		}
	}
	var tracks []vulnTrack
	for _, product := range products {
		for _, selector := range product.Selectors {
			tracks = append(tracks, vulnTrack{Package: product.Package, Selector: selector, Lupetto: newest[product.Package+"\x00"+selector], Upstream: product.Upstream[selector]})
		}
	}
	return tracks
}

func vulnTargets(tracks []vulnTrack, platform string) []vulnTarget {
	var targets []vulnTarget
	for _, track := range tracks {
		if track.Lupetto != "" {
			targets = append(targets, vulnTarget{track.Package, track.Selector, vulnscan.SourceLupetto, track.Lupetto, platform})
		}
		if track.Upstream != "" {
			targets = append(targets, vulnTarget{track.Package, track.Selector, vulnscan.SourceUpstream, track.Upstream, platform})
		}
	}
	return targets
}

// scanDue: never attempted, a different image, or last attempted at least
// one interval ago.
func scanDue(state *vulnscan.State, target vulnTarget, now time.Time, interval time.Duration) bool {
	track := state.Track(target.Package, target.Selector)
	if track == nil {
		return true
	}
	side := track.Side(target.Source)
	return side == nil || side.LastAttempt.IsZero() || side.Reference != target.Reference || now.Sub(side.LastAttempt) >= interval
}

// requestScan starts a pass, or queues one after the running pass. all
// rescans every image; otherwise only due images are scanned.
func (s *Server) requestScan(all bool) bool {
	v := s.vulns
	if v == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.running {
		v.queued, v.queuedAll = true, v.queuedAll || all
		return true
	}
	v.running = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			s.scanPass(all)
			v.mu.Lock()
			if !v.queued || s.ctx.Err() != nil {
				v.running, v.queued, v.queuedAll, v.current = false, false, false, ""
				v.mu.Unlock()
				return
			}
			all, v.queued, v.queuedAll = v.queuedAll, false, false
			v.mu.Unlock()
		}
	}()
	return true
}

func (s *Server) scanPass(all bool) {
	v := s.vulns
	status := s.status.snapshot()
	if status.Document == nil {
		return
	}
	platform, err := vulnscan.Platform(status.Document.Architecture)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	products, err := s.listProducts(ctx)
	cancel()
	if err != nil {
		return
	}
	tracks := vulnTracks(status.Document, products.Products)
	configured := map[string]vulnTrack{}
	for _, track := range tracks {
		configured[track.Package+"\x00"+track.Selector] = track
	}
	now := time.Now()
	var due []vulnTarget
	v.update(func(state *vulnscan.State) {
		state.Prune(func(pkg, selector string) (bool, bool) {
			track, ok := configured[pkg+"\x00"+selector]
			return ok, track.Upstream != ""
		})
		for _, target := range vulnTargets(tracks, platform) {
			if all || scanDue(state, target, now, v.interval) {
				due = append(due, target)
			}
		}
	})
	if len(due) == 0 {
		return
	}
	session, err := s.openScanDB()
	if err != nil {
		at := time.Now().UTC()
		v.update(func(state *vulnscan.State) {
			for _, target := range due {
				state.RecordFailure(target.Package, target.Selector, target.Source, target.Reference, at, err)
			}
		})
		return
	}
	defer session.Close()
	for _, target := range due {
		if s.ctx.Err() != nil {
			return
		}
		v.mu.Lock()
		v.current = target.label()
		v.mu.Unlock()
		result, err := session.Scan(s.ctx, target.Reference, target.Platform)
		// Shutdown is not a failed scan.
		if s.ctx.Err() != nil {
			return
		}
		v.update(func(state *vulnscan.State) {
			if err != nil {
				state.RecordFailure(target.Package, target.Selector, target.Source, target.Reference, time.Now().UTC(), err)
				return
			}
			state.RecordSuccess(target.Package, target.Selector, target.Source, result)
		})
	}
	v.mu.Lock()
	v.current = ""
	v.mu.Unlock()
}

// openScanDB updates the database, falling back to the installed one when
// the update check or download fails.
func (s *Server) openScanDB() (scanSession, error) {
	v := s.vulns
	checked := time.Now().UTC()
	session, updateErr := v.engine.Open(true)
	err := updateErr
	if updateErr != nil {
		session, err = v.engine.Open(false)
		if err != nil {
			err = fmt.Errorf("vulnerability database unavailable: update failed (%v) and none is installed: %w", updateErr, err)
		}
	}
	v.update(func(state *vulnscan.State) {
		state.DBCheckedAt, state.DBError = checked, ""
		if updateErr != nil {
			state.DBError = vulnscan.ErrorText(updateErr)
		}
		if err == nil {
			db := session.Database()
			state.DB = &db
		}
	})
	return session, err
}

func (s *Server) vulnScanView() VulnScanView {
	v := s.vulns
	state := v.store.Snapshot()
	v.mu.Lock()
	defer v.mu.Unlock()
	return VulnScanView{GrypeVersion: vulnscan.GrypeVersion, Interval: intervalText(v.interval), Running: v.running, Current: v.current, DB: state.DB, DBCheckedAt: state.DBCheckedAt, DBError: state.DBError, StoreError: v.storeErr, SaveError: v.saveErr}
}

// vulnRows builds one row per tracked selector, in products-file order. When
// the products file cannot be read there are no rows and the error says why.
func (s *Server) vulnRows(ctx context.Context) ([]VulnRow, *vulnscan.State, bool, error) {
	status := s.status.snapshot()
	state := s.vulns.store.Snapshot()
	products, err := s.listProducts(ctx)
	if err != nil {
		return nil, &state, status.Document == nil, err
	}
	list := products.Products
	now := time.Now()
	var rows []VulnRow
	for _, track := range vulnTracks(status.Document, list) {
		row := VulnRow{Package: track.Package, Selector: track.Selector, DetailURL: "/vulnerabilities/" + url.PathEscape(track.Package) + "/" + url.PathEscape(track.Selector)}
		stored := state.Track(track.Package, track.Selector)
		var lupetto, upstream *vulnscan.Side
		if stored != nil {
			lupetto, upstream = stored.Lupetto, stored.Upstream
		}
		row.Lupetto = vulnSide(lupetto, track.Lupetto, now, s.vulns.interval)
		row.Upstream = vulnSide(upstream, track.Upstream, now, s.vulns.interval)
		if row.Lupetto.Counts != nil && row.Upstream.Counts != nil {
			delta := vulnDelta(*row.Lupetto.Counts, *row.Upstream.Counts)
			row.Delta = &delta
			row.DBMismatch = !row.Lupetto.DBBuilt.Equal(*row.Upstream.DBBuilt)
		}
		rows = append(rows, row)
	}
	return rows, &state, status.Document == nil, nil
}

func vulnSide(side *vulnscan.Side, reference string, now time.Time, interval time.Duration) VulnSide {
	view := VulnSide{Configured: reference != "", Reference: reference}
	if side == nil || reference == "" {
		return view
	}
	if !side.Success && !side.LastAttempt.IsZero() {
		at := side.LastAttempt
		view.LastAttempt, view.Error = &at, side.Error
	}
	if result := side.Result; result != nil {
		counts, scanned, built := result.Counts, result.ScannedAt, result.DB.Built
		view.Counts, view.ScannedAt, view.DBBuilt, view.Digest = &counts, &scanned, &built, result.Image.Digest
		view.Stale = side.Stale(reference, now, interval)
	}
	return view
}

func vulnDelta(lupetto, upstream vulnscan.Counts) VulnDelta {
	delta := VulnDelta{Critical: upstream.Critical - lupetto.Critical, High: upstream.High - lupetto.High, Total: upstream.Total - lupetto.Total}
	delta.Magnitude = max(delta.Total, -delta.Total)
	if upstream.Total > 0 {
		delta.Percent = fmt.Sprintf("%.0f%%", 100*float64(delta.Magnitude)/float64(upstream.Total))
	}
	delta.Detail = "critical: " + vulnDifference(delta.Critical) + " · high: " + vulnDifference(delta.High)
	return delta
}

// vulnDifference describes upstream minus Lupetto from Lupetto's side.
func vulnDifference(n int) string {
	switch {
	case n > 0:
		return fmt.Sprintf("%d fewer", n)
	case n < 0:
		return fmt.Sprintf("%d more", -n)
	}
	return "same"
}

// intervalText formats a scan interval without zero units ("24h", not "24h0m0s").
func intervalText(d time.Duration) string {
	text := d.String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}

func (s *Server) vulnerabilities(w http.ResponseWriter, r *http.Request) {
	if s.vulns == nil {
		http.Error(w, "vulnerability scanning is off (--scan-interval 0)", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rows, _, statusMissing, err := s.vulnRows(ctx)
	view := VulnerabilitiesView{BaseView: s.base(), Scan: s.vulnScanView(), Rows: rows, StatusMissing: statusMissing}
	if err != nil {
		view.Scan.ProductsError = err.Error()
	}
	for _, row := range rows {
		if row.Delta == nil {
			continue
		}
		if view.Totals == nil {
			view.Totals = &VulnTotals{}
		}
		view.Totals.Tracks++
		view.Totals.Lupetto = view.Totals.Lupetto.Plus(*row.Lupetto.Counts)
		view.Totals.Upstream = view.Totals.Upstream.Plus(*row.Upstream.Counts)
	}
	if view.Totals != nil {
		view.Totals.Delta = vulnDelta(view.Totals.Lupetto, view.Totals.Upstream)
	}
	s.render(w, r, "vulnerabilities", view)
}

func (s *Server) vulnerabilityTrack(w http.ResponseWriter, r *http.Request) {
	if s.vulns == nil {
		http.Error(w, "vulnerability scanning is off (--scan-interval 0)", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rows, state, _, err := s.vulnRows(ctx)
	pkg, selector := r.PathValue("package"), r.PathValue("selector")
	if err != nil {
		// Whether the track is configured is unknown, so this is not a 404.
		view := VulnTrackView{BaseView: s.base(), Scan: s.vulnScanView(), Row: VulnRow{Package: pkg, Selector: selector}}
		view.Scan.ProductsError = err.Error()
		s.renderStatus(w, r, "vulnerability", view, http.StatusServiceUnavailable)
		return
	}
	for _, row := range rows {
		if row.Package != pkg || row.Selector != selector {
			continue
		}
		view := VulnTrackView{BaseView: s.base(), Scan: s.vulnScanView(), Row: row}
		var lupetto, upstream []vulnscan.Issue
		if stored := state.Track(pkg, selector); stored != nil {
			if row.Lupetto.Counts != nil {
				lupetto = stored.Lupetto.Result.Issues
			}
			if row.Upstream.Counts != nil {
				upstream = stored.Upstream.Result.Issues
			}
		}
		switch {
		case row.Lupetto.Counts != nil && row.Upstream.Counts != nil:
			comparison := vulnscan.Compare(lupetto, upstream)
			view.Comparison = &comparison
		case row.Lupetto.Counts != nil:
			view.Source, view.Issues = vulnscan.SourceLupetto, lupetto
		case row.Upstream.Counts != nil:
			view.Source, view.Issues = vulnscan.SourceUpstream, upstream
		}
		s.render(w, r, "vulnerability", view)
		return
	}
	http.Error(w, "track is not in the products file", http.StatusNotFound)
}

func (s *Server) rescan(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if !s.requestScan(true) {
		http.Error(w, "vulnerability scanning is off or the server is stopping", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, "/vulnerabilities", http.StatusSeeOther)
}

// vulnLink gives an Images row its comparison link and the totals of the
// last successful scans; a side that was never scanned has no count.
func (s *Server) vulnLink(state *vulnscan.State, track Track) *VulnLink {
	link := &VulnLink{URL: "/vulnerabilities/" + url.PathEscape(track.Package) + "/" + url.PathEscape(track.Selector)}
	stored := state.Track(track.Package, track.Selector)
	if stored == nil {
		return link
	}
	now := time.Now()
	newest := ""
	if track.Newest != nil && track.Repository != "" {
		newest = track.Repository + "@" + track.Newest.Digest
	}
	for _, side := range []struct {
		stored    *vulnscan.Side
		reference string
		total     **int
	}{{stored.Lupetto, newest, &link.Lupetto}, {stored.Upstream, "", &link.Upstream}} {
		if side.stored == nil || side.stored.Result == nil {
			continue
		}
		total := side.stored.Result.Counts.Total
		*side.total = &total
		reference := side.reference
		if reference == "" {
			reference = side.stored.Reference
		}
		link.Stale = link.Stale || side.stored.Stale(reference, now, s.vulns.interval)
	}
	return link
}
