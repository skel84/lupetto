package explorer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const HistoryLimit = 50
const PackageResultLimit = 200

type Config struct {
	Listen          string
	AllowedHosts    []string
	Products        string
	LupettoBinary   string
	EnableBuilds    bool
	RefreshInterval time.Duration
	Renderer        Renderer
	// ScanInterval is the vulnerability rescan interval; 0 turns scanning,
	// its pages and its metrics off.
	ScanInterval time.Duration
	// ScanMaxImageSize rejects images with more compressed layer bytes.
	ScanMaxImageSize int64
	// ScanResults and ScanCache override the results file and the Grype
	// database directory (tests); empty means the data and cache defaults.
	ScanResults, ScanCache string
	// Version identifies the Explorer to the Grype database server.
	Version string
	// Log receives operator messages, such as a products file that cannot be
	// read; nil discards them.
	Log        io.Writer
	scanEngine scanEngine
}

func DefaultConfig() Config {
	return Config{Listen: "127.0.0.1:8080", LupettoBinary: "lupetto", RefreshInterval: 15 * time.Minute, ScanInterval: DefaultScanInterval, ScanMaxImageSize: DefaultScanMaxImageSize}
}

type Server struct {
	config        Config
	cli           *CLI
	renderer      Renderer
	token         string
	allowedHosts  []hostRule
	status        statusCache
	discovery     discoveryCache
	discoverSlots chan struct{}
	dashboard     dashboardState
	signatures    signatureCache
	jobs          jobRunner
	vulns         *vulnScanner
	productsLoad  productsLoad
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	productsMu    sync.Mutex
	started       bool
	closing       bool
	statusPending bool
	wg            sync.WaitGroup
	handler       http.Handler
}

func New(config Config) (*Server, error) {
	if config.Products == "" {
		return nil, errors.New("--products is required")
	}
	if config.RefreshInterval <= 0 {
		return nil, errors.New("--refresh-interval must be positive")
	}
	if config.ScanInterval < 0 {
		return nil, errors.New("--scan-interval must not be negative")
	}
	if config.ScanInterval > 0 && config.ScanMaxImageSize <= 0 {
		return nil, errors.New("--scan-max-image-size must be positive")
	}
	_, _, err := net.SplitHostPort(config.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid --listen: %w", err)
	}
	allowedHosts, err := parseAllowedHosts(config.AllowedHosts)
	if err != nil {
		return nil, err
	}
	cli, err := NewCLI(config.LupettoBinary)
	if err != nil {
		return nil, err
	}
	renderer := config.Renderer
	if renderer == nil {
		renderer, err = embeddedRenderer()
		if err != nil {
			return nil, err
		}
	}
	vulns, err := newVulnScanner(config)
	if err != nil {
		return nil, err
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, fmt.Errorf("create CSRF token: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: config, cli: cli, renderer: renderer, token: hex.EncodeToString(entropy[:]), allowedHosts: allowedHosts, discoverSlots: make(chan struct{}, 4), signatures: newSignatureCache(), vulns: vulns, ctx: ctx, cancel: cancel}
	s.jobs = jobRunner{cli: cli, ctx: ctx, enabled: config.EnableBuilds, limit: HistoryLimit, logBytes: defaultLogBytes, afterFinish: func(record *BuildRecord) {
		s.invalidateSignatures(record)
		s.refreshAfterBuild()
	}}
	s.handler = s.safe(s.routes())
	return s, nil
}
func (s *Server) Handler() http.Handler { return s.handler }
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{Addr: s.config.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
}
func (s *Server) Start() {
	s.mu.Lock()
	if s.started || s.closing {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.wg.Add(1)
	s.mu.Unlock()
	s.RefreshStatus()
	s.refreshDiscovery()
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.config.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.RefreshStatus()
				s.refreshDiscovery()
			}
		}
	}()
}
func (s *Server) RefreshStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshStatusLocked()
}
func (s *Server) refreshStatusLocked() bool {
	if s.closing || !s.status.begin() {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
		defer cancel()
		products, productsErr := s.listProducts(ctx)
		if productsErr == nil && len(products.Products) == 0 {
			s.status.mu.Lock()
			s.status.view = StatusView{Empty: true}
			s.status.mu.Unlock()
		} else {
			document, err := s.cli.Status(ctx, s.config.Products)
			s.status.finish(document, err)
			if err == nil {
				s.warmSignatures(document)
				// Scans the images that are new or due; status supplies the
				// newest digests.
				s.requestScan(false)
			}
		}
		s.mu.Lock()
		if s.statusPending {
			s.statusPending = false
			s.refreshStatusLocked()
		}
		s.mu.Unlock()
	}()
	return true
}
func (s *Server) refreshAfterBuild() {
	s.invalidateInventory()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.refreshStatusLocked() && !s.closing {
		s.statusPending = true
	}
}
func (s *Server) refreshDiscovery() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || !s.discovery.begin() {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
		defer cancel()
		document, err := s.cli.Discover(ctx, "")
		s.discovery.finish(document, err)
	}()
	return true
}

// Close stops background CLI calls and cancels the current build, waiting for
// its failure record / graceful SIGTERM handling (then the CLI kill deadline).
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.mu.Unlock()
	s.jobs.close()
	done := make(chan struct{})
	go func() { s.wg.Wait(); s.jobs.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run owns HTTP shutdown as well as CLI supervision. Caller supplies the
// SIGINT/SIGTERM-aware context; failures never print environment values.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return err
	}
	httpServer := s.HTTPServer()
	s.Start()
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-served:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	closeErr := s.Close(shutdownCtx)
	shutdownErr := httpServer.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		_ = httpServer.Close()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return errors.Join(closeErr, shutdownErr)
}
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.images)
	mux.HandleFunc("GET /images", s.images)
	mux.HandleFunc("GET /images/{package}/{selector}", s.image)
	mux.HandleFunc("GET /images/{package}/{selector}/sbom/{digest}", s.downloadSignedSBOM)
	mux.HandleFunc("GET /catalog", s.packages)
	mux.HandleFunc("GET /catalog/{name}", s.packageDetail)
	mux.HandleFunc("GET /builds", s.builds)
	mux.HandleFunc("GET /builds/{id}", s.buildDetail)
	mux.HandleFunc("GET /builds/{id}/logs", s.jobLogs)
	mux.HandleFunc("GET /builds/{id}/sbom", s.downloadSPDX)
	mux.HandleFunc("POST /builds/{id}/cancel", s.cancelJob)
	mux.HandleFunc("GET /products/track", s.tracking)
	mux.HandleFunc("POST /products/{action}", s.editProducts)
	mux.HandleFunc("GET /tracks/{package}/{selector}", s.image)
	mux.HandleFunc("GET /packages", s.packages)
	mux.HandleFunc("GET /packages/{name}", s.packageDetail)
	mux.HandleFunc("GET /jobs", s.builds)
	mux.HandleFunc("GET /jobs/{id}", s.buildDetail)
	mux.HandleFunc("GET /jobs/{id}/logs", s.jobLogs)
	mux.HandleFunc("POST /status/refresh", s.refresh)
	mux.HandleFunc("POST /builds", s.build)
	mux.HandleFunc("POST /jobs/{id}/cancel", s.cancelJob)
	mux.HandleFunc("GET /vulnerabilities", s.vulnerabilities)
	mux.HandleFunc("GET /vulnerabilities/{package}/{selector}", s.vulnerabilityTrack)
	mux.HandleFunc("POST /vulnerabilities/scan", s.rescan)
	mux.Handle("GET /metrics", s.metricsHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(embeddedStatic())))
	return mux
}
func (s *Server) base() BaseView {
	return BaseView{CSRFToken: s.token, BuildsEnabled: s.config.EnableBuilds, Shell: s.shell()}
}
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, model any) {
	s.renderStatus(w, r, name, model, http.StatusOK)
}

// renderStatus renders like render with another HTTP status code.
func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, name string, model any, code int) {
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(model)
		return
	}
	var page bytes.Buffer
	if err := s.renderer.Render(&page, name, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(page.Bytes())
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	view := OverviewView{BaseView: s.base(), Status: s.status.snapshot(), Tracks: []TrackSummary{}}
	if view.Status.Document != nil {
		for _, track := range view.Status.Document.Tracks {
			summary := TrackSummary{Track: track, DetailURL: "/tracks/" + url.PathEscape(track.Package) + "/" + url.PathEscape(track.Selector), OutdatedCount: len(track.Outdated), UnevaluatedFixCount: len(track.UnevaluatedFixes)}
			for _, fix := range track.MissingFixes {
				if fix.ReachableByTrack {
					summary.ReachableFixCount++
				} else {
					summary.UnreachableFixCount++
				}
			}
			view.Tracks = append(view.Tracks, summary)
		}
	}
	s.render(w, r, "overview", view)
}
func (s *Server) track(w http.ResponseWriter, r *http.Request) {
	status := s.status.snapshot()
	if status.Document != nil {
		for _, track := range status.Document.Tracks {
			if track.Package == r.PathValue("package") && track.Selector == r.PathValue("selector") {
				s.render(w, r, "track", TrackView{BaseView: s.base(), Status: status, Track: track})
				return
			}
		}
	}
	http.Error(w, "track is not present in cached status; wait for or request a refresh", http.StatusNotFound)
}
func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	document, lastError, refreshing := s.discovery.snapshot()
	if document == nil && !refreshing {
		s.refreshDiscovery()
		_, lastError, refreshing = s.discovery.snapshot()
	}
	query := r.URL.Query().Get("q")
	if len(query) > 256 {
		http.Error(w, "package query exceeds 256 bytes", http.StatusBadRequest)
		return
	}
	view := PackagesView{BaseView: s.base(), Query: query, Packages: []PackageItem{}, Limit: PackageResultLimit, LastError: lastError, Refreshing: refreshing}
	tracked := map[string]bool{}
	if status := s.status.snapshot(); status.Document != nil {
		for _, track := range status.Document.Tracks {
			tracked[track.Package] = true
			if track.Latest != nil {
				tracked[track.Latest.Name] = true
			}
		}
	}
	if document != nil {
		// Metadata only: do not expose the unbounded full all-packages array.
		metadata := *document
		metadata.Packages = nil
		view.Document = &metadata
		for _, pkg := range document.Packages {
			if !strings.Contains(strings.ToLower(pkg.Name), strings.ToLower(query)) && !strings.Contains(strings.ToLower(pkg.Description), strings.ToLower(query)) {
				continue
			}
			view.TotalMatches++
			if len(view.Packages) < PackageResultLimit {
				view.Packages = append(view.Packages, PackageItem{DiscoveredPackage: pkg, DetailURL: "/catalog/" + url.PathEscape(pkg.Name), Tracked: tracked[pkg.Name]})
			}
		}
	}
	s.render(w, r, "packages", view)
}
func (s *Server) packageDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validPackage(name) {
		http.Error(w, "invalid package name", http.StatusBadRequest)
		return
	}
	select {
	case s.discoverSlots <- struct{}{}:
		defer func() { <-s.discoverSlots }()
	default:
		http.Error(w, "package discovery is busy; retry shortly", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	// Shutdown cancels request-scoped discovery too, before HTTP draining.
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	document, err := s.cli.Discover(ctx, name)
	view := PackageView{BaseView: s.base(), Name: name, Document: document}
	if err != nil {
		view.Error = err.Error()
	}
	s.render(w, r, "package", view)
}
func (s *Server) jobList(w http.ResponseWriter, r *http.Request) {
	jobs, running := s.jobs.list()
	s.render(w, r, "jobs", JobsView{BaseView: s.base(), Jobs: jobs, Running: running, HistoryLimit: HistoryLimit})
}
func (s *Server) jobDetail(w http.ResponseWriter, r *http.Request) {
	job, log, ok := s.jobs.detail(r.PathValue("id"), 0)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "job", JobDetailView{BaseView: s.base(), Job: job, Log: log})
}
func (s *Server) jobLogs(w http.ResponseWriter, r *http.Request) {
	offset := int64(0)
	if raw := r.URL.Query().Get("offset"); raw != "" {
		var err error
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 {
			http.Error(w, "offset must be a nonnegative integer", http.StatusBadRequest)
			return
		}
	}
	_, log, ok := s.jobs.detail(r.PathValue("id"), offset)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, log)
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	s.RefreshStatus()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func oneField(r *http.Request, name string) string {
	if values := r.PostForm[name]; len(values) == 1 {
		return values[0]
	}
	return ""
}
func (s *Server) build(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	if !uniqueFields(w, r, "package", "selector", "apkVersion", "mode") {
		return
	}
	buildRequest := BuildRequest{Package: oneField(r, "package"), Selector: oneField(r, "selector"), APKVersion: oneField(r, "apkVersion"), Mode: oneField(r, "mode")}
	// A tracked package builds with its product's image options, so Explorer
	// rebuilds produce the image status compares against. Without a readable
	// products file the build is refused rather than built without it.
	if s.jobs.enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		products, err := s.listProducts(ctx)
		cancel()
		if err != nil {
			http.Error(w, "cannot read the products file for the build's image configuration: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		for _, product := range products.Products {
			if product.Package == buildRequest.Package {
				buildRequest.Entrypoint, buildRequest.CABundle = product.Entrypoint, product.CABundle
			}
		}
	}
	if buildRequest.Mode == "publish" {
		buildRequest.Load, buildRequest.LoadReason = publishLoadDecision(s.dashboard.inventorySnapshot())
	}
	job, err := s.jobs.start(buildRequest)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, ErrBuildsDisabled) {
			code = http.StatusForbidden
		}
		if errors.Is(err, ErrJobRunning) {
			code = http.StatusConflict
		}
		if errors.Is(err, ErrShuttingDown) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), code)
		return
	}
	http.Redirect(w, r, "/builds/"+job.ID, http.StatusSeeOther)
}
func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	found, err := s.jobs.cancelJob(r.PathValue("id"))
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/builds/"+r.PathValue("id"), http.StatusSeeOther)
}
func (s *Server) safe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: no-referrer makes browsers send
		// "Origin: null" on same-origin form POSTs, which authorize rejects.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		// Prometheus scrapes pod addresses; /metrics serves read-only
		// aggregates and no CSRF token, so it needs no DNS-rebinding guard.
		if !s.hostAllowed(r.Host) && !(r.URL.Path == "/metrics" && (r.Method == http.MethodGet || r.Method == http.MethodHead)) {
			http.Error(w, "Host is not allowed; configure --allowed-host for the intended external hostname", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		parsed, err := url.Parse(origin)
		// A TLS-terminating ingress forwards HTTP. Check the browser authority
		// exactly, accepting either web scheme without trusting proxy headers.
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host != r.Host || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			http.Error(w, "same-origin Origin is required", http.StatusForbidden)
			return false
		}
	} else if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "same-origin Origin or Sec-Fetch-Site is required", http.StatusForbidden)
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid or oversized form", http.StatusBadRequest)
		return false
	}
	token := oneField(r, "csrfToken")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}
