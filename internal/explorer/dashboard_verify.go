package explorer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Signature status comes only from `lupetto verify --json`. Results are cached
// per process by (configured key path, digest reference); verification runs in
// the background with at most verifyWorkers CLI processes and one check per
// reference at a time. Pages never wait for it.
const (
	verifyWorkers          = 2
	verifyLongTTL          = time.Hour
	verifyShortTTL         = 5 * time.Minute
	verifyTimeout          = 2 * time.Minute
	verifyCacheLimit       = 1024
	signedSBOMSlots        = 2
	signedSBOMTimeout      = 25 * time.Second
	signedSBOMWriteTimeout = 2 * time.Minute
	verifyDetailMaxRunes   = 240
)

type verifyKey struct{ keyPath, reference string }
type verifyEntry struct {
	doc      *VerifyDocument
	err      string
	storedAt time.Time
	expires  time.Time
	queued   bool
	running  bool
	gen      uint64
}
type signatureCache struct {
	mu        sync.Mutex
	enabled   bool
	keyPath   string
	allowHTTP bool
	// keySHA256 is the trusted-key fingerprint the CLI last reported; a
	// change (key rotated in place at the same path) discards all results.
	keySHA256 string
	entries   map[verifyKey]*verifyEntry
	queue     []string
	workers   int
	now       func() time.Time
	slots     chan struct{}
}

func newSignatureCache() signatureCache {
	keyPath := os.Getenv("LUPETTO_COSIGN_PUBLIC_KEY")
	return signatureCache{
		enabled:   strings.TrimSpace(keyPath) != "",
		keyPath:   keyPath,
		allowHTTP: os.Getenv("LUPETTO_COSIGN_ALLOW_HTTP") == "true",
		entries:   map[verifyKey]*verifyEntry{},
		now:       time.Now,
		slots:     make(chan struct{}, signedSBOMSlots),
	}
}
func (c *signatureCache) key(reference string) verifyKey { return verifyKey{c.keyPath, reference} }
func (c *signatureCache) config() SignatureConfigView {
	if c.enabled {
		return SignatureConfigView{Enabled: true}
	}
	return SignatureConfigView{Reason: "No trusted public key is configured (LUPETTO_COSIGN_PUBLIC_KEY is not set), so signatures are not checked."}
}

// verifyTTL keeps positive results long. Invalid is kept short too: a
// transient Cosign, Rekor or TUF failure the CLI cannot tell from a rejection
// must not show a correctly signed image as Invalid for long.
func verifyTTL(d *VerifyDocument) time.Duration {
	long := func(state string) bool {
		return state == "signed" || state == "attested"
	}
	if long(d.Signature.State) && long(d.Attestation.State) {
		return verifyLongTTL
	}
	return verifyShortTTL
}
func shortDetail(message string) string {
	message, _, _ = strings.Cut(strings.TrimSpace(message), "\n")
	if runes := []rune(message); len(runes) > verifyDetailMaxRunes {
		message = string(runes[:verifyDetailMaxRunes]) + "…"
	}
	return message
}

// storeLocked records a completed check. A path the CLI wrote is never cached.
func (c *signatureCache) storeLocked(e *verifyEntry, doc *VerifyDocument, err error) {
	if err == nil && doc.Trust.PublicKeySHA256 != c.keySHA256 {
		if c.keySHA256 != "" {
			c.resetLocked(func(verifyKey) bool { return true })
		}
		c.keySHA256 = doc.Trust.PublicKeySHA256
	}
	now := c.now()
	e.storedAt = now
	if err != nil {
		e.doc, e.err, e.expires = nil, shortDetail(err.Error()), now.Add(verifyShortTTL)
		return
	}
	copy := *doc
	if copy.Attestation.SBOM != nil {
		sbom := *copy.Attestation.SBOM
		sbom.Path = ""
		copy.Attestation.SBOM = &sbom
	}
	e.doc, e.err, e.expires = &copy, "", now.Add(verifyTTL(&copy))
}
func (c *signatureCache) entryLocked(reference string) *verifyEntry {
	key := c.key(reference)
	if e := c.entries[key]; e != nil {
		return e
	}
	if len(c.entries) >= verifyCacheLimit {
		for k, e := range c.entries {
			if !e.queued && !e.running {
				delete(c.entries, k)
			}
		}
	}
	e := &verifyEntry{}
	c.entries[key] = e
	return e
}

// scheduleVerify queues references whose result is missing or expired. Lock
// order is Server.mu, then signatureCache.mu (as for other background work).
func (s *Server) scheduleVerify(references ...string) {
	c := &s.signatures
	if !c.enabled || len(references) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return
	}
	c.mu.Lock()
	now := c.now()
	for _, reference := range references {
		if len(reference) > 1024 || !digestReferencePattern.MatchString(reference) {
			continue
		}
		e := c.entryLocked(reference)
		if e.queued || e.running || !e.storedAt.IsZero() && now.Before(e.expires) {
			continue
		}
		e.queued = true
		c.queue = append(c.queue, reference)
	}
	spawn := min(verifyWorkers-c.workers, len(c.queue))
	if spawn < 0 {
		spawn = 0
	}
	c.workers += spawn
	c.mu.Unlock()
	for range spawn {
		s.wg.Add(1)
		go s.verifyWorker()
	}
}
func (s *Server) verifyWorker() {
	defer s.wg.Done()
	c := &s.signatures
	for {
		c.mu.Lock()
		if len(c.queue) == 0 || s.ctx.Err() != nil {
			for _, reference := range c.queue {
				if e := c.entries[c.key(reference)]; e != nil {
					e.queued = false
				}
			}
			c.queue = nil
			c.workers--
			c.mu.Unlock()
			return
		}
		reference := c.queue[0]
		c.queue = c.queue[1:]
		e := c.entryLocked(reference)
		e.queued, e.running = false, true
		gen := e.gen
		c.mu.Unlock()

		ctx, cancel := context.WithTimeout(s.ctx, verifyTimeout)
		doc, err := s.cli.Verify(ctx, reference, "", c.allowHTTP)
		cancel()

		c.mu.Lock()
		e.running = false
		switch {
		case s.ctx.Err() != nil:
			// Shutdown: a canceled check is not a result.
		case e.gen != gen:
			// A build published this digest during the check; check again.
			e.queued = true
			c.queue = append(c.queue, reference)
		default:
			c.storeLocked(e, doc, err)
		}
		c.mu.Unlock()
	}
}

// invalidateSignatures drops cached results for digests a finished build
// published, signed, or attested. Without a record the build's registry side
// effects are unknown, so every cached result is dropped.
func (s *Server) invalidateSignatures(record *BuildRecord) {
	c := &s.signatures
	digests := map[string]bool{}
	all := record == nil
	if record != nil {
		for _, stage := range []StageOutcome{record.Stages.Publication, record.Stages.Signing, record.Stages.Attestation} {
			for _, value := range []string{stage.Digest, stage.ImmutableReference} {
				if i := strings.LastIndex(value, "sha256:"); i >= 0 && imageDigestPattern.MatchString(value[i:]) {
					digests[value[i:]] = true
				}
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(func(key verifyKey) bool { return all || digests[key.reference[len(key.reference)-71:]] })
}

// resetLocked discards matching results; a check running for one of them is
// discarded too and run again (see gen in verifyWorker).
func (c *signatureCache) resetLocked(match func(verifyKey) bool) {
	for key, e := range c.entries {
		if match(key) {
			e.gen++
			e.doc, e.err, e.storedAt, e.expires = nil, "", time.Time{}, time.Time{}
		}
	}
}

// warmSignatures queues the newest registry image of every track after a
// status refresh; detail pages queue the other images they show.
func (s *Server) warmSignatures(document *StatusDocument) {
	if document == nil {
		return
	}
	references := []string{}
	for _, track := range document.Tracks {
		if track.Newest != nil && track.Repository != "" {
			references = append(references, track.Repository+"@"+track.Newest.Digest)
		}
	}
	s.scheduleVerify(references...)
}

// signatureView returns the cached state for one track image and queues a
// check when it is missing or expired. It never waits for verification.
func (s *Server) signatureView(track Track, image Image) *SignatureView {
	c := &s.signatures
	if !c.enabled {
		return &SignatureView{State: "not-checked", Label: "Not checked", Detail: c.config().Reason}
	}
	reference := track.Repository + "@" + image.Digest
	if track.Repository == "" || len(reference) > 1024 || !digestReferencePattern.MatchString(reference) {
		return &SignatureView{State: "not-checked", Label: "Not checked", Detail: "This image has no digest reference that can be verified."}
	}
	s.scheduleVerify(reference)
	c.mu.Lock()
	var entry verifyEntry
	if e := c.entries[c.key(reference)]; e != nil {
		entry = *e
	}
	c.mu.Unlock()
	view := &SignatureView{Rechecking: entry.queued || entry.running}
	switch {
	case entry.storedAt.IsZero() && view.Rechecking:
		view.State, view.Label, view.Rechecking = "checking", "Checking…", false
		view.Detail = "Verification is running in the background."
	case entry.storedAt.IsZero():
		view.State, view.Label = "not-checked", "Not checked yet"
	case entry.doc == nil:
		view.State, view.Label, view.Detail = "error", "Error", entry.err
		view.CheckedAt = entry.storedAt.UTC()
	default:
		d := entry.doc
		view.CheckedAt = d.CheckedAt
		view.KeySHA256 = d.Trust.PublicKeySHA256
		view.TransparencyLog = d.TransparencyLog
		view.LocalOnly = d.TransparencyLog == "skipped-local"
		view.State = d.Signature.State
		view.Detail = shortDetail(d.Signature.Error)
		switch d.Signature.State {
		case "signed":
			view.Label = "Signed"
		case "unsigned":
			view.Label = "Unsigned"
		case "invalid":
			view.Label = "Invalid"
		default:
			view.Label = "Error"
		}
		view.Attestation = d.Attestation.State
		view.AttestationDetail = shortDetail(d.Attestation.Error)
		switch d.Attestation.State {
		case "attested":
			view.AttestationLabel = "SBOM attested"
			if d.Attestation.SBOM != nil {
				view.SBOMPackages = d.Attestation.SBOM.Packages
			}
			view.SBOMURL = "/images/" + url.PathEscape(track.Package) + "/" + url.PathEscape(track.Selector) + "/sbom/" + image.Digest
		case "absent":
			view.AttestationLabel = "No SBOM attestation"
		case "invalid":
			view.AttestationLabel = "Invalid SBOM attestation"
		default:
			view.AttestationLabel = "SBOM check error"
		}
	}
	return view
}

// attachSignatures fills a row's signature views: every track image, or only
// the newest one for the Images home. It reports whether any is still pending.
func (s *Server) attachSignatures(row *ProductRow, newestOnly bool) bool {
	row.Signatures = map[string]*SignatureView{}
	pending := false
	for _, image := range row.Track.Images {
		if newestOnly && (row.Track.Newest == nil || image.Digest != row.Track.Newest.Digest) {
			continue
		}
		if _, seen := row.Signatures[image.Digest]; seen {
			continue
		}
		view := s.signatureView(row.Track, image)
		row.Signatures[image.Digest] = view
		pending = pending || view.State == "checking"
	}
	if row.Track.Newest != nil {
		row.NewestSignature = row.Signatures[row.Track.Newest.Digest]
		if row.NewestSignature == nil {
			row.NewestSignature = s.signatureView(row.Track, *row.Track.Newest)
			pending = pending || row.NewestSignature.State == "checking"
		}
	}
	return pending
}

// downloadSignedSBOM serves the SPDX predicate of a verified attestation. The
// image must be in the cached status and cached as attested; the CLI then
// verifies again and writes the predicate into a private temporary directory,
// whose bytes must match the SHA-256 it reports. Nothing is served from cache.
func (s *Server) downloadSignedSBOM(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if !imageDigestPattern.MatchString(digest) {
		http.Error(w, "invalid image digest", http.StatusBadRequest)
		return
	}
	var track *Track
	var image *Image
	if status := s.status.snapshot(); status.Document != nil {
	tracks:
		for _, t := range status.Document.Tracks {
			if t.Package != r.PathValue("package") || t.Selector != r.PathValue("selector") {
				continue
			}
			for _, i := range t.Images {
				if i.Digest == digest {
					track, image = &t, &i
					break tracks
				}
			}
		}
	}
	if track == nil || track.Repository == "" {
		http.Error(w, "image is not a registry image of this track in the cached status", http.StatusNotFound)
		return
	}
	c := &s.signatures
	if !c.enabled {
		http.Error(w, c.config().Reason, http.StatusConflict)
		return
	}
	reference := track.Repository + "@" + image.Digest
	if len(reference) > 1024 || !digestReferencePattern.MatchString(reference) {
		http.Error(w, "image has no verifiable digest reference", http.StatusNotFound)
		return
	}
	c.mu.Lock()
	cached := c.entries[c.key(reference)]
	attested := cached != nil && cached.doc != nil && cached.doc.Attestation.State == "attested"
	c.mu.Unlock()
	if !attested {
		http.Error(w, "no verified SPDX attestation is known for this image; wait for its signature check to report it as attested", http.StatusConflict)
		return
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		http.Error(w, "signed SBOM downloads are busy; retry shortly", http.StatusServiceUnavailable)
		return
	}
	readCtx, finish, err := s.dashboardReadContext()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer finish()
	ctx, cancel := context.WithTimeout(readCtx, signedSBOMTimeout)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()

	dir, err := os.MkdirTemp("", "lupetto-explorer-sbom-")
	if err != nil {
		http.Error(w, "cannot create a private temporary directory", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)
	if dir, err = filepath.Abs(dir); err != nil {
		http.Error(w, "cannot resolve the private temporary directory", http.StatusInternalServerError)
		return
	}
	const name = "attested.spdx.json"
	c.mu.Lock()
	var gen uint64
	if e := c.entries[c.key(reference)]; e != nil {
		gen = e.gen
	}
	c.mu.Unlock()
	doc, err := s.cli.Verify(ctx, reference, filepath.Join(dir, name), c.allowHTTP)
	if err != nil {
		http.Error(w, "fresh verification failed: "+shortDetail(err.Error()), http.StatusBadGateway)
		return
	}
	c.mu.Lock()
	// A build that invalidated this digest during the check wins (gen).
	if e := c.entries[c.key(reference)]; e != nil && !e.running && e.gen == gen {
		c.storeLocked(e, doc, nil)
	}
	c.mu.Unlock()
	if doc.Attestation.State != "attested" {
		http.Error(w, "the SPDX attestation is no longer verified (state: "+doc.Attestation.State+")", http.StatusConflict)
		return
	}
	data, err := readPrivateFile(dir, name)
	if err != nil {
		http.Error(w, "verified SBOM could not be read: "+err.Error(), http.StatusBadGateway)
		return
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != doc.Attestation.SBOM.SHA256 {
		http.Error(w, "verified SBOM bytes do not match the attestation's reported SHA-256", http.StatusBadGateway)
		return
	}
	if !json.Valid(data) {
		http.Error(w, "verified SBOM is not valid JSON", http.StatusBadGateway)
		return
	}
	// Verification used most of the request's time; give the body its own
	// write budget instead of the remainder of the server WriteTimeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(signedSBOMWriteTimeout))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Content-Type", "application/spdx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+signedSBOMFilename(*image)+`"`)
	_, _ = w.Write(data)
}

// readPrivateFile reads one regular file from Explorer's own temporary
// directory, refusing symlinks, FIFOs and oversized content.
func readPrivateFile(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("SBOM output must be a regular file")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxDocumentBytes {
		return nil, errors.New("SBOM output must be a regular file no larger than 32 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocumentBytes {
		return nil, errOutputLimit
	}
	return data, nil
}

// signedSBOMFilename derives a header-safe name from registry annotations,
// which are untrusted: only [A-Za-z0-9._+-] survive.
func signedSBOMFilename(image Image) string {
	safe := func(value string, limit int) string {
		var b strings.Builder
		for _, r := range value {
			if b.Len() >= limit {
				break
			}
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '+' || r == '-' {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
			}
		}
		return strings.Trim(b.String(), ".")
	}
	parts := []string{"lupetto"}
	if name := safe(image.Name, 64); name != "" {
		parts = append(parts, name)
	}
	if version := safe(image.Version, 64); version != "" {
		parts = append(parts, version)
	}
	parts = append(parts, strings.TrimPrefix(image.Digest, "sha256:")[:12])
	return strings.Join(parts, "-") + ".spdx.json"
}
