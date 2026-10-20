package explorer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func (s *Server) inventory(ctx context.Context) InventoryView {
	s.dashboard.mu.Lock()
	view, fresh := s.dashboard.inventory, time.Since(s.dashboard.inventoryAt) < 15*time.Second
	s.dashboard.mu.Unlock()
	if fresh {
		return view
	}
	result := s.dashboard.loads.DoChan("inventory", func() (any, error) {
		s.dashboard.mu.Lock()
		view, fresh := s.dashboard.inventory, time.Since(s.dashboard.inventoryAt) < 15*time.Second
		generation := s.dashboard.inventoryGeneration
		s.dashboard.mu.Unlock()
		if fresh {
			return view, nil
		}
		readCtx, finish, err := s.dashboardReadContext()
		if err != nil {
			view.Error = err.Error()
			return view, nil
		}
		defer finish()
		document, err := s.cli.Images(readCtx)
		s.dashboard.mu.Lock()
		defer s.dashboard.mu.Unlock()
		if err != nil {
			s.dashboard.inventory.Error = err.Error()
		} else {
			s.dashboard.inventory = InventoryView{Document: document}
		}
		// A build/edit that finished during the read must not make older
		// inventory fresh for another TTL.
		if s.dashboard.inventoryGeneration == generation {
			s.dashboard.inventoryAt = time.Now()
		}
		return s.dashboard.inventory, nil
	})
	select {
	case loaded := <-result:
		return loaded.Val.(InventoryView)
	case <-ctx.Done():
		view = s.dashboard.inventorySnapshot()
		view.Error = ctx.Err().Error()
		return view
	}
}
func (s *Server) invalidateInventory() {
	s.dashboard.mu.Lock()
	s.dashboard.inventoryAt = time.Time{}
	s.dashboard.inventoryGeneration++
	s.dashboard.mu.Unlock()
}
func (s *Server) inspect(ctx context.Context, reference string) (*InspectDocument, error) {
	s.dashboard.mu.Lock()
	document := s.dashboard.inspect[reference]
	s.dashboard.mu.Unlock()
	if document != nil {
		return document, nil
	}
	result := s.dashboard.loads.DoChan("inspect:"+reference, func() (any, error) {
		s.dashboard.mu.Lock()
		document := s.dashboard.inspect[reference]
		s.dashboard.mu.Unlock()
		if document != nil {
			return document, nil
		}
		readCtx, finish, err := s.dashboardReadContext()
		if err != nil {
			return nil, err
		}
		defer finish()
		document, err = s.cli.Inspect(readCtx, reference)
		if err != nil {
			return nil, err
		}
		s.dashboard.mu.Lock()
		defer s.dashboard.mu.Unlock()
		if s.dashboard.inspect == nil || len(s.dashboard.inspect) >= 256 {
			s.dashboard.inspect = map[string]*InspectDocument{}
		}
		s.dashboard.inspect[reference] = document
		return document, nil
	})
	select {
	case loaded := <-result:
		if loaded.Err != nil {
			return nil, loaded.Err
		}
		return loaded.Val.(*InspectDocument), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Shared reads outlive a disconnected client, but not the server. Register
// them before Close can start waiting; no new subprocess starts after closing.
func (s *Server) dashboardReadContext() (context.Context, func(), error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, nil, ErrShuttingDown
	}
	s.wg.Add(1)
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, 25*time.Second)
	return ctx, func() { cancel(); s.wg.Done() }, nil
}
func (s *Server) images(w http.ResponseWriter, r *http.Request) {
	query, filter := r.URL.Query().Get("q"), r.URL.Query().Get("filter")
	if filter == "action" {
		filter = "needs-action"
	}
	if filter == "notbuilt" {
		filter = "not-in-registry"
	}
	if len(query) > 256 {
		http.Error(w, "image query exceeds 256 bytes", 400)
		return
	}
	if filter != "" && filter != "all" && filter != "needs-action" && filter != "current" && filter != "not-in-registry" && filter != "critical" {
		http.Error(w, "invalid image filter", 400)
		return
	}
	view := ImagesView{BaseView: s.base(), Status: s.status.snapshot(), Inventory: s.inventory(r.Context()), Products: []ProductRow{}, Groups: []ProductGroup{}, Query: query, Filter: filter}
	view.Empty = view.Status.Empty
	if view.Status.Document != nil {
		tracks := append([]Track(nil), view.Status.Document.Tracks...)
		sort.SliceStable(tracks, func(i, j int) bool { return tracks[i].Package < tracks[j].Package })
		for _, track := range tracks {
			row := joinTrack(track, view.Inventory.Document)
			view.Summary.All++
			if row.Severity.Critical > 0 {
				view.Summary.MissingCritical++
			}
			if row.NeedsAction {
				view.Summary.NeedsAction++
			}
			if track.State == "current" {
				view.Summary.Current++
			}
			if track.State == "not-built" {
				view.Summary.NotInRegistry++
			}
			if !strings.Contains(strings.ToLower(track.Package), strings.ToLower(query)) {
				continue
			}
			if filter == "needs-action" && !row.NeedsAction || filter == "current" && track.State != "current" || filter == "not-in-registry" && track.State != "not-built" {
				continue
			}
			if filter == "critical" && row.Severity.Critical == 0 {
				continue
			}
			if s.attachSignatures(&row, true) {
				view.SignaturesPending = true
			}
			view.Products = append(view.Products, row)
			view.TotalMatches++
			if len(view.Groups) == 0 || view.Groups[len(view.Groups)-1].Package != row.Package {
				view.Groups = append(view.Groups, ProductGroup{Package: row.Package, DetailURL: row.DetailURL, Rows: []ProductRow{}})
			}
			last := len(view.Groups) - 1
			view.Groups[last].Rows = append(view.Groups[last].Rows, row)
		}
	}
	if value := r.URL.Query().Get("tracked"); validPackage(value) {
		view.Notice.Tracked = value
	}
	if value := r.URL.Query().Get("untracked"); validPackage(value) {
		view.Notice.Untracked = value
	}
	view.BaseView = s.base()
	s.render(w, r, "images", view)
}
func (s *Server) image(w http.ResponseWriter, r *http.Request) {
	status := s.status.snapshot()
	var track *Track
	if status.Document != nil {
		for _, t := range status.Document.Tracks {
			if t.Package == r.PathValue("package") && t.Selector == r.PathValue("selector") {
				copy := t
				track = &copy
				break
			}
		}
	}
	if track == nil {
		http.Error(w, "track is not present in cached status; wait for or request a refresh", 404)
		return
	}
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}
	switch tab {
	case "overview", "vulnerabilities", "packages", "compare", "builds":
	default:
		http.Error(w, "invalid image tab", 400)
		return
	}
	inventory := s.inventory(r.Context())
	view := ImageView{BaseView: s.base(), Status: status, Inventory: inventory, Product: joinTrack(*track, inventory.Document), Tab: tab, Versions: []PackageSet{}, FixedByRebuilding: []MissingFix{}, NeedsAnotherVersion: []MissingFix{}, Builds: []BuildItem{}}
	view.SignaturesPending = s.attachSignatures(&view.Product, false)
	for _, f := range track.MissingFixes {
		if f.ReachableByTrack {
			view.FixedByRebuilding = append(view.FixedByRebuilding, f)
		} else {
			view.NeedsAnotherVersion = append(view.NeedsAnotherVersion, f)
		}
	}
	for _, t := range status.Document.Tracks {
		if t.Package == track.Package {
			view.Siblings = append(view.Siblings, ImageSibling{Selector: t.Selector, URL: "/images/" + url.PathEscape(t.Package) + "/" + url.PathEscape(t.Selector), Current: t.Selector == track.Selector})
		}
	}
	siblingTracks := []Track{*track}
	for _, t := range status.Document.Tracks {
		if t.Package == track.Package && t.Selector != track.Selector {
			siblingTracks = append(siblingTracks, t)
		}
	}
	seen := map[string]bool{}
	for _, t := range siblingTracks {
		for _, image := range t.Images {
			if !seen[image.Digest] {
				seen[image.Digest] = true
				view.Versions = append(view.Versions, PackageSet{Key: image.Digest, Label: image.Version + " · registry · " + shortDigest(image.Digest), Source: "registry"})
			}
		}
		for _, row := range joinTrack(t, inventory.Document).Versions {
			for _, b := range row.Builds {
				if !seen[b.ID] {
					seen[b.ID] = true
					view.Versions = append(view.Versions, PackageSet{Key: b.ID, Label: b.Version + " · local build", Source: "local", SPDXURL: b.SPDXURL})
				}
			}
		}
	}
	jobs, _ := s.jobs.list()
	for _, item := range mergeBuilds(inventory.Document, jobs) {
		if item.Package == track.Package || track.Latest != nil && item.Package == track.Latest.Name || item.Record != nil && item.Record.Request.Package == track.Package {
			view.Builds = append(view.Builds, item)
		}
	}
	if tab == "packages" {
		key := r.URL.Query().Get("version")
		if key == "" && len(view.Versions) > 0 {
			key = view.Versions[0].Key
		}
		view.Packages = s.productPackageSet(r.Context(), siblingTracks, inventory.Document, key)
		if view.Packages.Source == "registry" {
		signature:
			for _, t := range siblingTracks {
				for _, image := range t.Images {
					if image.Digest == view.Packages.Key {
						view.Packages.Signature = s.signatureView(t, image)
						break signature
					}
				}
			}
		}
	}
	if tab == "compare" {
		view.Compare.From = r.URL.Query().Get("from")
		view.Compare.To = r.URL.Query().Get("to")
		view.Compare.Changes = []PackageChange{}
		if view.Compare.From == "" && len(view.Versions) > 0 {
			view.Compare.From = view.Versions[0].Key
		}
		if view.Compare.To == "" && len(view.Versions) > 1 {
			view.Compare.To = view.Versions[1].Key
		}
		if view.Compare.From != "" && view.Compare.To != "" {
			view.Compare.Before = s.productPackageSet(r.Context(), siblingTracks, inventory.Document, view.Compare.From)
			view.Compare.After = s.productPackageSet(r.Context(), siblingTracks, inventory.Document, view.Compare.To)
			if view.Compare.Before.Error != "" || view.Compare.After.Error != "" {
				view.Compare.Error = "Package evidence unavailable for one or both selections"
			} else {
				view.Compare.Changes = diffPackages(view.Compare.Before.Packages, view.Compare.After.Packages)
			}
		} else {
			view.Compare.Error = "Two versions with package evidence are required to compare"
		}
		for _, change := range view.Compare.Changes {
			switch change.Kind {
			case "added":
				view.Compare.Added++
			case "removed":
				view.Compare.Removed++
			case "changed":
				view.Compare.Changed++
			}
		}
		if view.Compare.Error == "" {
			view.Compare.Unchanged = len(view.Compare.Before.Packages) - view.Compare.Removed - view.Compare.Changed
		}
	}
	s.render(w, r, "image", view)
}
func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}
func (s *Server) packageSet(ctx context.Context, track Track, inventory *ImagesDocument, key string) PackageSet {
	set := PackageSet{Key: key, Packages: []PackageIdentity{}}
	for _, image := range track.Images {
		if image.Digest != key {
			continue
		}
		set.Label = image.Version
		set.Source = "registry"
		if track.Newest != nil && track.Newest.Digest == key {
			set.Packages = track.Installed
			return set
		}
		d, err := s.inspect(ctx, track.Repository+"@"+image.Digest)
		if err != nil {
			set.Error = err.Error()
		} else {
			set.Packages = d.Packages
		}
		return set
	}
	if inventory != nil {
		for _, b := range inventory.Builds {
			if buildID(b) != key {
				continue
			}
			// The selection must belong to the track; never expose another build by arbitrary ID.
			allowed := false
			for _, row := range joinTrack(track, inventory).Versions {
				for _, item := range row.Builds {
					if item.ID == key {
						allowed = true
					}
				}
			}
			if !allowed {
				break
			}
			set.Source = "local"
			set.Label = buildItem(b).Version
			data, err := readValidatedSPDX(b)
			if err != nil {
				set.Error = err.Error()
				return set
			}
			set.Packages, err = spdxPackages(data)
			if err != nil {
				set.Error = err.Error()
			} else {
				set.SPDXURL = "/builds/" + key + "/sbom"
			}
			return set
		}
	}
	set.Error = "No retained package evidence for this selection"
	return set
}
func (s *Server) builds(w http.ResponseWriter, r *http.Request) {
	inventory := s.inventory(r.Context())
	jobs, running := s.jobs.list()
	items := mergeBuilds(inventory.Document, jobs)
	if pkg := r.URL.Query().Get("package"); pkg != "" {
		filtered := []BuildItem{}
		for _, item := range items {
			if item.Package == pkg || item.Record != nil && item.Record.Request.Package == pkg {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	s.render(w, r, "jobs", JobsView{BaseView: s.base(), Jobs: jobs, Items: items, Inventory: inventory, Running: running, HistoryLimit: HistoryLimit})
}
func (s *Server) buildDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, log, ok := s.jobs.detail(id, 0)
	if ok {
		item := liveItem(job)
		if job.Record != nil {
			inventory := s.inventory(r.Context())
			items := mergeBuilds(inventory.Document, []JobView{job})
			for _, candidate := range items {
				if candidate.ID == id {
					item = candidate
					break
				}
			}
		}
		s.render(w, r, "job", JobDetailView{BaseView: s.base(), Job: job, Log: log, Item: item, HasLog: true})
		return
	}
	inventory := s.inventory(r.Context())
	if inventory.Document != nil {
		for _, b := range inventory.Document.Builds {
			if buildID(b) == id {
				s.render(w, r, "job", JobDetailView{BaseView: s.base(), Item: buildItem(b)})
				return
			}
		}
	}
	http.NotFound(w, r)
}
func (s *Server) downloadSPDX(w http.ResponseWriter, r *http.Request) {
	inventory := s.inventory(r.Context())
	if inventory.Document != nil {
		for _, b := range inventory.Document.Builds {
			if buildID(b) != r.PathValue("id") {
				continue
			}
			data, err := readValidatedSPDX(b)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/spdx+json")
			w.Header().Set("Content-Disposition", `attachment; filename="lupetto-`+buildID(b)+`.spdx.json"`)
			_, _ = w.Write(data)
			return
		}
	}
	http.NotFound(w, r)
}
func (s *Server) tracking(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	d, err := s.cli.Products(ctx, s.config.Products, "list", "", nil)
	view := TrackingView{BaseView: s.base(), Package: r.URL.Query().Get("package"), Selector: r.URL.Query().Get("selector"), Products: d}
	if err != nil {
		view.Error = err.Error()
	}
	s.render(w, r, "tracking", view)
}
func (s *Server) editProducts(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r) {
		return
	}
	action := r.PathValue("action")
	if action != "add" && action != "remove" {
		http.NotFound(w, r)
		return
	}
	if !uniqueFields(w, r, "package", "selector", "selectors") {
		return
	}
	if oneField(r, "selector") != "" && oneField(r, "selectors") != "" {
		http.Error(w, "provide selector or selectors, not both", 400)
		return
	}
	name := oneField(r, "package")
	raw := oneField(r, "selectors")
	if raw == "" {
		raw = oneField(r, "selector")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	s.productsMu.Lock()
	d, err := s.cli.Products(ctx, s.config.Products, action, name, strings.Fields(raw))
	s.productsMu.Unlock()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "tracking", TrackingView{BaseView: s.base(), Package: name, Selector: raw, Error: fmt.Sprintf("Tracking could not be changed: %v. The products file and its directory must be writable (mount the directory, not a single file).", err)})
		return
	}
	s.refreshAfterBuild()
	key := "tracked"
	if action == "remove" {
		key = "untracked"
	}
	_ = d
	http.Redirect(w, r, "/?"+key+"="+url.QueryEscape(name), http.StatusSeeOther)
}

func (s *Server) shell() ShellView {
	status := s.status.snapshot()
	shell := ShellView{StatusRefreshing: status.Refreshing, RegistryState: "unknown", DockerState: "unknown", Signatures: s.signatures.config()}
	if d := status.Document; d != nil {
		shell.Registry = d.Registry + "/" + d.Repository
		shell.StatusComputedAt = d.ComputedAt
		shell.IndexSHA256 = d.IndexSHA256
		shell.FeedSHA256 = d.Security.SHA256
		shell.Architecture = d.Architecture
		shell.RegistryState = "ready"
		for _, track := range d.Tracks {
			if track.State == "error" {
				shell.RegistryState = "error"
				break
			}
		}
	}
	if status.LastError != "" {
		shell.RegistryState = "error"
	}
	inventoryView := s.dashboard.inventorySnapshot()
	shell.PublishLoad, shell.PublishLoadReason = publishLoadDecision(inventoryView)
	shell.PublishSigning = publishSigningState(s.config.EnableBuilds, os.Getenv)
	inventory := inventoryView.Document
	if inventory != nil {
		shell.DockerState = "unavailable"
		if inventory.Docker.Available {
			shell.DockerState = "available"
		}
		shell.DockerReason = inventory.Docker.Reason
	}
	jobs, _ := s.jobs.list()
	for _, job := range jobs {
		if job.State == "running" {
			item := liveItem(job)
			shell.RunningBuild = &item
			break
		}
	}
	return shell
}

// publishSigningState says whether a "Build & publish" started now would be
// signed. It reads only the inherited environment's presence and values, never
// the key or token file: "" when builds or publication are not enabled, "key"
// when LUPETTO_COSIGN_KEY or LUPETTO_COSIGN_IDENTITY_TOKEN_FILE (keyless) is
// set, "refused" when neither is and LUPETTO_REQUIRE_SIGNING is true (the CLI
// rejects the build), else "unsigned".
func publishSigningState(builds bool, getenv func(string) string) string {
	switch {
	case !builds || getenv("LUPETTO_REGISTRY") == "" || getenv("LUPETTO_REPOSITORY") == "":
		return ""
	case getenv("LUPETTO_COSIGN_KEY") != "" || getenv("LUPETTO_COSIGN_IDENTITY_TOKEN_FILE") != "":
		return "key"
	case getenv("LUPETTO_REQUIRE_SIGNING") == "true":
		return "refused"
	}
	return "unsigned"
}

func (s *Server) productPackageSet(ctx context.Context, tracks []Track, inventory *ImagesDocument, key string) PackageSet {
	for _, track := range tracks {
		for _, image := range track.Images {
			if image.Digest == key {
				return s.packageSet(ctx, track, inventory, key)
			}
		}
		for _, row := range joinTrack(track, inventory).Versions {
			for _, build := range row.Builds {
				if build.ID == key {
					return s.packageSet(ctx, track, inventory, key)
				}
			}
		}
	}
	return PackageSet{Key: key, Packages: []PackageIdentity{}, Error: "No retained package evidence for this selection"}
}

func uniqueFields(w http.ResponseWriter, r *http.Request, names ...string) bool {
	for _, name := range names {
		if len(r.PostForm[name]) > 1 {
			http.Error(w, "form field "+name+" must occur at most once", http.StatusBadRequest)
			return false
		}
	}
	return true
}
