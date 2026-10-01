package explorer

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type dashboardState struct {
	mu                  sync.Mutex
	inventory           InventoryView
	inventoryAt         time.Time
	inspect             map[string]*InspectDocument
	loads               singleflight.Group
	inventoryGeneration uint64
}

func (d *dashboardState) inventorySnapshot() InventoryView {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inventory
}

func publishLoadDecision(inventory InventoryView) (bool, string) {
	if inventory.Document == nil {
		return false, "Docker availability is unknown"
	}
	if inventory.Document.Docker.Available {
		return true, ""
	}
	reason := inventory.Document.Docker.Reason
	if reason == "" {
		reason = "Docker is unavailable"
	}
	return false, reason
}

func buildID(b InventoryBuild) string {
	sum := sha256.Sum256([]byte(b.RecordPath))
	return "record-" + hex.EncodeToString(sum[:12])
}
func buildItem(b InventoryBuild) BuildItem {
	item := BuildItem{ID: buildID(b), State: b.Status, StartedAt: b.RecordedAt, Record: b.Record, Error: b.Error}
	item.DetailURL = "/builds/" + item.ID
	if b.BuildTime != nil {
		item.StartedAt = *b.BuildTime
	}
	if b.Record != nil {
		item.Package = b.Record.Request.Package
		item.Load = b.Record.Request.Load
		if b.Record.Request.Publish {
			item.Mode = "publish"
		} else if item.Load {
			item.Mode = "local"
		}
		item.State = b.Record.Outcome
		if b.Record.Selection != nil {
			item.Package = b.Record.Selection.Package
			item.Version = b.Record.Selection.Version
		}
	}
	item.Stages = buildStages(b.Record, false)
	if b.SPDX.Present {
		item.SPDXURL = item.DetailURL + "/sbom"
	}
	return item
}
func buildStages(record *BuildRecord, running bool) []BuildStage {
	stages := []BuildStage{{"resolve", "not-attempted"}, {"build", "not-attempted"}, {"validate", "not-attempted"}, {"load", "not-attempted"}, {"publish", "not-attempted"}, {"sign", "not-attempted"}, {"attest", "not-attempted"}}
	if record == nil {
		if running {
			stages[0].Status = "running"
		}
		return stages
	}
	if record.Selection != nil {
		stages[0].Status = "completed"
	}
	stages[1].Status = record.Stages.Build.Status
	if record.Evidence != nil && record.Evidence.SPDXValidated {
		stages[2].Status = "completed"
	}
	stages[3].Status = record.Stages.Load.Status
	stages[4].Status = record.Stages.Publication.Status
	stages[5].Status = record.Stages.Signing.Status
	stages[6].Status = record.Stages.Attestation.Status
	if record.Failure != nil {
		stage := record.Failure.Stage
		idx := -1
		switch {
		case strings.Contains(stage, "valid") || stage == "installed" || stage == "spdx":
			idx = 2
		case strings.Contains(stage, "load") || strings.Contains(stage, "docker") || stage == "readable-tag":
			idx = 3
		case stage == "publication":
			idx = 4
		case stage == "signing" || stage == "cosign-version":
			idx = 5
		case stage == "attestation":
			idx = 6
		case stage == "build" || stage == "lock":
			idx = 1
		case stage == "record":
			idx = -1
		}
		if idx >= 0 {
			stages[idx].Status = "failed"
		}
	}
	return stages
}
func liveItem(job JobView) BuildItem {
	item := BuildItem{ID: job.ID, DetailURL: "/builds/" + job.ID, Package: job.Request.Package, Version: job.Request.APKVersion, State: job.State, StartedAt: job.StartedAt, Record: job.Record, Error: job.Error, Live: true, Stages: buildStages(job.Record, job.State == "running")}
	item.Mode, item.Load, item.LoadReason = job.Request.Mode, job.Request.Load, job.Request.LoadReason
	if job.State == "running" {
		item.Stages = job.Progress
		if len(item.Stages) != 7 {
			item.Stages = liveStages("", job.Request)
		}
	}
	if job.Record != nil && job.Record.Selection != nil {
		item.Package = job.Record.Selection.Package
		item.Version = job.Record.Selection.Version
	}
	return item
}
func mergeBuilds(inventory *ImagesDocument, jobs []JobView) []BuildItem {
	items := []BuildItem{}
	workspaces := map[string]bool{}
	for _, job := range jobs {
		item := liveItem(job)
		if job.Record != nil {
			workspaces[job.Record.Workspace] = true
			if inventory != nil {
				for _, b := range inventory.Builds {
					if b.Workspace == job.Record.Workspace && b.SPDX.Present {
						item.SPDXURL = "/builds/" + buildID(b) + "/sbom"
						break
					}
				}
			}
		}
		items = append(items, item)
	}
	if inventory != nil {
		for _, b := range inventory.Builds {
			if !workspaces[b.Workspace] {
				items = append(items, buildItem(b))
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].StartedAt.After(items[j].StartedAt) })
	return items
}
func severityCounts(track Track) SeverityCounts {
	byID := map[string]string{}
	add := func(ids []string, advisories []Advisory) {
		for _, id := range ids {
			if _, ok := byID[id]; !ok {
				byID[id] = "unknown"
			}
		}
		for _, a := range advisories {
			byID[a.ID] = a.Severity
		}
	}
	for _, f := range track.MissingFixes {
		add(f.IDs, f.Advisories)
	}
	for _, f := range track.UnevaluatedFixes {
		add(f.IDs, f.Advisories)
	}
	c := SeverityCounts{Total: len(byID)}
	for _, severity := range byID {
		switch severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}
func joinTrack(track Track, inventory *ImagesDocument) ProductRow {
	row := ProductRow{Package: track.Package, Selector: track.Selector, Track: track, DetailURL: "/images/" + url.PathEscape(track.Package) + "/" + url.PathEscape(track.Selector), Versions: []VersionRow{}, Severity: severityCounts(track)}
	indexes := map[PackageIdentity]int{}
	add := func(identity PackageIdentity) int {
		if i, ok := indexes[identity]; ok {
			return i
		}
		i := len(row.Versions)
		indexes[identity] = i
		row.Versions = append(row.Versions, VersionRow{Identity: identity, Key: identity.Name + "@" + identity.Version + "/" + identity.Architecture, Registry: []Image{}, LocalImages: []DockerImage{}, Builds: []BuildItem{}})
		return i
	}
	if track.Latest != nil {
		row.Versions[add(*track.Latest)].Latest = true
	}
	for _, image := range track.Images {
		i := add(PackageIdentity{image.Name, image.Version, image.Architecture})
		row.Versions[i].Registry = append(row.Versions[i].Registry, image)
	}
	matches := func(identity PackageIdentity) bool {
		if track.Latest != nil {
			if identity.Name != track.Latest.Name || identity.Architecture != track.Latest.Architecture {
				return false
			}
		} else {
			found := false
			for _, image := range track.Images {
				if image.Name == identity.Name && image.Architecture == identity.Architecture {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		upstream := strings.Split(identity.Version, "-r")[0]
		return upstream == track.Selector || strings.HasPrefix(upstream, track.Selector+".")
	}
	if inventory != nil {
		for _, image := range inventory.Docker.Images {
			if image.IdentityKnown && image.Identity != nil && matches(*image.Identity) {
				i := add(*image.Identity)
				row.Versions[i].LocalImages = append(row.Versions[i].LocalImages, image)
			}
		}
		for _, build := range inventory.Builds {
			if build.Record == nil || build.Record.Selection == nil || build.Record.Stages.Build.Status != "completed" {
				continue
			}
			s := build.Record.Selection
			identity := PackageIdentity{s.Package, s.Version, s.Architecture}
			if matches(identity) {
				i := add(identity)
				row.Versions[i].Builds = append(row.Versions[i].Builds, buildItem(build))
			}
		}
	}
	row.Action = PrimaryAction{Kind: "build", Package: track.Package, Selector: track.Selector, Mode: "publish"}
	row.NeedsAction = true
	switch track.State {
	case "current":
		row.Verdict = "Up to date"
		row.NeedsAction = false
		row.Action.Label = "Build locally"
		row.Action.Mode = "local"
	case "update-available":
		row.Verdict = "Update available"
		row.Action.Label = "Update"
	case "fixes-available":
		row.Verdict = "Fixes available"
		row.Action.Label = "Rebuild for fixes"
	case "not-built":
		row.Verdict = "Not in registry"
		row.Action.Label = "Build & publish"
	default:
		row.Verdict = "Unable to compare"
		row.Action = PrimaryAction{Label: "Edit tracking", Kind: "tracking", URL: "/products/track?package=" + url.QueryEscape(track.Package) + "&selector=" + url.QueryEscape(track.Selector), Package: track.Package, Selector: track.Selector}
	}
	if track.State == "current" && (len(track.UnevaluatedFixes) > 0 || len(track.MissingFixes) > 0) {
		row.Verdict = "Up to date · review advisories"
	}
	switch track.State {
	case "current":
		row.VerdictKind = "ok"
	case "update-available":
		row.VerdictKind = "update"
	case "fixes-available":
		row.VerdictKind = "rebuild"
	case "not-built":
		row.VerdictKind = "notbuilt"
	default:
		row.VerdictKind = "error"
	}
	for _, fix := range track.MissingFixes {
		if !fix.ReachableByTrack {
			row.UnreachableCount++
		}
	}
	if track.Latest != nil && track.Newest != nil && track.Latest.Version != track.Newest.Version {
		row.VerdictDetail = track.Newest.Version + " → " + track.Latest.Version
	}
	if track.State == "not-built" {
		for _, version := range row.Versions {
			if len(version.LocalImages) > 0 || len(version.Builds) > 0 {
				row.Verdict = "Local only"
				row.VerdictKind = "local"
				break
			}
		}
	}
	return row
}
func diffPackages(before, after []PackageIdentity) []PackageChange {
	type key struct{ name, arch string }
	a := map[key]string{}
	b := map[key]string{}
	for _, p := range before {
		a[key{p.Name, p.Architecture}] = p.Version
	}
	for _, p := range after {
		b[key{p.Name, p.Architecture}] = p.Version
	}
	changes := []PackageChange{}
	for k, v := range a {
		other, ok := b[k]
		if !ok {
			changes = append(changes, PackageChange{k.name, k.arch, v, "", "removed"})
		} else if other != v {
			changes = append(changes, PackageChange{k.name, k.arch, v, other, "changed"})
		}
	}
	for k, v := range b {
		if _, ok := a[k]; !ok {
			changes = append(changes, PackageChange{k.name, k.arch, "", v, "added"})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		return changes[i].Architecture < changes[j].Architecture
	})
	return changes
}

func liveStages(log string, request BuildRequest) []BuildStage {
	return liveStagesAt(livePhase(log), request)
}
func livePhase(log string) int {
	active := 0
	markers := []struct {
		text  string
		stage int
	}{
		{"Locking apko dependencies", 1}, {"Composing OCI image", 1},
		{"Checking installed APK", 2}, {"Validating SPDX", 2},
		{"Exporting Docker", 3}, {"Loading", 3}, {"Inspecting Docker", 3}, {"Tagging readable", 3},
		{"Pushing OCI image to registry", 4}, {"Verifying registry", 4}, {"Signing", 5}, {"Attesting", 6},
	}
	position := -1
	for _, marker := range markers {
		if i := strings.LastIndex(log, "lupetto: "+marker.text); i > position {
			position = i
			active = marker.stage
		}
	}
	return active
}
func liveStagesAt(active int, request BuildRequest) []BuildStage {
	stages := buildStages(nil, true)
	for i := range stages {
		if stages[i].Status == "not-attempted" {
			stages[i].Status = "pending"
		}
	}
	if !request.Load {
		stages[3].Status = "skipped"
	}
	if request.Mode == "local" {
		stages[4].Status = "skipped"
		stages[5].Status = "skipped"
		stages[6].Status = "skipped"
	}
	for i := range active {
		if stages[i].Status != "skipped" {
			stages[i].Status = "completed"
		}
	}
	if stages[active].Status != "skipped" {
		stages[active].Status = "running"
	}
	return stages
}
