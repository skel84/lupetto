// Package vulnscan scans images with the Grype library for the Explorer's
// upstream comparison, and keeps the results across restarts. It must not
// import CLI build, publication or signing packages.
package vulnscan

import (
	"sort"
	"strings"
)

// Severity levels, lowest to highest. Grype reports these (title-cased); any
// other value counts as unknown.
const (
	Unknown    = "unknown"
	Negligible = "negligible"
	Low        = "low"
	Medium     = "medium"
	High       = "high"
	Critical   = "critical"
)

// Severities lists every level from most to least severe.
var Severities = []string{Critical, High, Medium, Low, Negligible, Unknown}

func rank(severity string) int {
	switch severity {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Negligible:
		return 1
	}
	return 0
}

// NormalizeSeverity maps a scanner severity to one of the levels above.
func NormalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	if rank(severity) == 0 {
		return Unknown
	}
	return severity
}

// Counts holds unique issues per severity.
type Counts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
	Total      int `json:"total"`
}

func (c *Counts) add(severity string) {
	switch severity {
	case Critical:
		c.Critical++
	case High:
		c.High++
	case Medium:
		c.Medium++
	case Low:
		c.Low++
	case Negligible:
		c.Negligible++
	default:
		c.Unknown++
	}
	c.Total++
}

// Get returns the count for one severity level.
func (c Counts) Get(severity string) int {
	switch severity {
	case Critical:
		return c.Critical
	case High:
		return c.High
	case Medium:
		return c.Medium
	case Low:
		return c.Low
	case Negligible:
		return c.Negligible
	case Unknown:
		return c.Unknown
	}
	return 0
}

// Plus returns the per-severity sum of two counts.
func (c Counts) Plus(other Counts) Counts {
	return Counts{
		Critical: c.Critical + other.Critical, High: c.High + other.High, Medium: c.Medium + other.Medium,
		Low: c.Low + other.Low, Negligible: c.Negligible + other.Negligible, Unknown: c.Unknown + other.Unknown,
		Total: c.Total + other.Total,
	}
}

// Related is another identifier the scanner links to a finding, with the
// severity its own record gives.
type Related struct {
	ID       string
	Severity string
}

// Package identifies the affected package of a finding.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// Finding is one scanner match before deduplication.
type Finding struct {
	ID          string
	Severity    string
	Related     []Related
	Package     Package
	FixState    string
	FixVersions []string
}

// Affected is one package an issue was found in, with the versions the
// scanner lists as fixing it there.
type Affected struct {
	Package
	FixVersions []string `json:"fixVersions,omitempty"`
}

// Issue is one vulnerability after merging every identifier that refers to it.
type Issue struct {
	// ID is the first CVE identifier when there is one, else the first
	// identifier in sort order; Aliases holds the others.
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases,omitempty"`
	Severity string     `json:"severity"`
	Packages []Affected `json:"packages"`
	// FixState is "fixed" when any finding has a fix, else the scanner's
	// state (not-fixed, wont-fix or unknown).
	FixState string `json:"fixState"`
}

// IDs returns the issue's primary identifier followed by its aliases.
func (i Issue) IDs() []string { return append([]string{i.ID}, i.Aliases...) }

// Summarize merges findings into issues: identifiers are grouped by alias
// (a finding's ID with each related ID, transitively), so an advisory reported
// as a CVE and a GHSA, or against several packages, counts once. A finding's
// severity is its own record's, or the highest related record's when its own
// is unknown; an issue takes the highest severity of its findings.
func Summarize(findings []Finding) ([]Issue, Counts) {
	parent := map[string]string{}
	var find func(string) string
	find = func(id string) string {
		if parent[id] == "" || parent[id] == id {
			parent[id] = id
			return id
		}
		root := find(parent[id])
		parent[id] = root
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if rb < ra {
				ra, rb = rb, ra
			}
			parent[rb] = ra
		}
	}
	for _, finding := range findings {
		if finding.ID == "" {
			continue
		}
		find(finding.ID)
		for _, related := range finding.Related {
			if related.ID != "" {
				union(finding.ID, related.ID)
			}
		}
	}
	type group struct {
		ids      map[string]bool
		severity string
		packages map[Package]map[string]bool
		fixState string
	}
	groups := map[string]*group{}
	for _, finding := range findings {
		if finding.ID == "" {
			continue
		}
		root := find(finding.ID)
		g := groups[root]
		if g == nil {
			g = &group{ids: map[string]bool{}, severity: Unknown, packages: map[Package]map[string]bool{}}
			groups[root] = g
		}
		g.ids[finding.ID] = true
		own := NormalizeSeverity(finding.Severity)
		severity := own
		for _, related := range finding.Related {
			if related.ID == "" {
				continue
			}
			g.ids[related.ID] = true
			if r := NormalizeSeverity(related.Severity); own == Unknown && rank(r) > rank(severity) {
				severity = r
			}
		}
		if rank(severity) > rank(g.severity) {
			g.severity = severity
		}
		fixes := g.packages[finding.Package]
		if fixes == nil {
			fixes = map[string]bool{}
			g.packages[finding.Package] = fixes
		}
		for _, version := range finding.FixVersions {
			if version != "" {
				fixes[version] = true
			}
		}
		if fixRank(finding.FixState) > fixRank(g.fixState) {
			g.fixState = finding.FixState
		}
	}
	issues := make([]Issue, 0, len(groups))
	var counts Counts
	for _, g := range groups {
		ids := sortedKeys(g.ids)
		primary := ids[0]
		for _, id := range ids {
			if strings.HasPrefix(id, "CVE-") {
				primary = id
				break
			}
		}
		aliases := make([]string, 0, len(ids)-1)
		for _, id := range ids {
			if id != primary {
				aliases = append(aliases, id)
			}
		}
		packages := make([]Affected, 0, len(g.packages))
		for p, fixes := range g.packages {
			affected := Affected{Package: p, FixVersions: sortedKeys(fixes)}
			if len(affected.FixVersions) == 0 {
				affected.FixVersions = nil
			}
			packages = append(packages, affected)
		}
		sort.Slice(packages, func(a, b int) bool {
			if packages[a].Name != packages[b].Name {
				return packages[a].Name < packages[b].Name
			}
			if packages[a].Version != packages[b].Version {
				return packages[a].Version < packages[b].Version
			}
			return packages[a].Type < packages[b].Type
		})
		fixState := g.fixState
		if fixState == "" {
			fixState = "unknown"
		}
		issue := Issue{ID: primary, Severity: g.severity, Packages: packages, FixState: fixState}
		if len(aliases) > 0 {
			issue.Aliases = aliases
		}
		issues = append(issues, issue)
		counts.add(g.severity)
	}
	SortIssues(issues)
	return issues, counts
}

// fixRank prefers "fixed" over the states that say no fix is known.
func fixRank(state string) int {
	switch state {
	case "fixed":
		return 4
	case "not-fixed":
		return 3
	case "wont-fix":
		return 2
	case "unknown":
		return 1
	}
	return 0
}

// SortIssues orders issues by severity, then identifier.
func SortIssues(issues []Issue) {
	sort.SliceStable(issues, func(a, b int) bool {
		if ra, rb := rank(issues[a].Severity), rank(issues[b].Severity); ra != rb {
			return ra > rb
		}
		return issues[a].ID < issues[b].ID
	})
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Pair is an issue found in both images.
type Pair struct {
	Lupetto  Issue `json:"lupetto"`
	Upstream Issue `json:"upstream"`
}

// Comparison splits two images' issues by where they occur. Issues match
// when they share any identifier, including aliases.
type Comparison struct {
	// Removed are upstream issues not found in the Lupetto image.
	Removed []Issue `json:"removed"`
	// Remaining are found in both images.
	Remaining []Pair `json:"remaining"`
	// New are Lupetto issues not found in the upstream image.
	New []Issue `json:"new"`
}

// Compare matches the Lupetto image's issues against the upstream image's.
func Compare(lupetto, upstream []Issue) Comparison {
	byID := map[string]int{}
	for index, issue := range upstream {
		for _, id := range issue.IDs() {
			if _, seen := byID[id]; !seen {
				byID[id] = index
			}
		}
	}
	matched := make([]bool, len(upstream))
	comparison := Comparison{Removed: []Issue{}, Remaining: []Pair{}, New: []Issue{}}
	for _, issue := range lupetto {
		index, found := -1, false
		for _, id := range issue.IDs() {
			if i, ok := byID[id]; ok {
				index, found = i, true
				break
			}
		}
		if !found {
			comparison.New = append(comparison.New, issue)
			continue
		}
		matched[index] = true
		comparison.Remaining = append(comparison.Remaining, Pair{Lupetto: issue, Upstream: upstream[index]})
	}
	for index, issue := range upstream {
		if !matched[index] {
			comparison.Removed = append(comparison.Removed, issue)
		}
	}
	return comparison
}
