package status

import "time"

const Version = 2

const (
	NotBuilt        = "not-built"
	UpdateAvailable = "update-available"
	// ConfigChanged means the newest image matches the selected APK but was
	// built with a different image configuration (entrypoint) than the
	// product now requests.
	ConfigChanged  = "config-changed"
	FixesAvailable = "fixes-available"
	Current        = "current"
	Error          = "error"
)

type Identity struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Advisory struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	SeveritySource string `json:"severitySource"`
}

type SeveritySummary struct {
	IDCount           int            `json:"idCount"`
	ResolvedCount     int            `json:"resolvedCount"`
	UnknownCount      int            `json:"unknownCount"`
	PendingCount      int            `json:"pendingCount"`
	FetchFailureCount int            `json:"fetchFailureCount"`
	SourceCounts      map[string]int `json:"sourceCounts"`
}

type Image struct {
	Digest       string            `json:"digest"`
	Tags         []string          `json:"tags"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Architecture string            `json:"architecture"`
	Created      time.Time         `json:"created"`
	Annotations  map[string]string `json:"annotations"`
}

type OutdatedPackage struct {
	Name             string `json:"name"`
	Architecture     string `json:"architecture"`
	InstalledVersion string `json:"installedVersion"`
	LatestVersion    string `json:"latestVersion"`
}

type MissingFix struct {
	Name             string     `json:"name"`
	Architecture     string     `json:"architecture"`
	InstalledVersion string     `json:"installedVersion"`
	FixedVersion     string     `json:"fixedVersion"`
	AvailableVersion string     `json:"availableVersion"`
	IDs              []string   `json:"ids"`
	ReachableByTrack bool       `json:"reachableByTrack"`
	Advisories       []Advisory `json:"advisories"`
	MaxSeverity      string     `json:"maxSeverity"`
}

// UnevaluatedFix retains a secdb entry with an unorderable fixed-version key
// or no recognised advisory IDs. Installed fields appear only on track issues.
type UnevaluatedFix struct {
	Name             string     `json:"name"`
	FixedVersion     string     `json:"fixedVersion"`
	IDs              []string   `json:"ids"`
	InstalledVersion string     `json:"installedVersion,omitempty"`
	Architecture     string     `json:"architecture,omitempty"`
	Advisories       []Advisory `json:"advisories"`
	MaxSeverity      string     `json:"maxSeverity"`
}

type Track struct {
	Package           string            `json:"package"`
	Selector          string            `json:"selector"`
	State             string            `json:"state"`
	Entrypoint        []string          `json:"entrypoint,omitempty"`
	Error             string            `json:"error,omitempty"`
	Latest            *Identity         `json:"latest,omitempty"`
	Repository        string            `json:"repository,omitempty"`
	Images            []Image           `json:"images"`
	Newest            *Image            `json:"newest,omitempty"`
	Installed         []Identity        `json:"installed"`
	Outdated          []OutdatedPackage `json:"outdated"`
	MissingFixes      []MissingFix      `json:"missingFixes"`
	UnevaluatedFixes  []UnevaluatedFix  `json:"unevaluatedFixes"`
	ArtifactCount     int               `json:"artifactCount"`
	UnidentifiedCount int               `json:"unidentifiedCount"`
}

type SecuritySource struct {
	URL                 string           `json:"url"`
	SHA256              string           `json:"sha256"`
	Unsigned            bool             `json:"unsigned"`
	FixedOnly           bool             `json:"fixedOnly"`
	WolfiOnly           bool             `json:"wolfiOnly"`
	UnevaluatedFixCount int              `json:"unevaluatedFixCount"`
	UnevaluatedFixes    []UnevaluatedFix `json:"unevaluatedFixes"`
	Severity            SeveritySummary  `json:"severity"`
}

type Document struct {
	Version      int            `json:"version"`
	Kind         string         `json:"kind"`
	ComputedAt   time.Time      `json:"computedAt"`
	Architecture string         `json:"architecture"`
	Registry     string         `json:"registry"`
	Repository   string         `json:"repository"`
	IndexSHA256  string         `json:"indexSHA256"`
	Security     SecuritySource `json:"security"`
	Tracks       []Track        `json:"tracks"`
}
