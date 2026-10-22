// Package explorer supervises the standalone CLI; it does not implement index,
// registry, security comparison, or image-build logic.
package explorer

import "time"

// These decoding types belong to Explorer, not to the CLI's Go packages.
type PackageIdentity struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
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
type MissingFix struct {
	Name             string     `json:"name"`
	Architecture     string     `json:"architecture"`
	InstalledVersion string     `json:"installedVersion"`
	FixedVersion     string     `json:"fixedVersion"`
	AvailableVersion string     `json:"availableVersion"`
	IDs              []string   `json:"ids"`
	ReachableByTrack bool       `json:"reachableByTrack"`
	Advisories       []Advisory `json:"advisories,omitempty"`
	MaxSeverity      string     `json:"maxSeverity,omitempty"`
}
type UnevaluatedFix struct {
	Name             string     `json:"name"`
	InstalledVersion string     `json:"installedVersion,omitempty"`
	Architecture     string     `json:"architecture,omitempty"`
	FixedVersion     string     `json:"fixedVersion"`
	IDs              []string   `json:"ids"`
	Advisories       []Advisory `json:"advisories,omitempty"`
	MaxSeverity      string     `json:"maxSeverity,omitempty"`
}
type Track struct {
	Package           string            `json:"package"`
	Selector          string            `json:"selector"`
	State             string            `json:"state"`
	Error             string            `json:"error,omitempty"`
	Latest            *PackageIdentity  `json:"latest,omitempty"`
	Repository        string            `json:"repository,omitempty"`
	Images            []Image           `json:"images"`
	Newest            *Image            `json:"newest,omitempty"`
	Installed         []PackageIdentity `json:"installed"`
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
	Severity            SeveritySummary  `json:"severity,omitempty"`
}
type StatusDocument struct {
	Kind         string         `json:"kind"`
	Version      int            `json:"version"`
	ComputedAt   time.Time      `json:"computedAt"`
	Architecture string         `json:"architecture"`
	Registry     string         `json:"registry"`
	Repository   string         `json:"repository"`
	IndexSHA256  string         `json:"indexSHA256"`
	Security     SecuritySource `json:"security"`
	Tracks       []Track        `json:"tracks"`
}
type DiscoveredPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}
type DiscoverDocument struct {
	Kind         string              `json:"kind"`
	Version      int                 `json:"version"`
	Package      string              `json:"package,omitempty"`
	Architecture string              `json:"architecture"`
	IndexSHA256  string              `json:"indexSHA256"`
	Packages     []DiscoveredPackage `json:"packages"`
}
type BuildRequest struct {
	Package    string `json:"package"`
	Selector   string `json:"selector"`
	APKVersion string `json:"apkVersion"`
	Mode       string `json:"mode,omitempty"`
	Load       bool   `json:"load"`
	LoadReason string `json:"loadReason,omitempty"`
	// Entrypoint and CABundle come from the tracked product in the products
	// file, never from a form field; empty means the image has neither.
	Entrypoint []string `json:"entrypoint,omitempty"`
	CABundle   bool     `json:"caBundle,omitempty"`
}
type RecordSelection struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	IndexSHA256  string `json:"indexSHA256"`
}
type RecordFailure struct {
	Stage               string `json:"stage"`
	Error               string `json:"error"`
	SideEffectsPossible bool   `json:"sideEffectsPossible"`
}
type StageOutcome struct {
	Status                     string `json:"status"`
	Reference                  string `json:"reference,omitempty"`
	Digest                     string `json:"digest,omitempty"`
	ImmutableReference         string `json:"immutableReference,omitempty"`
	Verified                   bool   `json:"verified,omitempty"`
	ImageReference             string `json:"imageReference,omitempty"`
	BuildReference             string `json:"buildReference,omitempty"`
	DockerImageID              string `json:"dockerImageID,omitempty"`
	ReadableReferenceConfirmed bool   `json:"readableReferenceConfirmed,omitempty"`
}
type RecordStages struct {
	Build       StageOutcome `json:"build"`
	Load        StageOutcome `json:"load"`
	Publication StageOutcome `json:"publication"`
	Signing     StageOutcome `json:"signing"`
	Attestation StageOutcome `json:"attestation"`
}
type RecordEvidence struct {
	ApkoVersion    string `json:"apkoVersion"`
	ImageDirectory string `json:"imageDirectory"`
	ImageDigest    string `json:"imageDigest"`
	LockPath       string `json:"lockPath"`
	SPDXPath       string `json:"spdxPath"`
	SPDXSHA256     string `json:"spdxSHA256"`
	SPDXValidated  bool   `json:"spdxValidated"`
}
type RecordRequest struct {
	BuildRequest
	Publish bool `json:"publish"`
	Sign    bool `json:"sign"`
}
type BuildRecord struct {
	Version   int              `json:"version"`
	Command   string           `json:"command"`
	Outcome   string           `json:"outcome"`
	Failure   *RecordFailure   `json:"failure,omitempty"`
	Workspace string           `json:"workspace,omitempty"`
	Request   RecordRequest    `json:"request"`
	Selection *RecordSelection `json:"selection,omitempty"`
	Evidence  *RecordEvidence  `json:"evidence,omitempty"`
	Stages    RecordStages     `json:"stages"`
}

// BaseView is embedded in every page. Never turn CLI strings into template.HTML.
type BaseView struct {
	CSRFToken     string    `json:"csrfToken"`
	BuildsEnabled bool      `json:"buildsEnabled"`
	Shell         ShellView `json:"shell"`
}
type StatusView struct {
	Document   *StatusDocument `json:"document,omitempty"`
	LastError  string          `json:"lastError,omitempty"`
	Refreshing bool            `json:"refreshing"`
	Empty      bool            `json:"empty"`
}
type TrackSummary struct {
	Track               Track  `json:"track"`
	DetailURL           string `json:"detailURL"`
	OutdatedCount       int    `json:"outdatedCount"`
	ReachableFixCount   int    `json:"reachableFixCount"`
	UnreachableFixCount int    `json:"unreachableFixCount"`
	UnevaluatedFixCount int    `json:"unevaluatedFixCount"`
}
type OverviewView struct {
	BaseView
	Status StatusView     `json:"status"`
	Tracks []TrackSummary `json:"tracks"`
}
type TrackView struct {
	BaseView
	Status StatusView `json:"status"`
	Track  Track      `json:"track"`
}
type PackageItem struct {
	DiscoveredPackage
	DetailURL string `json:"detailURL"`
	Tracked   bool   `json:"tracked"`
}
type PackagesView struct {
	BaseView
	Query        string            `json:"query"`
	Packages     []PackageItem     `json:"packages"`
	TotalMatches int               `json:"totalMatches"`
	Limit        int               `json:"limit"`
	Document     *DiscoverDocument `json:"document,omitempty"`
	LastError    string            `json:"lastError,omitempty"`
	Refreshing   bool              `json:"refreshing"`
}
type PackageView struct {
	BaseView
	Name     string            `json:"name"`
	Document *DiscoverDocument `json:"document,omitempty"`
	Error    string            `json:"error,omitempty"`
}
type JobView struct {
	ID              string       `json:"id"`
	Request         BuildRequest `json:"request"`
	State           string       `json:"state"`
	StartedAt       time.Time    `json:"startedAt"`
	EndedAt         *time.Time   `json:"endedAt,omitempty"`
	ExitCode        *int         `json:"exitCode,omitempty"`
	Record          *BuildRecord `json:"record,omitempty"`
	Error           string       `json:"error,omitempty"`
	CancelRequested bool         `json:"cancelRequested"`
	Progress        []BuildStage `json:"progress"`
}
type JobsView struct {
	BaseView
	Jobs         []JobView     `json:"jobs"`
	Running      bool          `json:"running"`
	HistoryLimit int           `json:"historyLimit"`
	Items        []BuildItem   `json:"items"`
	Inventory    InventoryView `json:"inventory"`
}
type JobDetailView struct {
	BaseView
	Job    JobView   `json:"job"`
	Log    LogChunk  `json:"log"`
	Item   BuildItem `json:"item"`
	HasLog bool      `json:"hasLog"`
}

// Offsets are absolute stderr byte positions, even after old bytes are dropped.
type LogChunk struct {
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"nextOffset"`
	Text       string `json:"text"`
	Truncated  bool   `json:"truncated"`
	Done       bool   `json:"done"`
}
