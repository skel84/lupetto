package explorer

import "time"

type Product struct {
	Package   string   `json:"package"`
	Selectors []string `json:"selectors"`
}
type ProductsDocument struct {
	Kind     string    `json:"kind"`
	Version  int       `json:"version"`
	Products []Product `json:"products"`
	Changed  bool      `json:"changed"`
	Message  string    `json:"message"`
}
type SPDXArtifact struct {
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
type InventoryBuild struct {
	Workspace     string       `json:"workspace"`
	RecordPath    string       `json:"recordPath"`
	RecordVersion int          `json:"recordVersion"`
	Status        string       `json:"status"`
	Error         string       `json:"error,omitempty"`
	RecordedAt    time.Time    `json:"recordedAt"`
	BuildTime     *time.Time   `json:"buildTime,omitempty"`
	Record        *BuildRecord `json:"record,omitempty"`
	SPDX          SPDXArtifact `json:"spdx"`
}
type DockerImage struct {
	ID             string           `json:"id"`
	Tags           []string         `json:"tags"`
	Created        time.Time        `json:"created"`
	Size           int64            `json:"size"`
	IdentityKnown  bool             `json:"identityKnown"`
	IdentitySource string           `json:"identitySource"`
	Identity       *PackageIdentity `json:"identity,omitempty"`
}
type DockerInventory struct {
	Available bool          `json:"available"`
	Reason    string        `json:"reason,omitempty"`
	Images    []DockerImage `json:"images"`
}
type ImagesDocument struct {
	Kind       string           `json:"kind"`
	Version    int              `json:"version"`
	ComputedAt time.Time        `json:"computedAt"`
	Builds     []InventoryBuild `json:"builds"`
	Docker     DockerInventory  `json:"docker"`
}
type InspectDocument struct {
	Kind         string            `json:"kind"`
	Version      int               `json:"version"`
	Reference    string            `json:"reference"`
	Digest       string            `json:"digest"`
	Unidentified bool              `json:"unidentified"`
	Identity     *PackageIdentity  `json:"identity,omitempty"`
	Created      *time.Time        `json:"created,omitempty"`
	Packages     []PackageIdentity `json:"packages"`
}
type InventoryView struct {
	Document *ImagesDocument `json:"document,omitempty"`
	Error    string          `json:"error,omitempty"`
}
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}
type PrimaryAction struct {
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	URL      string `json:"url,omitempty"`
	Package  string `json:"package"`
	Selector string `json:"selector"`
	Mode     string `json:"mode"`
}
type VersionRow struct {
	Identity    PackageIdentity `json:"identity"`
	Key         string          `json:"key"`
	Registry    []Image         `json:"registry"`
	LocalImages []DockerImage   `json:"localImages"`
	Builds      []BuildItem     `json:"builds"`
	Latest      bool            `json:"latest"`
}
type ProductRow struct {
	Package          string         `json:"package"`
	Selector         string         `json:"selector"`
	Track            Track          `json:"track"`
	DetailURL        string         `json:"detailURL"`
	Versions         []VersionRow   `json:"versions"`
	Verdict          string         `json:"verdict"`
	VerdictKind      string         `json:"verdictKind"`
	VerdictDetail    string         `json:"verdictDetail"`
	UnreachableCount int            `json:"unreachableCount"`
	NeedsAction      bool           `json:"needsAction"`
	Severity         SeverityCounts `json:"severity"`
	Action           PrimaryAction  `json:"action"`
}
type ImagesView struct {
	BaseView
	Status       StatusView     `json:"status"`
	Inventory    InventoryView  `json:"inventory"`
	Products     []ProductRow   `json:"products"`
	Query        string         `json:"query"`
	Filter       string         `json:"filter"`
	TotalMatches int            `json:"totalMatches"`
	Groups       []ProductGroup `json:"groups"`
	Summary      ImagesSummary  `json:"summary"`
	Notice       ImagesNotice   `json:"notice"`
	Empty        bool           `json:"empty"`
}
type PackageSet struct {
	Key      string            `json:"key"`
	Label    string            `json:"label"`
	Source   string            `json:"source"`
	Packages []PackageIdentity `json:"packages"`
	SPDXURL  string            `json:"spdxURL,omitempty"`
	Error    string            `json:"error,omitempty"`
}
type PackageChange struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	Before       string `json:"before,omitempty"`
	After        string `json:"after,omitempty"`
	Kind         string `json:"kind"`
}
type CompareView struct {
	From      string          `json:"from"`
	To        string          `json:"to"`
	Before    PackageSet      `json:"before"`
	After     PackageSet      `json:"after"`
	Changes   []PackageChange `json:"changes"`
	Error     string          `json:"error,omitempty"`
	Added     int             `json:"added"`
	Removed   int             `json:"removed"`
	Changed   int             `json:"changed"`
	Unchanged int             `json:"unchanged"`
}
type ImageView struct {
	BaseView
	Status              StatusView     `json:"status"`
	Inventory           InventoryView  `json:"inventory"`
	Product             ProductRow     `json:"product"`
	Tab                 string         `json:"tab"`
	Versions            []PackageSet   `json:"versions"`
	Packages            PackageSet     `json:"packages"`
	Compare             CompareView    `json:"compare"`
	FixedByRebuilding   []MissingFix   `json:"fixedByRebuilding"`
	NeedsAnotherVersion []MissingFix   `json:"needsAnotherVersion"`
	Builds              []BuildItem    `json:"builds"`
	Siblings            []ImageSibling `json:"siblings"`
}
type BuildStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type BuildItem struct {
	ID        string       `json:"id"`
	DetailURL string       `json:"detailURL"`
	Package   string       `json:"package"`
	Version   string       `json:"version"`
	State     string       `json:"state"`
	StartedAt time.Time    `json:"startedAt"`
	Record    *BuildRecord `json:"record,omitempty"`
	Error     string       `json:"error,omitempty"`
	Stages    []BuildStage `json:"stages"`
	Live      bool         `json:"live"`
	SPDXURL   string       `json:"spdxURL,omitempty"`
}
type TrackingView struct {
	BaseView
	Package  string            `json:"package"`
	Selector string            `json:"selector"`
	Products *ProductsDocument `json:"products,omitempty"`
	Error    string            `json:"error,omitempty"`
	Message  string            `json:"message,omitempty"`
}

type ProductGroup struct {
	Package   string       `json:"package"`
	DetailURL string       `json:"detailURL"`
	Rows      []ProductRow `json:"rows"`
}
type ImagesSummary struct {
	All             int `json:"all"`
	NeedsAction     int `json:"needsAction"`
	Current         int `json:"current"`
	NotInRegistry   int `json:"notInRegistry"`
	MissingCritical int `json:"missingCritical"`
}
type ImagesNotice struct {
	Tracked   string `json:"tracked"`
	Untracked string `json:"untracked"`
}
type ImageSibling struct {
	Selector string `json:"selector"`
	URL      string `json:"url"`
	Current  bool   `json:"current"`
}
type ShellView struct {
	Registry         string     `json:"registry"`
	RegistryState    string     `json:"registryState"`
	DockerState      string     `json:"dockerState"`
	DockerReason     string     `json:"dockerReason"`
	RunningBuild     *BuildItem `json:"runningBuild,omitempty"`
	StatusComputedAt time.Time  `json:"statusComputedAt"`
	StatusRefreshing bool       `json:"statusRefreshing"`
	IndexSHA256      string     `json:"indexSHA256"`
	FeedSHA256       string     `json:"feedSHA256"`
	Architecture     string     `json:"architecture"`
}
