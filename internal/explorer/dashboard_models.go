package explorer

import (
	"encoding/json"
	"time"
)

type Product struct {
	Package    string   `json:"package"`
	Selectors  []string `json:"selectors"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	CABundle   bool     `json:"caBundle,omitempty"`
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

// An unreadable CLI history item has no record modification timestamp and
// encodes recordedAt as an empty string. Keep it as unknown, not a fatal
// document incompatibility that would hide all other inventory.
func (b *InventoryBuild) UnmarshalJSON(data []byte) error {
	type record InventoryBuild
	var decoded record
	wire := struct {
		*record
		RecordedAt string `json:"recordedAt"`
	}{record: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.RecordedAt != "" {
		var err error
		decoded.RecordedAt, err = time.Parse(time.RFC3339Nano, wire.RecordedAt)
		if err != nil {
			return err
		}
	}
	*b = InventoryBuild(decoded)
	return nil
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

// VerifyDocument is the CLI's kind "verify" version-1 signature-status fact.
type VerifyDocument struct {
	Kind            string            `json:"kind"`
	Version         int               `json:"version"`
	Reference       string            `json:"reference"`
	Digest          string            `json:"digest"`
	CheckedAt       time.Time         `json:"checkedAt"`
	Trust           VerifyTrust       `json:"trust"`
	TransparencyLog string            `json:"transparencyLog"`
	Signature       VerifySignature   `json:"signature"`
	Attestation     VerifyAttestation `json:"attestation"`
}

// VerifyTrust is a key fingerprint or, for keyless trust, the identity policy.
type VerifyTrust struct {
	PublicKeySHA256           string `json:"publicKeySHA256,omitempty"`
	CertificateIdentity       string `json:"certificateIdentity,omitempty"`
	CertificateIdentityRegexp string `json:"certificateIdentityRegexp,omitempty"`
	CertificateOIDCIssuer     string `json:"certificateOIDCIssuer,omitempty"`
}
type VerifySignature struct {
	State     string          `json:"state"`
	Error     string          `json:"error,omitempty"`
	Artifacts int             `json:"artifacts"`
	Identity  *VerifyIdentity `json:"identity,omitempty"`
}

// VerifyIdentity is the verified certificate subject of a keyless signature.
type VerifyIdentity struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}
type VerifyAttestation struct {
	State         string      `json:"state"`
	Error         string      `json:"error,omitempty"`
	Artifacts     int         `json:"artifacts"`
	PredicateType string      `json:"predicateType,omitempty"`
	SBOM          *VerifySBOM `json:"sbom,omitempty"`
}
type VerifySBOM struct {
	SHA256   string `json:"sha256"`
	Packages int    `json:"packages"`
	Path     string `json:"path,omitempty"`
}

// SignatureView is Explorer's display of one registry image's cached verify
// result. It never changes a track state or verdict.
type SignatureView struct {
	State             string    `json:"state"`
	Label             string    `json:"label"`
	Detail            string    `json:"detail,omitempty"`
	Attestation       string    `json:"attestation,omitempty"`
	AttestationLabel  string    `json:"attestationLabel,omitempty"`
	AttestationDetail string    `json:"attestationDetail,omitempty"`
	SBOMPackages      int       `json:"sbomPackages,omitempty"`
	SBOMURL           string    `json:"sbomURL,omitempty"`
	TransparencyLog   string    `json:"transparencyLog,omitempty"`
	LocalOnly         bool      `json:"localOnly"`
	KeySHA256         string    `json:"keySHA256,omitempty"`
	Signer            string    `json:"signer,omitempty"`
	CheckedAt         time.Time `json:"checkedAt"`
	Rechecking        bool      `json:"rechecking"`
}
type SignatureConfigView struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
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
	// Signatures is keyed by registry digest; NewestSignature is Track.Newest's.
	Signatures      map[string]*SignatureView `json:"signatures"`
	NewestSignature *SignatureView            `json:"newestSignature,omitempty"`
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
	// SignaturesPending is true while a shown image has no verify result yet.
	SignaturesPending bool `json:"signaturesPending"`
}
type PackageSet struct {
	Key      string            `json:"key"`
	Label    string            `json:"label"`
	Source   string            `json:"source"`
	Packages []PackageIdentity `json:"packages"`
	SPDXURL  string            `json:"spdxURL,omitempty"`
	Error    string            `json:"error,omitempty"`
	// Signature is set for registry sets only.
	Signature *SignatureView `json:"signature,omitempty"`
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
	SignaturesPending   bool           `json:"signaturesPending"`
}
type BuildStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type BuildItem struct {
	ID         string       `json:"id"`
	DetailURL  string       `json:"detailURL"`
	Package    string       `json:"package"`
	Version    string       `json:"version"`
	State      string       `json:"state"`
	StartedAt  time.Time    `json:"startedAt"`
	Record     *BuildRecord `json:"record,omitempty"`
	Error      string       `json:"error,omitempty"`
	Stages     []BuildStage `json:"stages"`
	Live       bool         `json:"live"`
	SPDXURL    string       `json:"spdxURL,omitempty"`
	Mode       string       `json:"mode,omitempty"`
	Load       bool         `json:"load"`
	LoadReason string       `json:"loadReason,omitempty"`
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
	Registry          string              `json:"registry"`
	RegistryState     string              `json:"registryState"`
	DockerState       string              `json:"dockerState"`
	DockerReason      string              `json:"dockerReason"`
	PublishLoad       bool                `json:"publishLoad"`
	PublishLoadReason string              `json:"publishLoadReason"`
	PublishSigning    string              `json:"publishSigning"`
	RunningBuild      *BuildItem          `json:"runningBuild,omitempty"`
	StatusComputedAt  time.Time           `json:"statusComputedAt"`
	StatusRefreshing  bool                `json:"statusRefreshing"`
	IndexSHA256       string              `json:"indexSHA256"`
	FeedSHA256        string              `json:"feedSHA256"`
	Architecture      string              `json:"architecture"`
	Signatures        SignatureConfigView `json:"signatures"`
}
