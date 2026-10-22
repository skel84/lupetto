package build

import "lupetto/internal/imageconfig"

// Request is one resolved build or sbom workflow. Selector and Version are
// mutually exclusive ways to choose the exact APK.
type Request struct {
	Command     string
	PackageName string
	Selector    string
	Version     string
	// Arch is the Wolfi target architecture; empty means the host's.
	Arch   string
	NoLoad bool
	// Image is the optional image configuration; empty adds nothing.
	Image       imageconfig.Options
	Publication PublicationOptions
	Signing     SigningOptions
}
