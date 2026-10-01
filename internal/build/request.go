package build

// Request is one resolved build or sbom workflow. Selector and Version are
// mutually exclusive ways to choose the exact APK.
type Request struct {
	Command     string
	PackageName string
	Selector    string
	Version     string
	NoLoad      bool
	Publication PublicationOptions
	Signing     SigningOptions
}
