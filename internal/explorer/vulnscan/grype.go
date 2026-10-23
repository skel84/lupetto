package vulnscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/hex"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/syftjson"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// GrypeVersion is the Grype library version the Explorer links. Keep it in
// step with go.mod; it is shown with every result.
const GrypeVersion = "v0.121.0"

// Config sets up an Engine.
type Config struct {
	// CacheDir holds the vulnerability database (under CacheDir/db).
	CacheDir string
	// MaxCompressedBytes rejects images whose compressed layers exceed it.
	MaxCompressedBytes int64
	// Timeout bounds one image's scan.
	Timeout time.Duration
	// Keychain resolves registry credentials; nil uses the Docker config
	// (DOCKER_CONFIG or ~/.docker). Resolution errors fall back to anonymous.
	Keychain authn.Keychain
	// Version identifies the Explorer to the database server.
	Version string
}

// Engine opens Grype database sessions. Only one session should be open at
// a time; each session scans one image at a time.
type Engine struct {
	config   Config
	keychain authn.Keychain
}

// NewEngine validates config.
func NewEngine(config Config) (*Engine, error) {
	if !filepath.IsAbs(config.CacheDir) {
		return nil, errors.New("vulnerability scan cache directory must be absolute")
	}
	if config.MaxCompressedBytes <= 0 || config.Timeout <= 0 {
		return nil, errors.New("vulnerability scan size limit and timeout must be positive")
	}
	keychain := config.Keychain
	if keychain == nil {
		keychain = authn.DefaultKeychain
	}
	return &Engine{config: config, keychain: anonymousFallback{keychain}}, nil
}

// anonymousFallback lets public images be pulled when no usable credential
// configuration exists (for example a missing credential helper).
type anonymousFallback struct{ inner authn.Keychain }

func (k anonymousFallback) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	authenticator, err := k.inner.Resolve(resource)
	if err != nil || authenticator == nil {
		return authn.Anonymous, nil
	}
	return authenticator, nil
}

func (e *Engine) options() *options.Grype {
	opts := options.DefaultGrype(clio.Identification{Name: "lupetto-explorer", Version: e.config.Version})
	opts.DB.Dir = filepath.Join(e.config.CacheDir, "db")
	return opts
}

// Session is an open vulnerability database.
type Session struct {
	engine   *Engine
	provider vulnerability.Provider
	matcher  grype.VulnerabilityMatcher
	opts     *options.Grype
	DB       DBInfo
}

// Open loads the database, first checking for and installing an update when
// update is set. Grype refuses a database older than its maximum age.
func (e *Engine) Open(update bool) (*Session, error) {
	opts := e.options()
	provider, status, err := grype.LoadVulnerabilityDB(opts.ToClientConfig(), opts.ToCuratorConfig(), update)
	if err != nil {
		return nil, fmt.Errorf("load vulnerability database: %w", err)
	}
	if status == nil || status.Error != nil {
		provider.Close()
		if status != nil {
			return nil, fmt.Errorf("load vulnerability database: %w", status.Error)
		}
		return nil, errors.New("load vulnerability database: no status reported")
	}
	ignore := append([]match.IgnoreRule(nil), opts.Ignore...)
	if !opts.MatchUpstreamKernelHeaders {
		ignore = append(ignore, ignoreLinuxKernelHeaders...)
	}
	vexProcessor, err := vex.NewProcessor(vex.ProcessorOptions{IgnoreRules: ignore})
	if err != nil {
		provider.Close()
		return nil, err
	}
	session := &Session{engine: e, provider: provider, opts: opts, DB: DBInfo{Built: status.Built.UTC(), Schema: status.SchemaVersion}}
	session.matcher = grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		IgnoreRules:           ignore,
		Matchers:              matcher.NewDefaultMatchers(matcherConfig(opts)),
		VexProcessor:          vexProcessor,
		// Only adds what matchers set aside (for example Wolfi "not affected"
		// records) to the ignored list, so Suppressed can count it; matches
		// are unchanged.
		IncludeMatcherSuppressions: true,
	}
	return session, nil
}

// Close releases the database and removes unpacked image layers.
func (s *Session) Close() error {
	defer stereoscope.Cleanup()
	return s.provider.Close()
}

// Grype's CLI default ignore rule for Linux kernel headers (root.go).
var ignoreLinuxKernelHeaders = []match.IgnoreRule{
	{Package: match.IgnoreRulePackage{Name: "kernel-headers", UpstreamName: "kernel", Type: string(syftPkg.RpmPkg)}, MatchType: match.ExactIndirectMatch},
	{Package: match.IgnoreRulePackage{Name: "linux(-.*)?-headers-.*", UpstreamName: "linux.*", Type: string(syftPkg.DebPkg)}, MatchType: match.ExactIndirectMatch},
	{Package: match.IgnoreRulePackage{Name: "linux-libc-dev", UpstreamName: "linux", Type: string(syftPkg.DebPkg)}, MatchType: match.ExactIndirectMatch},
	{Package: match.IgnoreRulePackage{Name: "linux-kbuild-.*", UpstreamName: "linux.*", Type: string(syftPkg.DebPkg)}, MatchType: match.ExactIndirectMatch},
}

// matcherConfig is Grype's CLI getMatcherConfig.
func matcherConfig(opts *options.Grype) matcher.Config {
	return matcher.Config{
		Java:       java.MatcherConfig{ExternalSearchConfig: opts.ExternalSources.ToJavaMatcherConfig(), UseCPEs: opts.Match.Java.UseCPEs},
		Ruby:       ruby.MatcherConfig(opts.Match.Ruby),
		Python:     python.MatcherConfig(opts.Match.Python),
		Dotnet:     dotnet.MatcherConfig(opts.Match.Dotnet),
		Javascript: javascript.MatcherConfig(opts.Match.Javascript),
		Golang: golang.MatcherConfig{
			UseCPEs:                                opts.Match.Golang.UseCPEs,
			AlwaysUseCPEForStdlib:                  opts.Match.Golang.AlwaysUseCPEForStdlib,
			AllowMainModulePseudoVersionComparison: opts.Match.Golang.AllowMainModulePseudoVersionComparison,
		},
		Rust:  rust.MatcherConfig(opts.Match.Rust),
		Hex:   hex.MatcherConfig(opts.Match.Hex),
		Stock: stock.MatcherConfig(opts.Match.Stock),
		Dpkg:  dpkg.MatcherConfig{MissingEpochStrategy: opts.Match.Dpkg.MissingEpochStrategy, UseCPEsForEOL: opts.Match.Dpkg.UseCPEsForEOL, UseCPEs: opts.Match.Dpkg.UseCPEs},
		Rpm:   rpm.MatcherConfig{MissingEpochStrategy: opts.Match.Rpm.MissingEpochStrategy, UseCPEsForEOL: opts.Match.Rpm.UseCPEsForEOL, UseCPEs: opts.Match.Rpm.UseCPEs},
	}
}

// Platform maps a Wolfi architecture to an OCI platform.
func Platform(architecture string) (string, error) {
	switch architecture {
	case "x86_64", "amd64":
		return "linux/amd64", nil
	case "aarch64", "arm64":
		return "linux/arm64", nil
	}
	return "", fmt.Errorf("unsupported architecture %q", architecture)
}

// Scan scans one image for platform (for example linux/amd64).
func (s *Session) Scan(ctx context.Context, reference, platform string) (Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, s.engine.config.Timeout)
	defer cancel()
	info, err := s.engine.resolve(ctx, reference, platform)
	if err != nil {
		return Scan{}, err
	}
	ref, _ := name.ParseReference(reference)
	input := ref.Context().Name() + "@" + info.ManifestDigest
	imagePlatform, err := image.NewPlatform(platform)
	if err != nil {
		return Scan{}, err
	}
	registryOptions := s.opts.Registry.ToOptions()
	registryOptions.Keychain = s.engine.keychain
	src, err := syft.GetSource(ctx, input, syft.DefaultGetSourceConfig().
		WithSources("registry").
		WithRegistryOptions(registryOptions).
		WithPlatform(imagePlatform))
	if err != nil {
		return Scan{}, fmt.Errorf("pull %s: %w", input, err)
	}
	defer src.Close()
	// Grype's CLI catalog settings (getProviderConfig), with one worker.
	sbomConfig := syft.DefaultCreateSBOMConfig()
	sbomConfig.Packages.JavaArchive.IncludeIndexedArchives = s.opts.Search.IncludeIndexedArchives
	sbomConfig.Packages.JavaArchive.IncludeUnindexedArchives = s.opts.Search.IncludeUnindexedArchives
	sbomConfig.Packages.Golang = sbomConfig.Packages.Golang.WithCaptureSymbols(cataloging.SymbolScopeAll)
	sbomConfig.Compliance.MissingVersion = cataloging.ComplianceActionDrop
	sbomConfig = sbomConfig.WithParallelism(1)
	document, err := syft.CreateSBOM(ctx, src, sbomConfig)
	if err != nil {
		return Scan{}, fmt.Errorf("catalog %s: %w", input, err)
	}
	if document == nil {
		return Scan{}, fmt.Errorf("catalog %s: no packages", input)
	}
	// pkg.Provide cannot be canceled, so catalog above and hand Grype the
	// SBOM in its own lossless format; Grype then prepares packages exactly
	// as for an image.
	var encoded bytes.Buffer
	if err := syftjson.NewFormatEncoder().Encode(&encoded, *document); err != nil {
		return Scan{}, fmt.Errorf("encode SBOM: %w", err)
	}
	document = nil
	packages, packageContext, _, err := pkg.ProvideFromReader(bytes.NewReader(encoded.Bytes()), pkg.ProviderConfig{
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: s.opts.GenerateMissingCPEs,
			Distro:              pkg.DistroConfig{FixChannels: distro.DefaultFixChannels()},
		},
	})
	if err != nil {
		return Scan{}, fmt.Errorf("read packages: %w", err)
	}
	encoded = bytes.Buffer{}
	if err := ctx.Err(); err != nil {
		return Scan{}, err
	}
	remaining, ignored, err := s.matcher.FindMatchesContext(ctx, packages, packageContext)
	if err != nil {
		return Scan{}, fmt.Errorf("match vulnerabilities: %w", err)
	}
	if packageContext.Distro != nil {
		info.Distro = packageContext.Distro.String()
	}
	findings := make([]Finding, 0, remaining.Count())
	for _, m := range remaining.Sorted() {
		finding := Finding{
			ID:          m.Vulnerability.ID,
			Severity:    s.severity(m.Vulnerability.Reference),
			Package:     Package{Name: m.Package.Name, Version: m.Package.Version, Type: string(m.Package.Type)},
			FixState:    string(m.Vulnerability.Fix.State),
			FixVersions: m.Vulnerability.Fix.Versions,
		}
		for _, related := range m.Vulnerability.RelatedVulnerabilities {
			finding.Related = append(finding.Related, Related{ID: related.ID, Severity: s.severity(related)})
		}
		findings = append(findings, finding)
	}
	issues, counts := Summarize(findings)
	return Scan{
		Image: info, ScannedAt: time.Now().UTC(), DB: s.DB, Packages: len(packages),
		Matches: remaining.Count(), Suppressed: len(ignored), Counts: counts, Issues: issues,
	}, nil
}

func (s *Session) severity(ref vulnerability.Reference) string {
	metadata, err := s.provider.VulnerabilityMetadata(ref)
	if err != nil || metadata == nil {
		return Unknown
	}
	return NormalizeSeverity(metadata.Severity)
}

// resolve reads the image's manifest for platform, checks its size, and
// fixes the digest to scan so a moving tag cannot change mid-scan.
func (e *Engine) resolve(ctx context.Context, reference, platform string) (ImageInfo, error) {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("invalid image reference %q", reference)
	}
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return ImageInfo{}, err
	}
	descriptor, err := remote.Get(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(e.keychain), remote.WithPlatform(*want), remote.WithTransport(httpsUnlessLoopback{remote.DefaultTransport}))
	if err != nil {
		return ImageInfo{}, fmt.Errorf("read %s: %w", reference, err)
	}
	img, err := descriptor.Image()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("read %s for %s: %w", reference, platform, err)
	}
	config, err := img.ConfigFile()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("read %s config: %w", reference, err)
	}
	if config.OS != want.OS || config.Architecture != want.Architecture {
		return ImageInfo{}, fmt.Errorf("%s is %s/%s, not %s", reference, config.OS, config.Architecture, platform)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return ImageInfo{}, fmt.Errorf("read %s manifest: %w", reference, err)
	}
	size := manifest.Config.Size
	for _, layer := range manifest.Layers {
		size += layer.Size
	}
	if size > e.config.MaxCompressedBytes {
		return ImageInfo{}, fmt.Errorf("%s has %d bytes of compressed layers, above the %d-byte scan limit", reference, size, e.config.MaxCompressedBytes)
	}
	digest, err := img.Digest()
	if err != nil {
		return ImageInfo{}, err
	}
	return ImageInfo{Reference: reference, Digest: descriptor.Digest.String(), ManifestDigest: digest.String(), Platform: platform, CompressedBytes: size}, nil
}

// httpsUnlessLoopback refuses plain HTTP except to literal loopback hosts,
// the CLI's local-development exception.
type httpsUnlessLoopback struct{ inner http.RoundTripper }

func (t httpsUnlessLoopback) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" && !loopback(request.URL.Hostname()) {
		return nil, fmt.Errorf("refusing plain HTTP to %s", request.URL.Host)
	}
	return t.inner.RoundTrip(request)
}

func loopback(host string) bool {
	return strings.EqualFold(host, "localhost") || strings.HasPrefix(host, "127.") || host == "::1"
}
