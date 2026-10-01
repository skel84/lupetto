package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/docker/cli/cli/config"
	dockertypes "github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const maxRegistryMetadataBytes = 4 << 20

type publicationOutcome struct {
	status, reference, pushedDigest, immutableReference string
	verified                                            bool
}

// Only safe, stage-specific text enters this type. Registry bodies, URLs,
// subprocess output, argument strings, and credential-helper diagnostics are
// never wrapped; detail is a fixed classification chosen by Lupetto.
type publicationStageError struct {
	stage, detail string
	cause         error
}

func (e *publicationStageError) Error() string {
	if e.cause != nil {
		return e.stage + " canceled: " + e.cause.Error()
	}
	if e.detail != "" {
		return e.stage + " failed (" + e.detail + ")"
	}
	return e.stage + " failed"
}
func (e *publicationStageError) Unwrap() error { return e.cause }

func stageCancellation(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func safeStageError(ctx context.Context, stage string, err error) error {
	return &publicationStageError{stage: stage, cause: stageCancellation(ctx, err)}
}

var (
	errPlainHTTPRefused        = errors.New("plain HTTP refused for non-loopback registry")
	errRegistrySchemeRefused   = errors.New("unsupported registry URL scheme")
	errRegistryContentMismatch = errors.New("registry content mismatch")
	errUnsupportedLayer        = errors.New("unsupported layer compression")
	safeRegistryCode           = regexp.MustCompile(`^[A-Z_]{1,32}$`)
)

// registryStageError reports the stage plus, at most, a fixed classification,
// an HTTP status, and registry error codes from a closed character set.
func registryStageError(ctx context.Context, stage string, err error) error {
	if cause := stageCancellation(ctx, err); cause != nil {
		return &publicationStageError{stage: stage, cause: cause}
	}
	return &publicationStageError{stage: stage, detail: registryErrorDetail(err)}
}

func registryErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errPlainHTTPRefused) {
		return "plain HTTP refused for non-loopback registry"
	}
	if errors.Is(err, errRegistrySchemeRefused) {
		return "unsupported registry URL scheme refused"
	}
	if errors.Is(err, errRegistryContentMismatch) {
		return "content mismatch"
	}
	if errors.Is(err, errUnsupportedLayer) {
		return "unsupported layer compression"
	}
	var registryErr *transport.Error
	if errors.As(err, &registryErr) {
		detail := fmt.Sprintf("HTTP %d", registryErr.StatusCode)
		var codes []string
		seen := make(map[string]bool)
		for _, diagnostic := range registryErr.Errors {
			code := string(diagnostic.Code)
			if !safeRegistryCode.MatchString(code) || seen[code] || len(codes) == 8 {
				continue
			}
			seen[code] = true
			codes = append(codes, code)
		}
		if len(codes) != 0 {
			detail += "; " + strings.Join(codes, ",")
		}
		return detail
	}
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "TLS verification failed"
	}
	var dns *net.DNSError
	var op *net.OpError
	if errors.As(err, &dns) || errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &op) && op.Op == "dial") {
		return "registry unreachable"
	}
	return ""
}

type boundedIdentityOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedIdentityOutput) Write(data []byte) (int, error) {
	if !w.overflow {
		if len(w.data)+len(data) > 4096 {
			w.data = nil
			w.overflow = true
		} else {
			w.data = append(w.data, data...)
		}
	}
	return len(data), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

// loopbackHTTPOnly is the innermost registry transport. It applies to every
// request, including ping fallbacks, token-realm requests, and redirects:
// plain HTTP is sent only to localhost or a loopback IP literal.
type loopbackHTTPOnly struct{ base http.RoundTripper }

func (t loopbackHTTPOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	refuse := func(err error) (*http.Response, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if req.URL == nil {
		return refuse(errRegistrySchemeRefused)
	}
	switch {
	case strings.EqualFold(req.URL.Scheme, "https"):
	case strings.EqualFold(req.URL.Scheme, "http"):
		if !loopbackHost(req.URL.Hostname()) {
			return refuse(errPlainHTTPRefused)
		}
	default:
		return refuse(errRegistrySchemeRefused)
	}
	return t.base.RoundTrip(req)
}

// dockerConfigKeychain reads only Docker's client configuration (DOCKER_CONFIG
// or ~/.docker/config.json, including credsStore/credHelpers). Unlike
// authn.DefaultKeychain it never falls back to Podman/containers auth files.
// The lookup mirrors go-containerregistry v0.22.1 authn/keychain.go.
type dockerConfigKeychain struct{}

func (dockerConfigKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return nil, err
	}
	var cfg, empty dockertypes.AuthConfig
	for _, key := range []string{target.String(), target.RegistryStr()} {
		if key == name.DefaultRegistry {
			key = authn.DefaultAuthKey
		}
		cfg, err = cf.GetAuthConfig(key)
		if err != nil {
			return nil, err
		}
		cfg.ServerAddress = ""
		if cfg != empty {
			break
		}
	}
	if cfg == empty {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

// publicationSource is the single validated image from the apko layout. Raw
// manifest and config bytes are checksum-verified local blobs; readback is
// compared against these bytes, not re-read files.
type publicationSource struct {
	image          v1.Image
	manifest       []byte
	manifestDigest string
	mediaType      types.MediaType
	config         []byte
	configDigest   string
	configFile     v1.ConfigFile
	layers         []string
}

func openPublicationSource(ctx context.Context, imageDir, arch string) (publicationSource, error) {
	var source publicationSource
	if err := ctx.Err(); err != nil {
		return source, err
	}
	expectedArch, err := ociArchitecture(arch)
	if err != nil {
		return source, err
	}
	index, err := layout.Path(imageDir).ImageIndex()
	if err != nil {
		return source, err
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return source, err
	}
	if len(indexManifest.Manifests) != 1 {
		return source, errors.New("ambiguous source image")
	}
	descriptor := indexManifest.Manifests[0]
	if descriptor.Platform == nil || descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != expectedArch {
		return source, errors.New("source platform mismatch")
	}
	if descriptor.MediaType != types.OCIManifestSchema1 && descriptor.MediaType != types.DockerManifestSchema2 {
		return source, errors.New("unsupported source manifest media type")
	}
	source.manifestDigest, source.mediaType = descriptor.Digest.String(), descriptor.MediaType
	if source.manifest, err = readOCIBlob(imageDir, source.manifestDigest, maxRegistryMetadataBytes); err != nil {
		return source, err
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(source.manifest))
	if err != nil {
		return source, err
	}
	source.configDigest = manifest.Config.Digest.String()
	if source.config, err = readOCIBlob(imageDir, source.configDigest, maxRegistryMetadataBytes); err != nil {
		return source, err
	}
	if err := json.Unmarshal(source.config, &source.configFile); err != nil {
		return source, err
	}
	config := source.configFile
	if config.OS != "linux" || config.Architecture != expectedArch || config.RootFS.Type != "layers" {
		return source, errors.New("source config platform/rootfs mismatch")
	}
	if len(manifest.Layers) == 0 || len(manifest.Layers) != len(config.RootFS.DiffIDs) {
		return source, errors.New("source layer count mismatch")
	}
	for i, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest.String()) || !digestPattern.MatchString(config.RootFS.DiffIDs[i].String()) {
			return source, errors.New("invalid source layer digest")
		}
		source.layers = append(source.layers, layer.Digest.String())
	}
	if source.image, err = index.Image(descriptor.Digest); err != nil {
		return source, err
	}
	return source, ctx.Err()
}

// publishOCIImage pushes the validated layout manifest unchanged and verifies
// the registry copy by digest-addressed readback before reporting success.
func publishOCIImage(ctx context.Context, services buildServices, result buildResult, opts publicationOptions) (publicationOutcome, error) {
	outcome := publicationOutcome{status: "skipped"}
	if err := validatePublicationOptions(opts); err != nil {
		return outcome, safeStageError(ctx, "publication configuration", err)
	}
	if !opts.enabled() {
		return outcome, nil
	}
	outcome.status = "failed"
	fail := func(stage string, err error) (publicationOutcome, error) {
		return outcome, registryStageError(ctx, stage, err)
	}
	target, err := publicationReferences(indexedPackage{name: result.packageName, version: result.version}, result.arch, result.workspace, opts)
	if err != nil {
		return fail("publication reference", err)
	}
	outcome.reference = target.reference
	source, err := openPublicationSource(ctx, result.imageDir, result.arch)
	if err != nil {
		return fail("publication source", err)
	}
	keychain := services.registryKeychain
	if keychain == nil {
		keychain = dockerConfigKeychain{}
	}
	options := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(keychain),
		remote.WithTransport(loopbackHTTPOnly{base: cmp.Or(services.registryTransport, remote.DefaultTransport)}),
		remote.WithUserAgent("lupetto"),
	}

	buildStage(ctx, "Pushing OCI image to registry")
	if err := ctx.Err(); err != nil {
		return fail("publication push", err)
	}
	if err := remote.Write(target.tag, source.image, options...); err != nil {
		return fail("publication push", err)
	}
	// The manifest bytes were pushed unchanged, so the local manifest digest is
	// the registry digest; readback below proves it before it is verified.
	digest := source.manifestDigest
	outcome.pushedDigest, outcome.immutableReference = digest, target.repository+"@"+digest

	puller, err := remote.NewPuller(options...)
	if err != nil {
		return fail("publication readback", err)
	}
	readback := append(append([]remote.Option(nil), options...), remote.Reuse(puller))
	digestReference := func(blob string) (name.Digest, error) {
		return name.NewDigest(target.repository+"@"+blob, target.nameOptions()...)
	}
	sameManifest := func(data []byte) bool {
		return len(data) <= maxRegistryMetadataBytes && "sha256:"+sha256Hex(data) == digest && bytes.Equal(data, source.manifest)
	}

	buildStage(ctx, "Verifying registry manifest by digest")
	immutable, err := digestReference(digest)
	if err != nil {
		return fail("publication manifest readback", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication manifest readback", err)
	}
	byDigest, err := remote.Get(immutable, readback...)
	if err != nil {
		return fail("publication manifest readback", err)
	}
	if !sameManifest(byDigest.Manifest) || byDigest.Digest.String() != digest || byDigest.MediaType != source.mediaType {
		return fail("publication manifest readback", errRegistryContentMismatch)
	}

	buildStage(ctx, "Verifying registry tag")
	if err := ctx.Err(); err != nil {
		return fail("publication tag readback", err)
	}
	// Verify the tag by its body; a Docker-Content-Digest header is not evidence.
	byTag, err := remote.Get(target.tag, readback...)
	if err != nil {
		return fail("publication tag readback", err)
	}
	if !sameManifest(byTag.Manifest) {
		return fail("publication tag readback", errRegistryContentMismatch)
	}

	buildStage(ctx, "Verifying registry config and layers")
	if err := verifyRegistryConfig(ctx, source, digestReference, readback); err != nil {
		return fail("publication config readback", err)
	}
	for i, layerDigest := range source.layers {
		if err := ctx.Err(); err != nil {
			return fail("publication layer readback", err)
		}
		reference, err := digestReference(layerDigest)
		if err != nil {
			return fail("publication layer readback", err)
		}
		layer, err := remote.Layer(reference, readback...)
		if err != nil {
			return fail("publication layer readback", err)
		}
		compressed, err := layer.Compressed()
		if err != nil {
			return fail("publication layer readback", err)
		}
		err = verifyRegistryLayer(ctx, compressed, layerDigest, source.configFile.RootFS.DiffIDs[i].String())
		_ = compressed.Close()
		if err != nil {
			return fail("publication layer readback", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return fail("publication manifest retention", err)
	}
	if err := writeExclusiveFile(filepath.Join(result.workspace, "published-manifest.json"), byDigest.Manifest); err != nil {
		return fail("publication manifest retention", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication manifest retention", err)
	}
	outcome.status, outcome.verified = "published", true
	return outcome, nil
}

func verifyRegistryConfig(ctx context.Context, source publicationSource, digestReference func(string) (name.Digest, error), options []remote.Option) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reference, err := digestReference(source.configDigest)
	if err != nil {
		return err
	}
	layer, err := remote.Layer(reference, options...)
	if err != nil {
		return err
	}
	blob, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer blob.Close()
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, blob}, maxRegistryMetadataBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxRegistryMetadataBytes || "sha256:"+sha256Hex(data) != source.configDigest || !bytes.Equal(data, source.config) {
		return errRegistryContentMismatch
	}
	return ctx.Err()
}

// verifyRegistryLayer reads the compressed stream once: the compressed bytes
// must hash to the manifest digest and the gunzipped stream to the diffID. No
// buffer is sized from registry- or manifest-claimed lengths.
func verifyRegistryLayer(ctx context.Context, compressed io.Reader, wantDigest, wantDiffID string) error {
	compressedHash := sha256.New()
	source := &firstReadError{reader: contextReader{ctx, compressed}}
	stream := bufio.NewReader(io.TeeReader(source, compressedHash))
	// Transport/verification read errors are reported as such; only format
	// and hash disagreements are classified as content mismatches.
	failed := func(err error) error {
		if cause := stageCancellation(ctx, err); cause != nil {
			return cause
		}
		if source.err != nil {
			return source.err
		}
		return errRegistryContentMismatch
	}
	magic, err := stream.Peek(2)
	if err != nil {
		return failed(err)
	}
	if magic[0] != 0x1f || magic[1] != 0x8b {
		return errUnsupportedLayer
	}
	gz, err := gzip.NewReader(stream)
	if err != nil {
		return failed(err)
	}
	uncompressedHash := sha256.New()
	_, err = io.Copy(uncompressedHash, contextReader{ctx, gz})
	_ = gz.Close()
	if err == nil {
		// Hash any compressed bytes after the gzip stream (and let the
		// verifying reader see EOF) before comparing the compressed digest.
		_, err = io.Copy(io.Discard, stream)
	}
	if err != nil {
		return failed(err)
	}
	if "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != wantDigest || "sha256:"+hex.EncodeToString(uncompressedHash.Sum(nil)) != wantDiffID {
		return errRegistryContentMismatch
	}
	return ctx.Err()
}

type firstReadError struct {
	reader io.Reader
	err    error
}

func (r *firstReadError) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	if err != nil && err != io.EOF && r.err == nil {
		r.err = err
	}
	return n, err
}

func writeExclusiveFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
