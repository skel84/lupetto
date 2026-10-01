package build

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

const maxRegistryMetadataBytes = registry.MaxMetadataBytes

type PublicationOutcome struct {
	Status, Reference, PushedDigest, ImmutableReference string
	Verified                                            bool
}

type publicationStageError = registry.StageError

func stageCancellation(ctx context.Context, err error) error {
	return registry.StageCancellation(ctx, err)
}

func safeStageError(ctx context.Context, stage string, err error) error {
	return registry.SafeStageError(ctx, stage, err)
}

var (
	errPlainHTTPRefused        = registry.ErrPlainHTTPRefused
	errRegistrySchemeRefused   = registry.ErrSchemeRefused
	errRegistryContentMismatch = registry.ErrContentMismatch
	errUnsupportedLayer        = registry.ErrUnsupportedLayer
)

func registryStageError(ctx context.Context, stage string, err error) error {
	return registry.SafeError(ctx, stage, err)
}

func registryErrorDetail(err error) string {
	return registry.ErrorDetail(err)
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

type loopbackHTTPOnly struct{ base http.RoundTripper }

func (t loopbackHTTPOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	return registry.GuardTransport(t.base).RoundTrip(req)
}

type dockerConfigKeychain = registry.DockerConfigKeychain

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
func publishOCIImage(ctx context.Context, services Services, result Result, opts PublicationOptions) (PublicationOutcome, error) {
	outcome := PublicationOutcome{Status: "skipped"}
	if err := validatePublicationOptions(opts); err != nil {
		return outcome, safeStageError(ctx, "publication configuration", err)
	}
	if !opts.Enabled() {
		return outcome, nil
	}
	outcome.Status = "failed"
	fail := func(stage string, err error) (PublicationOutcome, error) {
		return outcome, registryStageError(ctx, stage, err)
	}
	target, err := publicationReferences(wolfi.Package{Name: result.PackageName, Version: result.Version}, result.Arch, result.Workspace, opts)
	if err != nil {
		return fail("publication reference", err)
	}
	outcome.Reference = target.reference
	source, err := openPublicationSource(ctx, result.ImageDir, result.Arch)
	if err != nil {
		return fail("publication source", err)
	}
	// Push only the manifest validated against the selected APK; a layout
	// changed after validation must not be published as verified.
	if source.manifestDigest != result.ImageDigest {
		return fail("publication source", errRegistryContentMismatch)
	}
	options := registry.ClientOptions(ctx, services.RegistryTransport, services.RegistryKeychain)

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
	outcome.PushedDigest, outcome.ImmutableReference = digest, target.repository+"@"+digest

	puller, err := remote.NewPuller(options...)
	if err != nil {
		return fail("publication readback", err)
	}
	readback := append(append([]remote.Option(nil), options...), remote.Reuse(puller))
	digestReference := func(blob string) (name.Digest, error) {
		return name.NewDigest(target.repository+"@"+blob, target.nameOptions()...)
	}
	sameManifest := func(data []byte) bool {
		return len(data) <= maxRegistryMetadataBytes && "sha256:"+wolfi.SHA256Hex(data) == digest && bytes.Equal(data, source.manifest)
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
	if err := writeExclusiveFile(filepath.Join(result.Workspace, "published-manifest.json"), byDigest.Manifest); err != nil {
		return fail("publication manifest retention", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication manifest retention", err)
	}
	outcome.Status, outcome.Verified = "published", true
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
	if len(data) > maxRegistryMetadataBytes || "sha256:"+wolfi.SHA256Hex(data) != source.configDigest || !bytes.Equal(data, source.config) {
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
