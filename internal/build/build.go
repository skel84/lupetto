// Package build is Lupetto's single exact-build pipeline: request and option
// resolution, apko composition, lock/image/SPDX validation, Docker loading,
// OCI publication, Cosign signing, and version-6 result records. Progress is
// reported through a context Reporter; the pipeline has no terminal code.
package build

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"lupetto/internal/wolfi"
)

// ApkoVersion is the exact apko release this build path requires.
const ApkoVersion = "1.4.5"

type sourceDateEpochContextKey struct{}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Result carries every stage outcome and the evidence of one workflow.
type Result struct {
	Command                                                          string
	Request                                                          RecordRequest
	PackageName, Version, Arch, IndexSHA256                          string
	Workspace, ImageDir, ImageDigest, LockPath, SPDXPath, SPDXSHA256 string
	Selected, Validated                                              bool
	ImageReference, BuildReference                                   string
	Build, DockerLoad, DockerImageID                                 string
	ReadableConfirmed                                                bool
	Signing, Attestation                                             string
	Publication                                                      PublicationOutcome
	// Record holds the exact version-6 document written to result.json.
	Record []byte
}

// Run executes the pipeline with the production tool, network, and registry
// boundaries.
func Run(ctx context.Context, request Request) (Result, error) {
	return RunWith(ctx, request, Services{
		Command: ExecuteLocalCommand, CacheDir: os.UserCacheDir,
		PublicFile: wolfi.GetPublicFile, SigningKey: wolfi.GetSigningKey,
		SigningCommand: executeSigningCommand,
	})
}

// Only external boundaries are replaceable; selection and artifact validation
// always use the same implementation.
type Services struct {
	Command        CommandFunc
	SigningCommand CommandFunc
	CacheDir       func() (string, error)
	PublicFile     func(context.Context, string, int64) ([]byte, error)
	SigningKey     func(context.Context) ([]byte, error)
	// RegistryTransport nil means remote.DefaultTransport. Either way it is
	// wrapped by the loopback-only plain-HTTP guard.
	RegistryTransport http.RoundTripper
	// RegistryKeychain nil means Docker's client configuration only.
	RegistryKeychain authn.Keychain
}

// RunWith executes the pipeline with the given external boundaries. After
// option validation, every failure is a *WorkflowFailure.
func RunWith(ctx context.Context, request Request, services Services) (Result, error) {
	if err := validatePublicationOptions(request.Publication); err != nil {
		return Result{}, err
	}
	if err := validateSigningOptions(request.Signing, request.Publication); err != nil {
		return Result{}, err
	}
	result := InitialResult(request)
	// Publication workflows keep their sanitized stage-only failure messages.
	sanitize := request.Publication.Enabled()
	fail := func(stage string, err error) (Result, error) {
		return result, NewWorkflowFailure(result, stage, err, sanitize)
	}
	buildFail := func(err error) (Result, error) {
		result.Build = "failed"
		return fail("build", err)
	}
	if err := ctx.Err(); err != nil {
		return buildFail(err)
	}
	if request.Signing.Enabled() {
		buildStage(ctx, "Checking Cosign v3.1.3 compatibility")
		if err := requireCosignVersion(ctx, services.SigningCommand); err != nil {
			return fail("cosign-version", err)
		}
	}
	buildStage(ctx, "Checking build tools")
	arch, err := wolfi.TargetArch()
	if err != nil {
		return buildFail(err)
	}
	if err := RequireApkoVersion(ctx, services.Command); err != nil {
		return buildFail(err)
	}
	buildStage(ctx, "Creating build workspace")
	cacheDir, err := services.CacheDir()
	if err != nil {
		return buildFail(fmt.Errorf("find user cache: %w", err))
	}
	root := filepath.Join(cacheDir, "lupetto", "builds")
	if err := os.MkdirAll(root, 0700); err != nil {
		return buildFail(fmt.Errorf("create build directory: %w", err))
	}
	workspace, err := os.MkdirTemp(root, "image-")
	if err != nil {
		return buildFail(fmt.Errorf("create build workspace: %w", err))
	}
	buildReference := "lupetto/local:build-" + strings.TrimPrefix(filepath.Base(workspace), "image-")
	result.Workspace, result.BuildReference = workspace, buildReference

	buildStage(ctx, "Fetching signed APKINDEX")
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", wolfi.Repository, arch)
	index, err := services.PublicFile(ctx, indexURL, 32<<20)
	if err != nil {
		return buildFail(err)
	}
	indexDigest := wolfi.SHA256Hex(index)
	if err := os.WriteFile(filepath.Join(workspace, "APKINDEX.tar.gz"), index, 0600); err != nil {
		return buildFail(fmt.Errorf("retain APKINDEX: %w", err))
	}
	if err := os.WriteFile(filepath.Join(workspace, "APKINDEX.sha256"), []byte(indexDigest+"\n"), 0600); err != nil {
		return buildFail(fmt.Errorf("retain APKINDEX checksum: %w", err))
	}
	buildStage(ctx, "Fetching Wolfi signing key")
	key, err := services.SigningKey(ctx)
	if err != nil {
		return buildFail(err)
	}
	keyPath := filepath.Join(workspace, "wolfi-signing.rsa.pub")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return buildFail(fmt.Errorf("retain Wolfi key: %w", err))
	}
	buildStage(ctx, "Verifying APKINDEX signature")
	verifiedIndex, err := wolfi.VerifyAPKINDEX(index, key)
	if err != nil {
		return buildFail(err)
	}
	buildStage(ctx, "Selecting exact APK")
	packages, err := wolfi.ParseAPKINDEX(verifiedIndex, request.PackageName)
	if err != nil {
		return buildFail(err)
	}
	selected, err := wolfi.SelectPackage(packages, request.PackageName, request.Selector, request.Version, arch)
	if err != nil {
		return buildFail(err)
	}
	result.PackageName, result.Version, result.Arch, result.IndexSHA256, result.Selected = selected.Name, selected.Version, arch, indexDigest, true
	imageReference, err := readableImageReference(selected, arch)
	if err != nil {
		return buildFail(err)
	}
	result.ImageReference = imageReference
	if request.Publication.Enabled() {
		// The selected component is now known; reject a full-reference bound
		// or normalization failure before composition/loading, without
		// resolving another APK.
		if _, err := publicationReferences(selected, arch, workspace, request.Publication); err != nil {
			return buildFail(err)
		}
	}
	buildMessage(ctx, "Selected %s@%s; local reference %s; build reference %s", selected.Name, selected.Version, imageReference, buildReference)
	configPath := filepath.Join(workspace, "apko.yaml")
	created := time.Now().UTC().Truncate(time.Second)
	config := fmt.Sprintf("contents:\n  keyring:\n    - %s\n  repositories:\n    - %s\n  packages:\n    - %s\narchs:\n  - %s\nannotations:\n  org.opencontainers.image.version: %s\n  org.opencontainers.image.created: %s\n  lupetto.apk.name: %s\n  lupetto.apk.version: %s\n  lupetto.apk.architecture: %s\n  lupetto.index.sha256: %s\n", strconv.Quote(keyPath), wolfi.Repository, strconv.Quote(selected.Name+"="+selected.Version), arch, strconv.Quote(selected.Version), strconv.Quote(created.Format(time.RFC3339)), strconv.Quote(selected.Name), strconv.Quote(selected.Version), strconv.Quote(selected.Arch), strconv.Quote(indexDigest))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return buildFail(fmt.Errorf("retain apko config: %w", err))
	}
	lockPath := filepath.Join(workspace, "lock.json")
	buildStage(ctx, "Locking apko dependencies")
	if err := runApko(ctx, services.Command, "lock", "--arch", arch, "--output", lockPath, configPath); err != nil {
		return buildFail(err)
	}
	if err := checkSelectedLock(lockPath, selected); err != nil {
		return buildFail(err)
	}

	sbomDir := filepath.Join(workspace, "sbom")
	if err := os.Mkdir(sbomDir, 0700); err != nil {
		return buildFail(fmt.Errorf("create SPDX directory: %w", err))
	}
	imageDir := filepath.Join(workspace, "image")
	if err := os.Mkdir(imageDir, 0700); err != nil {
		return buildFail(fmt.Errorf("create OCI layout directory: %w", err))
	}
	buildStage(ctx, "Composing OCI image with apko")
	// apko replaces the configured created annotation with its build epoch.
	// Pin that epoch for this subprocess only; an inherited SOURCE_DATE_EPOCH
	// must not turn actual build time into an APK's historical build time.
	buildContext := context.WithValue(ctx, sourceDateEpochContextKey{}, strconv.FormatInt(created.Unix(), 10))
	if err := runApko(buildContext, services.Command, "build", "--build-date", created.Format(time.RFC3339), "--arch", arch, "--sbom-path", sbomDir, "--sbom-formats", "spdx", "--vcs=false", "--lockfile", lockPath, configPath, buildReference, imageDir+string(os.PathSeparator)); err != nil {
		return buildFail(err)
	}
	buildStage(ctx, "Checking installed APK")
	imageDigest, err := checkImagePackage(imageDir, selected)
	if err != nil {
		return buildFail(err)
	}
	buildStage(ctx, "Validating SPDX against apko lock")
	spdxPath := filepath.Join(sbomDir, "sbom-"+arch+".spdx.json")
	spdxSHA256, err := validateSPDX(lockPath, spdxPath, arch)
	if err != nil {
		return buildFail(fmt.Errorf("validate SPDX against apko lock: %w", err))
	}
	result.Build, result.Validated = "completed", true
	result.ImageDir, result.ImageDigest, result.LockPath, result.SPDXPath, result.SPDXSHA256 = imageDir, imageDigest, lockPath, spdxPath, spdxSHA256

	if !request.NoLoad {
		imageID, err := loadDockerImage(ctx, services.Command, imageDir, workspace, buildReference, arch)
		if err != nil {
			result.DockerLoad = "failed"
			return fail("load", err)
		}
		result.DockerLoad, result.DockerImageID = "loaded", imageID
		if err := tagReadableDockerImage(ctx, services.Command, imageID, buildReference, imageReference, arch); err != nil {
			return fail("readable-tag", err)
		}
		result.ReadableConfirmed = true
	} else {
		buildMessage(ctx, "Docker loading skipped")
	}
	if request.Publication.Enabled() {
		result.Publication, err = publishOCIImage(ctx, services, result, request.Publication)
		if err != nil {
			return fail("publication", err)
		}
	}
	if request.Signing.Enabled() {
		outcome, signingErr := signAndAttestDigest(ctx, services.SigningCommand, result, request.Signing)
		result.Signing, result.Attestation = outcome.signing, outcome.attestation
		if signingErr != nil {
			stage := "signing"
			if outcome.signing == "signed" {
				stage = "attestation"
			}
			return fail(stage, signingErr)
		}
	}
	buildStage(ctx, "Recording build result")
	record, err := retainBuildResult(ctx, result)
	if err != nil {
		if !sanitize && result.DockerLoad == "loaded" {
			err = fmt.Errorf("Docker loading confirmed for %s and %s (image ID: %s), but result recording failed; imported image/tags remain: %w", imageReference, buildReference, result.DockerImageID, err)
		}
		return fail("record", err)
	}
	result.Record = record
	return result, nil
}

func RequireApkoVersion(ctx context.Context, command CommandFunc) error {
	output, err := command(ctx, "apko", "version")
	if err != nil {
		return fmt.Errorf("apko %s is required: %w", ApkoVersion, err)
	}
	if !strings.Contains(string(output), "GitVersion:    "+ApkoVersion+"\n") &&
		!strings.Contains(string(output), "GitVersion:    v"+ApkoVersion+"\n") {
		return fmt.Errorf("apko %s is required for this build path", ApkoVersion)
	}
	return nil
}

func runApko(ctx context.Context, command CommandFunc, args ...string) error {
	output, err := command(ctx, "apko", args...)
	if err != nil {
		return fmt.Errorf("apko %s failed: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return nil
}

func checkSelectedLock(path string, selected wolfi.Package) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read apko lock: %w", err)
	}
	var lock struct {
		Contents struct {
			Packages []struct {
				Name, Version, Architecture, Checksum string
			} `json:"packages"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("decode apko lock: %w", err)
	}
	matches := 0
	for _, pkg := range lock.Contents.Packages {
		if pkg.Name != selected.Name {
			continue
		}
		matches++
		if pkg.Version != selected.Version || pkg.Architecture != selected.Arch || pkg.Checksum != selected.Checksum {
			return fmt.Errorf("apko lock does not match selected %s@%s and APKINDEX checksum", selected.Name, selected.Version)
		}
	}
	if matches != 1 {
		return fmt.Errorf("apko lock has %d entries for selected %s@%s", matches, selected.Name, selected.Version)
	}
	return nil
}

func readOCIBlob(dir, digest string, maxBytes int64) ([]byte, error) {
	if !digestPattern.MatchString(digest) {
		return nil, fmt.Errorf("invalid OCI digest %q", digest)
	}
	path := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OCI blob %s: %w", digest, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("OCI blob %s exceeds %d bytes", digest, maxBytes)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.TrimPrefix(digest, "sha256:") {
		return nil, fmt.Errorf("OCI blob %s checksum mismatch", digest)
	}
	return data, nil
}

// checkImagePackage returns the validated local OCI manifest digest.
func checkImagePackage(dir string, selected wolfi.Package) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, "oci-layout")); err != nil {
		return "", fmt.Errorf("OCI layout missing: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return "", fmt.Errorf("read OCI index: %w", err)
	}
	var index struct {
		Manifests []struct {
			Digest   string
			Platform struct{ Architecture, OS string }
		}
	}
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) != 1 {
		return "", fmt.Errorf("expected one OCI image manifest: %v", err)
	}
	platform := index.Manifests[0].Platform
	if platform.OS != "linux" || (selected.Arch == "x86_64" && platform.Architecture != "amd64") || (selected.Arch == "aarch64" && platform.Architecture != "arm64") {
		return "", fmt.Errorf("OCI image platform does not match %s", selected.Arch)
	}
	data, err = readOCIBlob(dir, index.Manifests[0].Digest, 4<<20)
	if err != nil {
		return "", fmt.Errorf("read OCI manifest: %w", err)
	}
	var manifest struct{ Layers []struct{ Digest string } }
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Layers) != 1 {
		return "", fmt.Errorf("expected one OCI image layer: %v", err)
	}
	layerDigest := manifest.Layers[0].Digest
	if !digestPattern.MatchString(layerDigest) {
		return "", fmt.Errorf("invalid OCI layer digest %q", layerDigest)
	}
	layerPath := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(layerDigest, "sha256:"))
	layer, err := os.Open(layerPath)
	if err != nil {
		return "", fmt.Errorf("open OCI layer: %w", err)
	}
	defer layer.Close()
	layerHash := sha256.New()
	if _, err := io.Copy(layerHash, layer); err != nil {
		return "", fmt.Errorf("hash OCI layer: %w", err)
	}
	if hex.EncodeToString(layerHash.Sum(nil)) != strings.TrimPrefix(layerDigest, "sha256:") {
		return "", fmt.Errorf("OCI layer checksum mismatch")
	}
	if _, err := layer.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind OCI layer: %w", err)
	}
	installed, err := wolfi.ReadInstalledPackages(layer)
	if err != nil {
		return "", err
	}
	for _, pkg := range installed {
		if pkg.Name == selected.Name {
			if pkg.Version == selected.Version && pkg.Arch == selected.Arch {
				return index.Manifests[0].Digest, nil
			}
			return "", fmt.Errorf("OCI image contains a different version or architecture of %s", selected.Name)
		}
	}
	return "", fmt.Errorf("OCI image does not contain selected %s@%s", selected.Name, selected.Version)
}
