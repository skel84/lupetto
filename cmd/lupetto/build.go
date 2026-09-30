package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const apkoBuildVersion = "1.4.5"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type buildResult struct {
	packageName, version, arch, indexSHA256, workspace, imageDir, spdxPath, spdxSHA256 string
	imageReference, buildReference, dockerLoad, dockerImageID                          string
	publication                                                                        publicationOutcome
}

type evidenceResult struct {
	Version        int                  `json:"version"`
	PackageName    string               `json:"packageName"`
	PackageVersion string               `json:"packageVersion"`
	Architecture   string               `json:"architecture"`
	IndexSHA256    string               `json:"indexSHA256"`
	ApkoVersion    string               `json:"apkoVersion"`
	ImageDirectory string               `json:"imageDirectory"`
	LockPath       string               `json:"lockPath"`
	SPDXPath       string               `json:"spdxPath"`
	SPDXSHA256     string               `json:"spdxSHA256"`
	SPDXValidated  bool                 `json:"spdxValidated"`
	ImageReference string               `json:"imageReference"`
	BuildReference string               `json:"buildReference"`
	DockerLoad     string               `json:"dockerLoad"`
	DockerImageID  string               `json:"dockerImageID,omitempty"`
	Publication    *publicationEvidence `json:"publication,omitempty"`
	Build          string               `json:"build,omitempty"`
	Signing        string               `json:"signing,omitempty"`
	Attestation    string               `json:"attestation,omitempty"`
}

func buildLocal(ctx context.Context, request buildRequest) (buildResult, error) {
	return buildLocalWith(ctx, request, buildServices{
		command: executeLocalCommand, cacheDir: os.UserCacheDir,
		publicFile: getPublicFile, signingKey: getWolfiSigningKey,
		publicationCommand: executePublicationCommand,
	})
}

// Only external boundaries are replaceable; selection and artifact validation
// always use the same implementation.
type buildServices struct {
	command            localCommand
	publicationCommand localCommand
	cacheDir           func() (string, error)
	publicFile         func(context.Context, string, int64) ([]byte, error)
	signingKey         func(context.Context) ([]byte, error)
}

func buildLocalWith(ctx context.Context, request buildRequest, services buildServices) (buildResult, error) {
	earlyFail := func(err error) (buildResult, error) {
		if request.publication.enabled() {
			result := buildResult{dockerLoad: "skipped", publication: publicationOutcome{status: "skipped"}}
			return result, newWorkflowFailure(result, "build", err, false)
		}
		return buildResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return earlyFail(err)
	}
	if err := validatePublicationOptions(request.publication); err != nil {
		return buildResult{}, err
	}
	if request.publication.enabled() && request.noLoad {
		return buildResult{}, fmt.Errorf("publication requires Docker loading; --no-load is incompatible")
	}
	buildStage(ctx, "Checking build tools")
	arch, err := targetArch()
	if err != nil {
		return earlyFail(err)
	}
	if err := requireApkoVersion(ctx, services.command); err != nil {
		return earlyFail(err)
	}
	buildStage(ctx, "Creating build workspace")
	cacheDir, err := services.cacheDir()
	if err != nil {
		return earlyFail(fmt.Errorf("find user cache: %w", err))
	}
	root := filepath.Join(cacheDir, "lupetto", "builds")
	if err := os.MkdirAll(root, 0700); err != nil {
		return earlyFail(fmt.Errorf("create build directory: %w", err))
	}
	workspace, err := os.MkdirTemp(root, "image-")
	if err != nil {
		return earlyFail(fmt.Errorf("create build workspace: %w", err))
	}
	buildReference := "lupetto/local:build-" + strings.TrimPrefix(filepath.Base(workspace), "image-")
	result := buildResult{workspace: workspace, dockerLoad: "skipped", publication: publicationOutcome{status: "skipped"}}
	fail := func(err error) (buildResult, error) {
		if request.publication.enabled() {
			return result, newWorkflowFailure(result, "build", err, false)
		}
		return buildResult{}, fmt.Errorf("%w (workspace: %s)", err, workspace)
	}

	buildStage(ctx, "Fetching signed APKINDEX")
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", wolfiRepository, arch)
	index, err := services.publicFile(ctx, indexURL, 32<<20)
	if err != nil {
		return fail(err)
	}
	indexDigest := sha256Hex(index)
	if err := os.WriteFile(filepath.Join(workspace, "APKINDEX.tar.gz"), index, 0600); err != nil {
		return fail(fmt.Errorf("retain APKINDEX: %w", err))
	}
	if err := os.WriteFile(filepath.Join(workspace, "APKINDEX.sha256"), []byte(indexDigest+"\n"), 0600); err != nil {
		return fail(fmt.Errorf("retain APKINDEX checksum: %w", err))
	}
	buildStage(ctx, "Fetching Wolfi signing key")
	key, err := services.signingKey(ctx)
	if err != nil {
		return fail(err)
	}
	keyPath := filepath.Join(workspace, "wolfi-signing.rsa.pub")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return fail(fmt.Errorf("retain Wolfi key: %w", err))
	}
	buildStage(ctx, "Verifying APKINDEX signature")
	verifiedIndex, err := verifyAPKINDEX(index, key)
	if err != nil {
		return fail(err)
	}
	buildStage(ctx, "Selecting exact APK")
	packages, err := parseAPKINDEX(verifiedIndex, request.packageName)
	if err != nil {
		return fail(err)
	}
	selected, err := selectPackage(packages, request, arch)
	if err != nil {
		return fail(err)
	}
	imageReference, err := readableImageReference(selected, arch)
	if err != nil {
		return fail(err)
	}
	if request.publication.enabled() {
		// The selected component is now known; reject a full-reference bound
		// failure before composition/loading, without resolving another APK.
		if _, err := publicationReferences(selected, arch, workspace, request.publication); err != nil {
			return fail(err)
		}
	}
	buildMessage(ctx, "Selected %s@%s; local reference %s; build reference %s", selected.name, selected.version, imageReference, buildReference)
	configPath := filepath.Join(workspace, "apko.yaml")
	config := fmt.Sprintf("contents:\n  keyring:\n    - %s\n  repositories:\n    - %s\n  packages:\n    - %s\narchs:\n  - %s\n", strconv.Quote(keyPath), wolfiRepository, strconv.Quote(selected.name+"="+selected.version), arch)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fail(fmt.Errorf("retain apko config: %w", err))
	}
	lockPath := filepath.Join(workspace, "lock.json")
	buildStage(ctx, "Locking apko dependencies")
	if err := runApko(ctx, services.command, "lock", "--arch", arch, "--output", lockPath, configPath); err != nil {
		return fail(err)
	}
	if err := checkSelectedLock(lockPath, selected); err != nil {
		return fail(err)
	}

	sbomDir := filepath.Join(workspace, "sbom")
	if err := os.Mkdir(sbomDir, 0700); err != nil {
		return fail(fmt.Errorf("create SPDX directory: %w", err))
	}
	imageDir := filepath.Join(workspace, "image")
	if err := os.Mkdir(imageDir, 0700); err != nil {
		return fail(fmt.Errorf("create OCI layout directory: %w", err))
	}
	buildStage(ctx, "Composing OCI image with apko")
	if err := runApko(ctx, services.command, "build", "--arch", arch, "--sbom-path", sbomDir, "--sbom-formats", "spdx", "--vcs=false", "--lockfile", lockPath, configPath, buildReference, imageDir+string(os.PathSeparator)); err != nil {
		return fail(err)
	}
	buildStage(ctx, "Checking installed APK")
	if err := checkImagePackage(imageDir, selected); err != nil {
		return fail(err)
	}
	buildStage(ctx, "Validating SPDX against apko lock")
	spdxPath := filepath.Join(sbomDir, "sbom-"+arch+".spdx.json")
	spdxSHA256, err := validateSPDX(lockPath, spdxPath, arch)
	if err != nil {
		return fail(fmt.Errorf("validate SPDX against apko lock: %w", err))
	}
	result = buildResult{
		packageName: selected.name, version: selected.version, arch: arch,
		indexSHA256: indexDigest, workspace: workspace, imageDir: imageDir,
		spdxPath: spdxPath, spdxSHA256: spdxSHA256, imageReference: imageReference,
		buildReference: buildReference, dockerLoad: "skipped", publication: publicationOutcome{status: "skipped"},
	}
	if !request.noLoad {
		imageID, err := loadDockerImage(ctx, services.command, imageDir, workspace, buildReference, arch)
		if err != nil {
			if request.publication.enabled() {
				result.dockerLoad = "failed"
				return result, newWorkflowFailure(result, "load", err, true)
			}
			return fail(err)
		}
		result.dockerLoad, result.dockerImageID = "loaded", imageID
		if err := tagReadableDockerImage(ctx, services.command, imageID, buildReference, imageReference, arch); err != nil {
			if request.publication.enabled() {
				return result, newWorkflowFailure(result, "readable-tag", err, true)
			}
			return fail(err)
		}
	}
	if request.noLoad {
		buildMessage(ctx, "Docker loading skipped")
	}
	if request.publication.enabled() {
		command := services.publicationCommand
		if command == nil {
			command = services.command // Injected fixtures; production always supplies the safe adapter.
		}
		result.publication, err = publishDockerImage(ctx, command, result, request.publication)
		if err != nil {
			return result, newWorkflowFailure(result, "publication", err, true)
		}
	}
	buildStage(ctx, "Recording build result")
	if err := retainBuildResult(ctx, result, lockPath); err != nil {
		if request.publication.enabled() {
			return result, newWorkflowFailure(result, "record", err, true)
		}
		if result.dockerLoad == "loaded" {
			return fail(fmt.Errorf("Docker loading confirmed for %s and %s (image ID: %s), but result recording failed; imported image/tags remain: %w", imageReference, buildReference, result.dockerImageID, err))
		}
		return fail(err)
	}
	return result, nil
}

func requireApkoVersion(ctx context.Context, command localCommand) error {
	output, err := command(ctx, "apko", "version")
	if err != nil {
		return fmt.Errorf("apko %s is required: %w", apkoBuildVersion, err)
	}
	if !strings.Contains(string(output), "GitVersion:    "+apkoBuildVersion+"\n") {
		return fmt.Errorf("apko %s is required for this build path", apkoBuildVersion)
	}
	return nil
}

func runApko(ctx context.Context, command localCommand, args ...string) error {
	output, err := command(ctx, "apko", args...)
	if err != nil {
		return fmt.Errorf("apko %s failed: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return nil
}

func checkSelectedLock(path string, selected indexedPackage) error {
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
		if pkg.Name != selected.name {
			continue
		}
		matches++
		if pkg.Version != selected.version || pkg.Architecture != selected.arch || pkg.Checksum != selected.checksum {
			return fmt.Errorf("apko lock does not match selected %s@%s and APKINDEX checksum", selected.name, selected.version)
		}
	}
	if matches != 1 {
		return fmt.Errorf("apko lock has %d entries for selected %s@%s", matches, selected.name, selected.version)
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

func checkImagePackage(dir string, selected indexedPackage) error {
	if _, err := os.Stat(filepath.Join(dir, "oci-layout")); err != nil {
		return fmt.Errorf("OCI layout missing: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return fmt.Errorf("read OCI index: %w", err)
	}
	var index struct {
		Manifests []struct {
			Digest   string
			Platform struct{ Architecture, OS string }
		}
	}
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) != 1 {
		return fmt.Errorf("expected one OCI image manifest: %v", err)
	}
	platform := index.Manifests[0].Platform
	if platform.OS != "linux" || (selected.arch == "x86_64" && platform.Architecture != "amd64") || (selected.arch == "aarch64" && platform.Architecture != "arm64") {
		return fmt.Errorf("OCI image platform does not match %s", selected.arch)
	}
	data, err = readOCIBlob(dir, index.Manifests[0].Digest, 4<<20)
	if err != nil {
		return fmt.Errorf("read OCI manifest: %w", err)
	}
	var manifest struct{ Layers []struct{ Digest string } }
	if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Layers) != 1 {
		return fmt.Errorf("expected one OCI image layer: %v", err)
	}
	layerDigest := manifest.Layers[0].Digest
	if !digestPattern.MatchString(layerDigest) {
		return fmt.Errorf("invalid OCI layer digest %q", layerDigest)
	}
	layerPath := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(layerDigest, "sha256:"))
	layer, err := os.Open(layerPath)
	if err != nil {
		return fmt.Errorf("open OCI layer: %w", err)
	}
	defer layer.Close()
	layerHash := sha256.New()
	if _, err := io.Copy(layerHash, layer); err != nil {
		return fmt.Errorf("hash OCI layer: %w", err)
	}
	if hex.EncodeToString(layerHash.Sum(nil)) != strings.TrimPrefix(layerDigest, "sha256:") {
		return fmt.Errorf("OCI layer checksum mismatch")
	}
	if _, err := layer.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind OCI layer: %w", err)
	}
	gz, err := gzip.NewReader(layer)
	if err != nil {
		return fmt.Errorf("open OCI layer gzip: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return fmt.Errorf("installed APK database missing from OCI image")
		}
		if err != nil {
			return fmt.Errorf("read OCI layer tar: %w", err)
		}
		if header.Name != "usr/lib/apk/db/installed" {
			continue
		}
		if header.Size > 8<<20 {
			return fmt.Errorf("installed APK database exceeds 8 MiB")
		}
		installed, err := io.ReadAll(io.LimitReader(archive, (8<<20)+1))
		if err != nil {
			return fmt.Errorf("read installed APK database: %w", err)
		}
		for _, record := range strings.Split(string(installed), "\n\n") {
			if strings.Contains("\n"+record+"\n", "\nP:"+selected.name+"\n") {
				if strings.Contains("\n"+record+"\n", "\nV:"+selected.version+"\n") && strings.Contains("\n"+record+"\n", "\nA:"+selected.arch+"\n") {
					return nil
				}
				return fmt.Errorf("OCI image contains a different version or architecture of %s", selected.name)
			}
		}
		return fmt.Errorf("OCI image does not contain selected %s@%s", selected.name, selected.version)
	}
}
