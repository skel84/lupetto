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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const apkoBuildVersion = "1.4.5"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type buildResult struct {
	packageName, version, indexSHA256, workspace, imageDir string
}

func buildLocal(ctx context.Context, request buildRequest) (buildResult, error) {
	arch, err := targetArch()
	if err != nil {
		return buildResult{}, err
	}
	if err := requireApkoVersion(ctx); err != nil {
		return buildResult{}, err
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return buildResult{}, fmt.Errorf("find user cache: %w", err)
	}
	root := filepath.Join(cacheDir, "lupetto", "builds")
	if err := os.MkdirAll(root, 0700); err != nil {
		return buildResult{}, fmt.Errorf("create build directory: %w", err)
	}
	workspace, err := os.MkdirTemp(root, "postgresql-17-")
	if err != nil {
		return buildResult{}, fmt.Errorf("create build workspace: %w", err)
	}
	fail := func(err error) (buildResult, error) {
		return buildResult{}, fmt.Errorf("%w (workspace: %s)", err, workspace)
	}

	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", wolfiRepository, arch)
	index, err := getPublicFile(ctx, indexURL, 32<<20)
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
	key, err := getPublicFile(ctx, wolfiKeyURL, 16<<10)
	if err != nil {
		return fail(err)
	}
	if sha256Hex(key) != wolfiKeySHA256 {
		return fail(fmt.Errorf("Wolfi signing key fingerprint changed; refusing to use untrusted key"))
	}
	keyPath := filepath.Join(workspace, "wolfi-signing.rsa.pub")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return fail(fmt.Errorf("retain Wolfi key: %w", err))
	}
	verifiedIndex, err := verifyAPKINDEX(index, key)
	if err != nil {
		return fail(err)
	}
	packages, err := parseAPKINDEX(verifiedIndex)
	if err != nil {
		return fail(err)
	}
	selected, err := selectPostgres(packages, request, arch)
	if err != nil {
		return fail(err)
	}
	configPath := filepath.Join(workspace, "apko.yaml")
	config := fmt.Sprintf("contents:\n  keyring:\n    - %s\n  repositories:\n    - %s\n  packages:\n    - %s\narchs:\n  - %s\n", strconv.Quote(keyPath), wolfiRepository, strconv.Quote(postgresAPK+"="+selected.version), arch)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fail(fmt.Errorf("retain apko config: %w", err))
	}
	lockPath := filepath.Join(workspace, "lock.json")
	if err := runApko(ctx, "lock", "--arch", arch, "--output", lockPath, configPath); err != nil {
		return fail(err)
	}
	if err := checkSelectedLock(lockPath, selected); err != nil {
		return fail(err)
	}

	imageDir := filepath.Join(workspace, "image")
	if err := os.Mkdir(imageDir, 0700); err != nil {
		return fail(fmt.Errorf("create OCI layout directory: %w", err))
	}
	tag := "lupetto/postgresql:" + selected.version
	if err := runApko(ctx, "build", "--arch", arch, "--sbom=false", "--vcs=false", "--lockfile", lockPath, configPath, tag, imageDir+string(os.PathSeparator)); err != nil {
		return fail(err)
	}
	if err := checkImagePackage(imageDir, selected); err != nil {
		return fail(err)
	}
	return buildResult{packageName: postgresAPK, version: selected.version, indexSHA256: indexDigest, workspace: workspace, imageDir: imageDir}, nil
}

func requireApkoVersion(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "apko", "version").Output()
	if err != nil {
		return fmt.Errorf("apko %s is required: %w", apkoBuildVersion, err)
	}
	if !strings.Contains(string(output), "GitVersion:    "+apkoBuildVersion+"\n") {
		return fmt.Errorf("apko %s is required for this build path", apkoBuildVersion)
	}
	return nil
}

func runApko(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "apko", args...).CombinedOutput()
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
