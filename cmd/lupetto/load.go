package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type localCommand func(context.Context, string, ...string) ([]byte, error)

func executeLocalCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output := &localCommandOutput{}
	if liveCommandDiagnostics(executable, args) {
		output.progress = progressFromContext(ctx)
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if ctx.Err() != nil {
		return output.capture.Bytes(), ctx.Err()
	}
	return output.capture.Bytes(), err
}

type localCommandOutput struct {
	capture  bytes.Buffer
	progress *buildProgress
}

func (w *localCommandOutput) Write(data []byte) (int, error) {
	n, err := w.capture.Write(data)
	w.progress.Write(data)
	return n, err
}

func liveCommandDiagnostics(executable string, args []string) bool {
	switch filepath.Base(executable) {
	case "apko":
		return len(args) != 0 && (args[0] == "lock" || args[0] == "build")
	case "docker":
		return len(args) >= 2 && args[0] == "image" && args[1] == "load"
	default:
		return false
	}
}

type contextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w contextWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.writer.Write(data)
	if err == nil {
		err = w.ctx.Err()
	}
	return n, err
}

func ociArchitecture(arch string) (string, error) {
	switch arch {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Docker target architecture %q", arch)
	}
}

// The config digest identifies content; Docker's inspected ID varies by store.
func exportDockerArchive(ctx context.Context, imageDir, archivePath, reference, arch string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	expectedArch, err := ociArchitecture(arch)
	if err != nil {
		return "", err
	}
	index, err := layout.Path(imageDir).ImageIndex()
	if err != nil {
		return "", fmt.Errorf("open OCI layout: %w", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("read OCI index: %w", err)
	}
	if len(manifest.Manifests) != 1 {
		return "", fmt.Errorf("expected one OCI image manifest, got %d", len(manifest.Manifests))
	}
	descriptor := manifest.Manifests[0]
	if descriptor.Platform == nil || descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != expectedArch {
		return "", fmt.Errorf("OCI index platform does not match linux/%s", expectedArch)
	}
	if _, err := readOCIBlob(imageDir, descriptor.Digest.String(), 4<<20); err != nil {
		return "", fmt.Errorf("validate OCI manifest: %w", err)
	}
	image, err := index.Image(descriptor.Digest)
	if err != nil {
		return "", fmt.Errorf("open OCI image: %w", err)
	}
	configDigest, err := image.ConfigName()
	if err != nil {
		return "", fmt.Errorf("read OCI config digest: %w", err)
	}
	configBytes, err := readOCIBlob(imageDir, configDigest.String(), 4<<20)
	if err != nil {
		return "", fmt.Errorf("validate OCI config: %w", err)
	}
	var config v1.ConfigFile
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return "", fmt.Errorf("decode OCI config: %w", err)
	}
	if config.OS != "linux" || config.Architecture != expectedArch {
		return "", fmt.Errorf("OCI config platform does not match linux/%s", expectedArch)
	}
	// This generated local reference intentionally has no explicit registry.
	tag, err := name.NewTag(reference)
	if err != nil {
		return "", fmt.Errorf("invalid local image reference: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("create Docker archive: %w", err)
	}
	// Keep even a partial archive for diagnostics, without masking write errors.
	writeErr := tarball.Write(tag, image, contextWriter{ctx: ctx, writer: file})
	closeErr := file.Close()
	if writeErr != nil {
		return "", fmt.Errorf("write Docker archive: %w", writeErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close Docker archive: %w", closeErr)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return configDigest.String(), nil
}

func loadDockerImage(ctx context.Context, command localCommand, imageDir, workspace, reference, arch string) (string, error) {
	loadStarted := false
	fail := func(stage string, err error) (string, error) {
		sideEffect := "Docker load was not started"
		if loadStarted {
			sideEffect = "Docker load was attempted and may have left an imported image/tag; cancellation cannot undo daemon work"
		}
		return "", fmt.Errorf("%s for %s failed: %w; composition completed but loading was not confirmed; %s", stage, reference, err, sideEffect)
	}
	buildStage(ctx, "Exporting Docker archive")
	archivePath := filepath.Join(workspace, "docker-image.tar")
	imageID, err := exportDockerArchive(ctx, imageDir, archivePath, reference, arch)
	if err != nil {
		return fail("Docker archive conversion", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("Docker load", err)
	}
	buildStage(ctx, "Loading image into Docker")
	loadStarted = true
	output, err := command(ctx, "docker", "image", "load", "--input", archivePath)
	if err != nil {
		return fail("Docker load", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output))))
	}
	if err := ctx.Err(); err != nil {
		return fail("Docker inspect", err)
	}
	buildStage(ctx, "Inspecting Docker image identity")
	output, err = command(ctx, "docker", "image", "inspect", "--format", `{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}`, reference)
	if err != nil {
		return fail("Docker inspect", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output))))
	}
	// Request only identity fields; never collect or persist image configuration.
	var inspected struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
	}
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fail("Docker inspect identity", fmt.Errorf("decode Docker image identity: %w", err))
	}
	expectedArch, err := ociArchitecture(arch)
	if err != nil {
		return fail("Docker inspect identity", err)
	}
	if !digestPattern.MatchString(inspected.ID) || inspected.OS != "linux" || inspected.Architecture != expectedArch {
		return fail("Docker inspect identity", fmt.Errorf("expected a sha256 image ID and linux/%s; got image ID %q and %s/%s", expectedArch, inspected.ID, inspected.OS, inspected.Architecture))
	}
	if inspected.ID != imageID {
		// The containerd image store reports a manifest ID rather than the
		// config ID. Verify the imported content, not an assumed ID mapping.
		buildStage(ctx, "Saving Docker image for identity fallback")
		savedPath := filepath.Join(workspace, "docker-loaded.tar")
		file, err := os.OpenFile(savedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fail("Docker saved identity", fmt.Errorf("create saved image archive: %w", err))
		}
		if err := file.Close(); err != nil {
			return fail("Docker saved identity", fmt.Errorf("close saved image archive: %w", err))
		}
		output, err := command(ctx, "docker", "image", "save", "--output", savedPath, reference)
		if err != nil {
			return fail("Docker save", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output))))
		}
		if err := ctx.Err(); err != nil {
			return fail("Docker saved identity", err)
		}
		buildStage(ctx, "Verifying saved Docker image identity")
		tag, err := name.NewTag(reference)
		if err != nil {
			return fail("Docker saved identity", err)
		}
		savedImage, err := tarball.ImageFromPath(savedPath, &tag)
		if err != nil {
			return fail("Docker saved identity", fmt.Errorf("read saved image: %w", err))
		}
		savedConfig, err := savedImage.ConfigName()
		if err != nil {
			return fail("Docker saved identity", fmt.Errorf("read saved config digest: %w", err))
		}
		if savedConfig.String() != imageID {
			return fail("Docker saved identity", fmt.Errorf("expected OCI config digest %s; saved image has %s", imageID, savedConfig))
		}
	}
	// Identity is confirmed even if cancellation now prevents result recording.
	return inspected.ID, nil
}

// Finalize the mutable readable tag only from the already verified local ID.
func tagReadableDockerImage(ctx context.Context, command localCommand, imageID, buildReference, reference, arch string) error {
	fail := func(stage string, err error) error {
		return fmt.Errorf("%s for %s failed: %w; unique image %s was imported and verified (image ID: %s), but readable tagging was not confirmed and may already have changed local tags; cancellation cannot undo daemon work", stage, reference, err, buildReference, imageID)
	}
	if err := ctx.Err(); err != nil {
		return fail("Docker readable tag", err)
	}
	buildStage(ctx, "Tagging readable Docker reference")
	output, err := command(ctx, "docker", "image", "tag", imageID, reference)
	if err != nil {
		return fail("Docker readable tag", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output))))
	}
	if err := ctx.Err(); err != nil {
		return fail("Docker readable inspect", err)
	}
	buildStage(ctx, "Inspecting readable Docker reference")
	output, err = command(ctx, "docker", "image", "inspect", "--format", `{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}`, reference)
	if err != nil {
		return fail("Docker readable inspect", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output))))
	}
	var inspected struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
	}
	if err := json.Unmarshal(output, &inspected); err != nil {
		return fail("Docker readable inspect identity", fmt.Errorf("decode Docker image identity: %w", err))
	}
	expectedArch, err := ociArchitecture(arch)
	if err != nil {
		return fail("Docker readable inspect identity", err)
	}
	if !digestPattern.MatchString(inspected.ID) || inspected.ID != imageID || inspected.OS != "linux" || inspected.Architecture != expectedArch {
		return fail("Docker readable inspect identity", fmt.Errorf("expected verified image ID %s and linux/%s; got image ID %q and %s/%s", imageID, expectedArch, inspected.ID, inspected.OS, inspected.Architecture))
	}
	// Cancellation during final inspection leaves the mutable tag unconfirmed.
	if err := ctx.Err(); err != nil {
		return fail("Docker readable inspect identity", err)
	}
	return nil
}

func retainBuildResult(ctx context.Context, result buildResult, lockPath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("finalize build result: %w", err)
	}
	record := evidenceResult{
		Version: 3, PackageName: result.packageName, PackageVersion: result.version,
		Architecture: result.arch, IndexSHA256: result.indexSHA256, ApkoVersion: apkoBuildVersion,
		ImageDirectory: result.imageDir, LockPath: lockPath, SPDXPath: result.spdxPath,
		SPDXSHA256: result.spdxSHA256, SPDXValidated: true, ImageReference: result.imageReference,
		BuildReference: result.buildReference, DockerLoad: result.dockerLoad, DockerImageID: result.dockerImageID,
	}
	if result.publication.status != "" && result.publication.status != "skipped" {
		publication := result.publication.evidence()
		record.Version, record.Publication = 4, &publication
		record.Build, record.Signing, record.Attestation = "completed", "skipped", "skipped"
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode build result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("finalize build result: %w", err)
	}
	path := filepath.Join(result.workspace, "result.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("retain build result: %w", err)
	}
	_, writeErr := contextWriter{ctx: ctx, writer: file}.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil {
		writeErr = ctx.Err()
	}
	if writeErr != nil {
		// A partial/canceled record must not look like a successful build.
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("retain build result: %w (remove incomplete result: %v)", writeErr, removeErr)
		}
		return fmt.Errorf("retain build result: %w", writeErr)
	}
	return nil
}
