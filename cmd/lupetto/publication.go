package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

type publicationOutcome struct {
	status, reference, pushedDigest, immutableReference string
	verified                                            bool
}

type publicationEvidence struct {
	Status             string `json:"status"`
	Reference          string `json:"reference,omitempty"`
	PushedDigest       string `json:"pushedDigest,omitempty"`
	ImmutableReference string `json:"immutableReference,omitempty"`
	Verified           bool   `json:"verified"`
}

func (p publicationOutcome) evidence() publicationEvidence {
	return publicationEvidence{p.status, p.reference, p.pushedDigest, p.immutableReference, p.verified}
}

// Only safe, stage-specific errors enter this type. In particular subprocess
// output, argument strings and credential-helper diagnostics are never wrapped.
type workflowFailure struct {
	result                                   buildResult
	build, load, signing, attestation, stage string
	attempted                                bool
	cause                                    error
	failureRecord                            bool
}

func (f *workflowFailure) Error() string {
	return fmt.Sprintf("%s stage failed (workspace: %s): %v", f.stage, f.result.workspace, f.cause)
}
func (f *workflowFailure) Unwrap() error { return f.cause }

type publicationStageError struct {
	stage string
	cause error
}

func (e *publicationStageError) Error() string {
	if e.cause != nil {
		return e.stage + " canceled: " + e.cause.Error()
	}
	return e.stage + " failed"
}
func (e *publicationStageError) Unwrap() error { return e.cause }

func safeStageError(ctx context.Context, stage string, err error) error {
	var cause error
	if ctx != nil && ctx.Err() != nil {
		cause = ctx.Err()
	} else if errors.Is(err, context.Canceled) {
		cause = context.Canceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		cause = context.DeadlineExceeded
	}
	return &publicationStageError{stage: stage, cause: cause}
}

func newWorkflowFailure(result buildResult, stage string, cause error, attempted bool) *workflowFailure {
	f := &workflowFailure{result: result, build: "completed", load: result.dockerLoad,
		signing: "skipped", attestation: "skipped", stage: stage, attempted: attempted,
		cause: safeStageError(nil, stage, cause)}
	var safe *publicationStageError
	if errors.As(cause, &safe) {
		f.cause = safe
	}
	if stage == "build" {
		f.build, f.load = "failed", "not-attempted"
	}
	if stage == "readable-tag" {
		f.load = "loaded; readable tag unconfirmed"
	}
	if stage != "publication" && stage != "record" {
		f.result.publication.status = "skipped"
	}
	f.failureRecord = retainWorkflowFailure(f) == nil
	return f
}

func retainWorkflowFailure(f *workflowFailure) error {
	if f.result.workspace == "" {
		return errors.New("no workspace")
	}
	record := struct {
		Version        int                 `json:"version"`
		Workspace      string              `json:"workspace"`
		Stage          string              `json:"stage"`
		Build          string              `json:"build"`
		Load           string              `json:"load"`
		Publication    publicationEvidence `json:"publication"`
		ImageReference string              `json:"imageReference,omitempty"`
		BuildReference string              `json:"buildReference,omitempty"`
		DockerImageID  string              `json:"dockerImageID,omitempty"`
		Signing        string              `json:"signing"`
		Attestation    string              `json:"attestation"`
		Attempted      bool                `json:"sideEffectsPossible"`
		Error          string              `json:"error"`
	}{4, f.result.workspace, f.stage, f.build, f.load, f.result.publication.evidence(),
		f.result.imageReference, f.result.buildReference, f.result.dockerImageID,
		f.signing, f.attestation, f.attempted, f.cause.Error()}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(f.result.workspace, "failure.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func reportWorkflowFailure(stderr io.Writer, err error) bool {
	var f *workflowFailure
	if !errors.As(err, &f) {
		return false
	}
	p := f.result.publication
	fmt.Fprintf(stderr, "lupetto: build: %s; Docker load: %s; publication: %s; signing: %s; attestation: %s\n", f.build, f.load, p.status, f.signing, f.attestation)
	if p.reference != "" {
		fmt.Fprintf(stderr, "lupetto: publication reference: %s\n", p.reference)
	}
	if p.pushedDigest != "" {
		fmt.Fprintf(stderr, "lupetto: captured pushed digest: %s; immutable reference: %s; identity verified: %t\n", p.pushedDigest, p.immutableReference, p.verified)
	}
	fmt.Fprintf(stderr, "lupetto: %v\n", f)
	if f.attempted {
		fmt.Fprintln(stderr, "lupetto: Docker operations were attempted and may have changed local/remote tags, published an image, or pulled content; cancellation cannot undo daemon work; no rollback attempted")
	}
	if !f.failureRecord {
		fmt.Fprintln(stderr, "lupetto: sanitized failure record could not be retained")
	}
	return true
}

const dockerIdentityFormat = `{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}`

func publishDockerImage(ctx context.Context, command localCommand, result buildResult, opts publicationOptions) (publicationOutcome, error) {
	outcome := publicationOutcome{status: "skipped"}
	if err := validatePublicationOptions(opts); err != nil {
		return outcome, safeStageError(ctx, "publication configuration", err)
	}
	if !opts.enabled() {
		return outcome, nil
	}
	outcome.status = "failed"
	fail := func(stage string, err error) (publicationOutcome, error) {
		return outcome, safeStageError(ctx, stage, err)
	}
	if result.dockerLoad != "loaded" || !digestPattern.MatchString(result.dockerImageID) {
		return fail("publication requires verified Docker loading", nil)
	}
	target, err := publicationReferences(indexedPackage{name: result.packageName, version: result.version}, result.arch, result.workspace, opts)
	if err != nil {
		return fail("publication reference", err)
	}
	outcome.reference = target.reference
	if err := ctx.Err(); err != nil {
		return fail("publication tag", err)
	}
	buildStage(ctx, "Tagging unique registry reference")
	if _, err := command(ctx, "docker", "image", "tag", result.dockerImageID, target.reference); err != nil {
		return fail("publication tag", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication inspect", err)
	}
	buildStage(ctx, "Verifying unique registry tag")
	output, err := command(ctx, "docker", "image", "inspect", "--format", dockerIdentityFormat, target.reference)
	if err != nil {
		return fail("publication inspect", err)
	}
	identity, err := decodePublicationIdentity(output)
	if err != nil {
		return fail("publication inspect identity", err)
	}
	arch, err := ociArchitecture(result.arch)
	if err != nil || identity.ID != result.dockerImageID || identity.OS != "linux" || identity.Architecture != arch {
		return fail("publication tag identity mismatch", nil)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication push", err)
	}
	buildStage(ctx, "Pushing unique registry reference")
	output, err = command(ctx, "docker", "image", "push", target.reference)
	if err != nil {
		return fail("publication push", err)
	}
	digest, err := parsePushDigest(output, remoteTag(target.reference))
	if err != nil {
		return fail("publication push digest capture", err)
	}
	outcome.pushedDigest, outcome.immutableReference = digest, target.repository+"@"+digest
	if err := ctx.Err(); err != nil {
		return fail("publication immutable pull", err)
	}
	buildStage(ctx, "Pulling immutable registry image")
	if _, err := command(ctx, "docker", "image", "pull", outcome.immutableReference); err != nil {
		return fail("publication immutable pull", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication immutable save", err)
	}
	archivePath := filepath.Join(result.workspace, "docker-published.tar")
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail("publication immutable archive", err)
	}
	if err := file.Close(); err != nil {
		return fail("publication immutable archive", err)
	}
	buildStage(ctx, "Saving immutable registry image")
	if _, err := command(ctx, "docker", "image", "save", "--output", archivePath, outcome.immutableReference); err != nil {
		return fail("publication immutable save", err)
	}
	// Docker writes into the private precreated archive, never a world-readable file.
	if err := os.Chmod(archivePath, 0600); err != nil {
		return fail("publication immutable archive", err)
	}
	buildStage(ctx, "Verifying published image content")
	if err := verifyPublishedArchive(ctx, result.imageDir, archivePath, result.arch); err != nil {
		return fail("publication immutable identity", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("publication immutable identity", err)
	}
	outcome.status, outcome.verified = "published", true
	return outcome, nil
}

func remoteTag(reference string) string { return reference[strings.LastIndexByte(reference, ':')+1:] }

type publicationIdentity struct {
	ID           string `json:"Id"`
	OS           string `json:"Os"`
	Architecture string `json:"Architecture"`
}

func decodePublicationIdentity(data []byte) (publicationIdentity, error) {
	var identity publicationIdentity
	if len(data) > 4096 {
		return identity, errors.New("oversized identity")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return identity, errors.New("invalid identity")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return identity, errors.New("ambiguous identity")
		}
		seen[key] = true
		var field *string
		switch key {
		case "Id":
			field = &identity.ID
		case "Os":
			field = &identity.OS
		case "Architecture":
			field = &identity.Architecture
		default:
			return identity, errors.New("invalid identity fields")
		}
		if err := decoder.Decode(field); err != nil {
			return identity, errors.New("invalid identity")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 {
		return identity, errors.New("invalid identity")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return identity, errors.New("ambiguous identity")
	}
	if !digestPattern.MatchString(identity.ID) || identity.OS != "linux" || (identity.Architecture != "amd64" && identity.Architecture != "arm64") {
		return identity, errors.New("invalid identity")
	}
	return identity, nil
}

// The adapter has no capturing or live diagnostic writer. Push retains only a
// bounded grammar candidate; unmatched diagnostic lines are discarded as they
// arrive. Inspect retains only a small identity object and re-encodes its fields.
func executePublicationCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if executable != "docker" || len(args) < 3 || args[0] != "image" {
		return nil, errors.New("unsupported publication command")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stderr, command.Stdout = io.Discard, io.Discard
	var push *pushSummaryFilter
	var inspect *boundedIdentityOutput
	switch args[1] {
	case "tag":
		if len(args) != 4 {
			return nil, errors.New("invalid publication command")
		}
	case "pull":
		if len(args) != 3 {
			return nil, errors.New("invalid publication command")
		}
	case "save":
		if len(args) != 5 || args[2] != "--output" {
			return nil, errors.New("invalid publication command")
		}
	case "push":
		if len(args) != 3 {
			return nil, errors.New("invalid publication command")
		}
		push = &pushSummaryFilter{expected: remoteTag(args[2])}
		command.Stdout = push
	case "inspect":
		if len(args) != 5 || args[2] != "--format" || args[3] != dockerIdentityFormat {
			return nil, errors.New("invalid publication command")
		}
		inspect = &boundedIdentityOutput{}
		command.Stdout = inspect
	default:
		return nil, errors.New("unsupported publication command")
	}
	if err := command.Run(); err != nil {
		return nil, safeStageError(ctx, "Docker publication command", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if push != nil {
		digest, err := push.finish()
		if err != nil {
			return nil, err
		}
		return []byte(push.expected + ": digest: " + digest + " size: 0\n"), nil
	}
	if inspect != nil {
		if inspect.overflow {
			return nil, errors.New("invalid publication identity output")
		}
		identity, err := decodePublicationIdentity(inspect.data)
		if err != nil {
			return nil, errors.New("invalid publication identity output")
		}
		return json.Marshal(identity)
	}
	return nil, nil
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

var pushSummaryPattern = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}): digest: (sha256:[0-9a-f]{64}) size: [0-9]+$`)

// No transcript is accumulated: only a possible tag token and its supported
// summary suffix survive until the current newline. Other lines are discarded.
type pushSummaryFilter struct {
	expected  string
	candidate []byte
	discard   bool
	summary   bool
	count     int
	invalid   bool
	digest    string
}

func (w *pushSummaryFilter) Write(data []byte) (int, error) {
	for _, b := range data {
		if b == '\n' || b == '\r' {
			w.endLine()
			continue
		}
		if w.discard {
			continue
		}
		if len(w.candidate) >= 256 {
			w.invalid = w.invalid || w.summary
			w.candidate = nil
			w.discard = true
			continue
		}
		if !w.summary {
			colon := bytes.IndexByte(w.candidate, ':')
			if colon < 0 {
				if b != ':' && !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '.' || b == '-') {
					w.candidate = nil
					w.discard = true
					continue
				}
				if len(w.candidate) > 128 {
					w.candidate = nil
					w.discard = true
					continue
				}
			} else {
				marker := " digest: "
				position := len(w.candidate) - colon - 1
				if position >= len(marker) || b != marker[position] {
					w.candidate = nil
					w.discard = true
					continue
				}
				if position == len(marker)-2 {
					w.summary = true
				}
			}
		}
		w.candidate = append(w.candidate, b)
	}
	return len(data), nil
}

func (w *pushSummaryFilter) endLine() {
	if w.summary && !w.discard {
		w.count++
		match := pushSummaryPattern.FindSubmatch(w.candidate)
		if match == nil || string(match[1]) != w.expected {
			w.invalid = true
		} else {
			w.digest = string(match[2])
		}
	}
	w.candidate, w.discard, w.summary = nil, false, false
}
func (w *pushSummaryFilter) finish() (string, error) {
	w.endLine()
	if w.invalid || w.count != 1 || w.digest == "" {
		return "", errors.New("publication digest summary missing, invalid, or ambiguous")
	}
	return w.digest, nil
}
func parsePushDigest(data []byte, expected string) (string, error) {
	filter := &pushSummaryFilter{expected: expected}
	_, _ = filter.Write(data)
	return filter.finish()
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

type savedManifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

func sourcePublicationConfig(ctx context.Context, imageDir, arch string) (string, v1.ConfigFile, error) {
	var config v1.ConfigFile
	if err := ctx.Err(); err != nil {
		return "", config, err
	}
	expectedArch, err := ociArchitecture(arch)
	if err != nil {
		return "", config, err
	}
	index, err := layout.Path(imageDir).ImageIndex()
	if err != nil {
		return "", config, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return "", config, err
	}
	if len(manifest.Manifests) != 1 {
		return "", config, errors.New("ambiguous source image")
	}
	descriptor := manifest.Manifests[0]
	if descriptor.Platform == nil || descriptor.Platform.OS != "linux" || descriptor.Platform.Architecture != expectedArch {
		return "", config, errors.New("source platform mismatch")
	}
	if _, err := readOCIBlob(imageDir, descriptor.Digest.String(), 4<<20); err != nil {
		return "", config, err
	}
	image, err := index.Image(descriptor.Digest)
	if err != nil {
		return "", config, err
	}
	digest, err := image.ConfigName()
	if err != nil {
		return "", config, err
	}
	data, err := readOCIBlob(imageDir, digest.String(), 4<<20)
	if err != nil {
		return "", config, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", config, err
	}
	if config.OS != "linux" || config.Architecture != expectedArch || config.RootFS.Type != "layers" {
		return "", config, errors.New("source config platform/rootfs mismatch")
	}
	layers, err := image.Manifest()
	if err != nil {
		return "", config, err
	}
	if len(layers.Layers) != len(config.RootFS.DiffIDs) {
		return "", config, errors.New("source layer count mismatch")
	}
	for _, digest := range config.RootFS.DiffIDs {
		if !digestPattern.MatchString(digest.String()) {
			return "", config, errors.New("invalid source diffID")
		}
	}
	return digest.String(), config, nil
}

func validArchiveName(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != "." && name != ".." && !strings.HasPrefix(name, "../")
}

// Read metadata only in pass one, then hash actual uncompressed layer streams in
// pass two. No extraction, layer-size allocation or trust in config claims.
func verifyPublishedArchive(ctx context.Context, imageDir, archivePath, arch string) error {
	configDigest, source, err := sourcePublicationConfig(ctx, imageDir, arch)
	if err != nil {
		return err
	}
	var manifest []savedManifest
	var manifestBytes, config []byte
	entries := make(map[string]byte)
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	tr := tar.NewReader(contextReader{ctx, file})
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("malformed saved archive")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !validArchiveName(name) {
			return errors.New("invalid saved archive entry")
		}
		if _, exists := entries[name]; exists {
			return errors.New("ambiguous saved archive entry")
		}
		entries[name] = header.Typeflag
		if len(entries) > 100000 {
			return errors.New("oversized saved archive index")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return errors.New("unsupported saved archive entry")
		}
		if name == "manifest.json" {
			if header.Size < 0 || header.Size > 4<<20 {
				return errors.New("oversized saved manifest")
			}
			manifestBytes, err = io.ReadAll(contextReader{ctx, tr})
			if err != nil {
				return err
			}
		} else if _, err := io.Copy(io.Discard, contextReader{ctx, tr}); err != nil {
			return err
		}
	}
	// tar.Reader stops at the end marker; a concatenated second archive or
	// non-padding suffix must not evade the single-image ambiguity checks.
	var padding [32768]byte
	for {
		n, err := (contextReader{ctx, file}).Read(padding[:])
		for _, b := range padding[:n] {
			if b != 0 {
				return errors.New("unexpected saved archive suffix")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || len(manifest) != 1 {
		return errors.New("ambiguous saved image manifest")
	}
	selected := manifest[0]
	if !validArchiveName(selected.Config) || selected.Config == "manifest.json" {
		return errors.New("invalid saved config path")
	}
	if len(selected.Layers) != len(source.RootFS.DiffIDs) {
		return errors.New("saved layer count mismatch")
	}
	wanted := make(map[string]bool)
	for _, name := range selected.Layers {
		kind, exists := entries[name]
		if !validArchiveName(name) || name == selected.Config || name == "manifest.json" || !exists || (kind != tar.TypeReg && kind != tar.TypeRegA) {
			return errors.New("invalid saved layer path")
		}
		wanted[name] = true
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tr = tar.NewReader(contextReader{ctx, file})
	hashes := make(map[string]string)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("malformed saved layer archive")
		}
		if header.Name == selected.Config {
			if (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Size < 0 || header.Size > 4<<20 {
				return errors.New("invalid saved config entry")
			}
			config, err = io.ReadAll(contextReader{ctx, tr})
			if err != nil {
				return err
			}
			continue
		}
		if !wanted[header.Name] {
			continue
		}
		stream := bufio.NewReader(contextReader{ctx, tr})
		var reader io.Reader = stream
		var compressed *gzip.Reader
		magic, _ := stream.Peek(2)
		if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
			compressed, err = gzip.NewReader(stream)
			if err != nil {
				return errors.New("invalid saved compressed layer")
			}
			reader = compressed
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, contextReader{ctx, reader})
		if compressed != nil {
			_ = compressed.Close()
		}
		if copyErr != nil {
			return copyErr
		}
		hashes[header.Name] = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	}
	if config == nil || "sha256:"+sha256Hex(config) != configDigest {
		return errors.New("saved config digest mismatch")
	}
	var saved v1.ConfigFile
	if err := json.Unmarshal(config, &saved); err != nil {
		return errors.New("invalid saved config")
	}
	if saved.OS != source.OS || saved.Architecture != source.Architecture {
		return errors.New("saved platform mismatch")
	}
	for i, name := range selected.Layers {
		if hashes[name] != source.RootFS.DiffIDs[i].String() {
			return errors.New("saved ordered layer content mismatch")
		}
	}
	return ctx.Err()
}
