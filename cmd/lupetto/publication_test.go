package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const publicationCanary = "secretcanary-never-retain"
const fixturePushDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func publicationSummary(tag string) []byte {
	return []byte(tag + ": digest: " + fixturePushDigest + " size: 532\n")
}

func TestPushDigestStrictExpectedUniqueSummary(t *testing.T) {
	valid := string(publicationSummary("unique-build-123"))
	for _, tc := range []struct {
		name, output string
		valid        bool
	}{
		{"ordinary", "The push refers to repository [localhost:5000/team/image]\nlayer: Pushed\n" + valid, true},
		{"unterminated", strings.TrimSuffix(valid, "\n"), true},
		{"crlf", strings.ReplaceAll(valid, "\n", "\r\n"), true},
		{"missing", publicationCanary, false},
		{"wrong tag", string(publicationSummary("unrelated")), false},
		{"wrong then right", string(publicationSummary("unrelated")) + valid, false},
		{"repeated", valid + valid, false},
		{"conflicting", valid + strings.ReplaceAll(valid, "aaaa", "bbbb"), false},
		{"short", "unique-build-123: digest: sha256:abcd size: 532\n", false},
		{"uppercase", strings.ReplaceAll(valid, "aaaa", "AAAA"), false},
		{"algorithm", strings.Replace(valid, "sha256:", "sha512:", 1), false},
		{"malformed size", strings.Replace(valid, "532", "unknown", 1), false},
		{"missing value", "unique-build-123: digest:\n" + valid, false},
		{"suffix", strings.TrimSuffix(valid, "\n") + " " + publicationCanary + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := parsePushDigest([]byte(tc.output), "unique-build-123")
			if tc.valid && (err != nil || digest != fixturePushDigest) {
				t.Fatalf("digest=%q err=%v", digest, err)
			}
			if !tc.valid && (err == nil || digest != "") {
				t.Fatalf("digest=%q err=%v", digest, err)
			}
			if err != nil && strings.Contains(err.Error(), publicationCanary) {
				t.Fatal("diagnostic escaped parser")
			}
		})
	}
}

func TestPushFilterChunkingAndBoundedDiscard(t *testing.T) {
	filter := &pushSummaryFilter{expected: "unique"}
	for _, chunk := range []string{publicationCanary + " " + strings.Repeat("x", 1<<20) + "\n", "uni", "que: dig", "est: sha256:", strings.Repeat("a", 64), " size: 532\n"} {
		if n, err := filter.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write=%d err=%v", n, err)
		}
		if len(filter.candidate) > 256 || strings.Contains(string(filter.candidate), publicationCanary) {
			t.Fatal("retained diagnostic transcript")
		}
	}
	if digest, err := filter.finish(); digest != fixturePushDigest || err != nil {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
}

// This archive has real config JSON and a real uncompressed tar layer, like
// Docker save. The source fixture carries the same layer compressed in OCI.
func writePublicationArchive(t *testing.T, destination string, config, compressedLayer []byte, mutation string) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(compressedLayer))
	if err != nil {
		t.Fatal(err)
	}
	layer, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	configName, layerName := "config.json", "layer/layer.tar"
	if mutation == "blob config" {
		configName = "blobs/sha256/" + sha256Hex(config)
	}
	if mutation == "config" {
		config = bytes.Replace(config, []byte("FIXTURE=value"), []byte("FIXTURE=changed"), 1)
	}
	if mutation == "layer" {
		layer = append(layer, []byte("different actual bytes")...)
	}
	if mutation == "gzip" {
		layer = compressedLayer
	}
	manifest := []savedManifest{{Config: configName, Layers: []string{layerName}}}
	if mutation == "ambiguous" {
		manifest = append(manifest, manifest[0])
	}
	if mutation == "missing layer" {
		manifest[0].Layers = []string{"missing/layer.tar"}
	}
	if mutation == "traversal" {
		manifest[0].Layers = []string{"../layer.tar"}
	}
	if mutation == "layer count" {
		manifest[0].Layers = nil
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if mutation == "malformed" {
		manifestBytes = []byte("invalid " + publicationCanary)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(file)
	entries := []struct {
		name string
		data []byte
	}{{configName, config}, {layerName, layer}, {"manifest.json", manifestBytes}}
	if mutation == "duplicate" {
		entries = append(entries, entries[1])
	}
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if mutation == "symlink" {
		if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/tmp/forbidden"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if mutation == "trailing archive" {
		if _, err := file.Write([]byte("a second archive after the end marker")); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func publicationTestResult(t *testing.T, arch string) (buildResult, []byte, []byte) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "image-test123")
	imageDir := filepath.Join(workspace, "image")
	id, config, layer := makeLoadOCI(t, imageDir, "fixture", "1-r0", arch)
	return buildResult{packageName: "fixture", version: "1-r0", arch: arch, workspace: workspace,
		imageDir: imageDir, imageReference: "lupetto/fixture:1-r0-amd64", buildReference: "lupetto/local:build-test123",
		dockerLoad: "loaded", dockerImageID: id}, config, layer
}

func TestPublicationArchiveActualContentIdentity(t *testing.T) {
	for _, arch := range []string{"x86_64", "aarch64"} {
		for _, mutation := range []string{"", "gzip", "blob config", "config", "layer", "layer count", "missing layer", "ambiguous", "malformed", "duplicate", "symlink", "traversal", "trailing archive"} {
			t.Run(arch+"/"+mutation, func(t *testing.T) {
				result, config, layer := publicationTestResult(t, arch)
				archive := filepath.Join(result.workspace, "saved.tar")
				writePublicationArchive(t, archive, config, layer, mutation)
				err := verifyPublishedArchive(context.Background(), result.imageDir, archive, arch)
				valid := mutation == "" || mutation == "gzip" || mutation == "blob config"
				if (err == nil) != valid {
					t.Fatalf("mutation=%q err=%v", mutation, err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := verifyPublishedArchive(ctx, result.imageDir, archive, arch); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation=%v", err)
				}
			})
		}
	}
}

func TestPublicationUsesVerifiedIDAndImmutableContent(t *testing.T) {
	result, config, layer := publicationTestResult(t, "x86_64")
	// Docker's containerd store may report a manifest ID, not the config digest.
	result.dockerImageID = "sha256:" + strings.Repeat("b", 64)
	opts := publicationOptions{registry: "localhost:5000", repository: "team/images"}
	target, err := publicationReferences(indexedPackage{name: result.packageName, version: result.version}, result.arch, result.workspace, opts)
	if err != nil {
		t.Fatal(err)
	}
	immutable := target.repository + "@" + fixturePushDigest
	var calls [][]string
	command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, args...))
		switch args[1] {
		case "inspect":
			return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":"amd64"}`, result.dockerImageID)), nil
		case "push":
			return publicationSummary(remoteTag(target.reference)), nil
		case "save":
			writePublicationArchive(t, args[3], config, layer, "")
		}
		return []byte(publicationCanary), nil
	}
	outcome, err := publishDockerImage(context.Background(), command, result, opts)
	if err != nil || outcome.status != "published" || !outcome.verified || outcome.pushedDigest != fixturePushDigest || outcome.immutableReference != immutable {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	want := [][]string{
		{"docker", "image", "tag", result.dockerImageID, target.reference},
		{"docker", "image", "inspect", "--format", dockerIdentityFormat, target.reference},
		{"docker", "image", "push", target.reference},
		{"docker", "image", "pull", immutable},
		{"docker", "image", "save", "--output", filepath.Join(result.workspace, "docker-published.tar"), immutable},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q want=%q", calls, want)
	}
	if info, err := os.Stat(filepath.Join(result.workspace, "docker-published.tar")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("archive mode=%v err=%v", info, err)
	}
}

func TestPublicationFailureSanitizationAndCapturedDigest(t *testing.T) {
	for _, failure := range []string{"tag", "inspect", "inspect mismatch", "inspect secret JSON", "push", "push missing", "push duplicate", "push wrong", "push malformed", "pull", "save", "layer", "config", "ambiguous", "cancel push", "cancel pull", "cancel save"} {
		t.Run(failure, func(t *testing.T) {
			result, config, layer := publicationTestResult(t, "x86_64")
			opts := publicationOptions{registry: "localhost:5000", repository: "team/images"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				stage := args[1]
				if failure == stage {
					return []byte(publicationCanary), errors.New(publicationCanary)
				}
				if failure == "cancel "+stage {
					cancel()
				}
				switch stage {
				case "inspect":
					if failure == "inspect secret JSON" {
						return []byte(`{"Id":"` + publicationCanary + `","Os":"linux","Architecture":"amd64"}`), nil
					}
					id := result.dockerImageID
					if failure == "inspect mismatch" {
						id = fixturePushDigest
					}
					return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":"amd64"}`, id)), nil
				case "push":
					summary := publicationSummary(remoteTag(args[2]))
					switch failure {
					case "push missing":
						return []byte(publicationCanary), nil
					case "push duplicate":
						return append(summary, summary...), nil
					case "push wrong":
						return publicationSummary("unrelated"), nil
					case "push malformed":
						return []byte(remoteTag(args[2]) + ": digest: " + publicationCanary + " size: 0\n"), nil
					}
					return summary, nil
				case "save":
					writePublicationArchive(t, args[3], config, layer, failure)
				}
				return nil, nil
			}
			outcome, err := publishDockerImage(ctx, command, result, opts)
			if err == nil || outcome.status != "failed" || outcome.verified || strings.Contains(err.Error(), publicationCanary) {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
			captured := failure == "pull" || failure == "save" || failure == "layer" || failure == "config" || failure == "ambiguous" || strings.HasPrefix(failure, "cancel ")
			if (outcome.pushedDigest != "") != captured {
				t.Fatalf("digest capture: %+v", outcome)
			}
			if captured && (outcome.pushedDigest != fixturePushDigest || !strings.HasSuffix(outcome.immutableReference, "@"+fixturePushDigest)) {
				t.Fatalf("lost digest: %+v", outcome)
			}
			if strings.HasPrefix(failure, "cancel ") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			result.publication = outcome
			wf := newWorkflowFailure(result, "publication", err, true)
			var stderr bytes.Buffer
			if !reportWorkflowFailure(&stderr, wf) || strings.Contains(stderr.String(), publicationCanary) {
				t.Fatalf("unsafe stderr=%q", stderr.String())
			}
			data, readErr := os.ReadFile(filepath.Join(result.workspace, "failure.json"))
			if readErr != nil || bytes.Contains(data, []byte(publicationCanary)) {
				t.Fatalf("record=%q err=%v", data, readErr)
			}
			if info, err := os.Stat(filepath.Join(result.workspace, "failure.json")); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("record mode=%v err=%v", info, err)
			}
		})
	}
}

func fakePublicationDocker(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PUBLICATION_SECRET", publicationCanary)
}

func TestProductionPublicationAdapterSuppressesDiagnostics(t *testing.T) {
	for _, stage := range []string{"tag", "pull", "save", "push", "inspect"} {
		t.Run(stage, func(t *testing.T) {
			body := "printf '%s\\n' \"$PUBLICATION_SECRET\" >&2\n"
			args := []string{"image", stage, "localhost:5000/team/image:unique"}
			switch stage {
			case "push":
				body += "printf '%s\\n' \"$PUBLICATION_SECRET ignored\"\nprintf '%s\\n' 'unique: digest: " + fixturePushDigest + " size: 532'"
			case "inspect":
				body += "printf '%s\\n' '{\"Id\":\"" + fixturePushDigest + "\",\"Os\":\"linux\",\"Architecture\":\"amd64\"}'"
				args = []string{"image", "inspect", "--format", dockerIdentityFormat, args[2]}
			case "tag":
				body += "printf '%s\\n' \"$PUBLICATION_SECRET\""
				args = []string{"image", "tag", fixturePushDigest, args[2]}
			case "save":
				body += "printf '%s\\n' \"$PUBLICATION_SECRET\""
				args = []string{"image", "save", "--output", filepath.Join(t.TempDir(), "saved.tar"), args[2]}
			default:
				body += "printf '%s\\n' \"$PUBLICATION_SECRET\""
			}
			fakePublicationDocker(t, body)
			var diagnostics bytes.Buffer
			progress := newBuildProgress(context.Background(), &diagnostics, false)
			ctx := context.WithValue(context.Background(), buildProgressKey{}, progress)
			output, err := executePublicationCommand(ctx, "docker", args...)
			progress.Close()
			if err != nil || bytes.Contains(output, []byte(publicationCanary)) || diagnostics.Len() != 0 {
				t.Fatalf("output=%q err=%v diagnostics=%q", output, err, diagnostics.String())
			}
			if stage == "push" && string(output) != "unique: digest: "+fixturePushDigest+" size: 0\n" {
				t.Fatalf("unexpected push output %q", output)
			}
			if stage != "push" && stage != "inspect" && len(output) != 0 {
				t.Fatalf("retained stdout=%q", output)
			}
		})
	}
}

func TestProductionPublicationAdapterFailuresAreSecretSafe(t *testing.T) {
	for _, failure := range []string{"exit", "wrong", "duplicate", "missing", "malformed", "inspect secret", "inspect oversized", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			body := "printf '%s\\n' \"$PUBLICATION_SECRET\" >&2\n"
			args := []string{"image", "push", "localhost:5000/team/image:unique"}
			valid := "printf '%s\\n' 'unique: digest: " + fixturePushDigest + " size: 532'\n"
			switch failure {
			case "exit":
				body += valid + "printf '%s\\n' \"$PUBLICATION_SECRET\"\nexit 9"
			case "wrong":
				body += strings.ReplaceAll(valid, "unique:", "unrelated:")
			case "duplicate":
				body += valid + valid
			case "missing":
				body += "printf '%s\\n' \"$PUBLICATION_SECRET\""
			case "malformed":
				body += "printf '%s\\n' \"unique: digest: $PUBLICATION_SECRET size: 532\""
			case "inspect secret":
				body += "printf '%s\\n' \"{\\\"Id\\\":\\\"$PUBLICATION_SECRET\\\",\\\"Os\\\":\\\"linux\\\",\\\"Architecture\\\":\\\"amd64\\\"}\""
				args = []string{"image", "inspect", "--format", dockerIdentityFormat, args[2]}
			case "inspect oversized":
				body += "printf '%5000s' x"
				args = []string{"image", "inspect", "--format", dockerIdentityFormat, args[2]}
			case "cancel":
				body += "exec sleep 30"
			}
			fakePublicationDocker(t, body)
			ctx := context.Background()
			if failure == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			}
			output, err := executePublicationCommand(ctx, "docker", args...)
			if err == nil || len(output) != 0 || strings.Contains(err.Error(), publicationCanary) {
				t.Fatalf("output=%q err=%v", output, err)
			}
			if failure == "cancel" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation=%v", err)
			}
		})
	}
}

func TestPublicationArchiveOrderedMultipleLayers(t *testing.T) {
	result, configBytes, firstCompressed := publicationTestResult(t, "x86_64")
	gz, err := gzip.NewReader(bytes.NewReader(firstCompressed))
	if err != nil {
		t.Fatal(err)
	}
	first, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	_ = gz.Close()
	var second bytes.Buffer
	tw := tar.NewWriter(&second)
	data := []byte("second actual filesystem layer")
	if err := tw.WriteHeader(&tar.Header{Name: "second-file", Mode: 0600, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(second.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	secondDigest := writeOCIBlob(t, result.imageDir, compressed.Bytes())
	var config map[string]any
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	config["rootfs"] = map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + sha256Hex(first), "sha256:" + sha256Hex(second.Bytes())}}
	configBytes, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configDigest := writeOCIBlob(t, result.imageDir, configBytes)
	indexBytes, err := os.ReadFile(filepath.Join(result.imageDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct{ Manifests []struct{ Digest string } }
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := readOCIBlob(result.imageDir, index.Manifests[0].Digest, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["config"] = map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(configBytes)}
	layers := manifest["layers"].([]any)
	manifest["layers"] = append(layers, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": secondDigest, "size": compressed.Len()})
	manifestBytes, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := writeOCIBlob(t, result.imageDir, manifestBytes)
	indexBytes, err = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{map[string]any{"digest": manifestDigest, "size": len(manifestBytes), "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": map[string]string{"os": "linux", "architecture": "amd64"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.imageDir, "index.json"), indexBytes, 0600); err != nil {
		t.Fatal(err)
	}
	for _, order := range []string{"correct", "reversed", "repeated"} {
		t.Run(order, func(t *testing.T) {
			paths := []string{"first/layer.tar", "second/layer.tar"}
			if order == "reversed" {
				paths[0], paths[1] = paths[1], paths[0]
			}
			if order == "repeated" {
				paths[1] = paths[0]
			}
			manifestBytes, err := json.Marshal([]savedManifest{{Config: "config.json", Layers: paths}})
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(result.workspace, "saved-"+order+".tar")
			file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(file)
			for _, entry := range []struct {
				name string
				data []byte
			}{{"config.json", configBytes}, {"first/layer.tar", first}, {"second/layer.tar", second.Bytes()}, {"manifest.json", manifestBytes}} {
				if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(entry.data); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			err = verifyPublishedArchive(context.Background(), result.imageDir, filename, result.arch)
			if (err == nil) != (order == "correct") {
				t.Fatalf("order=%s err=%v", order, err)
			}
		})
	}
}

func TestPublicationSkippedWithoutDockerAndFailureRecordWriteDoesNotHideCause(t *testing.T) {
	called := false
	command := func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }
	outcome, err := publishDockerImage(context.Background(), command, buildResult{}, publicationOptions{})
	if err != nil || outcome.status != "skipped" || called {
		t.Fatalf("outcome=%+v err=%v called=%v", outcome, err, called)
	}
	result := buildResult{workspace: t.TempDir(), dockerLoad: "loaded", publication: publicationOutcome{status: "published", pushedDigest: fixturePushDigest, verified: true}}
	if err := os.Mkdir(filepath.Join(result.workspace, "failure.json"), 0700); err != nil {
		t.Fatal(err)
	}
	failure := newWorkflowFailure(result, "record", context.Canceled, true)
	if failure.failureRecord || !errors.Is(failure, context.Canceled) || failure.result.publication.status != "published" || !failure.result.publication.verified {
		t.Fatalf("failure=%+v", failure)
	}
	var stderr bytes.Buffer
	if !reportWorkflowFailure(&stderr, failure) || !strings.Contains(stderr.String(), "publication: published") || !strings.Contains(stderr.String(), "could not be retained") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if reportWorkflowFailure(&stderr, errors.New("ordinary")) {
		t.Fatal("consumed an unrelated failure")
	}
}

func TestPublicationInspectStrictBoundedIdentity(t *testing.T) {
	valid := fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":"amd64"}`, fixturePushDigest)
	for _, data := range []string{
		valid + valid,
		strings.TrimSuffix(valid, "}") + `,"Id":"` + fixturePushDigest + `"}`,
		strings.TrimSuffix(valid, "}") + `,"Credential":"` + publicationCanary + `"}`,
		strings.Replace(valid, "linux", "windows", 1),
		strings.Replace(valid, "amd64", publicationCanary, 1),
		strings.Replace(valid, fixturePushDigest, publicationCanary, 1),
		"[" + valid + "]",
		strings.Repeat("x", 4097),
	} {
		if _, err := decodePublicationIdentity([]byte(data)); err == nil || strings.Contains(err.Error(), publicationCanary) {
			t.Fatalf("unsafe or accepted identity err=%v", err)
		}
	}
	if identity, err := decodePublicationIdentity([]byte(valid)); err != nil || identity.ID != fixturePushDigest {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}
