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
)

// A synthetic single-image OCI fixture, not an interoperability claim.
func makeLoadOCI(t *testing.T, dir, pkg, version, arch string) (string, []byte, []byte) {
	t.Helper()
	ociArch, err := ociArchitecture(arch)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	marshal := func(value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var uncompressed bytes.Buffer
	tw := tar.NewWriter(&uncompressed)
	installed := []byte("P:" + pkg + "\nV:" + version + "\nA:" + arch + "\n\n")
	if err := tw.WriteHeader(&tar.Header{Name: "usr/lib/apk/db/installed", Mode: 0600, Size: int64(len(installed))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(installed); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(uncompressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	layer := compressed.Bytes()
	layerDigest := writeOCIBlob(t, dir, layer)
	config := marshal(map[string]any{
		"architecture": ociArch, "os": "linux",
		"config": map[string]any{"Env": []string{"FIXTURE=value"}, "Entrypoint": []string{"/bin/fixture"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + sha256Hex(uncompressed.Bytes())}},
	})
	configDigest := writeOCIBlob(t, dir, config)
	manifest := marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": len(layer)}},
	})
	manifestDigest := writeOCIBlob(t, dir, manifest)
	write(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	write(filepath.Join(dir, "index.json"), marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest),
			"platform": map[string]string{"os": "linux", "architecture": ociArch},
		}},
	}))
	return configDigest, config, layer
}

func TestDockerArchiveFidelityAndIdentity(t *testing.T) {
	for _, arch := range []string{"x86_64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			workspace := t.TempDir()
			imageID, config, layer := makeLoadOCI(t, filepath.Join(workspace, "image"), "fixture", "1-r0", arch)
			path := filepath.Join(workspace, "docker-image.tar")
			reference := "lupetto/local:build-fixture"
			got, err := exportDockerArchive(context.Background(), filepath.Join(workspace, "image"), path, reference, arch)
			if err != nil || got != imageID {
				t.Fatalf("id=%q err=%v", got, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("archive mode: info=%v err=%v", info, err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			entries := map[string][]byte{}
			tr := tar.NewReader(file)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				entries[h.Name], err = io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
			}
			var manifest []struct {
				Config           string
				RepoTags, Layers []string
			}
			if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest) != 1 || !reflect.DeepEqual(manifest[0].RepoTags, []string{reference}) || len(manifest[0].Layers) != 1 {
				t.Fatalf("manifest=%+v", manifest)
			}
			if !bytes.Equal(entries[manifest[0].Config], config) || !bytes.Equal(entries[manifest[0].Layers[0]], layer) {
				t.Fatal("conversion changed config or compressed layer bytes")
			}
			if "sha256:"+sha256Hex(entries[manifest[0].Config]) != imageID {
				t.Fatal("archive config digest differs from OCI image ID")
			}
		})
	}
}

func TestDockerLoadVerifiesInspectNotHumanOutput(t *testing.T) {
	workspace := t.TempDir()
	imageDir := filepath.Join(workspace, "image")
	imageID, _, _ := makeLoadOCI(t, imageDir, "fixture", "1-r0", "x86_64")
	reference := "lupetto/local:build-fixture"
	var calls [][]string
	command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{executable}, args...))
		if args[1] == "load" {
			return []byte("unrelated human-readable output"), nil
		}
		return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":"amd64"}`, imageID)), nil
	}
	got, err := loadDockerImage(context.Background(), command, imageDir, workspace, reference, "x86_64")
	if err != nil || got != imageID {
		t.Fatalf("id=%q err=%v", got, err)
	}
	want := [][]string{
		{"docker", "image", "load", "--input", filepath.Join(workspace, "docker-image.tar")},
		{"docker", "image", "inspect", "--format", `{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}`, reference},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q want=%q", calls, want)
	}
}

func TestDockerLoadFailuresAndCancellation(t *testing.T) {
	for _, failure := range []string{"archive", "load", "inspect", "invalid inspect", "image ID", "OS", "architecture", "cancel load", "cancel inspect"} {
		t.Run(failure, func(t *testing.T) {
			workspace := t.TempDir()
			imageDir := filepath.Join(workspace, "image")
			imageID, _, _ := makeLoadOCI(t, imageDir, "fixture", "1-r0", "x86_64")
			if failure == "archive" {
				if err := os.Remove(filepath.Join(imageDir, "index.json")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				calls++
				stage := args[1]
				if failure == "cancel "+stage {
					cancel()
					return nil, ctx.Err()
				}
				if failure == stage {
					return []byte("retained diagnostic"), errors.New("command failed")
				}
				if stage == "load" {
					return []byte("Loaded image: lupetto/local:build-fixture"), nil
				}
				if failure == "invalid inspect" {
					return []byte("not JSON"), nil
				}
				osName, arch := "linux", "amd64"
				if failure == "image ID" {
					imageID = "not-a-digest"
				}
				if failure == "OS" {
					osName = "windows"
				}
				if failure == "architecture" {
					arch = "arm64"
				}
				return []byte(fmt.Sprintf(`{"Id":%q,"Os":%q,"Architecture":%q}`, imageID, osName, arch)), nil
			}
			got, err := loadDockerImage(ctx, command, imageDir, workspace, "lupetto/local:build-fixture", "x86_64")
			if err == nil || got != "" || !strings.Contains(err.Error(), "composition completed but loading was not confirmed") || !strings.Contains(err.Error(), "lupetto/local:build-fixture") {
				t.Fatalf("id=%q err=%v", got, err)
			}
			if failure == "archive" {
				if calls != 0 || !strings.Contains(err.Error(), "load was not started") {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			} else if !strings.Contains(err.Error(), "may have left an imported image/tag") {
				t.Fatalf("missing side-effect warning: %v", err)
			}
			if failure == "load" || failure == "inspect" {
				if !strings.Contains(err.Error(), "retained diagnostic") {
					t.Fatalf("diagnostic lost: %v", err)
				}
			}
			if strings.HasPrefix(failure, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

// A deterministic context models cancellation between writes without timing races.
type cancelAfterChecks struct {
	context.Context
	checks, at int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks >= c.at {
		return context.Canceled
	}
	return nil
}

func TestDockerArchiveCanceledWriteRetainsPartialArchive(t *testing.T) {
	workspace := t.TempDir()
	imageDir := filepath.Join(workspace, "image")
	makeLoadOCI(t, imageDir, "fixture", "1-r0", "x86_64")
	path := filepath.Join(workspace, "docker-image.tar")
	ctx := &cancelAfterChecks{Context: context.Background(), at: 6}
	if id, err := exportDockerArchive(ctx, imageDir, path, "lupetto/local:build-fixture", "x86_64"); id != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("partial archive info=%v err=%v", info, err)
	}
}

func TestContextWriterCancellationDuringWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	writer := contextWriter{ctx: ctx, writer: cancelingWriter{cancel: cancel}}
	if n, err := writer.Write([]byte("fixture")); n != 7 || !errors.Is(err, context.Canceled) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if n, err := writer.Write([]byte("again")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled writer accepted more data: n=%d err=%v", n, err)
	}
}

type cancelingWriter struct {
	cancel context.CancelFunc
}

func (w cancelingWriter) Write(data []byte) (int, error) {
	w.cancel()
	return len(data), nil
}

func TestDockerArchiveRejectsInvalidOCIIdentity(t *testing.T) {
	for _, failure := range []string{"config checksum", "multiple images", "config platform", "target platform"} {
		t.Run(failure, func(t *testing.T) {
			workspace := t.TempDir()
			imageDir := filepath.Join(workspace, "image")
			configID, config, _ := makeLoadOCI(t, imageDir, "fixture", "1-r0", "x86_64")
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			arch := "x86_64"
			if failure == "target platform" {
				arch = "aarch64"
			}
			if failure == "config checksum" {
				write(filepath.Join(imageDir, "blobs", "sha256", strings.TrimPrefix(configID, "sha256:")), []byte("changed config"))
			}
			if failure == "multiple images" || failure == "config platform" {
				indexPath := filepath.Join(imageDir, "index.json")
				data, err := os.ReadFile(indexPath)
				if err != nil {
					t.Fatal(err)
				}
				var index map[string]any
				if err := json.Unmarshal(data, &index); err != nil {
					t.Fatal(err)
				}
				descriptors := index["manifests"].([]any)
				if failure == "multiple images" {
					index["manifests"] = append(descriptors, descriptors[0])
				} else {
					config = bytes.ReplaceAll(config, []byte(`"os":"linux"`), []byte(`"os":"windows"`))
					newConfigID := writeOCIBlob(t, imageDir, config)
					descriptor := descriptors[0].(map[string]any)
					manifestBytes, err := readOCIBlob(imageDir, descriptor["digest"].(string), 4<<20)
					if err != nil {
						t.Fatal(err)
					}
					var manifest map[string]any
					if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
						t.Fatal(err)
					}
					configDescriptor := manifest["config"].(map[string]any)
					configDescriptor["digest"], configDescriptor["size"] = newConfigID, len(config)
					manifestBytes, err = json.Marshal(manifest)
					if err != nil {
						t.Fatal(err)
					}
					descriptor["digest"], descriptor["size"] = writeOCIBlob(t, imageDir, manifestBytes), len(manifestBytes)
				}
				data, err = json.Marshal(index)
				if err != nil {
					t.Fatal(err)
				}
				write(indexPath, data)
			}
			path := filepath.Join(workspace, "docker-image.tar")
			if id, err := exportDockerArchive(context.Background(), imageDir, path, "lupetto/local:build-fixture", arch); err == nil || id != "" {
				t.Fatalf("id=%q err=%v", id, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid image produced archive: %v", err)
			}
		})
	}
}

func TestResultCanceledFinalizationLeavesNoSuccessRecord(t *testing.T) {
	for _, at := range []int{1, 3, 4, 5} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			workspace := t.TempDir()
			ctx := &cancelAfterChecks{Context: context.Background(), at: at}
			record, err := retainBuildResult(ctx, buildResult{workspace: workspace, dockerLoad: "skipped"})
			if !errors.Is(err, context.Canceled) || record != nil {
				t.Fatalf("err=%v", err)
			}
			if _, err := os.Stat(filepath.Join(workspace, "result.json")); !os.IsNotExist(err) {
				t.Fatalf("success result exists: %v", err)
			}
		})
	}
}

func TestLocalCommandHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executeLocalCommand(ctx, "not-an-executable"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

// Model docker save from the already-exported bytes, optionally changing the
// saved config or tag. The tests do not use a daemon or assert interoperability.
func writeSavedDockerFixture(t *testing.T, inputPath, outputPath, failure string) {
	t.Helper()
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if failure == "malformed archive" {
		if err := os.WriteFile(outputPath, []byte("not a Docker archive"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	entries := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name], err = io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
	}
	var manifest []struct {
		Config           string
		RepoTags, Layers []string
	}
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 1 {
		t.Fatalf("fixture manifests: %+v", manifest)
	}
	if failure == "bad saved config" {
		oldConfig := manifest[0].Config
		config := append(append([]byte(nil), entries[oldConfig]...), '\n')
		newConfig := "sha256:" + sha256Hex(config)
		delete(entries, oldConfig)
		entries[newConfig] = config
		manifest[0].Config = newConfig
	}
	if failure == "missing tag" {
		manifest[0].RepoTags = []string{"lupetto/local:build-another"}
	}
	entries["manifest.json"], err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var saved bytes.Buffer
	tw := tar.NewWriter(&saved)
	for filename, contents := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: filename, Mode: 0600, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, saved.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDockerLoadSavedConfigFallback(t *testing.T) {
	for _, failure := range []string{"", "bad saved config", "missing tag", "save", "malformed archive", "cancel save"} {
		name := failure
		if name == "" {
			name = "matching saved config"
		}
		t.Run(name, func(t *testing.T) {
			workspace := t.TempDir()
			imageDir := filepath.Join(workspace, "image")
			sourceID, _, _ := makeLoadOCI(t, imageDir, "fixture", "1-r0", "x86_64")
			inspectedID := "sha256:" + strings.Repeat("a", 64)
			if sourceID == inspectedID {
				t.Fatal("fixture accidentally matches the fallback ID")
			}
			reference := "lupetto/local:build-fixture"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls [][]string
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				calls = append(calls, append([]string{executable}, args...))
				switch args[1] {
				case "load":
					return []byte("Loaded image: not identity evidence"), nil
				case "inspect":
					return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":"amd64"}`, inspectedID)), nil
				case "save":
					if failure == "save" {
						return []byte("save diagnostic"), errors.New("save failed")
					}
					writeSavedDockerFixture(t, filepath.Join(workspace, "docker-image.tar"), args[3], failure)
					if failure == "cancel save" {
						cancel()
						return nil, ctx.Err()
					}
					return nil, nil
				default:
					t.Fatalf("unexpected Docker stage: %q", args)
					return nil, nil
				}
			}
			id, err := loadDockerImage(ctx, command, imageDir, workspace, reference, "x86_64")
			wantCalls := [][]string{
				{"docker", "image", "load", "--input", filepath.Join(workspace, "docker-image.tar")},
				{"docker", "image", "inspect", "--format", `{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}`, reference},
				{"docker", "image", "save", "--output", filepath.Join(workspace, "docker-loaded.tar"), reference},
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("calls=%q want=%q", calls, wantCalls)
			}
			if failure == "" {
				if err != nil || id != inspectedID {
					t.Fatalf("fallback id=%q err=%v", id, err)
				}
				info, err := os.Stat(filepath.Join(workspace, "docker-loaded.tar"))
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("saved archive mode: info=%v err=%v", info, err)
				}
			} else {
				if err == nil || id != "" || !strings.Contains(err.Error(), reference) || !strings.Contains(err.Error(), "composition completed but loading was not confirmed") || !strings.Contains(err.Error(), "may have left an imported image/tag") {
					t.Fatalf("id=%q err=%v", id, err)
				}
				if failure == "save" && !strings.Contains(err.Error(), "save diagnostic") {
					t.Fatalf("save diagnostic lost: %v", err)
				}
				if failure == "cancel save" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			}
		})
	}
}
