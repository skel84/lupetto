// Package buildtest holds synthetic fixtures shared by build and CLI tests:
// OCI layouts, Docker save archives, an in-process loopback registry, and
// secret canaries. It must not import internal/build.
package buildtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"lupetto/internal/wolfi"
)

func WriteOCIBlob(t *testing.T, dir string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", digest), data, 0600); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + digest
}

// OCIArch maps a Wolfi architecture to its OCI name for fixtures.
func OCIArch(t *testing.T, arch string) string {
	t.Helper()
	switch arch {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	}
	t.Fatalf("unsupported fixture architecture %q", arch)
	return ""
}

// A synthetic single-image OCI fixture, not an interoperability claim.
func MakeLoadOCI(t *testing.T, dir, pkg, version, arch string) (string, []byte, []byte) {
	t.Helper()
	ociArch := OCIArch(t, arch)
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
	layerDigest := WriteOCIBlob(t, dir, layer)
	config := marshal(map[string]any{
		"architecture": ociArch, "os": "linux",
		"config": map[string]any{"Env": []string{"FIXTURE=value"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + wolfi.SHA256Hex(uncompressed.Bytes())}},
	})
	configDigest := WriteOCIBlob(t, dir, config)
	manifest := marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": len(layer)}},
	})
	manifestDigest := WriteOCIBlob(t, dir, manifest)
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

// Model docker save from the already-exported bytes, optionally changing the
// saved config or tag. The tests do not use a daemon or assert interoperability.
func WriteSavedDockerFixture(t *testing.T, inputPath, outputPath, failure string) {
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
		newConfig := "sha256:" + wolfi.SHA256Hex(config)
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

func ManifestDigest(t *testing.T, imageDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(imageDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct{ Manifests []struct{ Digest string } }
	if err := json.Unmarshal(data, &index); err != nil || len(index.Manifests) != 1 {
		t.Fatalf("index=%s err=%v", data, err)
	}
	return index.Manifests[0].Digest
}

// BlobDigests returns the config and first layer digests of the
// fixture layout's single image.
func BlobDigests(t *testing.T, imageDir string) (string, string) {
	t.Helper()
	index, err := layout.Path(imageDir).ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	indexManifest, err := index.IndexManifest()
	if err != nil || len(indexManifest.Manifests) != 1 {
		t.Fatalf("index=%+v err=%v", indexManifest, err)
	}
	image, err := index.Image(indexManifest.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := image.Manifest()
	if err != nil || len(manifest.Layers) == 0 {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	return manifest.Config.Digest.String(), manifest.Layers[0].Digest.String()
}
