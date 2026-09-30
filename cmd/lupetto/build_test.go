package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSelectedLockRejectsSubstitution(t *testing.T) {
	selected := indexedPackage{name: "valkey-9.1", version: "9.1.2-r1", arch: "x86_64", checksum: "Q1exact"}
	path := filepath.Join(t.TempDir(), "lock.json")
	for _, tc := range []struct {
		name, version, checksum string
		wantError               bool
	}{
		{"exact", "9.1.2-r1", "Q1exact", false},
		{"wrong revision", "9.1.2-r0", "Q1exact", true},
		{"different package bytes", "9.1.2-r1", "Q1changed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock := map[string]any{"contents": map[string]any{"packages": []any{map[string]any{
				"name": "valkey-9.1", "version": tc.version, "architecture": "x86_64", "checksum": tc.checksum,
			}}}}
			data, _ := json.Marshal(lock)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			err := checkSelectedLock(path, selected)
			if (err != nil) != tc.wantError {
				t.Fatalf("lock check error = %v; want error %v", err, tc.wantError)
			}
		})
	}
}

func writeOCIBlob(t *testing.T, dir string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", digest), data, 0600); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + digest
}

func makeOCI(t *testing.T, version string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	installed := "P:valkey-9.1\nV:" + version + "\nA:x86_64\n\n"
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "usr/lib/apk/db/installed", Mode: 0600, Size: int64(len(installed))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(installed)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	layerDigest := writeOCIBlob(t, dir, layer.Bytes())
	manifest, _ := json.Marshal(map[string]any{"layers": []any{map[string]any{"digest": layerDigest}}})
	manifestDigest := writeOCIBlob(t, dir, manifest)
	index, _ := json.Marshal(map[string]any{"manifests": []any{map[string]any{
		"digest": manifestDigest, "platform": map[string]string{"architecture": "amd64", "os": "linux"},
	}}})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), index, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimPrefix(layerDigest, "sha256:")
}

func TestCheckImagePackageRequiresExactInstalledVersionAndLayerDigest(t *testing.T) {
	dir, layerDigest := makeOCI(t, "9.1.2-r1")
	selected := indexedPackage{name: "valkey-9.1", version: "9.1.2-r1", arch: "x86_64"}
	if err := checkImagePackage(dir, selected); err != nil {
		t.Fatalf("valid OCI image rejected: %v", err)
	}
	selected.version = "9.1.2-r0"
	if err := checkImagePackage(dir, selected); err == nil {
		t.Fatal("image with wrong selected package version accepted")
	}
	selected.version = "9.1.2-r1"
	layerPath := filepath.Join(dir, "blobs", "sha256", layerDigest)
	if err := os.WriteFile(layerPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkImagePackage(dir, selected); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered layer accepted: %v", err)
	}
}
