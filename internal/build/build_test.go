package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lupetto/internal/build/buildtest"
	"lupetto/internal/wolfi"
)

func TestBuildPublicationNoLoadAccepted(t *testing.T) {
	request := Request{NoLoad: true, Publication: PublicationOptions{Registry: "localhost:5000", Repository: "team/images"}}
	if err := validateSigningOptions(request.Signing, request.Publication); err != nil {
		t.Fatalf("--no-load publication rejected: %v", err)
	}
}

func TestBuildPublicationRejectedBeforeExternalBoundaries(t *testing.T) {
	for _, request := range []Request{
		{Publication: PublicationOptions{Registry: "localhost:5000"}},
		{Publication: PublicationOptions{Registry: "https://example.com", Repository: "team/images"}},
	} {
		services := Services{
			Command: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("tool called before validation")
				return nil, nil
			},
			DataDir: func() (string, error) { t.Fatal("workspace called before validation"); return "", nil },
			PublicFile: func(context.Context, string, int64) ([]byte, error) {
				t.Fatal("network called before validation")
				return nil, nil
			},
		}
		if _, err := RunWith(context.Background(), request, services); err == nil {
			t.Fatalf("accepted %+v", request)
		}
	}
}

func TestBuildSigningEarlierApkoFailureKeepsRequestedNotAttempted(t *testing.T) {
	request := Request{Publication: PublicationOptions{Registry: "localhost:5000", Repository: "team/images"},
		Signing: SigningOptions{Key: buildtest.CosignKey, AllowHTTP: true}}
	services := Services{
		SigningCommand: func(context.Context, string, ...string) ([]byte, error) { return []byte(CosignVersion), nil },
		Command: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(buildtest.SigningCanary), errors.New(buildtest.SigningCanary)
		},
		DataDir: func() (string, error) { t.Fatal("workspace used after failed apko preflight"); return "", nil },
	}
	result, err := RunWith(context.Background(), request, services)
	var wf *WorkflowFailure
	if !errors.As(err, &wf) || wf.Stage != "build" || wf.Result.Build != "failed" || result.Signing != "not-attempted" || result.Attestation != "not-attempted" || wf.Result.Signing != "not-attempted" || wf.Result.Attestation != "not-attempted" || strings.Contains(err.Error(), buildtest.SigningCanary) {
		t.Fatalf("result=%+v workflow=%+v err=%v", result, wf, err)
	}
}

func TestBuildSigningInvalidOptionsRejectedBeforeExternalBoundaries(t *testing.T) {
	for _, request := range []Request{
		{Signing: SigningOptions{Key: buildtest.CosignKey}},
		{Publication: PublicationOptions{Registry: "localhost:5000", Repository: "team/images"}, Signing: SigningOptions{Key: buildtest.CosignKey}},
		{Publication: PublicationOptions{Registry: "registry.example.invalid", Repository: "team/images"}, Signing: SigningOptions{Key: buildtest.CosignKey, AllowHTTP: true}},
		{NoLoad: true, Signing: SigningOptions{Key: buildtest.CosignKey, AllowHTTP: true}},
	} {
		services := Services{
			Command: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("tool invoked before validation")
				return nil, nil
			},
			SigningCommand: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign invoked before validation")
				return nil, nil
			},
			DataDir: func() (string, error) { t.Fatal("workspace invoked before validation"); return "", nil },
			PublicFile: func(context.Context, string, int64) ([]byte, error) {
				t.Fatal("network invoked before validation")
				return nil, nil
			},
		}
		if _, err := RunWith(context.Background(), request, services); err == nil {
			t.Fatalf("accepted %+v", request)
		}
	}
}

func TestCheckSelectedLockRejectsSubstitution(t *testing.T) {
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64", Checksum: "Q1exact"}
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
	layerDigest := buildtest.WriteOCIBlob(t, dir, layer.Bytes())
	manifest, _ := json.Marshal(map[string]any{"layers": []any{map[string]any{"digest": layerDigest}}})
	manifestDigest := buildtest.WriteOCIBlob(t, dir, manifest)
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
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	digest, err := checkImagePackage(dir, selected)
	if err != nil || !digestPattern.MatchString(digest) {
		t.Fatalf("valid OCI image rejected: digest=%q err=%v", digest, err)
	}
	selected.Version = "9.1.2-r0"
	if _, err := checkImagePackage(dir, selected); err == nil {
		t.Fatal("image with wrong selected package version accepted")
	}
	selected.Version = "9.1.2-r1"
	layerPath := filepath.Join(dir, "blobs", "sha256", layerDigest)
	if err := os.WriteFile(layerPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkImagePackage(dir, selected); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered layer accepted: %v", err)
	}
}

func TestCheckImagePackageKeepsFirstSelectedRecordSemantics(t *testing.T) {
	dir, _ := makeOCI(t, "9.1.2-r0\nA:x86_64\n\nP:valkey-9.1\nV:9.1.2-r1")
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	if _, err := checkImagePackage(dir, selected); err == nil || !strings.Contains(err.Error(), "different version or architecture") {
		t.Fatalf("later duplicate record must not mask wrong first selected version: %v", err)
	}
}

func TestBuildWorkspaceUnderDataRoot(t *testing.T) {
	stopped := errors.New("stop after workspace creation")
	apko := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("GitVersion:    " + ApkoVersion + "\n"), nil
	}
	data := filepath.Join(t.TempDir(), "data")
	result, err := RunWith(context.Background(), Request{NoLoad: true}, Services{
		Command:    apko,
		DataDir:    func() (string, error) { return data, nil },
		PublicFile: func(context.Context, string, int64) ([]byte, error) { return nil, stopped },
	})
	if !errors.Is(err, stopped) {
		t.Fatalf("err=%v", err)
	}
	root := filepath.Join(data, "lupetto", "builds")
	if filepath.Dir(result.Workspace) != root || !strings.HasPrefix(filepath.Base(result.Workspace), "image-") {
		t.Fatalf("workspace %q is not directly under %q", result.Workspace, root)
	}
	for _, directory := range []string{root, result.Workspace} {
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("%s: %v %v", directory, info, err)
		}
	}

	// Explorer refuses evidence below a symlinked builds root; the build must
	// not create evidence there.
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.MkdirAll(filepath.Join(linked, "lupetto"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, "lupetto", "builds")); err != nil {
		t.Fatal(err)
	}
	result, err = RunWith(context.Background(), Request{NoLoad: true}, Services{
		Command: apko,
		DataDir: func() (string, error) { return linked, nil },
		PublicFile: func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("workspace created below a symlinked root")
			return nil, nil
		},
	})
	var wf *WorkflowFailure
	if !errors.As(err, &wf) || wf.Stage != "build" || result.Workspace != "" || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked root: result=%+v err=%v", result, err)
	}

	invalid := errors.New("invalid configuration: LUPETTO_DATA_DIR must be an absolute path")
	result, err = RunWith(context.Background(), Request{NoLoad: true}, Services{
		Command: apko,
		DataDir: func() (string, error) { return "", invalid },
		PublicFile: func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("continued without a data root")
			return nil, nil
		},
	})
	if !errors.Is(err, invalid) || result.Workspace != "" {
		t.Fatalf("invalid data root: result=%+v err=%v", result, err)
	}
}
