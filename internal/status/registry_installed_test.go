package status

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"lupetto/internal/build/buildtest"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

func identityAnnotations(version string, created time.Time) map[string]string {
	return map[string]string{"org.opencontainers.image.version": version, "org.opencontainers.image.created": created.UTC().Format(time.RFC3339Nano), "lupetto.apk.name": "curl", "lupetto.apk.version": version, "lupetto.apk.architecture": "x86_64", "lupetto.index.sha256": strings.Repeat("a", 64)}
}

func fixtureImage(t *testing.T, version string) v1.Image {
	t.Helper()
	directory := t.TempDir()
	buildtest.MakeLoadOCI(t, directory, "curl", version, "x86_64")
	root, err := layout.FromPath(directory)
	if err != nil {
		t.Fatal(err)
	}
	index, err := root.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	image, err := index.Image(manifest.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

type rawManifest []byte

func (manifest rawManifest) RawManifest() ([]byte, error) { return manifest, nil }
func (manifest rawManifest) MediaType() (types.MediaType, error) {
	return types.OCIManifestSchema1, nil
}

type recordingTransport struct {
	base    http.RoundTripper
	mu      sync.Mutex
	methods []string
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.methods = append(transport.methods, request.Method+" "+request.URL.Path)
	transport.mu.Unlock()
	return transport.base.RoundTrip(request)
}

func TestRegistryAnnotationsArtifactsUnidentifiedDedupeAndReadOnly(t *testing.T) {
	docker := buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "auth", nil)
	buildtest.WriteDockerAuth(t, filepath.Join(docker, "config.json"), server.Host)
	ctx := context.Background()
	repository, err := registry.Repository(Options{Registry: server.Host, Repository: "status/nested"}, "curl")
	if err != nil {
		t.Fatal(err)
	}
	base := fixtureImage(t, "8.2-r1")
	image := mutate.Annotations(base, identityAnnotations("8.2-r1", time.Now().UTC())).(v1.Image)
	for _, tag := range []string{"first", "alias"} {
		if err := remote.Write(repository.Tag(tag), image, registry.RemoteOptions(ctx)...); err != nil {
			t.Fatal(err)
		}
	}
	if err := remote.Write(repository.Tag("legacy"), base, registry.RemoteOptions(ctx)...); err != nil {
		t.Fatal(err)
	}
	data, _ := image.RawManifest()
	var artifact map[string]any
	json.Unmarshal(data, &artifact)
	artifact["artifactType"] = "application/vnd.dev.sigstore.bundle.v0.3+json"
	artifact["subject"] = map[string]any{"digest": "sha256:" + strings.Repeat("a", 64), "mediaType": string(types.OCIManifestSchema1), "size": 42}
	artifactData, _ := json.Marshal(artifact)
	if err := remote.Put(repository.Tag("cosign-modern"), rawManifest(artifactData), registry.RemoteOptions(ctx)...); err != nil {
		t.Fatal(err)
	}
	if err := remote.Put(repository.Tag("cosign-alias"), rawManifest(artifactData), registry.RemoteOptions(ctx)...); err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{base: remote.DefaultTransport}
	reader := RemoteRegistry{Transport: transport}
	listing, err := reader.List(ctx, repository)
	// The modern subject-bearing bundle and the client's referrers fallback
	// index are two distinct non-image digests, not two counts for its aliases.
	if err != nil || len(listing.Images) != 1 || listing.ArtifactCount != 2 || listing.UnidentifiedCount != 1 {
		t.Fatalf("listing: %+v, %v", listing, err)
	}
	if strings.Join(listing.Images[0].Tags, ",") != "alias,first" || listing.Images[0].Annotations["lupetto.apk.name"] != "curl" {
		t.Fatalf("annotation/tag identity: %+v", listing.Images[0])
	}
	packages, err := reader.Installed(ctx, repository, listing.Images[0])
	if err != nil || len(packages) != 1 || packages[0].Version != "8.2-r1" {
		t.Fatalf("installed: %+v, %v", packages, err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, method := range transport.methods {
		if !strings.HasPrefix(method, "GET ") && !strings.HasPrefix(method, "HEAD ") {
			t.Fatalf("status mutated registry: %s", method)
		}
	}
	foundDigest := false
	for _, method := range transport.methods {
		if strings.Contains(method, "/manifests/sha256:") {
			foundDigest = true
		}
	}
	if !foundDigest {
		t.Fatal("no immutable manifest read")
	}
}

func TestManifestClassificationRequiredAnnotationsAndArtifacts(t *testing.T) {
	image := mutate.Annotations(fixtureImage(t, "8.2-r1"), identityAnnotations("8.2-r1", time.Now().UTC())).(v1.Image)
	data, _ := image.RawManifest()
	for _, key := range []string{"org.opencontainers.image.version", "org.opencontainers.image.created", "lupetto.apk.name", "lupetto.apk.version", "lupetto.apk.architecture", "lupetto.index.sha256"} {
		var document map[string]any
		json.Unmarshal(data, &document)
		delete(document["annotations"].(map[string]any), key)
		changed, _ := json.Marshal(document)
		if _, classification := classifyManifest(changed, "digest"); classification != "unidentified" {
			t.Fatalf("missing %s: %s", key, classification)
		}
	}
	for _, scenario := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"version mismatch", func(m map[string]any) {
			m["annotations"].(map[string]any)["org.opencontainers.image.version"] = "8.2-r2"
		}, "unidentified"},
		{"bad created", func(m map[string]any) {
			m["annotations"].(map[string]any)["org.opencontainers.image.created"] = "today"
		}, "unidentified"},
		{"non UTC", func(m map[string]any) {
			m["annotations"].(map[string]any)["org.opencontainers.image.created"] = "2026-10-01T10:00:00+02:00"
		}, "unidentified"},
		{"numeric UTC", func(m map[string]any) {
			m["annotations"].(map[string]any)["org.opencontainers.image.created"] = "2026-10-01T10:00:00+00:00"
		}, "image"},
		{"bad index", func(m map[string]any) { m["annotations"].(map[string]any)["lupetto.index.sha256"] = "xyz" }, "unidentified"},
		{"subject only", func(m map[string]any) { m["subject"] = map[string]any{"digest": "sha256:abc"} }, "artifact"},
		{"artifact type", func(m map[string]any) { m["artifactType"] = "application/vnd.dev.sigstore.bundle.v0.3+json" }, "artifact"},
		{"nonimage config", func(m map[string]any) {
			m["config"].(map[string]any)["mediaType"] = "application/vnd.oci.empty.v1+json"
		}, "artifact"},
		{"nonimage layer", func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.dev.cosign.simplesigning.v1+json"
		}, "artifact"},
		{"zstd image layer", func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["mediaType"] = string(types.OCILayerZStd)
		}, "image"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var document map[string]any
			json.Unmarshal(data, &document)
			scenario.mutate(document)
			changed, _ := json.Marshal(document)
			if _, classification := classifyManifest(changed, "digest"); classification != scenario.want {
				t.Fatalf("got %s want %s", classification, scenario.want)
			}
		})
	}
}

type tarEntry struct {
	name string
	kind byte
	data string
}

func layerBytes(t *testing.T, entries ...tarEntry) ([]byte, []byte) {
	t.Helper()
	var raw bytes.Buffer
	archive := tar.NewWriter(&raw)
	for _, entry := range entries {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: 0600, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(raw.Bytes())
	gz.Close()
	return compressed.Bytes(), raw.Bytes()
}

func TestLayerBoundedReadsWhiteoutsFullDigestAndStrictIdentities(t *testing.T) {
	database := "P:curl\nV:8.2-r1\nA:x86_64\n\n"
	for _, scenario := range []struct {
		name     string
		entries  []tarEntry
		removed  bool
		database bool
	}{
		{"database", []tarEntry{{"./", tar.TypeDir, ""}, {"./usr/lib/apk/db/installed", tar.TypeReg, database}}, false, true},
		{"installed whiteout", []tarEntry{{"usr/lib/apk/db/.wh.installed", tar.TypeReg, ""}}, true, false},
		{"ancestor whiteout", []tarEntry{{"usr/lib/apk/.wh.db", tar.TypeReg, ""}}, true, false},
		{"opaque parent", []tarEntry{{"usr/lib/apk/.wh..wh..opq", tar.TypeReg, ""}}, true, false},
		{"unrelated whiteout", []tarEntry{{"etc/.wh.installed", tar.TypeReg, ""}}, false, false},
		{"same layer wins", []tarEntry{{installedPath, tar.TypeReg, database}, {"usr/lib/apk/db/.wh.installed", tar.TypeReg, ""}}, true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			compressed, raw := layerBytes(t, scenario.entries...)
			data, removed, _, _, err := readInstalledLayer(context.Background(), bytes.NewReader(compressed), types.OCILayer, "sha256:"+wolfi.SHA256Hex(compressed), "sha256:"+wolfi.SHA256Hex(raw))
			if err != nil || removed != scenario.removed || (data != nil) != scenario.database {
				t.Fatalf("layer data=%q removed=%v err=%v", data, removed, err)
			}
		})
	}
	compressed, raw := layerBytes(t, tarEntry{installedPath, tar.TypeReg, database}, tarEntry{"last", tar.TypeReg, "last bytes hashed"})
	if _, _, _, _, err := readInstalledLayer(context.Background(), bytes.NewReader(compressed), types.OCILayer, "sha256:"+strings.Repeat("0", 64), "sha256:"+wolfi.SHA256Hex(raw)); err == nil {
		t.Fatal("wrong compressed digest accepted")
	}
	if _, _, _, _, err := readInstalledLayer(context.Background(), bytes.NewReader(compressed), types.OCILayer, "sha256:"+wolfi.SHA256Hex(compressed), "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong diffID accepted")
	}
	for _, invalid := range []string{"V:8.2-r1\nA:x86_64\n\n", database + database, "P:curl\nV:8.2-r1\nV:8.2-r2\nA:x86_64\n\n", "P:curl\nV:8.2-r1\n\n", "P:curl\nV:8.2-r1\nA:aarch64\n\n"} {
		if _, err := parseInstalledStrict([]byte(invalid), "x86_64"); err == nil {
			t.Fatalf("malformed DB accepted %q", invalid)
		}
	}
	for _, entry := range []tarEntry{{"../usr/lib/apk/db/installed", tar.TypeReg, database}, {installedPath, tar.TypeSymlink, ""}, {installedPath, tar.TypeReg, strings.Repeat("x", wolfi.MaxInstalledDatabaseBytes+1)}} {
		compressed, raw := layerBytes(t, entry)
		if _, _, _, _, err := readInstalledLayer(context.Background(), bytes.NewReader(compressed), types.OCILayer, "sha256:"+wolfi.SHA256Hex(compressed), "sha256:"+wolfi.SHA256Hex(raw)); err == nil {
			t.Fatalf("unsafe layer accepted %s", entry.name)
		}
	}
	limited := &countedReader{reader: strings.NewReader("12345"), ctx: context.Background(), limit: 3}
	if _, err := io.ReadAll(limited); err == nil {
		t.Fatal("stream bound ignored")
	}
	for _, budget := range []struct{ compressed, uncompressed int64 }{{1, MaxUncompressedLayerBytes}, {MaxCompressedLayerBytes, 1}} {
		if _, _, _, _, err := readInstalledLayerBounded(context.Background(), bytes.NewReader(compressed), types.OCILayer, "sha256:"+wolfi.SHA256Hex(compressed), "sha256:"+wolfi.SHA256Hex(raw), budget.compressed, budget.uncompressed); err == nil {
			t.Fatal("image byte budget ignored")
		}
	}
}

func TestRegistryInstalledOverlayAndTampering(t *testing.T) {
	for _, scenario := range []string{"overlay", "whiteout", "manifest", "config", "layer"} {
		t.Run(scenario, func(t *testing.T) {
			buildtest.IsolateRegistryAuth(t)
			mutation := scenario
			if scenario == "overlay" || scenario == "whiteout" {
				mutation = ""
			}
			server := buildtest.NewRegistry(t, mutation, nil)
			repo, err := registry.Repository(Options{Registry: server.Host, Repository: "status"}, "curl")
			if err != nil {
				t.Fatal(err)
			}
			image := fixtureImage(t, "8.1-r0")
			if scenario == "overlay" || scenario == "whiteout" {
				entries := []tarEntry{{"usr/lib/apk/db/.wh.installed", tar.TypeReg, ""}}
				if scenario == "overlay" {
					entries = append(entries, tarEntry{installedPath, tar.TypeReg, "P:curl\nV:8.1-r0\nA:x86_64\n\nP:dependency\nV:1.0-r0\nA:x86_64\n\n"})
				}
				compressed, _ := layerBytes(t, entries...)
				layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(compressed)), nil }, tarball.WithMediaType(types.OCILayer))
				if err != nil {
					t.Fatal(err)
				}
				image, err = mutate.AppendLayers(image, layer)
				if err != nil {
					t.Fatal(err)
				}
			}
			image = mutate.Annotations(image, identityAnnotations("8.1-r0", time.Now().UTC())).(v1.Image)
			manifest, _ := image.Manifest()
			server.TamperBlobs(manifest.Config.Digest.String(), manifest.Layers[0].Digest.String())
			if err := remote.Write(repo.Tag("test"), image, registry.RemoteOptions(context.Background())...); err != nil {
				t.Fatal(err)
			}
			digest, _ := image.Digest()
			metadata := Image{Digest: digest.String(), Name: "curl", Version: "8.1-r0", Architecture: "x86_64"}
			packages, err := (RemoteRegistry{}).Installed(context.Background(), repo, metadata)
			if scenario == "overlay" {
				if err != nil || len(packages) != 2 {
					t.Fatalf("overlay: %+v %v", packages, err)
				}
			} else if err == nil {
				t.Fatalf("%s tamper/deletion accepted %+v", scenario, packages)
			}
			if err != nil && strings.Contains(err.Error(), buildtest.PublicationCanary) {
				t.Fatal("registry diagnostics leaked")
			}
		})
	}
}

func TestRegistryMissingRepositoryAndSanitizedAuthFailure(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "", nil)
	repo, _ := name.NewRepository(server.Host+"/missing/curl", name.Insecure)
	listing, err := (RemoteRegistry{}).List(context.Background(), repo)
	if err != nil || len(listing.Images) != 0 {
		t.Fatalf("not-built repository: %+v %v", listing, err)
	}
	auth := buildtest.NewRegistry(t, "auth", nil)
	repo, _ = name.NewRepository(auth.Host+"/missing/curl", name.Insecure)
	if _, err := (RemoteRegistry{}).List(context.Background(), repo); err == nil || strings.Contains(err.Error(), buildtest.PublicationCanary) {
		t.Fatalf("authentication error: %v", err)
	}
}

func TestRegistryInstalledLayerCountAndAnnotatedTopLevelMismatch(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "", nil)
	repository, err := registry.Repository(Options{Registry: server.Host, Repository: "limits"}, "curl")
	if err != nil {
		t.Fatal(err)
	}
	image := mutate.Annotations(fixtureImage(t, "8.1-r0"), identityAnnotations("8.2-r0", time.Now().UTC())).(v1.Image)
	if err := remote.Write(repository.Tag("mismatched"), image, registry.RemoteOptions(context.Background())...); err != nil {
		t.Fatal(err)
	}
	digest, _ := image.Digest()
	if _, err := (RemoteRegistry{}).Installed(context.Background(), repository, Image{Digest: digest.String(), Name: "curl", Version: "8.2-r0", Architecture: "x86_64"}); err == nil {
		t.Fatal("annotated top-level differs from installed but accepted")
	}
	data, _ := image.RawManifest()
	var manifest map[string]any
	json.Unmarshal(data, &manifest)
	layer := manifest["layers"].([]any)[0]
	layers := make([]any, MaxLayers+1)
	for i := range layers {
		layers[i] = layer
	}
	manifest["layers"] = layers
	changed, _ := json.Marshal(manifest)
	if err := remote.Put(repository.Tag("too-many"), rawManifest(changed), registry.RemoteOptions(context.Background())...); err != nil {
		t.Fatal(err)
	}
	tooMany := Image{Digest: "sha256:" + wolfi.SHA256Hex(changed), Name: "curl", Version: "8.2-r0", Architecture: "x86_64"}
	if _, err := (RemoteRegistry{}).Installed(context.Background(), repository, tooMany); err == nil || !strings.Contains(err.Error(), "layer limit") {
		t.Fatalf("layer limit not enforced: %v", err)
	}
}
