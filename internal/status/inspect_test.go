package status

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"lupetto/internal/build/buildtest"
	"lupetto/internal/registry"
)

func TestInspectReferences(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, ref := range []string{"127.0.0.1:5000/team/curl@" + digest, "registry.example.invalid/team/curl@" + digest, "[::1]:5000/team/curl@" + digest} {
		if _, err := ParseInspectReference(ref); err != nil {
			t.Errorf("%s: %v", ref, err)
		}
	}
	for _, ref := range []string{"registry.example.invalid/team/curl:latest", "curl@" + digest, "team/curl@" + digest, "https://registry.example.invalid/team/curl@" + digest, "user:secret@registry.example.invalid/team/curl@" + digest, "registry.example.invalid/team/curl:tag@" + digest, "registry.example.invalid/team/curl@sha256:abc", "registry.example.invalid/team/curl@sha512:" + strings.Repeat("a", 64), "registry.example.invalid/team/curl@sha256:" + strings.Repeat("A", 64)} {
		if _, err := ParseInspectReference(ref); err == nil {
			t.Errorf("accepted %s", ref)
		}
	}
}

func TestInspectIdentifiedAndUnidentifiedCache(t *testing.T) {
	docker := buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "auth", nil)
	buildtest.WriteDockerAuth(t, filepath.Join(docker, "config.json"), server.Host)
	ctx := context.Background()
	repository, err := registry.Repository(Options{Registry: server.Host, Repository: "inspect"}, "curl")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewFileCache(filepath.Join(t.TempDir(), "installed"))
	if err != nil {
		t.Fatal(err)
	}
	base := fixtureImage(t, "8.2-r1")
	for _, identified := range []bool{true, false} {
		image := base
		if identified {
			image = mutate.Annotations(base, identityAnnotations("8.2-r1", time.Now().UTC())).(v1.Image)
		}
		if err := remote.Write(repository.Tag("test"), image, registry.RemoteOptions(ctx)...); err != nil {
			t.Fatal(err)
		}
		digest, err := image.Digest()
		if err != nil {
			t.Fatal(err)
		}
		reference := repository.Digest(digest.String()).Name()
		transport := &recordingTransport{base: remote.DefaultTransport}
		reader := RemoteRegistry{Transport: transport}
		first, err := InspectWith(ctx, reference, reader, cache)
		if err != nil {
			t.Fatal(err)
		}
		if first.Kind != "inspect" || first.Version != 1 || first.Digest != digest.String() || first.Unidentified == identified || len(first.Packages) != 1 || first.Packages[0].Version != "8.2-r1" {
			t.Fatalf("unexpected inspect: %+v", first)
		}
		if identified && (first.Identity == nil || first.Identity.Name != "curl" || first.Created == nil) {
			t.Fatalf("missing identity: %+v", first)
		}
		if !identified && first.Identity != nil {
			t.Fatalf("guessed identity: %+v", first)
		}
		transport.mu.Lock()
		transport.methods = nil
		transport.mu.Unlock()
		second, err := InspectWith(ctx, reference, reader, cache)
		if err != nil || len(second.Packages) != len(first.Packages) {
			t.Fatalf("second inspect: %+v %v", second, err)
		}
		transport.mu.Lock()
		for _, method := range transport.methods {
			if strings.Contains(method, "/blobs/") || strings.Contains(method, "/tags/") || (!strings.HasPrefix(method, "GET ") && !strings.HasPrefix(method, "HEAD ")) {
				t.Errorf("unexpected cached request: %s", method)
			}
		}
		transport.mu.Unlock()
	}
}

func TestInspectSanitizesErrors(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "auth", nil)
	_, err := InspectWith(context.Background(), server.Host+"/inspect/curl@sha256:"+strings.Repeat("a", 64), RemoteRegistry{}, nil)
	if err == nil || strings.Contains(err.Error(), "unauthorized") || strings.Contains(err.Error(), "http://") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestInspectRejectsIndex(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	server := buildtest.NewRegistry(t, "", nil)
	repository, err := registry.Repository(Options{Registry: server.Host, Repository: "inspect"}, "curl")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(repository.Tag("multi"), empty.Index, registry.RemoteOptions(context.Background())...); err != nil {
		t.Fatal(err)
	}
	digest, err := empty.Index.Digest()
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectWith(context.Background(), repository.Digest(digest.String()).Name(), RemoteRegistry{}, nil)
	if err == nil || !strings.Contains(err.Error(), "artifact or image index") {
		t.Fatalf("accepted index: %v", err)
	}
}
