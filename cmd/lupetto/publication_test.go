package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const publicationCanary = "secretcanary-never-retain"

// fixturePushDigest is a synthetic digest for tests that do not push.
const fixturePushDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const (
	registryTestUser     = "lupetto-test-user"
	registryTestPassword = "synthetic-password-never-retain"
)

// testRegistry is go-containerregistry's in-process OCI registry behind a
// loopback httptest server, with optional tampering and authentication. It
// speaks the real distribution protocol; it is not an argument-echo mock.
type testRegistry struct {
	server   *httptest.Server
	host     string
	mutation string
	cancel   context.CancelFunc
	auth     bool

	mu           sync.Mutex
	pushed       bool
	configDigest string
	layerDigest  string
	requests     []string
}

func isolateRegistryAuth(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, key := range []string{"HOME", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME"} {
		dir := filepath.Join(root, strings.ToLower(key))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, dir)
	}
	t.Setenv("REGISTRY_AUTH_FILE", filepath.Join(root, "missing-podman-auth.json"))
	return os.Getenv("DOCKER_CONFIG")
}

func writeDockerAuth(t *testing.T, path, host string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(registryTestUser + ":" + registryTestPassword))
	data, err := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{"auth": auth}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func newTestRegistry(t *testing.T, mutation string, cancel context.CancelFunc) *testRegistry {
	t.Helper()
	return newTestRegistryOn(t, "127.0.0.1:0", mutation, cancel)
}

func newTestRegistryOn(t *testing.T, address, mutation string, cancel context.CancelFunc) *testRegistry {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", address, err)
	}
	r := &testRegistry{mutation: mutation, cancel: cancel, auth: mutation == "auth"}
	inner := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serve(inner, w, req) }))
	r.server.Listener.Close()
	r.server.Listener = listener
	r.server.Start()
	t.Cleanup(r.server.Close)
	r.host = strings.TrimPrefix(r.server.URL, "http://")
	return r
}

func (r *testRegistry) serve(inner http.Handler, w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	pushed, configDigest, layerDigest := r.pushed, r.configDigest, r.layerDigest
	r.mu.Unlock()
	if r.auth {
		user, password, ok := req.BasicAuth()
		if !ok || user != registryTestUser || password != registryTestPassword {
			if req.Method == http.MethodHead {
				// Keep existence probes uninformative so the canary reaches
				// a real, body-bearing client error on upload.
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="lupetto-test"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"errors":[{"code":"UNAUTHORIZED","message":%q},{"code":%q},{"code":"UNAUTHORIZED","detail":%q}]}`, publicationCanary, publicationCanary, publicationCanary)
			return
		}
	}
	path := req.URL.Path
	isManifest := strings.Contains(path, "/manifests/")
	switch {
	case r.mutation == "cancel push" && req.Method == http.MethodPost && strings.Contains(path, "/blobs/uploads/"):
		r.cancel()
	case r.mutation == "reject manifest" && req.Method == http.MethodPut && isManifest:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"errors":[{"code":"MANIFEST_INVALID","message":%q},{"code":"lower-%s"}]}`, publicationCanary, publicationCanary)
		return
	}
	if pushed && req.Method == http.MethodGet {
		byDigest := strings.Contains(path, "/manifests/sha256:")
		switch {
		case r.mutation == "cancel readback" && byDigest:
			r.cancel()
		case r.mutation == "manifest" && byDigest,
			r.mutation == "tag" && isManifest && !byDigest,
			r.mutation == "config" && strings.HasSuffix(path, "/blobs/"+configDigest),
			r.mutation == "layer" && strings.HasSuffix(path, "/blobs/"+layerDigest),
			r.mutation == "media type" && byDigest:
			recorder := httptest.NewRecorder()
			inner.ServeHTTP(recorder, req)
			body := recorder.Body.Bytes()
			if r.mutation != "media type" {
				body = append(append([]byte(nil), body...), ' ')
			}
			for key, values := range recorder.Header() {
				w.Header()[key] = values
			}
			if r.mutation == "media type" {
				w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(body)
			return
		}
	}
	inner.ServeHTTP(w, req)
	if req.Method == http.MethodPut && isManifest {
		r.mu.Lock()
		r.pushed = true
		r.mu.Unlock()
	}
}

func (r *testRegistry) tamperBlobs(configDigest, layerDigest string) {
	r.mu.Lock()
	r.configDigest, r.layerDigest = configDigest, layerDigest
	r.mu.Unlock()
}

func publicationTestResult(t *testing.T, arch string) (buildResult, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "image-test123")
	imageDir := filepath.Join(workspace, "image")
	makeLoadOCI(t, imageDir, "fixture", "1-r0", arch)
	return buildResult{packageName: "fixture", version: "1-r0", arch: arch, workspace: workspace, imageDir: imageDir,
		imageReference: "lupetto/fixture:1-r0-amd64", buildReference: "lupetto/local:build-test123"}, fixtureManifestDigest(t, imageDir)
}

func fixtureManifestDigest(t *testing.T, imageDir string) string {
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

func fixtureBlobDigests(t *testing.T, imageDir string) (string, string) {
	t.Helper()
	source, err := openPublicationSource(context.Background(), imageDir, mustTargetArchFor(t, imageDir))
	if err != nil {
		t.Fatal(err)
	}
	return source.configDigest, source.layers[0]
}

func mustTargetArchFor(t *testing.T, imageDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(imageDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"arm64"`)) {
		return "aarch64"
	}
	return "x86_64"
}

func TestPublishOCIImagePushesLayoutAndVerifiesReadback(t *testing.T) {
	for _, arch := range []string{"x86_64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			isolateRegistryAuth(t)
			registry := newTestRegistry(t, "", nil)
			result, manifestDigest := publicationTestResult(t, arch)
			opts := publicationOptions{registry: registry.host, repository: "team/images"}
			var progress bytes.Buffer
			reporter := newBuildProgress(context.Background(), &progress, false)
			ctx := context.WithValue(context.Background(), buildProgressKey{}, reporter)
			outcome, err := publishOCIImage(ctx, buildServices{}, result, opts)
			reporter.Close()
			ociArch, _ := ociArchitecture(arch)
			wantReference := registry.host + "/team/images/fixture:1-r0-" + ociArch + "-build-test123"
			wantImmutable := registry.host + "/team/images/fixture@" + manifestDigest
			if err != nil || outcome != (publicationOutcome{status: "published", reference: wantReference, pushedDigest: manifestDigest, immutableReference: wantImmutable, verified: true}) {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
			for _, stage := range []string{"Pushing OCI image to registry", "Verifying registry manifest by digest", "Verifying registry tag", "Verifying registry config and layers"} {
				if !strings.Contains(progress.String(), "lupetto: "+stage+"\n") {
					t.Fatalf("missing progress %q: %s", stage, progress.String())
				}
			}
			// Independently resolve the unique tag through the same protocol.
			tag, err := name.NewTag(wantReference, name.StrictValidation)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := remote.Get(tag)
			if err != nil || descriptor.Digest.String() != manifestDigest {
				t.Fatalf("tag descriptor=%+v err=%v", descriptor, err)
			}
			local, err := readOCIBlob(result.imageDir, manifestDigest, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := os.ReadFile(filepath.Join(result.workspace, "published-manifest.json"))
			if err != nil || !bytes.Equal(retained, local) {
				t.Fatalf("retained manifest=%q err=%v", retained, err)
			}
			if info, err := os.Stat(filepath.Join(result.workspace, "published-manifest.json")); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("retained manifest mode=%v err=%v", info, err)
			}
		})
	}
}

func TestPublishOCIImageReadbackTamperingFailsUnverified(t *testing.T) {
	for _, tc := range []struct{ mutation, message string }{
		{"manifest", "publication manifest readback failed"},
		{"media type", "publication manifest readback failed (content mismatch)"},
		{"tag", "publication tag readback failed (content mismatch)"},
		{"config", "publication config readback failed"},
		{"layer", "publication layer readback failed"},
	} {
		t.Run(tc.mutation, func(t *testing.T) {
			isolateRegistryAuth(t)
			registry := newTestRegistry(t, tc.mutation, nil)
			result, manifestDigest := publicationTestResult(t, "x86_64")
			registry.tamperBlobs(fixtureBlobDigests(t, result.imageDir))
			outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
			if err == nil || err.Error() != tc.message {
				t.Fatalf("err=%v want %q", err, tc.message)
			}
			if outcome.status != "failed" || outcome.verified || outcome.pushedDigest != manifestDigest || !strings.HasSuffix(outcome.immutableReference, "@"+manifestDigest) {
				t.Fatalf("outcome=%+v", outcome)
			}
			if _, err := os.Stat(filepath.Join(result.workspace, "published-manifest.json")); !os.IsNotExist(err) {
				t.Fatalf("tampered readback retained manifest: %v", err)
			}
		})
	}
}

func TestPublishOCIImageRegistryRejectionIsSanitized(t *testing.T) {
	isolateRegistryAuth(t)
	registry := newTestRegistry(t, "reject manifest", nil)
	result, _ := publicationTestResult(t, "x86_64")
	outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (HTTP 400; MANIFEST_INVALID)" || outcome.pushedDigest != "" || outcome.status != "failed" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
}

func registryPushError(t *testing.T, host string, result buildResult, keychain authn.Keychain) error {
	t.Helper()
	source, err := openPublicationSource(context.Background(), result.imageDir, result.arch)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(host+"/team/images/raw:probe", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	return remote.Write(tag, source.image, remote.WithAuthFromKeychain(keychain))
}

func TestPublishOCIImageDockerConfigAuthentication(t *testing.T) {
	t.Run("docker config credentials", func(t *testing.T) {
		dockerConfig := isolateRegistryAuth(t)
		registry := newTestRegistry(t, "auth", nil)
		writeDockerAuth(t, filepath.Join(dockerConfig, "config.json"), registry.host)
		result, digest := publicationTestResult(t, "x86_64")
		outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
		if err != nil || outcome.status != "published" || !outcome.verified || outcome.pushedDigest != digest {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
	})
	t.Run("missing credentials sanitized 401", func(t *testing.T) {
		isolateRegistryAuth(t)
		registry := newTestRegistry(t, "auth", nil)
		result, _ := publicationTestResult(t, "x86_64")
		// The raw client error carries the registry-controlled canary; the
		// Lupetto error, record, and stderr must not.
		if raw := registryPushError(t, registry.host, result, authn.NewMultiKeychain()); raw == nil || !strings.Contains(raw.Error(), publicationCanary) {
			t.Fatalf("fixture does not expose the canary to the client: %v", raw)
		}
		outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
		if err == nil || err.Error() != "publication push failed (HTTP 401; UNAUTHORIZED)" || outcome.pushedDigest != "" || outcome.verified {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
		result.publication = outcome
		result.build, result.dockerLoad, result.signing, result.attestation = "completed", "skipped", "skipped", "skipped"
		failure := newWorkflowFailure(result, "publication", err, true)
		var stderr bytes.Buffer
		reportWorkflowFailure(&stderr, failure)
		data, readErr := os.ReadFile(filepath.Join(result.workspace, "failure.json"))
		for _, text := range []string{stderr.String(), string(data), string(failure.record)} {
			if strings.Contains(text, publicationCanary) || strings.Contains(text, registryTestPassword) {
				t.Fatalf("unsafe output: %s", text)
			}
		}
		if readErr != nil || !strings.Contains(string(data), "publication push failed (HTTP 401; UNAUTHORIZED)") {
			t.Fatalf("record=%s err=%v", data, readErr)
		}
	})
	t.Run("podman and containers auth files ignored", func(t *testing.T) {
		isolateRegistryAuth(t)
		registry := newTestRegistry(t, "auth", nil)
		podman := filepath.Join(t.TempDir(), "podman-auth.json")
		writeDockerAuth(t, podman, registry.host)
		t.Setenv("REGISTRY_AUTH_FILE", podman)
		writeDockerAuth(t, filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "containers", "auth.json"), registry.host)
		writeDockerAuth(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "containers", "auth.json"), registry.host)
		tag, err := name.NewTag(registry.host+"/team/images/fixture:probe", name.StrictValidation)
		if err != nil {
			t.Fatal(err)
		}
		// Control: upstream's default keychain would use the Podman file.
		if auth, err := authn.DefaultKeychain.Resolve(tag.Context()); err != nil || auth == authn.Anonymous {
			t.Fatalf("fixture not visible to the upstream Podman fallback: auth=%v err=%v", auth, err)
		}
		if auth, err := (dockerConfigKeychain{}).Resolve(tag.Context()); err != nil || auth != authn.Anonymous {
			t.Fatalf("Docker-only keychain used non-Docker auth: auth=%v err=%v", auth, err)
		}
		result, _ := publicationTestResult(t, "x86_64")
		outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
		if err == nil || err.Error() != "publication push failed (HTTP 401; UNAUTHORIZED)" || outcome.status != "failed" {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
	})
	t.Run("malformed docker config sanitized", func(t *testing.T) {
		dockerConfig := isolateRegistryAuth(t)
		registry := newTestRegistry(t, "auth", nil)
		if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), []byte("{"+publicationCanary), 0600); err != nil {
			t.Fatal(err)
		}
		result, _ := publicationTestResult(t, "x86_64")
		outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
		if err == nil || err.Error() != "publication push failed" || outcome.status != "failed" {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
	})
}

type recordingTransport struct {
	mu    sync.Mutex
	hosts []string
	base  http.RoundTripper
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Scheme+"://"+req.URL.Host)
	r.mu.Unlock()
	if r.base == nil {
		return nil, errors.New("synthetic " + publicationCanary + " transport unavailable")
	}
	return r.base.RoundTrip(req)
}

func TestLoopbackHTTPGuard(t *testing.T) {
	for _, tc := range []struct {
		url     string
		allowed bool
	}{
		{"http://10.0.0.1/v2/", false},
		{"http://10.0.0.1:5000/v2/", false},
		{"http://192.168.1.10:5000/v2/", false},
		{"http://registry.local/v2/", false},
		{"http://localhost.example/v2/", false},
		{"http://[2001:db8::1]:5000/v2/", false},
		{"ftp://127.0.0.1/v2/", false},
		{"http://127.0.0.1/v2/", true},
		{"http://127.0.0.1:5000/v2/", true},
		{"http://127.0.0.2:5000/v2/", true},
		{"http://[::1]:5000/v2/", true},
		{"http://localhost/v2/", true},
		{"http://LOCALHOST:5000/v2/", true},
		{"https://registry.example/v2/", true},
		{"https://10.0.0.1/v2/", true},
	} {
		t.Run(tc.url, func(t *testing.T) {
			base := &recordingTransport{}
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = loopbackHTTPOnly{base: base}.RoundTrip(req)
			if tc.allowed != (len(base.hosts) == 1) {
				t.Fatalf("allowed=%v base calls=%q err=%v", tc.allowed, base.hosts, err)
			}
			if !tc.allowed && (err == nil || strings.HasPrefix(tc.url, "http:") && !errors.Is(err, errPlainHTTPRefused)) {
				t.Fatalf("refusal err=%v", err)
			}
		})
	}
}

func TestPublishOCIImageRefusesNonLoopbackHTTPWithoutDialing(t *testing.T) {
	isolateRegistryAuth(t)
	base := &recordingTransport{}
	result, _ := publicationTestResult(t, "x86_64")
	// ggcr would fall back to HTTP for an RFC 1918 registry.
	outcome, err := publishOCIImage(context.Background(), buildServices{registryTransport: base}, result, publicationOptions{registry: "10.0.0.1:5000", repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (plain HTTP refused for non-loopback registry)" || outcome.status != "failed" || outcome.pushedDigest != "" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	for _, host := range base.hosts {
		if strings.HasPrefix(host, "http:") {
			t.Fatalf("plain HTTP reached the base transport: %q", base.hosts)
		}
	}
}

func TestPublishOCIImageGuardsTokenRealmRequests(t *testing.T) {
	isolateRegistryAuth(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// A public (TEST-NET-3) plain-HTTP realm passes ggcr's own private
		// address check; Lupetto's guard must still refuse it before dialing.
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://203.0.113.10/token",service="synthetic"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	base := &recordingTransport{base: http.DefaultTransport}
	result, _ := publicationTestResult(t, "x86_64")
	host := strings.TrimPrefix(server.URL, "http://")
	outcome, err := publishOCIImage(context.Background(), buildServices{registryTransport: base}, result, publicationOptions{registry: host, repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (plain HTTP refused for non-loopback registry)" || outcome.status != "failed" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	for _, called := range base.hosts {
		if strings.Contains(called, "203.0.113.10") {
			t.Fatalf("token realm reached the base transport: %q", base.hosts)
		}
	}
}

func TestPublishOCIImageAlternateLoopbackListeners(t *testing.T) {
	for _, address := range []string{"127.0.0.2:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			isolateRegistryAuth(t)
			registry := newTestRegistryOn(t, address, "", nil)
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(context.Background(), buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
			if err != nil || outcome.status != "published" || !outcome.verified || outcome.pushedDigest != digest {
				t.Fatalf("registry=%s outcome=%+v err=%v", registry.host, outcome, err)
			}
		})
	}
}

// Loopback authorities outside ggcr's own HTTP heuristic (127.0.0.2, bare
// localhost) still publish over loopback HTTP because Lupetto parses them with
// name.Insecure. The injected base dials the in-process registry for any host.
func TestPublishOCIImageLoopbackAliasesUseHTTPFallback(t *testing.T) {
	for _, authority := range []string{"127.0.0.2:5000", "localhost"} {
		t.Run(authority, func(t *testing.T) {
			isolateRegistryAuth(t)
			registry := newTestRegistry(t, "", nil)
			dialer := &net.Dialer{}
			base := &recordingTransport{base: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, registry.host)
			}}}
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(context.Background(), buildServices{registryTransport: base}, result, publicationOptions{registry: authority, repository: "team/images"})
			if err != nil || outcome.status != "published" || !outcome.verified || outcome.pushedDigest != digest || outcome.immutableReference != authority+"/team/images/fixture@"+digest {
				t.Fatalf("outcome=%+v err=%v calls=%q", outcome, err, base.hosts)
			}
		})
	}
}

func TestPublishOCIImageCancellation(t *testing.T) {
	for _, tc := range []struct {
		mutation string
		captured bool
	}{{"cancel push", false}, {"cancel readback", true}} {
		t.Run(tc.mutation, func(t *testing.T) {
			isolateRegistryAuth(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			registry := newTestRegistry(t, tc.mutation, cancel)
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(ctx, buildServices{}, result, publicationOptions{registry: registry.host, repository: "team/images"})
			if !errors.Is(err, context.Canceled) || outcome.status != "failed" || outcome.verified || (outcome.pushedDigest == digest) != tc.captured || (outcome.pushedDigest != "") != tc.captured {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
		})
	}
}

func TestPublishOCIImageRejectsInvalidSourceBeforeNetwork(t *testing.T) {
	isolateRegistryAuth(t)
	base := &recordingTransport{}
	result, digest := publicationTestResult(t, "x86_64")
	if err := os.WriteFile(filepath.Join(result.imageDir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), []byte(publicationCanary), 0600); err != nil {
		t.Fatal(err)
	}
	outcome, err := publishOCIImage(context.Background(), buildServices{registryTransport: base}, result, publicationOptions{registry: "registry.example", repository: "team/images"})
	if err == nil || err.Error() != "publication source failed" || len(base.hosts) != 0 || outcome.status != "failed" {
		t.Fatalf("outcome=%+v err=%v calls=%q", outcome, err, base.hosts)
	}
	if outcome, err := publishOCIImage(context.Background(), buildServices{registryTransport: base}, result, publicationOptions{}); err != nil || outcome.status != "skipped" || len(base.hosts) != 0 {
		t.Fatalf("disabled publication outcome=%+v err=%v", outcome, err)
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestVerifyRegistryLayerCompressedAndUncompressedDigests(t *testing.T) {
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	content := []byte("layer content")
	if err := tw.WriteHeader(&tar.Header{Name: "file", Mode: 0600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := gzipBytes(t, layer.Bytes())
	digest, diffID := "sha256:"+sha256Hex(compressed), "sha256:"+sha256Hex(layer.Bytes())
	trailing := append(append([]byte(nil), compressed...), []byte("trailing")...)
	for _, tc := range []struct {
		name, digest, diffID string
		data                 []byte
		want                 error
	}{
		{"valid", digest, diffID, compressed, nil},
		{"wrong diffID", digest, "sha256:" + sha256Hex([]byte("other")), compressed, errRegistryContentMismatch},
		{"wrong compressed digest", "sha256:" + sha256Hex([]byte("other")), diffID, compressed, errRegistryContentMismatch},
		{"uncompressed layer", "sha256:" + sha256Hex(layer.Bytes()), diffID, layer.Bytes(), errUnsupportedLayer},
		{"trailing data", "sha256:" + sha256Hex(trailing), diffID, trailing, errRegistryContentMismatch},
		{"truncated", digest, diffID, compressed[:len(compressed)/2], errRegistryContentMismatch},
		{"empty", digest, diffID, nil, errRegistryContentMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyRegistryLayer(context.Background(), bytes.NewReader(tc.data), tc.digest, tc.diffID)
			if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyRegistryLayer(ctx, bytes.NewReader(compressed), digest, diffID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestRegistryStageErrorSanitization(t *testing.T) {
	canary := errors.New(publicationCanary)
	registryErr := &transport.Error{StatusCode: http.StatusForbidden, Errors: []transport.Diagnostic{
		{Code: "DENIED", Message: publicationCanary}, {Code: transport.ErrorCode(publicationCanary)},
		{Code: "DENIED"}, {Code: "TOOMANYREQUESTS", Detail: publicationCanary}, {Code: "lower_case"}, {Code: transport.ErrorCode(strings.Repeat("A", 33))},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		err  error
		want string
	}{
		{context.Background(), fmt.Errorf("%w: %s", registryErr, publicationCanary), "publication push failed (HTTP 403; DENIED,TOOMANYREQUESTS)"},
		{context.Background(), &transport.Error{StatusCode: 401}, "publication push failed (HTTP 401)"},
		{context.Background(), fmt.Errorf("%s: %w", publicationCanary, errPlainHTTPRefused), "publication push failed (plain HTTP refused for non-loopback registry)"},
		{context.Background(), fmt.Errorf("%s: %w", publicationCanary, x509.UnknownAuthorityError{}), "publication push failed (TLS verification failed)"},
		{context.Background(), &net.OpError{Op: "dial", Net: "tcp", Err: canary}, "publication push failed (registry unreachable)"},
		{context.Background(), &net.DNSError{Name: publicationCanary, Err: publicationCanary}, "publication push failed (registry unreachable)"},
		{context.Background(), canary, "publication push failed"},
		{context.Background(), nil, "publication push failed"},
		{context.Background(), fmt.Errorf("%s: %w", publicationCanary, context.DeadlineExceeded), "publication push canceled: context deadline exceeded"},
		{ctx, canary, "publication push canceled: context canceled"},
	} {
		err := registryStageError(tc.ctx, "publication push", tc.err)
		if err.Error() != tc.want || strings.Contains(err.Error(), publicationCanary) {
			t.Fatalf("err=%q want=%q", err, tc.want)
		}
	}
}
