package build

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"lupetto/internal/build/buildtest"
	"lupetto/internal/wolfi"
)

func publicationTestResult(t *testing.T, arch string) (Result, string) {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "image-test123")
	imageDir := filepath.Join(workspace, "image")
	buildtest.MakeLoadOCI(t, imageDir, "fixture", "1-r0", arch)
	return Result{PackageName: "fixture", Version: "1-r0", Arch: arch, Workspace: workspace, ImageDir: imageDir,
		ImageReference: "lupetto/fixture:1-r0-amd64", BuildReference: "lupetto/local:build-test123"}, buildtest.ManifestDigest(t, imageDir)
}

func TestPublishOCIImagePushesLayoutAndVerifiesReadback(t *testing.T) {
	for _, arch := range []string{"x86_64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			buildtest.IsolateRegistryAuth(t)
			registry := buildtest.NewRegistry(t, "", nil)
			result, manifestDigest := publicationTestResult(t, arch)
			opts := PublicationOptions{Registry: registry.Host, Repository: "team/images"}
			var progress bytes.Buffer
			ctx := WithReporter(context.Background(), lineReporter{&progress})
			outcome, err := publishOCIImage(ctx, Services{}, result, opts)
			ociArch, _ := ociArchitecture(arch)
			wantReference := registry.Host + "/team/images/fixture:1-r0-" + ociArch + "-build-test123"
			wantImmutable := registry.Host + "/team/images/fixture@" + manifestDigest
			if err != nil || outcome != (PublicationOutcome{Status: "published", Reference: wantReference, PushedDigest: manifestDigest, ImmutableReference: wantImmutable, Verified: true}) {
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
			local, err := readOCIBlob(result.ImageDir, manifestDigest, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := os.ReadFile(filepath.Join(result.Workspace, "published-manifest.json"))
			if err != nil || !bytes.Equal(retained, local) {
				t.Fatalf("retained manifest=%q err=%v", retained, err)
			}
			if info, err := os.Stat(filepath.Join(result.Workspace, "published-manifest.json")); err != nil || info.Mode().Perm() != 0600 {
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
			buildtest.IsolateRegistryAuth(t)
			registry := buildtest.NewRegistry(t, tc.mutation, nil)
			result, manifestDigest := publicationTestResult(t, "x86_64")
			registry.TamperBlobs(buildtest.BlobDigests(t, result.ImageDir))
			outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
			if err == nil || err.Error() != tc.message {
				t.Fatalf("err=%v want %q", err, tc.message)
			}
			if outcome.Status != "failed" || outcome.Verified || outcome.PushedDigest != manifestDigest || !strings.HasSuffix(outcome.ImmutableReference, "@"+manifestDigest) {
				t.Fatalf("outcome=%+v", outcome)
			}
			if _, err := os.Stat(filepath.Join(result.Workspace, "published-manifest.json")); !os.IsNotExist(err) {
				t.Fatalf("tampered readback retained manifest: %v", err)
			}
		})
	}
}

func TestPublishOCIImageRegistryRejectionIsSanitized(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	registry := buildtest.NewRegistry(t, "reject manifest", nil)
	result, _ := publicationTestResult(t, "x86_64")
	outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (HTTP 400; MANIFEST_INVALID)" || outcome.PushedDigest != "" || outcome.Status != "failed" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
}

func registryPushError(t *testing.T, host string, result Result, keychain authn.Keychain) error {
	t.Helper()
	source, err := openPublicationSource(context.Background(), result.ImageDir, result.Arch)
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
		dockerConfig := buildtest.IsolateRegistryAuth(t)
		registry := buildtest.NewRegistry(t, "auth", nil)
		buildtest.WriteDockerAuth(t, filepath.Join(dockerConfig, "config.json"), registry.Host)
		result, digest := publicationTestResult(t, "x86_64")
		outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
		if err != nil || outcome.Status != "published" || !outcome.Verified || outcome.PushedDigest != digest {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
	})
	t.Run("missing credentials sanitized 401", func(t *testing.T) {
		buildtest.IsolateRegistryAuth(t)
		registry := buildtest.NewRegistry(t, "auth", nil)
		result, _ := publicationTestResult(t, "x86_64")
		// The raw client error carries the registry-controlled canary; the
		// Lupetto error, record, and stderr must not.
		if raw := registryPushError(t, registry.Host, result, authn.NewMultiKeychain()); raw == nil || !strings.Contains(raw.Error(), buildtest.PublicationCanary) {
			t.Fatalf("fixture does not expose the canary to the client: %v", raw)
		}
		outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
		if err == nil || err.Error() != "publication push failed (HTTP 401; UNAUTHORIZED)" || outcome.PushedDigest != "" || outcome.Verified {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
		result.Publication = outcome
		result.Build, result.DockerLoad, result.Signing, result.Attestation = "completed", "skipped", "skipped", "skipped"
		failure := NewWorkflowFailure(result, "publication", err, true)
		// The CLI prints the failure's Error text; the human report in
		// cmd/lupetto is covered by the CLI publication failure tests.
		data, readErr := os.ReadFile(filepath.Join(result.Workspace, "failure.json"))
		for _, text := range []string{failure.Error(), string(data), string(failure.Record)} {
			if strings.Contains(text, buildtest.PublicationCanary) || strings.Contains(text, buildtest.RegistryPassword) {
				t.Fatalf("unsafe output: %s", text)
			}
		}
		if readErr != nil || !strings.Contains(string(data), "publication push failed (HTTP 401; UNAUTHORIZED)") {
			t.Fatalf("record=%s err=%v", data, readErr)
		}
	})
	t.Run("podman and containers auth files ignored", func(t *testing.T) {
		buildtest.IsolateRegistryAuth(t)
		registry := buildtest.NewRegistry(t, "auth", nil)
		podman := filepath.Join(t.TempDir(), "podman-auth.json")
		buildtest.WriteDockerAuth(t, podman, registry.Host)
		t.Setenv("REGISTRY_AUTH_FILE", podman)
		buildtest.WriteDockerAuth(t, filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "containers", "auth.json"), registry.Host)
		buildtest.WriteDockerAuth(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "containers", "auth.json"), registry.Host)
		tag, err := name.NewTag(registry.Host+"/team/images/fixture:probe", name.StrictValidation)
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
		outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
		if err == nil || err.Error() != "publication push failed (HTTP 401; UNAUTHORIZED)" || outcome.Status != "failed" {
			t.Fatalf("outcome=%+v err=%v", outcome, err)
		}
	})
	t.Run("malformed docker config sanitized", func(t *testing.T) {
		dockerConfig := buildtest.IsolateRegistryAuth(t)
		registry := buildtest.NewRegistry(t, "auth", nil)
		if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), []byte("{"+buildtest.PublicationCanary), 0600); err != nil {
			t.Fatal(err)
		}
		result, _ := publicationTestResult(t, "x86_64")
		outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
		if err == nil || err.Error() != "publication push failed" || outcome.Status != "failed" {
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
		return nil, errors.New("synthetic " + buildtest.PublicationCanary + " transport unavailable")
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
	buildtest.IsolateRegistryAuth(t)
	base := &recordingTransport{}
	result, _ := publicationTestResult(t, "x86_64")
	// ggcr would fall back to HTTP for an RFC 1918 registry.
	outcome, err := publishOCIImage(context.Background(), Services{RegistryTransport: base}, result, PublicationOptions{Registry: "10.0.0.1:5000", Repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (plain HTTP refused for non-loopback registry)" || outcome.Status != "failed" || outcome.PushedDigest != "" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	for _, host := range base.hosts {
		if strings.HasPrefix(host, "http:") {
			t.Fatalf("plain HTTP reached the base transport: %q", base.hosts)
		}
	}
}

func TestPublishOCIImageGuardsTokenRealmRequests(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
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
	outcome, err := publishOCIImage(context.Background(), Services{RegistryTransport: base}, result, PublicationOptions{Registry: host, Repository: "team/images"})
	if err == nil || err.Error() != "publication push failed (plain HTTP refused for non-loopback registry)" || outcome.Status != "failed" {
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
			buildtest.IsolateRegistryAuth(t)
			registry := buildtest.NewRegistryOn(t, address, "", nil)
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
			if err != nil || outcome.Status != "published" || !outcome.Verified || outcome.PushedDigest != digest {
				t.Fatalf("registry=%s outcome=%+v err=%v", registry.Host, outcome, err)
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
			buildtest.IsolateRegistryAuth(t)
			registry := buildtest.NewRegistry(t, "", nil)
			dialer := &net.Dialer{}
			base := &recordingTransport{base: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, registry.Host)
			}}}
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(context.Background(), Services{RegistryTransport: base}, result, PublicationOptions{Registry: authority, Repository: "team/images"})
			if err != nil || outcome.Status != "published" || !outcome.Verified || outcome.PushedDigest != digest || outcome.ImmutableReference != authority+"/team/images/fixture@"+digest {
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
			buildtest.IsolateRegistryAuth(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			registry := buildtest.NewRegistry(t, tc.mutation, cancel)
			result, digest := publicationTestResult(t, "x86_64")
			outcome, err := publishOCIImage(ctx, Services{}, result, PublicationOptions{Registry: registry.Host, Repository: "team/images"})
			if !errors.Is(err, context.Canceled) || outcome.Status != "failed" || outcome.Verified || (outcome.PushedDigest == digest) != tc.captured || (outcome.PushedDigest != "") != tc.captured {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
		})
	}
}

func TestPublishOCIImageRejectsInvalidSourceBeforeNetwork(t *testing.T) {
	buildtest.IsolateRegistryAuth(t)
	base := &recordingTransport{}
	result, digest := publicationTestResult(t, "x86_64")
	if err := os.WriteFile(filepath.Join(result.ImageDir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), []byte(buildtest.PublicationCanary), 0600); err != nil {
		t.Fatal(err)
	}
	outcome, err := publishOCIImage(context.Background(), Services{RegistryTransport: base}, result, PublicationOptions{Registry: "registry.example", Repository: "team/images"})
	if err == nil || err.Error() != "publication source failed" || len(base.hosts) != 0 || outcome.Status != "failed" {
		t.Fatalf("outcome=%+v err=%v calls=%q", outcome, err, base.hosts)
	}
	if outcome, err := publishOCIImage(context.Background(), Services{RegistryTransport: base}, result, PublicationOptions{}); err != nil || outcome.Status != "skipped" || len(base.hosts) != 0 {
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
	digest, diffID := "sha256:"+wolfi.SHA256Hex(compressed), "sha256:"+wolfi.SHA256Hex(layer.Bytes())
	trailing := append(append([]byte(nil), compressed...), []byte("trailing")...)
	for _, tc := range []struct {
		name, digest, diffID string
		data                 []byte
		want                 error
	}{
		{"valid", digest, diffID, compressed, nil},
		{"wrong diffID", digest, "sha256:" + wolfi.SHA256Hex([]byte("other")), compressed, errRegistryContentMismatch},
		{"wrong compressed digest", "sha256:" + wolfi.SHA256Hex([]byte("other")), diffID, compressed, errRegistryContentMismatch},
		{"uncompressed layer", "sha256:" + wolfi.SHA256Hex(layer.Bytes()), diffID, layer.Bytes(), errUnsupportedLayer},
		{"trailing data", "sha256:" + wolfi.SHA256Hex(trailing), diffID, trailing, errRegistryContentMismatch},
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
	canary := errors.New(buildtest.PublicationCanary)
	registryErr := &transport.Error{StatusCode: http.StatusForbidden, Errors: []transport.Diagnostic{
		{Code: "DENIED", Message: buildtest.PublicationCanary}, {Code: transport.ErrorCode(buildtest.PublicationCanary)},
		{Code: "DENIED"}, {Code: "TOOMANYREQUESTS", Detail: buildtest.PublicationCanary}, {Code: "lower_case"}, {Code: transport.ErrorCode(strings.Repeat("A", 33))},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		err  error
		want string
	}{
		{context.Background(), fmt.Errorf("%w: %s", registryErr, buildtest.PublicationCanary), "publication push failed (HTTP 403; DENIED,TOOMANYREQUESTS)"},
		{context.Background(), &transport.Error{StatusCode: 401}, "publication push failed (HTTP 401)"},
		{context.Background(), fmt.Errorf("%s: %w", buildtest.PublicationCanary, errPlainHTTPRefused), "publication push failed (plain HTTP refused for non-loopback registry)"},
		{context.Background(), fmt.Errorf("%s: %w", buildtest.PublicationCanary, x509.UnknownAuthorityError{}), "publication push failed (TLS verification failed)"},
		{context.Background(), &net.OpError{Op: "dial", Net: "tcp", Err: canary}, "publication push failed (registry unreachable)"},
		{context.Background(), &net.DNSError{Name: buildtest.PublicationCanary, Err: buildtest.PublicationCanary}, "publication push failed (registry unreachable)"},
		{context.Background(), canary, "publication push failed"},
		{context.Background(), nil, "publication push failed"},
		{context.Background(), fmt.Errorf("%s: %w", buildtest.PublicationCanary, context.DeadlineExceeded), "publication push canceled: context deadline exceeded"},
		{ctx, canary, "publication push canceled: context canceled"},
	} {
		err := registryStageError(tc.ctx, "publication push", tc.err)
		if err.Error() != tc.want || strings.Contains(err.Error(), buildtest.PublicationCanary) {
			t.Fatalf("err=%q want=%q", err, tc.want)
		}
	}
}
