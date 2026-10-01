package buildtest

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
)

const PublicationCanary = "secretcanary-never-retain"

// PushDigest is a synthetic digest for tests that do not push.
const PushDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const (
	RegistryUser     = "lupetto-test-user"
	RegistryPassword = "synthetic-password-never-retain"
)

// Registry is go-containerregistry's in-process OCI registry behind a
// loopback httptest server, with optional tampering and authentication. It
// speaks the real distribution protocol; it is not an argument-echo mock.
type Registry struct {
	server   *httptest.Server
	Host     string
	mutation string
	cancel   context.CancelFunc
	auth     bool

	mu           sync.Mutex
	pushed       bool
	configDigest string
	layerDigest  string
	requests     []string
}

func IsolateRegistryAuth(t *testing.T) string {
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

func WriteDockerAuth(t *testing.T, path, host string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(RegistryUser + ":" + RegistryPassword))
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

func NewRegistry(t *testing.T, mutation string, cancel context.CancelFunc) *Registry {
	t.Helper()
	return NewRegistryOn(t, "127.0.0.1:0", mutation, cancel)
}

func NewRegistryOn(t *testing.T, address, mutation string, cancel context.CancelFunc) *Registry {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", address, err)
	}
	r := &Registry{mutation: mutation, cancel: cancel, auth: mutation == "auth"}
	inner := ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0)))
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serve(inner, w, req) }))
	r.server.Listener.Close()
	r.server.Listener = listener
	r.server.Start()
	t.Cleanup(r.server.Close)
	r.Host = strings.TrimPrefix(r.server.URL, "http://")
	return r
}

func (r *Registry) serve(inner http.Handler, w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	pushed, configDigest, layerDigest := r.pushed, r.configDigest, r.layerDigest
	r.mu.Unlock()
	if r.auth {
		user, password, ok := req.BasicAuth()
		if !ok || user != RegistryUser || password != RegistryPassword {
			if req.Method == http.MethodHead {
				// Keep existence probes uninformative so the canary reaches
				// a real, body-bearing client error on upload.
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="lupetto-test"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"errors":[{"code":"UNAUTHORIZED","message":%q},{"code":%q},{"code":"UNAUTHORIZED","detail":%q}]}`, PublicationCanary, PublicationCanary, PublicationCanary)
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
		fmt.Fprintf(w, `{"errors":[{"code":"MANIFEST_INVALID","message":%q},{"code":"lower-%s"}]}`, PublicationCanary, PublicationCanary)
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

func (r *Registry) TamperBlobs(configDigest, layerDigest string) {
	r.mu.Lock()
	r.configDigest, r.layerDigest = configDigest, layerDigest
	r.mu.Unlock()
}
