package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lupetto/internal/verify"
)

func verifyKeyFixture(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	path := filepath.Join(t.TempDir(), "trusted.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyCLI(t *testing.T) {
	key := verifyKeyFixture(t)
	other := verifyKeyFixture(t)
	remote := "registry.example.invalid/team/app@sha256:" + strings.Repeat("a", 64)
	loopback := "127.0.0.1:5000/team/app@sha256:" + strings.Repeat("a", 64)
	sbomOut := filepath.Join(t.TempDir(), "sbom.json")
	env := func(values map[string]string) func(string) (string, bool) {
		return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	}
	expectFingerprint := func(path string) string {
		request, err := verify.NewRequest(remote, path, false, "")
		if err != nil {
			t.Fatal(err)
		}
		return request.PublicKeySHA256()
	}
	for _, tc := range []struct {
		args      []string
		env       map[string]string
		key       string
		allowHTTP bool
		sbomOut   string
	}{
		{args: []string{"--json", "--cosign-public-key", key, remote}, key: key},
		{args: []string{remote, "--cosign-public-key=" + key, "--json"}, key: key},
		// The flag overrides the environment; the environment is used otherwise.
		{args: []string{"--json", "--cosign-public-key", key, remote}, env: map[string]string{"LUPETTO_COSIGN_PUBLIC_KEY": other}, key: key},
		{args: []string{"--json", remote}, env: map[string]string{"LUPETTO_COSIGN_PUBLIC_KEY": other}, key: other},
		{args: []string{"--json", "--cosign-allow-http", "--cosign-public-key", key, "--sbom-out", sbomOut, loopback}, key: key, allowHTTP: true, sbomOut: sbomOut},
		{args: []string{"--json", "--cosign-allow-http=true", "--cosign-public-key", key, loopback}, key: key, allowHTTP: true},
		{args: []string{"--json", "--cosign-allow-http=false", "--cosign-public-key", key, remote}, key: key},
	} {
		var stdout, stderr bytes.Buffer
		called := false
		code := runVerifyWith(context.Background(), tc.args, &stdout, &stderr, env(tc.env), func(_ context.Context, request verify.Request) (verify.Document, error) {
			called = true
			if request.PublicKeySHA256() != expectFingerprint(tc.key) || request.AllowHTTP != tc.allowHTTP || request.SBOMOut != tc.sbomOut {
				t.Fatalf("%v: %+v", tc.args, request)
			}
			return verify.Document{Kind: "verify", Version: 1, Reference: request.Reference.Name(), Signature: verify.Signature{State: "unsigned"}, Attestation: verify.Attestation{State: "absent"}}, nil
		})
		var document verify.Document
		if code != 0 || !called || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &document) != nil || document.Kind != "verify" || !strings.HasSuffix(stdout.String(), "}\n") {
			t.Fatalf("%v: code %d stdout %s stderr %s", tc.args, code, &stdout, &stderr)
		}
	}

	existing := filepath.Join(t.TempDir(), "exists.json")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		env  map[string]string
	}{
		{args: nil},
		{args: []string{"--json"}, env: map[string]string{"LUPETTO_COSIGN_PUBLIC_KEY": key}},
		{args: []string{"--json", remote}},
		{args: []string{"--json", remote}, env: map[string]string{"LUPETTO_COSIGN_PUBLIC_KEY": ""}},
		{args: []string{"--json", "--cosign-public-key=", remote}, env: map[string]string{"LUPETTO_COSIGN_PUBLIC_KEY": key}},
		{args: []string{"--json", "--cosign-public-key", remote}},
		{args: []string{"--json", "--cosign-public-key", key, "--cosign-public-key", key, remote}},
		{args: []string{"--json", "--json", "--cosign-public-key", key, remote}},
		{args: []string{"--json", "--cosign-public-key", key, remote, remote}},
		{args: []string{"--json", "--cosign-public-key", key, "--cosign-allow-http", remote}},
		{args: []string{"--json", "--cosign-public-key", key, loopback}},
		{args: []string{"--json", "--cosign-public-key", key, "--cosign-allow-http=false", loopback}},
		{args: []string{"--json", "--cosign-public-key", key, "--cosign-allow-http=yes", loopback}},
		{args: []string{"--json", "--cosign-public-key", key, "--cosign-allow-http", "--cosign-allow-http", loopback}},
		{args: []string{"--json", "--cosign-public-key", key, "--sbom-out", existing, remote}},
		{args: []string{"--json", "--cosign-public-key", key, "--sbom-out=", remote}},
		{args: []string{"--json", "--cosign-public-key", key, "registry.example.invalid/team/app:latest"}},
		{args: []string{"--json", "--cosign-public-key", key, "team/app@sha256:" + strings.Repeat("a", 64)}},
		{args: []string{"--json", "--cosign-public-key", filepath.Join(t.TempDir(), "missing.pub"), remote}},
		{args: []string{"--json", "--cosign-key", key, remote}},
		{args: []string{"--json", "--cosign-public-key", key, "--registry=x", remote}},
	} {
		var stdout, stderr bytes.Buffer
		if code := runVerifyWith(context.Background(), tc.args, &stdout, &stderr, env(tc.env), func(context.Context, verify.Request) (verify.Document, error) {
			t.Fatalf("%v: called on invalid invocation", tc.args)
			return verify.Document{}, nil
		}); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code %d stdout %s", tc.args, code, &stdout)
		}
	}

	var stdout, stderr bytes.Buffer
	if code := runVerifyWith(context.Background(), []string{"--json", "--cosign-public-key", key, remote}, &stdout, &stderr, env(nil), func(context.Context, verify.Request) (verify.Document, error) {
		return verify.Document{}, errors.New("Cosign v3.1.3 required failed")
	}); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Cosign v3.1.3 required") {
		t.Fatalf("failure code %d stdout %s stderr %s", code, &stdout, &stderr)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runVerifyWith(context.Background(), []string{"--cosign-public-key", key, remote}, &stdout, &stderr, env(nil), func(context.Context, verify.Request) (verify.Document, error) {
		return verify.Document{Reference: remote, TransparencyLog: "verified", Signature: verify.Signature{State: "invalid", Error: "Cosign verify rejected the artifacts (exit 1)", Artifacts: 1}, Attestation: verify.Attestation{State: "attested", Artifacts: 1, SBOM: &verify.SBOM{SHA256: "ab", Packages: 3}}}, nil
	}); code != 0 || !strings.Contains(stdout.String(), "Signature: invalid (1 artifacts): Cosign verify rejected") || !strings.Contains(stdout.String(), "(3 packages)") || strings.Contains(stdout.String(), "WARNING") {
		t.Fatalf("summary code %d stdout %s", code, &stdout)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"verify"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "verify requires") {
		t.Fatalf("dispatch %d %s", code, &stderr)
	}
	stdout.Reset()
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "lupetto verify [--json] [--cosign-public-key <file>]") {
		t.Fatalf("help %d %s", code, &stdout)
	}
}
