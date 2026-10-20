package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"lupetto/internal/status"
)

type rawManifest struct {
	data      []byte
	mediaType types.MediaType
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.data, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }

type fixture struct {
	t      *testing.T
	host   string
	repo   name.Repository
	digest string
}

// newFixture pushes one random image to an in-process registry without the
// referrers API, so referrers use the OCI referrers-tag fallback like registry:3.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	server := httptest.NewServer(ggcrregistry.New(ggcrregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")
	repo, err := name.NewRepository(host+"/team/images/app", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	image, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(repo.Tag("v1"), image); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, host: host, repo: repo, digest: digest.String()}
}

func (f *fixture) reference() string { return f.repo.Name() + "@" + f.digest }

func (f *fixture) put(ref name.Reference, data []byte, mediaType types.MediaType) {
	f.t.Helper()
	if err := remote.Put(ref, rawManifest{data: data, mediaType: mediaType}); err != nil {
		f.t.Fatal(err)
	}
}

// bundle stores a Sigstore bundle referrer manifest and returns its index descriptor.
func (f *fixture) bundle(predicateType string, describeAnnotations bool) map[string]any {
	f.t.Helper()
	annotations := map[string]string{"dev.sigstore.bundle.content": "dsse-envelope"}
	if predicateType != "" {
		annotations[predicateAnnotation] = predicateType
	}
	manifest := map[string]any{
		"schemaVersion": 2, "mediaType": string(types.OCIManifestSchema1),
		"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"config":       map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
		"layers":       []any{},
		"subject":      map[string]any{"mediaType": string(types.OCIManifestSchema1), "digest": f.digest, "size": 1},
		"annotations":  annotations,
	}
	data, _ := json.Marshal(manifest)
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	f.put(f.repo.Digest(digest), data, types.OCIManifestSchema1)
	descriptor := map[string]any{"mediaType": string(types.OCIManifestSchema1), "digest": digest, "size": len(data), "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"}
	if describeAnnotations {
		descriptor["annotations"] = annotations
	}
	return descriptor
}

func (f *fixture) referrers(descriptors ...map[string]any) {
	f.t.Helper()
	data, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": string(types.OCIImageIndex), "manifests": descriptors})
	f.put(f.repo.Tag(strings.Replace(f.digest, ":", "-", 1)), data, types.OCIImageIndex)
}

func (f *fixture) legacyTag(suffix string) {
	f.t.Helper()
	data, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": string(types.OCIManifestSchema1),
		"config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2}, "layers": []any{}})
	f.put(f.repo.Tag(strings.Replace(f.digest, ":", "-", 1)+suffix), data, types.OCIManifestSchema1)
}

func writePublicKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return path, hex.EncodeToString(sum[:])
}

type cosignCall struct{ args []string }

type fakeCosign struct {
	calls   []cosignCall
	results map[string]func() ([]byte, int, error)
}

func (f *fakeCosign) run(_ context.Context, args ...string) ([]byte, int, error) {
	f.calls = append(f.calls, cosignCall{args: append([]string(nil), args...)})
	if result := f.results[args[0]]; result != nil {
		return result()
	}
	return nil, 0, errors.New("unexpected Cosign command")
}

func returns(output []byte, exit int, err error) func() ([]byte, int, error) {
	return func() ([]byte, int, error) { return output, exit, err }
}

func signClaims(digests ...string) []byte {
	var claims []map[string]any
	for _, digest := range digests {
		claims = append(claims, map[string]any{"critical": map[string]any{"identity": map[string]any{"docker-reference": "x"}, "image": map[string]any{"docker-manifest-digest": digest}, "type": SignPredicateType}, "optional": map[string]any{}})
	}
	// Cosign v3.1.3 verify --key also returns verified attestation claims.
	claims = append(claims, map[string]any{"critical": map[string]any{"image": map[string]any{"docker-manifest-digest": digests[0]}, "type": SPDXPredicateType}})
	data, _ := json.Marshal(claims)
	return append(data, '\n')
}

const spdxPredicate = `{"SPDXID":"SPDXRef-DOCUMENT","packages":[{"name":"a"},{"name":"b"},{"name":"c"}],"spdxVersion":"SPDX-2.3"}`

func envelope(predicateType, subjectDigest, predicate string) []byte {
	statement := `{"_type":"https://in-toto.io/Statement/v0.1", "subject":[{"name":"x", "digest":{"sha256":"` + strings.TrimPrefix(subjectDigest, "sha256:") + `"}}], "predicateType":"` + predicateType + `", "predicate":` + predicate + `}`
	data, _ := json.Marshal(map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString([]byte(statement)), "signatures": []any{map[string]any{"sig": "x"}}})
	return append(data, '\n')
}

func (f *fixture) run(cosign *fakeCosign, sbomOut string) (Document, error) {
	f.t.Helper()
	key, _ := writePublicKey(f.t)
	request, err := NewRequest(f.reference(), key, Identity{}, true, sbomOut)
	if err != nil {
		f.t.Fatal(err)
	}
	return RunWith(context.Background(), request, Services{Cosign: cosign.run, Preflight: func(context.Context) error { return nil }, Now: func() time.Time { return time.Date(2026, 10, 2, 1, 2, 3, 0, time.FixedZone("x", 3600)) }})
}

func TestUnsignedImageDoesNotInvokeCosign(t *testing.T) {
	f := newFixture(t)
	cosign := &fakeCosign{}
	document, err := f.run(cosign, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cosign.calls) != 0 || document.Signature.State != StateUnsigned || document.Attestation.State != StateAbsent || document.Signature.Artifacts != 0 || document.Attestation.Artifacts != 0 {
		t.Fatalf("%+v calls %v", document, cosign.calls)
	}
	if document.Kind != "verify" || document.Version != 1 || document.Digest != f.digest || document.Reference != f.reference() || document.TransparencyLog != "skipped-local" || document.CheckedAt.Location() != time.UTC || document.CheckedAt.Hour() != 0 {
		t.Fatalf("%+v", document)
	}
	encoded, _ := json.Marshal(document)
	for _, absent := range []string{`"error"`, `"sbom"`, `"predicateType"`} {
		if strings.Contains(string(encoded), absent) {
			t.Fatalf("unexpected %s in %s", absent, encoded)
		}
	}
}

func TestAttestationOnlyIsUnsignedAndWritesSBOM(t *testing.T) {
	f := newFixture(t)
	f.referrers(f.bundle(SPDXPredicateType, true))
	cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){"verify-attestation": returns(envelope(SPDXPredicateType, f.digest, spdxPredicate), 0, nil)}}
	out := filepath.Join(t.TempDir(), "sbom.spdx.json")
	document, err := f.run(cosign, out)
	if err != nil {
		t.Fatal(err)
	}
	if document.Signature.State != StateUnsigned || document.Attestation.State != StateAttested || document.Attestation.Artifacts != 1 || document.Attestation.PredicateType != SPDXPredicateType {
		t.Fatalf("%+v", document)
	}
	if len(cosign.calls) != 1 || strings.Join(cosign.calls[0].args[:1], "") != "verify-attestation" {
		t.Fatalf("calls %v", cosign.calls)
	}
	args := strings.Join(cosign.calls[0].args, " ")
	if !strings.Contains(args, "--type spdxjson --allow-http-registry --insecure-ignore-tlog") || !strings.HasSuffix(args, " "+f.reference()) {
		t.Fatalf("args %s", args)
	}
	data, err := os.ReadFile(out)
	if err != nil || string(data) != spdxPredicate {
		t.Fatalf("sbom %q %v", data, err)
	}
	info, _ := os.Stat(out)
	sum := sha256.Sum256(data)
	if info.Mode().Perm() != 0o600 || document.Attestation.SBOM == nil || document.Attestation.SBOM.SHA256 != hex.EncodeToString(sum[:]) || document.Attestation.SBOM.Packages != 3 || document.Attestation.SBOM.Path != out {
		t.Fatalf("%v %+v", info.Mode(), document.Attestation.SBOM)
	}
	// The staged key file passed to Cosign is removed afterwards.
	if _, err := os.Stat(cosign.calls[0].args[2]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged key retained: %v", err)
	}
}

func TestSignedAndAttested(t *testing.T) {
	f := newFixture(t)
	f.referrers(f.bundle(SignPredicateType, true), f.bundle(SPDXPredicateType, true))
	cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){
		"verify":             returns(signClaims(f.digest), 0, nil),
		"verify-attestation": returns(envelope(SPDXPredicateType, f.digest, spdxPredicate), 0, nil),
	}}
	document, err := f.run(cosign, "")
	if err != nil {
		t.Fatal(err)
	}
	if document.Signature.State != StateSigned || document.Signature.Error != "" || document.Signature.Artifacts != 1 || document.Attestation.State != StateAttested || document.Attestation.SBOM.Path != "" {
		t.Fatalf("%+v", document)
	}
	if got := strings.Join(cosign.calls[0].args, " "); !strings.HasPrefix(got, "verify --key ") || !strings.HasSuffix(got, "--allow-http-registry --insecure-ignore-tlog "+f.reference()) {
		t.Fatalf("args %s", got)
	}
}

func TestInvalidOutcomes(t *testing.T) {
	other := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct {
		name               string
		verify, attest     func() ([]byte, int, error)
		signature, attests string
	}{
		{"cosign rejects", returns(nil, 1, nil), returns(nil, 1, nil), StateInvalid, StateInvalid},
		{"claim for other digest", returns(signClaims(other), 0, nil), returns(envelope(SPDXPredicateType, other, spdxPredicate), 0, nil), StateInvalid, StateInvalid},
		{"only attestation claims", returns([]byte(`[{"critical":{"image":{"docker-manifest-digest":"DIGEST"},"type":"https://spdx.dev/Document"}}]`), 0, nil), returns(envelope("https://slsa.dev/provenance/v1", "DIGEST", `{}`), 0, nil), StateInvalid, StateInvalid},
		{"empty output", returns(nil, 0, nil), returns(nil, 0, nil), StateInvalid, StateInvalid},
		{"non-object SPDX predicate", returns(signClaims("DIGEST"), 0, nil), returns(envelope(SPDXPredicateType, "DIGEST", `"text"`), 0, nil), StateSigned, StateInvalid},
		{"could not run", returns(nil, 0, errors.New("exec: not found")), returns(nil, 0, errors.New("exec: not found")), StateError, StateError},
		{"service unreachable", returns(nil, 1, ErrCosignUnreachable), returns(nil, 1, ErrCosignUnreachable), StateError, StateError},
		{"unparseable output", returns([]byte("not json"), 0, nil), returns([]byte("{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"!!\"}"), 0, nil), StateError, StateError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.referrers(f.bundle(SignPredicateType, true), f.bundle(SPDXPredicateType, true))
			swap := func(result func() ([]byte, int, error)) func() ([]byte, int, error) {
				return func() ([]byte, int, error) {
					output, exit, err := result()
					return []byte(strings.ReplaceAll(string(output), "DIGEST", f.digest)), exit, err
				}
			}
			// Attestation payloads embed the digest base64-encoded, so rebuild them.
			attest := tc.attest
			if tc.name == "only attestation claims" {
				attest = returns(envelope("https://slsa.dev/provenance/v1", f.digest, `{}`), 0, nil)
			}
			if tc.name == "non-object SPDX predicate" {
				attest = returns(envelope(SPDXPredicateType, f.digest, `"text"`), 0, nil)
			}
			cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){"verify": swap(tc.verify), "verify-attestation": attest}}
			out := filepath.Join(t.TempDir(), "sbom.json")
			document, err := f.run(cosign, out)
			if err != nil {
				t.Fatal(err)
			}
			if document.Signature.State != tc.signature || document.Attestation.State != tc.attests {
				t.Fatalf("%+v", document)
			}
			if tc.name == "service unreachable" && (!strings.Contains(document.Signature.Error, "could not reach") || !strings.Contains(document.Attestation.Error, "could not reach")) {
				t.Fatalf("outage not reported as unreachable: %+v", document)
			}
			if document.Attestation.State != StateAttested && (document.Attestation.Error == "" || document.Attestation.SBOM != nil || document.Attestation.PredicateType != "") {
				t.Fatalf("%+v", document.Attestation)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("SBOM written for unverified attestation: %v", err)
			}
		})
	}
}

func TestAttestationSubjectMismatchIsInvalid(t *testing.T) {
	f := newFixture(t)
	f.referrers(f.bundle(SPDXPredicateType, true))
	cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){"verify-attestation": returns(envelope(SPDXPredicateType, "sha256:"+strings.Repeat("c", 64), spdxPredicate), 0, nil)}}
	document, err := f.run(cosign, "")
	if err != nil {
		t.Fatal(err)
	}
	if document.Attestation.State != StateInvalid || !strings.Contains(document.Attestation.Error, "subject") || document.Attestation.SBOM != nil {
		t.Fatalf("%+v", document.Attestation)
	}
}

func TestArtifactClassification(t *testing.T) {
	f := newFixture(t)
	other := f.bundle(SignPredicateType, true)
	other["artifactType"] = "application/vnd.example.unrelated+json"
	// Unannotated descriptors are resolved from the referrer manifest; a bundle
	// without a predicate annotation is a candidate for both sections.
	f.referrers(f.bundle(SignPredicateType, false), f.bundle("", true), f.bundle("https://slsa.dev/provenance/v1", true), other)
	f.legacyTag(".sig")
	f.legacyTag(".att")
	counts, err := listArtifacts(context.Background(), mustDigest(t, f.reference()), status.RemoteRegistry{}.RemoteOptions(context.Background()))
	if err != nil || counts.signatures != 3 || counts.attestations != 2 {
		t.Fatalf("%+v %v", counts, err)
	}
}

func TestListingErrorIsError(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "secret-bearing body")
	}))
	t.Cleanup(server.Close)
	reference := strings.TrimPrefix(server.URL, "http://") + "/team/app@sha256:" + strings.Repeat("a", 64)
	key, _ := writePublicKey(t)
	request, err := NewRequest(reference, key, Identity{}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	cosign := &fakeCosign{}
	document, err := RunWith(context.Background(), request, Services{Cosign: cosign.run, Preflight: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(cosign.calls) != 0 || document.Signature.State != StateError || document.Attestation.State != StateError || document.Signature.Error != "referrer listing failed (HTTP 500)" || strings.Contains(document.Signature.Error, "secret") {
		t.Fatalf("%+v", document)
	}
}

func TestPreflightFailureIsGlobal(t *testing.T) {
	f := newFixture(t)
	key, _ := writePublicKey(t)
	request, err := NewRequest(f.reference(), key, Identity{}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	cosign := &fakeCosign{}
	if _, err := RunWith(context.Background(), request, Services{Cosign: cosign.run, Preflight: func(context.Context) error { return errors.New("Cosign v3.1.3 required failed") }}); err == nil || len(cosign.calls) != 0 {
		t.Fatalf("%v %v", err, cosign.calls)
	}
	if _, err := RunWith(context.Background(), Request{}, Services{Cosign: cosign.run, Preflight: func(context.Context) error { return nil }}); err == nil {
		t.Fatal("unvalidated request accepted")
	}
}

func TestNewRequestValidation(t *testing.T) {
	key, fingerprint := writePublicKey(t)
	digest := "@sha256:" + strings.Repeat("a", 64)
	request, err := NewRequest("registry.example.invalid/team/app"+digest, key, Identity{}, false, "")
	if err != nil || request.PublicKeySHA256() != fingerprint || request.AllowHTTP {
		t.Fatalf("%+v %v", request, err)
	}
	existing := filepath.Join(t.TempDir(), "exists.json")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reference string
		allowHTTP bool
		sbomOut   string
	}{
		{"registry.example.invalid/team/app" + digest, true, ""},
		{"127.0.0.1:5000/team/app" + digest, false, ""},
		{"localhost:5000/team/app" + digest, false, ""},
		{"registry.example.invalid/team/app:latest", false, ""},
		{"team/app" + digest, false, ""},
		{"https://registry.example.invalid/team/app" + digest, false, ""},
		{"user:pass@registry.example.invalid/team/app" + digest, false, ""},
		{"registry.example.invalid/team/app" + digest, false, existing},
		{"registry.example.invalid/team/app" + digest, false, link},
		{"registry.example.invalid/team/app" + digest, false, filepath.Join(t.TempDir(), "missing", "sbom.json")},
	} {
		if _, err := NewRequest(tc.reference, key, Identity{}, tc.allowHTTP, tc.sbomOut); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	if request, err := NewRequest("[::1]:5000/team/app"+digest, key, Identity{}, true, ""); err != nil || !request.AllowHTTP {
		t.Fatalf("loopback IPv6: %v", err)
	}
}

func TestPublicKeyValidation(t *testing.T) {
	dir := t.TempDir()
	valid, _ := writePublicKey(t)
	validPEM, _ := os.ReadFile(valid)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateDER, _ := x509.MarshalECPrivateKey(privateKey)
	for name, content := range map[string][]byte{
		"garbage":    []byte("not a key " + strings.Repeat("x", 10)),
		"private":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}),
		"encrypted":  pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: []byte("x")}),
		"two blocks": append(append([]byte{}, validPEM...), validPEM...),
		"bad der":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}),
		"cert type":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"too large":  append(append([]byte{}, validPEM...), make([]byte, MaxPublicKeyBytes)...),
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadPublicKey(path); err == nil {
			t.Fatalf("%s accepted", name)
		} else if strings.Contains(err.Error(), "MII") || strings.Contains(err.Error(), dir) {
			t.Fatalf("%s leaked content: %v", name, err)
		}
	}
	for _, path := range []string{filepath.Join(dir, "missing"), dir} {
		if _, _, err := loadPublicKey(path); err == nil {
			t.Fatalf("%s accepted", path)
		}
	}
}

func TestLegacySignatureClaimIsSigned(t *testing.T) {
	f := newFixture(t)
	f.legacyTag(".sig")
	claims := strings.ReplaceAll(string(signClaims(f.digest)), SignPredicateType, LegacySignClaimType)
	cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){"verify": returns([]byte(claims), 0, nil)}}
	document, err := f.run(cosign, "")
	if err != nil {
		t.Fatal(err)
	}
	if document.Signature.State != StateSigned || document.Signature.Artifacts != 1 {
		t.Fatalf("%+v", document.Signature)
	}
}

func TestUnreachablePatternSeparatesOutagesFromRejections(t *testing.T) {
	for _, text := range []string{
		`Get "https://registry.example/v2/": dial tcp: lookup registry.example: no such host`,
		`GET https://registry.example/v2/x/manifests/sha256-abc.sig: UNAUTHORIZED: authentication required`,
		`getting Rekor public keys: updating local metadata and targets: error updating to TUF remote mirror`,
		`Post "https://rekor.sigstore.dev/api/v1/log/entries/retrieve": net/http: TLS handshake timeout`,
		`unexpected status code 503 Service Unavailable`,
		`GET https://rekor.sigstore.dev/api/v1/log/entries: 429 Too Many Requests`,
		"Get \"https://harbor.example/v2/\": EOF\nerror during command execution: getting signatures\n",
		`reading response body: unexpected EOF`,
	} {
		if !unreachablePattern.MatchString(text) {
			t.Errorf("outage not recognized: %s", text)
		}
	}
	// Exact final lines of Cosign v3.1.3 rejections observed against Harbor.
	for _, text := range []string{
		`error during command execution: no signatures found`,
		`error during command execution: no matching attestations:`,
		`failed to verify log inclusion: transparency log certificate does not match`,
		`error during command execution: invalid signature when validating ASN.1 encoded signature`,
		`error during command execution: no matching signatures: stuff did not verify`,
	} {
		if unreachablePattern.MatchString(text) {
			t.Errorf("rejection treated as outage: %s", text)
		}
	}
}

func TestCosignEnvironmentDropsRepositoryOverride(t *testing.T) {
	got := cosignEnvironment([]string{"HOME=/h", "COSIGN_REPOSITORY=elsewhere/sigs", "COSIGN_PASSWORD=unused", "PATH=/bin"})
	if strings.Join(got, " ") != "HOME=/h COSIGN_PASSWORD=unused PATH=/bin" {
		t.Fatalf("%v", got)
	}
}

func TestExecuteCosignRejectsOtherCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"sign"}, {"attest"}, {"version"}} {
		if _, _, err := ExecuteCosign(context.Background(), args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func mustDigest(t *testing.T, reference string) name.Digest {
	t.Helper()
	parsed, err := ParseReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestKeylessIdentityTrust(t *testing.T) {
	f := newFixture(t)
	f.referrers(f.bundle(SignPredicateType, true), f.bundle(SPDXPredicateType, true))
	subject, issuer := "https://ci.example.invalid/workflows/release@refs/heads/main", "https://issuer.example.invalid"
	claims, _ := json.Marshal([]map[string]any{{"critical": map[string]any{"image": map[string]any{"docker-manifest-digest": f.digest}, "type": LegacySignClaimType}, "optional": map[string]any{"Subject": subject, "Issuer": issuer}}})
	cosign := &fakeCosign{results: map[string]func() ([]byte, int, error){
		"verify":             returns(claims, 0, nil),
		"verify-attestation": returns(envelope(SPDXPredicateType, f.digest, spdxPredicate), 0, nil),
	}}
	request, err := NewRequest(f.reference(), "", Identity{Regexp: "^https://ci[.]example[.]invalid/", Issuer: issuer}, true, "")
	if err != nil {
		t.Fatal(err)
	}
	document, err := RunWith(context.Background(), request, Services{Cosign: cosign.run, Preflight: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if document.Signature.State != StateSigned || document.Attestation.State != StateAttested || document.Signature.Identity == nil || *document.Signature.Identity != (CertificateIdentity{subject, issuer}) {
		t.Fatalf("%+v", document)
	}
	if document.Trust != (Trust{CertificateIdentityRegexp: "^https://ci[.]example[.]invalid/", CertificateOIDCIssuer: issuer}) {
		t.Fatalf("trust %+v", document.Trust)
	}
	policy := "--certificate-identity-regexp ^https://ci[.]example[.]invalid/ --certificate-oidc-issuer " + issuer
	for _, call := range cosign.calls {
		args := strings.Join(call.args, " ")
		if !strings.Contains(args, policy) || strings.Contains(args, "--key") {
			t.Fatalf("args %s", args)
		}
	}
	if len(cosign.calls) != 2 {
		t.Fatalf("calls %v", cosign.calls)
	}
}

func TestNewRequestTrustSelection(t *testing.T) {
	key, _ := writePublicKey(t)
	reference := "registry.example.invalid/team/app@sha256:" + strings.Repeat("a", 64)
	issuer := "https://issuer.example.invalid"
	for _, tc := range []struct {
		key      string
		identity Identity
	}{
		{"", Identity{}},
		{key, Identity{Exact: "ci", Issuer: issuer}},
		{"", Identity{Exact: "ci"}},
		{"", Identity{Issuer: issuer}},
		{"", Identity{Exact: "ci", Regexp: "ci", Issuer: issuer}},
		{"", Identity{Regexp: "(", Issuer: issuer}},
	} {
		if _, err := NewRequest(reference, tc.key, tc.identity, false, ""); err == nil {
			t.Fatalf("accepted key=%q identity=%+v", tc.key, tc.identity)
		}
	}
	if _, err := NewRequest(reference, "", Identity{Exact: "ci", Issuer: issuer}, false, ""); err != nil {
		t.Fatal(err)
	}
}
