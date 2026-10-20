// Package verify classifies a registry image's Cosign signature and SPDX
// attestation against one explicitly trusted public key or one keyless
// certificate identity policy. It reads only:
// Sigstore artifacts are listed through Lupetto's registry client and verified
// claims are parsed from Cosign v3.1.3 stdout; Cosign diagnostics are discarded.
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"lupetto/internal/registry"
	"lupetto/internal/status"
)

const (
	Kind    = "verify"
	Version = 1

	SignPredicateType = "https://sigstore.dev/cosign/sign/v1"
	// LegacySignClaimType is the simple-signing claim type of signatures in
	// Cosign's older tag-based format (`sha256-<hex>.sig`). Cosign verify only
	// returns image-signature claims in that format, never attestations.
	LegacySignClaimType = "cosign container image signature"
	SPDXPredicateType   = "https://spdx.dev/Document"

	predicateAnnotation = "dev.sigstore.bundle.predicateType"
	inTotoPayloadType   = "application/vnd.in-toto+json"

	// MaxCosignOutputBytes bounds verified Cosign stdout. Attestation envelopes
	// embed the complete SPDX predicate (base64), so the bound is generous.
	MaxCosignOutputBytes = 64 << 20
	// MaxReferrers bounds listed referrer descriptors (and therefore the
	// per-referrer manifest reads needed when a registry omits annotations).
	MaxReferrers = 128
	// MaxPublicKeyBytes bounds the trusted public key file.
	MaxPublicKeyBytes = 64 << 10
)

// Section states.
const (
	StateSigned   = "signed"
	StateUnsigned = "unsigned"
	StateAttested = "attested"
	StateAbsent   = "absent"
	StateInvalid  = "invalid"
	StateError    = "error"
)

var bundleArtifactType = regexp.MustCompile(`^application/vnd\.dev\.sigstore\.bundle(?:\.v0\.[0-9]+)?\+json$`)

type Document struct {
	Kind            string      `json:"kind"`
	Version         int         `json:"version"`
	Reference       string      `json:"reference"`
	Digest          string      `json:"digest"`
	CheckedAt       time.Time   `json:"checkedAt"`
	Trust           Trust       `json:"trust"`
	TransparencyLog string      `json:"transparencyLog"`
	Signature       Signature   `json:"signature"`
	Attestation     Attestation `json:"attestation"`
}

// Trust is either a public-key fingerprint or a keyless identity policy.
type Trust struct {
	PublicKeySHA256           string `json:"publicKeySHA256,omitempty"`
	CertificateIdentity       string `json:"certificateIdentity,omitempty"`
	CertificateIdentityRegexp string `json:"certificateIdentityRegexp,omitempty"`
	CertificateOIDCIssuer     string `json:"certificateOIDCIssuer,omitempty"`
}

type Signature struct {
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Artifacts int    `json:"artifacts"`
	// Identity is the verified certificate subject and issuer of a keyless
	// signature that matched the policy.
	Identity *CertificateIdentity `json:"identity,omitempty"`
}

type CertificateIdentity struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// Identity is a keyless trust policy: the certificate subject, exactly or as
// a Go regexp, and the exact OIDC issuer.
type Identity struct {
	Exact, Regexp, Issuer string
}

type Attestation struct {
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
	Artifacts     int    `json:"artifacts"`
	PredicateType string `json:"predicateType,omitempty"`
	SBOM          *SBOM  `json:"sbom,omitempty"`
}

type SBOM struct {
	SHA256   string `json:"sha256"`
	Packages int    `json:"packages"`
	Path     string `json:"path,omitempty"`
}

// Request is a validated invocation. Construct it with NewRequest.
type Request struct {
	Reference name.Digest
	AllowHTTP bool
	SBOMOut   string
	keyPEM    []byte
	keySHA256 string
	identity  Identity
}

// CosignFunc runs Cosign and returns its bounded stdout and exit code. A
// non-nil error means Cosign could not run to completion (not a verdict).
type CosignFunc func(ctx context.Context, args ...string) ([]byte, int, error)

type Services struct {
	Registry  status.RemoteRegistry
	Cosign    CosignFunc
	Preflight func(context.Context) error
	Now       func() time.Time
}

// ParseReference applies inspect's digest-reference rules.
func ParseReference(reference string) (name.Digest, error) {
	parsed, err := status.ParseInspectReference(reference)
	if err != nil {
		return name.Digest{}, errors.New("verify requires an explicit registry repository@sha256:digest reference (no tags, implicit Docker Hub names, URLs, or credentials)")
	}
	return parsed, nil
}

// NewRequest validates everything that does not need the network: the
// reference, the loopback-only HTTP exception, exactly one trust input (the
// public key or the identity policy), and that the SBOM output path does not
// already exist.
func NewRequest(reference, publicKeyPath string, identity Identity, allowHTTP bool, sbomOut string) (Request, error) {
	ref, err := ParseReference(reference)
	if err != nil {
		return Request{}, err
	}
	loopback := registry.AuthorityIsLoopback(ref.RegistryStr())
	if allowHTTP && !loopback {
		return Request{}, errors.New("--cosign-allow-http is restricted to literal-loopback registries")
	}
	if loopback && !allowHTTP {
		return Request{}, errors.New("verifying a literal-loopback registry reference requires --cosign-allow-http=true")
	}
	request := Request{Reference: ref, AllowHTTP: allowHTTP}
	switch keyless := identity != (Identity{}); {
	case publicKeyPath != "" && keyless:
		return Request{}, errors.New("verify trusts either a public key or a certificate identity, not both")
	case keyless:
		if (identity.Exact == "") == (identity.Regexp == "") {
			return Request{}, errors.New("keyless verify requires exactly one of --certificate-identity or --certificate-identity-regexp")
		}
		if identity.Issuer == "" {
			return Request{}, errors.New("keyless verify requires --certificate-oidc-issuer")
		}
		if _, err := regexp.Compile(identity.Regexp); err != nil {
			return Request{}, errors.New("--certificate-identity-regexp is not a valid Go regular expression")
		}
		request.identity = identity
	case publicKeyPath == "":
		return Request{}, errors.New("verify requires --cosign-public-key / LUPETTO_COSIGN_PUBLIC_KEY, or --certificate-identity[-regexp] with --certificate-oidc-issuer")
	default:
		if request.keyPEM, request.keySHA256, err = loadPublicKey(publicKeyPath); err != nil {
			return Request{}, err
		}
	}
	if sbomOut != "" {
		absolute, err := filepath.Abs(sbomOut)
		if err != nil {
			return Request{}, errors.New("invalid --sbom-out path")
		}
		if _, err := os.Lstat(absolute); err == nil {
			return Request{}, errors.New("--sbom-out must name a new file; the path already exists")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return Request{}, errors.New("--sbom-out path cannot be checked")
		}
		if info, err := os.Stat(filepath.Dir(absolute)); err != nil || !info.IsDir() {
			return Request{}, errors.New("--sbom-out parent directory does not exist")
		}
		request.SBOMOut = absolute
	}
	return request, nil
}

// PublicKeySHA256 is the hex SHA-256 of the key's DER SubjectPublicKeyInfo.
func (r Request) PublicKeySHA256() string { return r.keySHA256 }

func loadPublicKey(path string) ([]byte, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", errors.New("Cosign public key cannot be read")
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, "", errors.New("Cosign public key must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxPublicKeyBytes+1))
	if err != nil {
		return nil, "", errors.New("Cosign public key cannot be read")
	}
	if len(data) > MaxPublicKeyBytes {
		return nil, "", errors.New("Cosign public key file is too large")
	}
	block, rest := pem.Decode(data)
	// Never echo key material or PEM headers in diagnostics.
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errors.New("Cosign public key must be exactly one PEM PUBLIC KEY block")
	}
	if strings.Contains(block.Type, "PRIVATE") {
		return nil, "", errors.New("Cosign public key file contains a private key; supply the public key")
	}
	if block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, "", errors.New("Cosign public key must be exactly one PEM PUBLIC KEY block")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, "", errors.New("Cosign public key is not a valid SubjectPublicKeyInfo")
	}
	sum := sha256.Sum256(block.Bytes)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes}), hex.EncodeToString(sum[:]), nil
}

// Run verifies with the real registry client, Cosign, and version check.
func Run(ctx context.Context, request Request, preflight func(context.Context) error) (Document, error) {
	return RunWith(ctx, request, Services{Cosign: ExecuteCosign, Preflight: preflight})
}

// RunWith returns a document whenever the check completed, including
// unsigned, invalid, and per-section error states. Errors are global failures.
func RunWith(ctx context.Context, request Request, services Services) (Document, error) {
	if (request.keySHA256 == "" || len(request.keyPEM) == 0) && request.identity == (Identity{}) {
		return Document{}, errors.New("verify request was not validated")
	}
	if services.Now == nil {
		services.Now = time.Now
	}
	if services.Preflight == nil || services.Cosign == nil {
		return Document{}, errors.New("Cosign is not configured")
	}
	if err := services.Preflight(ctx); err != nil {
		return Document{}, err
	}
	ref := request.Reference
	document := Document{Kind: Kind, Version: Version, Reference: ref.Name(), Digest: ref.DigestStr(),
		CheckedAt: services.Now().UTC(), TransparencyLog: "verified"}
	var trust []string
	if identity := request.identity; identity != (Identity{}) {
		document.Trust = Trust{CertificateIdentity: identity.Exact, CertificateIdentityRegexp: identity.Regexp, CertificateOIDCIssuer: identity.Issuer}
		if identity.Exact != "" {
			trust = []string{"--certificate-identity", identity.Exact}
		} else {
			trust = []string{"--certificate-identity-regexp", identity.Regexp}
		}
		trust = append(trust, "--certificate-oidc-issuer", identity.Issuer)
	} else {
		// Hand Cosign exactly the validated key bytes that were fingerprinted.
		keyFile, cleanup, err := writeKeyFile(request.keyPEM)
		if err != nil {
			return Document{}, err
		}
		defer cleanup()
		document.Trust.PublicKeySHA256 = request.keySHA256
		trust = []string{"--key", keyFile}
	}
	var local []string
	if request.AllowHTTP {
		document.TransparencyLog = "skipped-local"
		local = []string{"--allow-http-registry", "--insecure-ignore-tlog"}
	}

	found, listErr := listArtifacts(ctx, ref, services.Registry.RemoteOptions(ctx))
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	document.Signature.Artifacts, document.Attestation.Artifacts = found.signatures, found.attestations
	if listErr != nil {
		message := listErr.Error()
		document.Signature = Signature{State: StateError, Error: message}
		document.Attestation = Attestation{State: StateError, Error: message}
		return document, nil
	}

	var predicate []byte
	if found.signatures == 0 {
		document.Signature.State = StateUnsigned
	} else {
		args := append(append([]string{"verify"}, trust...), local...)
		output, exit, err := services.Cosign(ctx, append(args, ref.Name())...)
		document.Signature.State, document.Signature.Error, document.Signature.Identity = classifySignature(ctx, output, exit, err, ref.DigestStr())
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	if found.attestations == 0 {
		document.Attestation.State = StateAbsent
	} else {
		args := append(append(append([]string{"verify-attestation"}, trust...), "--type", "spdxjson"), local...)
		output, exit, err := services.Cosign(ctx, append(args, ref.Name())...)
		var state, message string
		state, message, predicate = classifyAttestation(ctx, output, exit, err, ref.DigestStr())
		document.Attestation.State, document.Attestation.Error = state, message
		if state == StateAttested {
			packages, err := spdxPackageCount(predicate)
			if err != nil {
				document.Attestation.State, document.Attestation.Error, predicate = StateInvalid, err.Error(), nil
			} else {
				sum := sha256.Sum256(predicate)
				document.Attestation.PredicateType = SPDXPredicateType
				document.Attestation.SBOM = &SBOM{SHA256: hex.EncodeToString(sum[:]), Packages: packages}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	if request.SBOMOut != "" && document.Attestation.State == StateAttested {
		if err := writeNewFile(request.SBOMOut, predicate); err != nil {
			return Document{}, err
		}
		document.Attestation.SBOM.Path = request.SBOMOut
	}
	return document, nil
}

func writeKeyFile(keyPEM []byte) (string, func(), error) {
	file, err := os.CreateTemp("", "lupetto-verify-*.pub")
	if err != nil {
		return "", func() {}, errors.New("trusted key staging failed")
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := file.Write(keyPEM); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, errors.New("trusted key staging failed")
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, errors.New("trusted key staging failed")
	}
	return path, cleanup, nil
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("SBOM output could not be created as a new file")
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("SBOM output write failed")
	}
	return nil
}

type artifactCounts struct{ signatures, attestations int }

// listArtifacts finds candidate Sigstore artifacts without Cosign: bundle
// referrers (API or referrers-tag fallback) plus legacy .sig/.att tags.
func listArtifacts(ctx context.Context, ref name.Digest, options []remote.Option) (artifactCounts, error) {
	var counts artifactCounts
	index, err := remote.Referrers(ref, options...)
	if err != nil {
		return artifactCounts{}, registry.SafeError(ctx, "referrer listing", err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return artifactCounts{}, registry.SafeError(ctx, "referrer listing", err)
	}
	if len(manifest.Manifests) > MaxReferrers {
		return artifactCounts{}, fmt.Errorf("referrer listing failed (more than %d referrers)", MaxReferrers)
	}
	for _, descriptor := range manifest.Manifests {
		artifactType, annotations := descriptor.ArtifactType, descriptor.Annotations
		if artifactType != "" && !bundleArtifactType.MatchString(artifactType) {
			continue
		}
		if artifactType == "" || len(annotations) == 0 {
			artifactType, annotations, err = referrerManifest(ctx, ref, descriptor, options)
			if err != nil {
				return artifactCounts{}, err
			}
			if !bundleArtifactType.MatchString(artifactType) {
				continue
			}
		}
		predicateType, present := annotations[predicateAnnotation]
		switch {
		case !present:
			counts.signatures++
			counts.attestations++
		case predicateType == SignPredicateType:
			counts.signatures++
		case predicateType == SPDXPredicateType:
			counts.attestations++
		}
	}
	hexDigest := strings.TrimPrefix(ref.DigestStr(), "sha256:")
	for _, suffix := range []string{".sig", ".att"} {
		exists, err := tagExists(ctx, ref.Context().Tag("sha256-"+hexDigest+suffix), options)
		if err != nil {
			return artifactCounts{}, err
		}
		if exists && suffix == ".sig" {
			counts.signatures++
		} else if exists {
			counts.attestations++
		}
	}
	return counts, nil
}

func referrerManifest(ctx context.Context, ref name.Digest, descriptor v1.Descriptor, options []remote.Option) (string, map[string]string, error) {
	fetched, err := remote.Get(ref.Context().Digest(descriptor.Digest.String()), options...)
	if err != nil {
		return "", nil, registry.SafeError(ctx, "referrer manifest read", err)
	}
	var manifest struct {
		ArtifactType string `json:"artifactType"`
		Config       struct {
			MediaType string `json:"mediaType"`
		} `json:"config"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(fetched.Manifest, &manifest); err != nil {
		return "", nil, errors.New("referrer manifest read failed (invalid manifest)")
	}
	artifactType := manifest.ArtifactType
	if artifactType == "" {
		artifactType = manifest.Config.MediaType
	}
	return artifactType, manifest.Annotations, nil
}

func tagExists(ctx context.Context, tag name.Tag, options []remote.Option) (bool, error) {
	_, err := remote.Head(tag, options...)
	if err == nil {
		return true, nil
	}
	var failure *transport.Error
	if errors.As(err, &failure) && failure.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, registry.SafeError(ctx, "legacy Sigstore tag check", err)
}

// cosignOutcome maps a Cosign run that did not yield usable stdout. ok is
// true only when Cosign exited 0 and its stdout should be parsed.
func cosignOutcome(ctx context.Context, command string, exit int, err error) (state, message string, ok bool) {
	if err != nil || ctx.Err() != nil {
		if cause := registry.StageCancellation(ctx, err); cause != nil {
			return StateError, "Cosign " + command + " canceled", false
		}
		if errors.Is(err, ErrCosignUnreachable) {
			return StateError, "Cosign " + command + " could not reach the registry, transparency log, or trust root", false
		}
		return StateError, "Cosign " + command + " could not run", false
	}
	if exit != 0 {
		return StateInvalid, fmt.Sprintf("Cosign %s rejected the artifacts (exit %d)", command, exit), false
	}
	return "", "", true
}

func classifySignature(ctx context.Context, output []byte, exit int, err error, digest string) (string, string, *CertificateIdentity) {
	if state, message, ok := cosignOutcome(ctx, "verify", exit, err); !ok {
		return state, message, nil
	}
	type claim struct {
		Critical struct {
			Type  string `json:"type"`
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
		// Cosign adds the verified certificate's subject and issuer for
		// keyless signatures; key signatures have none.
		Optional struct {
			Subject string `json:"Subject"`
			Issuer  string `json:"Issuer"`
		} `json:"optional"`
	}
	var identity *CertificateIdentity
	decoder := json.NewDecoder(bytes.NewReader(output))
	matched, signClaims := false, 0
	for {
		var claims []claim
		if err := decoder.Decode(&claims); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return StateError, "Cosign verify output could not be parsed", nil
		}
		for _, c := range claims {
			if c.Critical.Type != SignPredicateType && c.Critical.Type != LegacySignClaimType {
				continue
			}
			signClaims++
			if c.Critical.Image.Digest == digest {
				matched = true
				if identity == nil && c.Optional.Subject != "" {
					identity = &CertificateIdentity{Subject: c.Optional.Subject, Issuer: c.Optional.Issuer}
				}
			}
		}
	}
	switch {
	case matched:
		return StateSigned, "", identity
	case signClaims != 0:
		return StateInvalid, "verified signature claims name a different digest", nil
	default:
		return StateInvalid, "no verified " + SignPredicateType + " claim for this digest", nil
	}
}

func classifyAttestation(ctx context.Context, output []byte, exit int, err error, digest string) (string, string, []byte) {
	if state, message, ok := cosignOutcome(ctx, "verify-attestation", exit, err); !ok {
		return state, message, nil
	}
	type envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	type statement struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate json.RawMessage `json:"predicate"`
	}
	wantHex := strings.TrimPrefix(digest, "sha256:")
	decoder := json.NewDecoder(bytes.NewReader(output))
	spdxStatements := 0
	for {
		var current envelope
		if err := decoder.Decode(&current); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return StateError, "Cosign verify-attestation output could not be parsed", nil
		}
		if current.PayloadType != inTotoPayloadType {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(current.Payload)
		if err != nil {
			return StateError, "Cosign verify-attestation payload could not be decoded", nil
		}
		var parsed statement
		if err := json.Unmarshal(payload, &parsed); err != nil {
			return StateError, "Cosign verify-attestation statement could not be parsed", nil
		}
		if parsed.PredicateType != SPDXPredicateType {
			continue
		}
		spdxStatements++
		for _, subject := range parsed.Subject {
			if subject.Digest["sha256"] == wantHex && len(parsed.Predicate) != 0 {
				// Keep the exact predicate bytes from the verified payload.
				return StateAttested, "", append([]byte(nil), parsed.Predicate...)
			}
		}
	}
	if spdxStatements != 0 {
		return StateInvalid, "verified SPDX attestation subject does not match this digest", nil
	}
	return StateInvalid, "no verified SPDX attestation for this digest", nil
}

func spdxPackageCount(predicate []byte) (int, error) {
	var document struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if !bytes.HasPrefix(bytes.TrimSpace(predicate), []byte("{")) || json.Unmarshal(predicate, &document) != nil {
		return 0, errors.New("verified SPDX predicate is not a JSON document")
	}
	return len(document.Packages), nil
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	if !w.overflow {
		if len(data) > MaxCosignOutputBytes-len(w.data) {
			w.data, w.overflow = nil, true
		} else {
			w.data = append(w.data, data...)
		}
	}
	return len(data), nil
}

// ErrCosignUnreachable reports a Cosign failure caused by network, registry
// access, or trust-root retrieval rather than by the artifacts themselves, so a
// service outage is an error state instead of an "invalid" verdict.
var ErrCosignUnreachable = errors.New("Cosign could not reach a required service")

// unreachablePattern matches Go network/TLS, HTTP 5xx/429, truncated
// connections, registry authorization, and TUF trust-root failure text in
// Cosign stderr.
var unreachablePattern = regexp.MustCompile(`(?im)dial tcp|no such host|connection refused|connection reset|i/o timeout|tls handshake|x509: |deadline exceeded|server misbehaving|network is unreachable|unexpected status code 5\d\d|status code: 5\d\d|\b(?:500|502|503|504) (?:internal server error|bad gateway|service unavailable|gateway timeout)|\b429\b|too many requests|unexpected EOF|\bEOF$|unauthorized|authentication required|denied: |\btuf\b|trusted root|updating local metadata`)

// stderrScan keeps a bounded prefix of Cosign stderr only for classification.
// It is never printed, retained, or attached to errors.
type stderrScan struct{ data []byte }

func (w *stderrScan) Write(data []byte) (int, error) {
	const limit = 256 << 10
	if room := limit - len(w.data); room > 0 {
		if len(data) > room {
			w.data = append(w.data, data[:room]...)
		} else {
			w.data = append(w.data, data...)
		}
	}
	return len(data), nil
}

// cosignEnvironment drops COSIGN_REPOSITORY: Lupetto lists artifacts in the
// image's own repository, so Cosign must verify the same artifacts.
func cosignEnvironment(environment []string) []string {
	kept := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "COSIGN_REPOSITORY=") {
			kept = append(kept, entry)
		}
	}
	return kept
}

// ExecuteCosign runs only Cosign verify/verify-attestation. Stdout is kept up
// to MaxCosignOutputBytes. Stderr can echo registry or credential details: it
// is only matched against unreachablePattern on failure, never printed,
// retained, or attached to errors.
func ExecuteCosign(ctx context.Context, args ...string) ([]byte, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if len(args) == 0 || (args[0] != "verify" && args[0] != "verify-attestation") {
		return nil, 0, errors.New("unsupported Cosign command")
	}
	command := exec.CommandContext(ctx, "cosign", args...)
	output, diagnostics := &boundedOutput{}, &stderrScan{}
	command.Stdout, command.Stderr = output, diagnostics
	command.Env = cosignEnvironment(os.Environ())
	err := command.Run()
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	if output.overflow {
		return nil, 0, errors.New("Cosign output exceeded limit")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code > 0 {
			if unreachablePattern.Match(diagnostics.data) {
				return nil, code, ErrCosignUnreachable
			}
			return nil, code, nil
		}
		return nil, 0, errors.New("Cosign terminated abnormally")
	}
	if err != nil {
		return nil, 0, errors.New("Cosign could not run")
	}
	return output.data, 0, nil
}
