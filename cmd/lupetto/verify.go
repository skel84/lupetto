package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"lupetto/internal/build"
	"lupetto/internal/verify"
)

const verifyUsage = "\n\nRead-only signature and SPDX attestation status:\n  lupetto verify [--json] [--cosign-public-key <file>] [(--certificate-identity <san> | --certificate-identity-regexp <re>) --certificate-oidc-issuer <url>] [--cosign-allow-http[=true|false]] [--sbom-out <file>] <registry-repository@sha256:digest>\nVerify trusts exactly one PEM public key from --cosign-public-key or LUPETTO_COSIGN_PUBLIC_KEY (the flag overrides the environment) and requires Cosign v3.1.3.\nKeyless: it instead trusts one certificate identity, --certificate-identity or --certificate-identity-regexp (Go syntax) with --certificate-oidc-issuer,\nor LUPETTO_COSIGN_CERTIFICATE_IDENTITY[_REGEXP] / LUPETTO_COSIGN_CERTIFICATE_OIDC_ISSUER; a key and an identity together are rejected.\nIt accepts only explicit digest references, lists Sigstore referrers and legacy .sig/.att tags with Docker credentials and the loopback-only HTTP guard, then runs cosign verify / verify-attestation --type spdxjson.\nSignature: signed, unsigned, invalid, or error; attestation: attested, absent, invalid, or error. Cosign diagnostics are discarded.\n--cosign-allow-http is required for, and restricted to, literal-loopback registries; it adds --allow-http-registry --insecure-ignore-tlog and reports transparencyLog skipped-local.\n--sbom-out writes the verified SPDX predicate to a new mode-0600 file only when the attestation is attested.\nVerify --json prints kind=verify, version=1. Exit 0 means the check completed (inspect the states); invocation errors exit 2, global failures exit 1, both without JSON."

type verifyRequest struct {
	reference      string
	json           bool
	publicKey      optionalValue
	identity       optionalValue
	identityRegexp optionalValue
	issuer         optionalValue
	sbomOut        optionalValue
	allowHTTP      optionalValue
}

type optionalValue struct {
	value string
	set   bool
}

func parseVerify(args []string) (verifyRequest, error) {
	var request verifyRequest
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" {
			if request.json {
				return verifyRequest{}, fmt.Errorf("--json may be specified only once")
			}
			request.json = true
			continue
		}
		flag, value, inline := strings.Cut(arg, "=")
		switch flag {
		case "--cosign-public-key", "--certificate-identity", "--certificate-identity-regexp", "--certificate-oidc-issuer", "--sbom-out":
			target := map[string]*optionalValue{"--cosign-public-key": &request.publicKey, "--certificate-identity": &request.identity,
				"--certificate-identity-regexp": &request.identityRegexp, "--certificate-oidc-issuer": &request.issuer, "--sbom-out": &request.sbomOut}[flag]
			if target.set {
				return verifyRequest{}, fmt.Errorf("%s may be specified only once", flag)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return verifyRequest{}, fmt.Errorf("%s requires a value", flag)
				}
				value = args[i]
			}
			if value == "" {
				return verifyRequest{}, fmt.Errorf("%s must not be empty", flag)
			}
			*target = optionalValue{value: value, set: true}
		case "--cosign-allow-http":
			if request.allowHTTP.set {
				return verifyRequest{}, fmt.Errorf("--cosign-allow-http may be specified only once")
			}
			if !inline {
				value = "true"
			}
			if value != "true" && value != "false" {
				return verifyRequest{}, fmt.Errorf("--cosign-allow-http must be true or false")
			}
			request.allowHTTP = optionalValue{value: value, set: true}
		default:
			if strings.HasPrefix(arg, "-") {
				return verifyRequest{}, fmt.Errorf("verify accepts only --json, --cosign-public-key, --certificate-identity, --certificate-identity-regexp, --certificate-oidc-issuer, --cosign-allow-http, and --sbom-out")
			}
			if request.reference != "" {
				return verifyRequest{}, fmt.Errorf("verify requires exactly one digest reference")
			}
			request.reference = arg
		}
	}
	if request.reference == "" {
		return verifyRequest{}, fmt.Errorf("verify requires one registry digest reference")
	}
	return request, nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runVerifyWith(ctx, args, stdout, stderr, os.LookupEnv, func(ctx context.Context, request verify.Request) (verify.Document, error) {
		return verify.Run(ctx, request, build.CosignPreflight)
	})
}

func runVerifyWith(ctx context.Context, args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool), check func(context.Context, verify.Request) (verify.Document, error)) int {
	parsed, err := parseVerify(args)
	var request verify.Request
	if err == nil {
		// Each flag independently overrides its environment input.
		effective := func(flag optionalValue, name string) string {
			if !flag.set && lookupEnv != nil {
				flag.value, _ = lookupEnv(name)
			}
			return flag.value
		}
		identity := verify.Identity{
			Exact:  effective(parsed.identity, "LUPETTO_COSIGN_CERTIFICATE_IDENTITY"),
			Regexp: effective(parsed.identityRegexp, "LUPETTO_COSIGN_CERTIFICATE_IDENTITY_REGEXP"),
			Issuer: effective(parsed.issuer, "LUPETTO_COSIGN_CERTIFICATE_OIDC_ISSUER"),
		}
		request, err = verify.NewRequest(parsed.reference, effective(parsed.publicKey, "LUPETTO_COSIGN_PUBLIC_KEY"), identity, parsed.allowHTTP.value == "true", parsed.sbomOut.value)
	}
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(err.Error()))
		return 2
	}
	document, err := check(ctx, request)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(err.Error()))
		return 1
	}
	if parsed.json {
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "lupetto: could not write verify JSON")
			return 1
		}
		if !writeJSONRecord(stdout, stderr, append(encoded, '\n')) {
			return 1
		}
		return 0
	}
	if err := writeVerifySummary(stdout, document); err != nil {
		fmt.Fprintln(stderr, "lupetto: could not write verify summary")
		return 1
	}
	return 0
}

func writeVerifySummary(out io.Writer, document verify.Document) error {
	section := func(state, message string, artifacts int) string {
		text := fmt.Sprintf("%s (%d artifacts)", state, artifacts)
		if message != "" {
			text += ": " + build.PlainText(message)
		}
		return text
	}
	attestation := document.Attestation
	trust := "Trusted key SHA-256: " + document.Trust.PublicKeySHA256
	if document.Trust.PublicKeySHA256 == "" {
		subject := document.Trust.CertificateIdentity
		if subject == "" {
			subject = "regexp " + document.Trust.CertificateIdentityRegexp
		}
		trust = fmt.Sprintf("Trusted identity: %s (issuer %s)", build.PlainText(subject), build.PlainText(document.Trust.CertificateOIDCIssuer))
	}
	if _, err := fmt.Fprintf(out, "Reference: %s\n%s\nTransparency log: %s\nSignature: %s\nSPDX attestation: %s\n", document.Reference, trust, document.TransparencyLog, section(document.Signature.State, document.Signature.Error, document.Signature.Artifacts), section(attestation.State, attestation.Error, attestation.Artifacts)); err != nil {
		return err
	}
	if identity := document.Signature.Identity; identity != nil {
		if _, err := fmt.Fprintf(out, "Signer: %s (issuer %s)\n", build.PlainText(identity.Subject), build.PlainText(identity.Issuer)); err != nil {
			return err
		}
	}
	if attestation.SBOM != nil {
		if _, err := fmt.Fprintf(out, "Verified SPDX: sha256:%s (%d packages)\n", attestation.SBOM.SHA256, attestation.SBOM.Packages); err != nil {
			return err
		}
		if attestation.SBOM.Path != "" {
			if _, err := fmt.Fprintf(out, "SBOM written: %s\n", build.PlainText(attestation.SBOM.Path)); err != nil {
				return err
			}
		}
	}
	if document.TransparencyLog == "skipped-local" {
		_, err := fmt.Fprintln(out, "WARNING: local HTTP verification without transparency-log evidence; not production evidence.")
		return err
	}
	return nil
}
