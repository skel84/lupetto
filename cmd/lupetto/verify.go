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

const verifyUsage = "\n\nRead-only signature and SPDX attestation status:\n  lupetto verify [--json] [--cosign-public-key <file>] [--cosign-allow-http[=true|false]] [--sbom-out <file>] <registry-repository@sha256:digest>\nVerify trusts exactly one PEM public key from --cosign-public-key or LUPETTO_COSIGN_PUBLIC_KEY (the flag overrides the environment) and requires Cosign v3.1.3.\nIt accepts only explicit digest references, lists Sigstore referrers and legacy .sig/.att tags with Docker credentials and the loopback-only HTTP guard, then runs cosign verify / verify-attestation --type spdxjson.\nSignature: signed, unsigned, invalid, or error; attestation: attested, absent, invalid, or error. Cosign diagnostics are discarded.\n--cosign-allow-http is required for, and restricted to, literal-loopback registries; it adds --allow-http-registry --insecure-ignore-tlog and reports transparencyLog skipped-local.\n--sbom-out writes the verified SPDX predicate to a new mode-0600 file only when the attestation is attested.\nVerify --json prints kind=verify, version=1. Exit 0 means the check completed (inspect the states); invocation errors exit 2, global failures exit 1, both without JSON."

type verifyRequest struct {
	reference string
	json      bool
	publicKey optionalValue
	sbomOut   optionalValue
	allowHTTP optionalValue
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
		case "--cosign-public-key", "--sbom-out":
			target := &request.publicKey
			if flag == "--sbom-out" {
				target = &request.sbomOut
			}
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
				return verifyRequest{}, fmt.Errorf("verify accepts only --json, --cosign-public-key, --cosign-allow-http, and --sbom-out")
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
		key := parsed.publicKey.value
		if !parsed.publicKey.set && lookupEnv != nil {
			key, _ = lookupEnv("LUPETTO_COSIGN_PUBLIC_KEY")
		}
		request, err = verify.NewRequest(parsed.reference, key, parsed.allowHTTP.value == "true", parsed.sbomOut.value)
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
	if _, err := fmt.Fprintf(out, "Reference: %s\nTrusted key SHA-256: %s\nTransparency log: %s\nSignature: %s\nSPDX attestation: %s\n", document.Reference, document.Trust.PublicKeySHA256, document.TransparencyLog, section(document.Signature.State, document.Signature.Error, document.Signature.Artifacts), section(attestation.State, attestation.Error, attestation.Artifacts)); err != nil {
		return err
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
