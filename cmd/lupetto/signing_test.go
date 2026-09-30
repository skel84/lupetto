package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const signingCanary = "synthetic-cosign-secret-never-retain"

func fakeSigningCosign(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cosign"), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("COSIGN_PASSWORD", signingCanary)
}

func TestExecuteSigningCommandPasswordInheritedAndAllDiagnosticsDiscarded(t *testing.T) {
	for _, stage := range []string{"sign", "attest", "version"} {
		t.Run(stage, func(t *testing.T) {
			body := "test \"$COSIGN_PASSWORD\" = '" + signingCanary + "' || exit 9\n" +
				"for arg in \"$@\"; do test \"$arg\" != \"$COSIGN_PASSWORD\" || exit 8; done\n" +
				"printf '%s\\n' \"$COSIGN_PASSWORD\" >&2\n"
			args := []string{stage, "--yes", "--key", "/synthetic/private-input", "registry.example.invalid/team/image@" + fixturePushDigest}
			if stage == "version" {
				args = []string{"version", "--json"}
				body += "printf '{\"gitVersion\":\"v3.1.3\",\"other\":\"%s\"}\\n' \"$COSIGN_PASSWORD\""
			} else {
				body += "printf '%s\\n' \"$COSIGN_PASSWORD\" \"$@\""
			}
			fakeSigningCosign(t, body)
			var diagnostics bytes.Buffer
			progress := newBuildProgress(context.Background(), &diagnostics, false)
			ctx := context.WithValue(context.Background(), buildProgressKey{}, progress)
			output, err := executeSigningCommand(ctx, "cosign", args...)
			progress.Close()
			if err != nil || diagnostics.Len() != 0 || bytes.Contains(output, []byte(signingCanary)) {
				t.Fatalf("output=%q err=%v diagnostics=%q", output, err, diagnostics.String())
			}
			if stage == "version" && string(output) != cosignSigningVersion || stage != "version" && len(output) != 0 {
				t.Fatalf("retained output=%q", output)
			}
		})
	}
}

func TestExecuteSigningCommandFailuresAndVersionParsingAreSecretSafe(t *testing.T) {
	for _, failure := range []string{"sign exit", "attest exit", "version exit", "version malformed", "version missing", "version oversized", "version secret", "version suffix", "cancel sign", "cancel attest", "cancel version"} {
		t.Run(failure, func(t *testing.T) {
			args := []string{"version", "--json"}
			body := "printf '%s\\n' \"$COSIGN_PASSWORD\" >&2\n"
			switch failure {
			case "sign exit", "attest exit":
				args = []string{strings.Fields(failure)[0], "--yes", "--key", "/synthetic/private-input", "registry.example.invalid/team/image@" + fixturePushDigest}
				body += "printf '%s\\n' \"$COSIGN_PASSWORD\" \"$@\"; exit 7"
			case "version exit":
				body += "printf '%s\\n' '{\"gitVersion\":\"v3.1.3\"}'; exit 7"
			case "version malformed":
				body += "printf '%s\\n' \"$COSIGN_PASSWORD\""
			case "version missing":
				body += "printf '{\"other\":\"%s\"}\\n' \"$COSIGN_PASSWORD\""
			case "version oversized":
				body += "printf '%5000s' x"
			case "version secret":
				body += "printf '{\"gitVersion\":\"%s\"}\\n' \"$COSIGN_PASSWORD\""
			case "version suffix":
				body += "printf '%s\\n' '{\"gitVersion\":\"v3.1.3-custom\"}'"
			case "cancel sign", "cancel attest", "cancel version":
				args = []string{strings.Fields(failure)[1], "--yes", "--key", "/synthetic/private-input", "registry.example.invalid/team/image@" + fixturePushDigest}
				if failure == "cancel version" {
					args = []string{"version", "--json"}
				}
				body += "exec sleep 30"
			}
			fakeSigningCosign(t, body)
			ctx := context.Background()
			if strings.HasPrefix(failure, "cancel") {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			}
			output, err := executeSigningCommand(ctx, "cosign", args...)
			if err == nil || len(output) != 0 || strings.Contains(err.Error(), signingCanary) || strings.Contains(err.Error(), "/synthetic/private-input") {
				t.Fatalf("output=%q err=%v", output, err)
			}
			if strings.HasPrefix(failure, "cancel") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation=%v", err)
			}
		})
	}
}

func TestRequireCosignExactVersionAndSafeErrors(t *testing.T) {
	for _, version := range []string{cosignSigningVersion, "v3.1.2", "v3.1.4", "3.1.3", "v3.1.3-custom", signingCanary, `{"gitVersion":"v3.1.3"}`, ""} {
		t.Run(version, func(t *testing.T) {
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				if executable != "cosign" || !reflect.DeepEqual(args, []string{"version", "--json"}) {
					t.Fatalf("unexpected preflight: %s %q", executable, args)
				}
				return []byte(version), nil
			}
			err := requireCosignVersion(context.Background(), command)
			if (err == nil) != (version == cosignSigningVersion) || err != nil && strings.Contains(err.Error(), signingCanary) {
				t.Fatalf("version=%q err=%v", version, err)
			}
		})
	}
	for _, mode := range []string{"error", "cancel", "cancel after response", "nil command"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := localCommand(func(context.Context, string, ...string) ([]byte, error) {
				if mode == "cancel" {
					t.Fatal("called version after cancellation")
				}
				if mode == "cancel after response" {
					cancel()
					return []byte(cosignSigningVersion), nil
				}
				return []byte(signingCanary), errors.New(signingCanary)
			})
			if mode == "cancel" {
				cancel()
			}
			if mode == "nil command" {
				command = nil
			}
			err := requireCosignVersion(ctx, command)
			if err == nil || strings.Contains(err.Error(), signingCanary) {
				t.Fatalf("error=%v", err)
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}

func signingTestResult(t *testing.T) buildResult {
	t.Helper()
	predicate := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`)
	filename := filepath.Join(t.TempDir(), "sbom-x86_64.spdx.json")
	if err := os.WriteFile(filename, predicate, 0600); err != nil {
		t.Fatal(err)
	}
	return buildResult{spdxPath: filename, spdxSHA256: sha256Hex(predicate), dockerImageID: "sha256:" + strings.Repeat("b", 64),
		publication: publicationOutcome{status: "published", verified: true, reference: "registry.example.invalid/team/image:unique",
			pushedDigest: fixturePushDigest, immutableReference: "registry.example.invalid/team/image@" + fixturePushDigest}}
}

func TestSignAndAttestSameCanonicalDigestExistingSPDXAndDefaultFlags(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "key config HTTP"}[configured], func(t *testing.T) {
			result := signingTestResult(t)
			opts := signingOptions{key: "/synthetic/key"}
			common := []string{"--yes", "--key", opts.key}
			if configured {
				opts.config, opts.allowHTTP = "/synthetic/config", true
				result.publication.reference = "localhost:5000/team/image:unique"
				result.publication.immutableReference = "localhost:5000/team/image@" + fixturePushDigest
				common = append(common, "--signing-config", opts.config, "--allow-http-registry")
			}
			before, err := os.ReadFile(result.spdxPath)
			if err != nil {
				t.Fatal(err)
			}
			var calls [][]string
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				if executable != "cosign" {
					t.Fatalf("unexpected executable %q", executable)
				}
				calls = append(calls, append([]string(nil), args...))
				return []byte(signingCanary), nil
			}
			outcome, err := signAndAttestDigest(context.Background(), command, result, opts)
			if err != nil || outcome.signing != "signed" || outcome.attestation != "attested" {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
			sign := append([]string{"sign"}, common...)
			sign = append(sign, result.publication.immutableReference)
			attest := append([]string{"attest"}, common...)
			attest = append(attest, "--type", "spdxjson", "--predicate", result.spdxPath, result.publication.immutableReference)
			if !reflect.DeepEqual(calls, [][]string{sign, attest}) {
				t.Fatalf("calls=%q want=%q", calls, [][]string{sign, attest})
			}
			after, err := os.ReadFile(result.spdxPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("SPDX regenerated: %v", err)
			}
		})
	}
}

func TestSigningRejectsUnverifiedMutableOrMismatchedDigest(t *testing.T) {
	for _, mutation := range []string{"unpublished", "unverified", "digest", "reference digest", "repository", "tag", "tagged digest", "algorithm", "missing target", "target digest", "missing registry"} {
		t.Run(mutation, func(t *testing.T) {
			result := signingTestResult(t)
			switch mutation {
			case "unpublished":
				result.publication.status = "failed"
			case "unverified":
				result.publication.verified = false
			case "digest":
				result.publication.pushedDigest = result.dockerImageID
			case "reference digest":
				result.publication.immutableReference = "registry.example.invalid/team/image@" + result.dockerImageID
			case "repository":
				result.publication.immutableReference = "registry.example.invalid/other/image@" + fixturePushDigest
			case "tag":
				result.publication.immutableReference = result.publication.reference
			case "tagged digest":
				result.publication.immutableReference = result.publication.reference + "@" + fixturePushDigest
			case "algorithm":
				result.publication.pushedDigest = "sha512:" + strings.Repeat("a", 128)
			case "missing target":
				result.publication.reference = ""
			case "target digest":
				result.publication.reference += "@" + fixturePushDigest
			case "missing registry":
				result.publication.reference = "team/image:unique"
				result.publication.immutableReference = "team/image@" + fixturePushDigest
			}
			outcome, err := signAndAttestDigest(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign called with invalid publication identity")
				return nil, nil
			}, result, signingOptions{key: "/synthetic/key"})
			if err == nil || outcome.signing != "failed" || outcome.attestation != "not-attempted" {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
		})
	}
}

func TestSigningHTTPPolicyRejectedBeforeCosign(t *testing.T) {
	for _, mode := range []string{"nonloopback HTTP", "loopback without consent"} {
		t.Run(mode, func(t *testing.T) {
			result := signingTestResult(t)
			opts := signingOptions{key: "/synthetic/key", allowHTTP: true}
			if mode == "loopback without consent" {
				opts.allowHTTP = false
				result.publication.reference = "localhost:5000/team/image:unique"
				result.publication.immutableReference = "localhost:5000/team/image@" + fixturePushDigest
			}
			outcome, err := signAndAttestDigest(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign called before HTTP policy validation")
				return nil, nil
			}, result, opts)
			if err == nil || outcome.signing != "failed" || outcome.attestation != "not-attempted" {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
		})
	}
}

func TestSigningStageFailuresChecksumAndCancellationPreserveOutcomes(t *testing.T) {
	for _, failure := range []string{"sign", "attest", "checksum", "read", "cancel before sign", "cancel sign", "cancel before attest", "cancel attest"} {
		t.Run(failure, func(t *testing.T) {
			result := signingTestResult(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "cancel before sign" {
				cancel()
			}
			signs, attests := 0, 0
			command := func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				switch args[0] {
				case "sign":
					signs++
					switch failure {
					case "sign":
						return []byte(signingCanary), errors.New(signingCanary)
					case "checksum":
						if err := os.WriteFile(result.spdxPath, []byte(signingCanary), 0600); err != nil {
							t.Fatal(err)
						}
					case "read":
						if err := os.Remove(result.spdxPath); err != nil {
							t.Fatal(err)
						}
					case "cancel sign":
						cancel()
					}
				case "attest":
					attests++
					if failure == "attest" {
						return []byte(signingCanary), errors.New(signingCanary)
					}
					if failure == "cancel attest" {
						cancel()
					}
				default:
					t.Fatalf("unexpected command %q", args)
				}
				return []byte(signingCanary), nil
			}
			if failure == "cancel before attest" {
				var diagnostics bytes.Buffer
				progress := newBuildProgress(ctx, cancelOnSigningStageWriter{output: &diagnostics, cancel: cancel, stage: "Attesting validated architecture SPDX"}, false)
				ctx = context.WithValue(ctx, buildProgressKey{}, progress)
				defer progress.Close()
			}
			outcome, err := signAndAttestDigest(ctx, command, result, signingOptions{key: "/synthetic/key"})
			signing, attestation := "signed", "failed"
			wantSigns, wantAttests := 1, 0
			if failure == "sign" || failure == "cancel sign" || failure == "cancel before sign" {
				signing, attestation = "failed", "not-attempted"
			}
			if failure == "cancel before sign" {
				wantSigns = 0
			}
			if failure == "attest" || failure == "cancel attest" {
				wantAttests = 1
			}
			if err == nil || strings.Contains(err.Error(), signingCanary) || outcome.signing != signing || outcome.attestation != attestation || signs != wantSigns || attests != wantAttests {
				t.Fatalf("outcome=%+v signs=%d attests=%d err=%v", outcome, signs, attests, err)
			}
			if strings.HasPrefix(failure, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}

func TestSigningDisabledNeverCallsCosign(t *testing.T) {
	outcome, err := signAndAttestDigest(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("Cosign called without signing request")
		return nil, nil
	}, buildResult{}, signingOptions{})
	if err != nil || outcome.signing != "skipped" || outcome.attestation != "skipped" {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
}

type cancelOnSigningStageWriter struct {
	output *bytes.Buffer
	cancel context.CancelFunc
	stage  string
}

func (w cancelOnSigningStageWriter) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	if strings.Contains(string(data), "lupetto: "+w.stage+"\n") {
		w.cancel()
	}
	return n, err
}
