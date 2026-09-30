package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureCosignKey = "/synthetic/" + signingCanary + "/key"
const fixtureCosignConfig = "/synthetic/" + signingCanary + "/config"

func signingCLIArgs(config bool) []string {
	args := append(publicationCLIArgs(), "--cosign-key", fixtureCosignKey, "--cosign-allow-http")
	if config {
		args = append(args, "--cosign-signing-config", fixtureCosignConfig)
	}
	return args
}

func clearSigningFixtureEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
		t.Setenv(key, "")
	}
}

func addSigningFixture(t *testing.T, f *pipelineFixture, failure string, cancel context.CancelFunc) {
	t.Helper()
	f.services.signingCommand = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		if executable != "cosign" || len(args) == 0 {
			t.Fatalf("unexpected signing command: %s %q", executable, args)
		}
		stage := args[0]
		f.events = append(f.events, "cosign "+stage)
		if stage == "version" {
			if f.workspace != "" {
				t.Fatal("Cosign checked after build workspace was used")
			}
			if failure == "version" {
				return []byte(signingCanary), errors.New(signingCanary)
			}
			if failure == "wrong version" {
				return []byte("v3.1.2"), nil
			}
			if failure == "cancel version" {
				cancel()
			}
			return []byte(cosignSigningVersion), nil
		}
		immutable := "localhost:5000/team/images/postgresql-17@" + fixturePushDigest
		if args[len(args)-1] != immutable {
			t.Fatalf("wrong signing identity: %q", args)
		}
		if failure == stage {
			return []byte(signingCanary), errors.New(signingCanary)
		}
		if failure == "cancel "+stage {
			cancel()
		}
		if stage == "sign" && (failure == "checksum" || failure == "read") {
			arch, err := targetArch()
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(f.workspace, "sbom", "sbom-"+arch+".spdx.json")
			if failure == "checksum" {
				if err := os.WriteFile(filename, []byte(signingCanary), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
		}
		return []byte(signingCanary), nil
	}
}

func TestBuildSigningSingleCompositionAndV5Evidence(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "custom config"}[configured], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, "", cancel)
			addPublicationFixture(t, f, "", cancel)
			addSigningFixture(t, f, "", cancel)
			var stdout, stderr bytes.Buffer
			var result buildResult
			code := runWithBuild(ctx, signingCLIArgs(configured), &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				var err error
				result, err = buildLocalWith(ctx, request, f.services)
				return result, err
			})
			if code != 0 || result.signing != "signed" || result.attestation != "attested" || result.publication.status != "published" || !result.publication.verified {
				t.Fatalf("code=%d result=%+v stderr=%q", code, result, stderr.String())
			}
			if len(f.events) == 0 || f.events[0] != "cosign version" {
				t.Fatalf("Cosign not checked before other boundaries: %q", f.events)
			}
			counts := make(map[string]int)
			for _, event := range f.events {
				counts[event]++
			}
			for _, stage := range []string{"index", "apko lock", "apko build", "cosign version", "cosign sign", "cosign attest"} {
				if counts[stage] != 1 {
					t.Fatalf("stage %q count=%d events=%q", stage, counts[stage], f.events)
				}
			}
			for _, stage := range []string{"Build completed", "Docker loaded:", "Registry published:", "Image signing: signed", "SPDX attestation: attested"} {
				if !strings.Contains(stdout.String(), stage) {
					t.Fatalf("missing %q: %q", stage, stdout.String())
				}
			}
			if strings.Contains(stdout.String(), signingCanary) || strings.Contains(stderr.String(), signingCanary) {
				t.Fatalf("unsafe output stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "loopback HTTP") || configured && !strings.Contains(stderr.String(), "custom service configuration") {
				t.Fatalf("missing explicit exception warning: %q", stderr.String())
			}
			data, err := os.ReadFile(filepath.Join(f.workspace, "result.json"))
			if err != nil || bytes.Contains(data, []byte(signingCanary)) {
				t.Fatalf("record=%q err=%v", data, err)
			}
			var record evidenceResult
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			if record.Version != 5 || record.Build != "completed" || record.Signing != "signed" || record.Attestation != "attested" || record.Publication == nil || !record.Publication.Verified || record.Publication.ImmutableReference != result.publication.immutableReference || record.SPDXSHA256 != result.spdxSHA256 {
				t.Fatalf("record=%+v", record)
			}
			info, err := os.Stat(filepath.Join(f.workspace, "result.json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("record permissions err=%v", err)
			}
			if _, err := os.Stat(filepath.Join(f.workspace, "failure.json")); !os.IsNotExist(err) {
				t.Fatalf("unexpected failure record: %v", err)
			}
		})
	}
}

func TestBuildSigningTypedPartialFailuresAndV5FailureOnly(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, tc := range []struct {
		name, local, remote, cosign, cancelStage, stage, build, load, publication, signing, attestation string
		verified                                                                                        bool
	}{
		{"composition", "build", "", "", "", "build", "failed", "not-attempted", "skipped", "not-attempted", "not-attempted", false},
		{"load", "load", "", "", "", "load", "completed", "failed", "skipped", "not-attempted", "not-attempted", false},
		{"readable tag", "readable ID mismatch", "", "", "", "readable-tag", "completed", "loaded; readable tag unconfirmed", "skipped", "not-attempted", "not-attempted", false},
		{"push", "", "push", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
		{"content", "", "layer", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
		{"publication cancel", "", "cancel pull", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
		{"sign", "", "", "sign", "", "signing", "completed", "loaded", "published", "failed", "not-attempted", true},
		{"sign cancel", "", "", "cancel sign", "", "signing", "completed", "loaded", "published", "failed", "not-attempted", true},
		{"before sign cancel", "", "", "", "Signing verified immutable registry image", "signing", "completed", "loaded", "published", "failed", "not-attempted", true},
		{"attest", "", "", "attest", "", "attestation", "completed", "loaded", "published", "signed", "failed", true},
		{"attest cancel", "", "", "cancel attest", "", "attestation", "completed", "loaded", "published", "signed", "failed", true},
		{"before attest cancel", "", "", "", "Attesting validated architecture SPDX", "attestation", "completed", "loaded", "published", "signed", "failed", true},
		{"checksum", "", "", "checksum", "", "attestation", "completed", "loaded", "published", "signed", "failed", true},
		{"read", "", "", "read", "", "attestation", "completed", "loaded", "published", "signed", "failed", true},
		{"record", "result recording", "", "", "", "record", "completed", "loaded", "published", "signed", "attested", true},
		{"record cancel", "", "", "", "Recording build result", "record", "completed", "loaded", "published", "signed", "attested", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, tc.local, cancel)
			addPublicationFixture(t, f, tc.remote, cancel)
			addSigningFixture(t, f, tc.cosign, cancel)
			var stdout, stderr bytes.Buffer
			var caught error
			stderrWriter := cancelOnSigningStageWriter{output: &stderr, cancel: cancel, stage: tc.cancelStage}
			code := runWithBuild(ctx, signingCLIArgs(true), &stdout, stderrWriter, func(ctx context.Context, request buildRequest) (buildResult, error) {
				result, err := buildLocalWith(ctx, request, f.services)
				caught = err
				return result, err
			})
			var wf *workflowFailure
			if code == 0 || stdout.Len() != 0 || !errors.As(caught, &wf) {
				t.Fatalf("code=%d stdout=%q error=%v", code, stdout.String(), caught)
			}
			if wf.stage != tc.stage || wf.build != tc.build || wf.load != tc.load || wf.result.publication.status != tc.publication || wf.result.publication.verified != tc.verified || wf.signing != tc.signing || wf.attestation != tc.attestation || wf.result.signing != tc.signing || wf.result.attestation != tc.attestation {
				t.Fatalf("workflow=%+v result=%+v", wf, wf.result)
			}
			if tc.verified && wf.result.publication.immutableReference != "localhost:5000/team/images/postgresql-17@"+fixturePushDigest {
				t.Fatalf("lost confirmed publication identity: %+v", wf.result.publication)
			}
			if strings.Contains(caught.Error(), signingCanary) || strings.Contains(stderr.String(), signingCanary) || strings.Contains(stderr.String(), publicationCanary) {
				t.Fatalf("unsafe error=%v stderr=%q", caught, stderr.String())
			}
			for _, stage := range []string{"build: " + tc.build, "Docker load: " + tc.load, "publication: " + tc.publication, "signing: " + tc.signing, "attestation: " + tc.attestation} {
				if !strings.Contains(stderr.String(), stage) {
					t.Fatalf("missing %q: %q", stage, stderr.String())
				}
			}
			if wf.attempted && !strings.Contains(stderr.String(), "no rollback attempted") {
				t.Fatalf("missing uncertainty warning: %q", stderr.String())
			}
			if strings.Contains(tc.name, "cancel") && !errors.Is(caught, context.Canceled) {
				t.Fatalf("lost cancellation: %v", caught)
			}
			counts := make(map[string]int)
			for _, event := range f.events {
				counts[event]++
			}
			if counts["apko build"] != 1 || counts["apko lock"] != 1 || counts["index"] != 1 {
				t.Fatalf("duplicate build/selection: %q", f.events)
			}
			if tc.signing == "not-attempted" && (counts["cosign sign"] != 0 || counts["cosign attest"] != 0) || tc.signing == "failed" && counts["cosign attest"] != 0 {
				t.Fatalf("called later signing stage: %q", f.events)
			}
			if (tc.cosign == "checksum" || tc.cosign == "read" || tc.cancelStage == "Attesting validated architecture SPDX") && counts["cosign attest"] != 0 {
				t.Fatalf("attested changed/unreadable/canceled predicate: %q", f.events)
			}
			assertNoSuccessRecord(t, f.workspace)
			data, err := os.ReadFile(filepath.Join(f.workspace, "failure.json"))
			if err != nil || bytes.Contains(data, []byte(signingCanary)) || bytes.Contains(data, []byte(publicationCanary)) {
				t.Fatalf("record=%q err=%v", data, err)
			}
			var record struct {
				Version                                  int
				Stage, Build, Load, Signing, Attestation string
				Publication                              publicationEvidence
			}
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			if record.Version != 5 || record.Stage != tc.stage || record.Build != tc.build || record.Load != tc.load || record.Signing != tc.signing || record.Attestation != tc.attestation || record.Publication.Status != tc.publication || record.Publication.Verified != tc.verified {
				t.Fatalf("record=%+v", record)
			}
			info, err := os.Stat(filepath.Join(f.workspace, "failure.json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("failure permissions err=%v", err)
			}
		})
	}
}

func TestBuildSigningVersionPreflightBeforeWorkspaceNetworkAndBuild(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, failure := range []string{"version", "wrong version", "cancel version"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			services := buildServices{
				command: func(context.Context, string, ...string) ([]byte, error) {
					t.Fatal("build tool invoked after failed signing preflight")
					return nil, nil
				},
				cacheDir: func() (string, error) { t.Fatal("workspace used after failed signing preflight"); return "", nil },
				publicFile: func(context.Context, string, int64) ([]byte, error) {
					t.Fatal("network used after failed signing preflight")
					return nil, nil
				},
				signingCommand: func(context.Context, string, ...string) ([]byte, error) {
					switch failure {
					case "version":
						return []byte(signingCanary), errors.New(signingCanary)
					case "cancel version":
						cancel()
						return []byte(cosignSigningVersion), nil
					default:
						return []byte("v3.1.4"), nil
					}
				},
			}
			var stdout, stderr bytes.Buffer
			var caught error
			code := runWithBuild(ctx, signingCLIArgs(true), &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				result, err := buildLocalWith(ctx, request, services)
				caught = err
				return result, err
			})
			var wf *workflowFailure
			if code != 1 || stdout.Len() != 0 || !errors.As(caught, &wf) || wf.stage != "cosign-version" || wf.result.workspace != "" || wf.build != "not-attempted" || wf.load != "not-attempted" || wf.signing != "not-attempted" || wf.attestation != "not-attempted" || wf.attempted {
				t.Fatalf("code=%d workflow=%+v error=%v stdout=%q", code, wf, caught, stdout.String())
			}
			if strings.Contains(stderr.String(), signingCanary) || strings.Contains(caught.Error(), signingCanary) {
				t.Fatalf("unsafe preflight diagnostics: %q", stderr.String())
			}
			if failure == "cancel version" && !errors.Is(caught, context.Canceled) {
				t.Fatalf("lost cancellation: %v", caught)
			}
		})
	}
}

func TestBuildSigningEarlierApkoFailureKeepsRequestedNotAttempted(t *testing.T) {
	request := buildRequest{publication: publicationOptions{registry: "localhost:5000", repository: "team/images"},
		signing: signingOptions{key: fixtureCosignKey, allowHTTP: true}}
	services := buildServices{
		signingCommand: func(context.Context, string, ...string) ([]byte, error) { return []byte(cosignSigningVersion), nil },
		command: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(signingCanary), errors.New(signingCanary)
		},
		cacheDir: func() (string, error) { t.Fatal("workspace used after failed apko preflight"); return "", nil },
	}
	result, err := buildLocalWith(context.Background(), request, services)
	var wf *workflowFailure
	if !errors.As(err, &wf) || wf.stage != "build" || wf.build != "failed" || result.signing != "not-attempted" || result.attestation != "not-attempted" || wf.signing != "not-attempted" || wf.attestation != "not-attempted" || strings.Contains(err.Error(), signingCanary) {
		t.Fatalf("result=%+v workflow=%+v err=%v", result, wf, err)
	}
}

func TestBuildSigningDisabledLocalPublicationNoLoadAndSBOMNeverInvokeCosign(t *testing.T) {
	for _, mode := range []string{"local", "publication", "no-load", "sbom"} {
		t.Run(mode, func(t *testing.T) {
			clearSigningFixtureEnvironment(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, "", cancel)
			f.services.signingCommand = func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign invoked without signing request")
				return nil, nil
			}
			args := []string{"build", "postgresql-17", "--apk-version", "17.10-r1"}
			if mode == "publication" {
				args = publicationCLIArgs()
				addPublicationFixture(t, f, "", cancel)
			}
			if mode == "no-load" {
				args = append(args, "--no-load")
			}
			if mode == "sbom" {
				args[0] = "sbom"
				t.Setenv("LUPETTO_REGISTRY", "invalid registry")
				t.Setenv("LUPETTO_REPOSITORY", "INVALID")
				t.Setenv("LUPETTO_COSIGN_KEY", fixtureCosignKey)
				t.Setenv("LUPETTO_COSIGN_SIGNING_CONFIG", fixtureCosignConfig)
				t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "invalid")
			}
			var stdout, stderr bytes.Buffer
			var result buildResult
			code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				if request.signing.enabled() {
					t.Fatal("unexpected signing request")
				}
				var err error
				result, err = buildLocalWith(ctx, request, f.services)
				return result, err
			})
			if code != 0 || result.signing != "skipped" || result.attestation != "skipped" {
				t.Fatalf("code=%d result=%+v stderr=%q", code, result, stderr.String())
			}
			data, err := os.ReadFile(filepath.Join(f.workspace, "result.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record evidenceResult
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			wantVersion := 3
			if mode == "publication" {
				wantVersion = 4
			}
			if record.Version != wantVersion {
				t.Fatalf("unexpected schema=%+v", record)
			}
		})
	}
}

func TestBuildSigningInvalidOptionsRejectedBeforeExternalBoundaries(t *testing.T) {
	for _, request := range []buildRequest{
		{signing: signingOptions{key: fixtureCosignKey}},
		{publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}, signing: signingOptions{key: fixtureCosignKey}},
		{publication: publicationOptions{registry: "registry.example.invalid", repository: "team/images"}, signing: signingOptions{key: fixtureCosignKey, allowHTTP: true}},
		{noLoad: true, publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}, signing: signingOptions{key: fixtureCosignKey, allowHTTP: true}},
	} {
		services := buildServices{
			command: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("tool invoked before validation")
				return nil, nil
			},
			signingCommand: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign invoked before validation")
				return nil, nil
			},
			cacheDir: func() (string, error) { t.Fatal("workspace invoked before validation"); return "", nil },
			publicFile: func(context.Context, string, int64) ([]byte, error) {
				t.Fatal("network invoked before validation")
				return nil, nil
			},
		}
		if _, err := buildLocalWith(context.Background(), request, services); err == nil {
			t.Fatalf("accepted %+v", request)
		}
	}
}
