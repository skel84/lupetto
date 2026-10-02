package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"lupetto/internal/build"
	"lupetto/internal/build/buildtest"
	"lupetto/internal/wolfi"
)

func signingCLIArgs(registry string, config bool) []string {
	args := append(publicationCLIArgs(registry), "--cosign-key", buildtest.CosignKey, "--cosign-allow-http")
	if config {
		args = append(args, "--cosign-signing-config", buildtest.CosignConfig)
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
	f.services.SigningCommand = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
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
				return []byte(buildtest.SigningCanary), errors.New(buildtest.SigningCanary)
			}
			if failure == "wrong version" {
				return []byte("v3.1.2"), nil
			}
			if failure == "cancel version" {
				cancel()
			}
			return []byte(build.CosignVersion), nil
		}
		immutable := f.registry.Host + "/team/images/postgresql-17@" + f.manifestDigest
		if args[len(args)-1] != immutable {
			t.Fatalf("wrong signing identity: %q", args)
		}
		if failure == stage {
			return []byte(buildtest.SigningCanary), errors.New(buildtest.SigningCanary)
		}
		if failure == "cancel "+stage {
			cancel()
		}
		if stage == "sign" && (failure == "checksum" || failure == "read") {
			arch, err := wolfi.TargetArch()
			if err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(f.workspace, "sbom", "sbom-"+arch+".spdx.json")
			if failure == "checksum" {
				if err := os.WriteFile(filename, []byte(buildtest.SigningCanary), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
		}
		return []byte(buildtest.SigningCanary), nil
	}
}

func TestBuildSigningSingleCompositionAndV6Record(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "custom config"}[configured], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, "", cancel)
			registry := addRegistryFixture(t, f, "", cancel)
			addSigningFixture(t, f, "", cancel)
			var stdout, stderr bytes.Buffer
			var result build.Result
			code := runWithBuild(ctx, signingCLIArgs(registry.Host, configured), &stdout, &stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
				var err error
				result, err = build.RunWith(ctx, request.Request, f.services)
				return result, err
			})
			if code != 0 || result.Signing != "signed" || result.Attestation != "attested" || result.Publication.Status != "published" || !result.Publication.Verified {
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
			if strings.Contains(stdout.String(), buildtest.SigningCanary) || strings.Contains(stderr.String(), buildtest.SigningCanary) {
				t.Fatalf("unsafe output stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "loopback HTTP") || configured && !strings.Contains(stderr.String(), "custom service configuration") {
				t.Fatalf("missing explicit exception warning: %q", stderr.String())
			}
			data := mustRead(t, filepath.Join(f.workspace, "result.json"))
			if bytes.Contains(data, []byte(buildtest.SigningCanary)) {
				t.Fatalf("record=%q", data)
			}
			record, raw := readRecord(t, filepath.Join(f.workspace, "result.json"))
			if record.Version != 6 || record.Stages.Build.Status != "completed" || record.Stages.Signing.Status != "signed" || record.Stages.Attestation.Status != "attested" || !record.Stages.Publication.Verified || record.Stages.Publication.ImmutableReference != result.Publication.ImmutableReference || record.Evidence == nil || record.Evidence.SPDXSHA256 != result.SPDXSHA256 || !record.Request.Sign || !record.Request.Publish || !record.Request.Load {
				t.Fatalf("record=%+v", record)
			}
			assertRecordShape(t, raw)
			if _, err := os.Stat(filepath.Join(f.workspace, "failure.json")); !os.IsNotExist(err) {
				t.Fatalf("unexpected failure record: %v", err)
			}
		})
	}
}

func TestBuildSigningTypedPartialFailuresAndV6FailureOnly(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, tc := range []struct {
		name, local, remote, cosign, cancelStage, stage, build, load, publication, signing, attestation string
		verified                                                                                        bool
	}{
		{"composition", "build", "", "", "", "build", "failed", "not-attempted", "not-attempted", "not-attempted", "not-attempted", false},
		{"load", "load", "", "", "", "load", "completed", "failed", "not-attempted", "not-attempted", "not-attempted", false},
		{"readable tag", "readable ID mismatch", "", "", "", "readable-tag", "completed", "loaded; readable tag unconfirmed", "not-attempted", "not-attempted", "not-attempted", false},
		{"push", "", "reject manifest", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
		{"content", "", "layer", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
		{"publication cancel", "", "cancel readback", "", "", "publication", "completed", "loaded", "failed", "not-attempted", "not-attempted", false},
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
			registry := addRegistryFixture(t, f, tc.remote, cancel)
			addSigningFixture(t, f, tc.cosign, cancel)
			var stdout, stderr bytes.Buffer
			var caught error
			stderrWriter := buildtest.CancelOnStageWriter{Output: &stderr, Cancel: cancel, Stage: tc.cancelStage}
			code := runWithBuild(ctx, signingCLIArgs(registry.Host, true), &stdout, stderrWriter, func(ctx context.Context, request cliRequest) (build.Result, error) {
				result, err := build.RunWith(ctx, request.Request, f.services)
				caught = err
				return result, err
			})
			var wf *build.WorkflowFailure
			if code == 0 || stdout.Len() != 0 || !errors.As(caught, &wf) {
				t.Fatalf("code=%d stdout=%q error=%v", code, stdout.String(), caught)
			}
			r := wf.Result
			load := r.DockerLoad
			if load == "loaded" && !r.ReadableConfirmed {
				load = "loaded; readable tag unconfirmed"
			}
			if wf.Stage != tc.stage || r.Build != tc.build || load != tc.load || r.Publication.Status != tc.publication || r.Publication.Verified != tc.verified || r.Signing != tc.signing || r.Attestation != tc.attestation {
				t.Fatalf("workflow=%+v result=%+v", wf, r)
			}
			if tc.verified && r.Publication.ImmutableReference != registry.Host+"/team/images/postgresql-17@"+f.manifestDigest {
				t.Fatalf("lost confirmed publication identity: %+v", r.Publication)
			}
			if strings.Contains(caught.Error(), buildtest.SigningCanary) || strings.Contains(stderr.String(), buildtest.SigningCanary) || strings.Contains(stderr.String(), buildtest.PublicationCanary) {
				t.Fatalf("unsafe error=%v stderr=%q", caught, stderr.String())
			}
			for _, stage := range []string{"build: " + tc.build, "Docker load: " + tc.load, "publication: " + tc.publication, "signing: " + tc.signing, "attestation: " + tc.attestation} {
				if !strings.Contains(stderr.String(), stage) {
					t.Fatalf("missing %q: %q", stage, stderr.String())
				}
			}
			if wf.SideEffects && !strings.Contains(stderr.String(), "no rollback attempted") {
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
			data := mustRead(t, filepath.Join(f.workspace, "failure.json"))
			if bytes.Contains(data, []byte(buildtest.SigningCanary)) || bytes.Contains(data, []byte(buildtest.PublicationCanary)) {
				t.Fatalf("record=%q", data)
			}
			record, _ := readRecord(t, filepath.Join(f.workspace, "failure.json"))
			wantLoad := strings.TrimSuffix(tc.load, "; readable tag unconfirmed")
			if record.Version != 6 || record.Failure == nil || record.Failure.Stage != tc.stage || record.Stages.Build.Status != tc.build || record.Stages.Load.Status != wantLoad || record.Stages.Load.ReadableReferenceConfirmed != (tc.load == "loaded") || record.Stages.Signing.Status != tc.signing || record.Stages.Attestation.Status != tc.attestation || record.Stages.Publication.Status != tc.publication || record.Stages.Publication.Verified != tc.verified {
				t.Fatalf("record=%+v", record)
			}
		})
	}
}

func TestBuildNoLoadPublicationAndSigningOrchestration(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newPipelineFixture(t, "", cancel)
	registry := addRegistryFixture(t, f, "", cancel)
	addSigningFixture(t, f, "", cancel)
	var stdout, stderr bytes.Buffer
	var result build.Result
	args := append(signingCLIArgs(registry.Host, false), "--no-load", "--json")
	code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
		var err error
		result, err = build.RunWith(ctx, request.Request, f.services)
		return result, err
	})
	if code != 0 || result.DockerLoad != "skipped" || result.Publication.Status != "published" || !result.Publication.Verified || result.Signing != "signed" || result.Attestation != "attested" {
		t.Fatalf("code=%d result=%+v stderr=%q", code, result, stderr.String())
	}
	want := []string{"cosign version", "apko version", "index", "apko lock", "apko build", "cosign sign", "cosign attest"}
	if strings.Join(f.events, ",") != strings.Join(want, ",") {
		t.Fatalf("events=%q want=%q", f.events, want)
	}
	if !bytes.Equal(stdout.Bytes(), mustRead(t, filepath.Join(f.workspace, "result.json"))) {
		t.Fatalf("--json stdout differs from result.json: %s", stdout.String())
	}
	record, _ := readRecord(t, filepath.Join(f.workspace, "result.json"))
	if record.Stages.Load.Status != "skipped" || record.Stages.Load.DockerImageID != "" || record.Stages.Load.ImageReference == "" || record.Stages.Signing.Status != "signed" || record.Request.Load {
		t.Fatalf("record=%+v", record)
	}
}

// assertRecordShape checks literal JSON names of a complete success record.
func assertRecordShape(t *testing.T, raw map[string]any) {
	t.Helper()
	keys := func(value any) string {
		object, _ := value.(map[string]any)
		var names []string
		for key := range object {
			names = append(names, key)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	stages, _ := raw["stages"].(map[string]any)
	for path, want := range map[string]string{
		"":                   "command,evidence,outcome,request,selection,stages,version,workspace",
		"request":            "apkVersion,load,package,publish,selector,sign",
		"selection":          "architecture,indexSHA256,package,version",
		"evidence":           "apkoVersion,imageDigest,imageDirectory,lockPath,spdxPath,spdxSHA256,spdxValidated",
		"stages":             "attestation,build,load,publication,signing",
		"stages.load":        "buildReference,dockerImageID,imageReference,readableReferenceConfirmed,status",
		"stages.publication": "digest,immutableReference,reference,status,verified",
		"stages.signing":     "status",
	} {
		var value any = raw
		if path != "" {
			parts := strings.Split(path, ".")
			if len(parts) == 2 {
				value = stages[parts[1]]
			} else {
				value = raw[path]
			}
		}
		if got := keys(value); got != want {
			t.Fatalf("%s keys=%q want %q", path, got, want)
		}
	}
	if raw["version"] != float64(6) || raw["outcome"] != "succeeded" {
		t.Fatalf("record=%v", raw)
	}
}

func TestBuildSigningVersionPreflightBeforeWorkspaceNetworkAndBuild(t *testing.T) {
	clearSigningFixtureEnvironment(t)
	for _, failure := range []string{"version", "wrong version", "cancel version"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			services := build.Services{
				Command: func(context.Context, string, ...string) ([]byte, error) {
					t.Fatal("build tool invoked after failed signing preflight")
					return nil, nil
				},
				DataDir: func() (string, error) { t.Fatal("workspace used after failed signing preflight"); return "", nil },
				PublicFile: func(context.Context, string, int64) ([]byte, error) {
					t.Fatal("network used after failed signing preflight")
					return nil, nil
				},
				SigningCommand: func(context.Context, string, ...string) ([]byte, error) {
					switch failure {
					case "version":
						return []byte(buildtest.SigningCanary), errors.New(buildtest.SigningCanary)
					case "cancel version":
						cancel()
						return []byte(build.CosignVersion), nil
					default:
						return []byte("v3.1.4"), nil
					}
				},
			}
			var stdout, stderr bytes.Buffer
			var caught error
			code := runWithBuild(ctx, signingCLIArgs("localhost:5000", true), &stdout, &stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
				result, err := build.RunWith(ctx, request.Request, services)
				caught = err
				return result, err
			})
			var wf *build.WorkflowFailure
			if code != 1 || stdout.Len() != 0 || !errors.As(caught, &wf) || wf.Stage != "cosign-version" || wf.Result.Workspace != "" || wf.Result.Build != "not-attempted" || wf.Result.DockerLoad != "not-attempted" || wf.Result.Publication.Status != "not-attempted" || wf.Result.Signing != "not-attempted" || wf.Result.Attestation != "not-attempted" || wf.SideEffects || len(wf.Record) == 0 {
				t.Fatalf("code=%d workflow=%+v error=%v stdout=%q", code, wf, caught, stdout.String())
			}
			if strings.Contains(stderr.String(), buildtest.SigningCanary) || strings.Contains(caught.Error(), buildtest.SigningCanary) {
				t.Fatalf("unsafe preflight diagnostics: %q", stderr.String())
			}
			if failure == "cancel version" && !errors.Is(caught, context.Canceled) {
				t.Fatalf("lost cancellation: %v", caught)
			}
		})
	}
}

func TestBuildSigningDisabledLocalPublicationNoLoadAndSBOMNeverInvokeCosign(t *testing.T) {
	for _, mode := range []string{"local", "publication", "no-load", "sbom"} {
		t.Run(mode, func(t *testing.T) {
			clearSigningFixtureEnvironment(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, "", cancel)
			f.services.SigningCommand = func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("Cosign invoked without signing request")
				return nil, nil
			}
			args := []string{"build", "postgresql-17", "--apk-version", "17.10-r1"}
			if mode == "publication" {
				registry := addRegistryFixture(t, f, "", cancel)
				args = publicationCLIArgs(registry.Host)
			}
			if mode == "no-load" {
				args = append(args, "--no-load")
			}
			if mode == "sbom" {
				args[0] = "sbom"
				t.Setenv("LUPETTO_REGISTRY", "invalid registry")
				t.Setenv("LUPETTO_REPOSITORY", "INVALID")
				t.Setenv("LUPETTO_COSIGN_KEY", buildtest.CosignKey)
				t.Setenv("LUPETTO_COSIGN_SIGNING_CONFIG", buildtest.CosignConfig)
				t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "invalid")
			}
			var stdout, stderr bytes.Buffer
			var result build.Result
			code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
				if request.Signing.Enabled() {
					t.Fatal("unexpected signing request")
				}
				var err error
				result, err = build.RunWith(ctx, request.Request, f.services)
				return result, err
			})
			if code != 0 || result.Signing != "skipped" || result.Attestation != "skipped" {
				t.Fatalf("code=%d result=%+v stderr=%q", code, result, stderr.String())
			}
			record, _ := readRecord(t, filepath.Join(f.workspace, "result.json"))
			wantPublication := "skipped"
			if mode == "publication" {
				wantPublication = "published"
			}
			if record.Version != 6 || record.Request.Sign || record.Stages.Signing.Status != "skipped" || record.Stages.Attestation.Status != "skipped" || record.Stages.Publication.Status != wantPublication {
				t.Fatalf("unexpected record=%+v", record)
			}
		})
	}
}
