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

// addRegistryFixture starts an in-process loopback registry with isolated
// Docker/Podman credential locations and tamper hooks keyed to the composed image.
func addRegistryFixture(t *testing.T, f *pipelineFixture, mutation string, cancel context.CancelFunc) *testRegistry {
	t.Helper()
	isolateRegistryAuth(t)
	registry := newTestRegistry(t, mutation, cancel)
	f.registry = registry
	f.afterBuild = append(f.afterBuild, func(imageDir string) {
		registry.tamperBlobs(fixtureBlobDigests(t, imageDir))
	})
	return registry
}

func publicationCLIArgs(registry string) []string {
	return []string{"build", "postgresql-17", "--apk-version", "17.10-r1", "--registry", registry, "--repository", "team/images"}
}

func readRecord(t *testing.T, path string) (buildRecord, map[string]any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record buildRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("record mode=%v err=%v", info, err)
	}
	return record, raw
}

func TestBuildPublicationSingleCompositionAndV6Record(t *testing.T) {
	for _, mode := range []string{"load", "fallback", "no-load"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			local := ""
			if mode == "fallback" {
				local = "fallback"
			}
			f := newPipelineFixture(t, local, cancel)
			registry := addRegistryFixture(t, f, "", cancel)
			args := publicationCLIArgs(registry.host)
			if mode == "no-load" {
				args = append(args, "--no-load")
			}
			var stdout, stderr bytes.Buffer
			var result buildResult
			code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				var err error
				result, err = buildLocalWith(ctx, request, f.services)
				return result, err
			})
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			immutable := registry.host + "/team/images/postgresql-17@" + f.manifestDigest
			if result.publication.status != "published" || !result.publication.verified || result.publication.pushedDigest != f.manifestDigest || result.publication.immutableReference != immutable {
				t.Fatalf("result=%+v", result)
			}
			counts := make(map[string]int)
			for _, event := range f.events {
				counts[event]++
				if mode == "no-load" && strings.HasPrefix(event, "docker ") {
					t.Fatalf("--no-load publication invoked Docker: %q", f.events)
				}
			}
			if counts["apko build"] != 1 || counts["apko lock"] != 1 || counts["index"] != 1 {
				t.Fatalf("resolved/composed multiple times: %q", f.events)
			}
			if !strings.Contains(stdout.String(), "Immutable reference: "+immutable) {
				t.Fatalf("stdout=%q", stdout.String())
			}
			record, raw := readRecord(t, filepath.Join(f.workspace, "result.json"))
			wantLoad := "loaded"
			if mode == "no-load" {
				wantLoad = "skipped"
			}
			if record.Version != 6 || record.Command != "build" || record.Outcome != "succeeded" || record.Failure != nil || record.Workspace != f.workspace ||
				record.Request != (recordRequest{Package: "postgresql-17", APKVersion: "17.10-r1", Load: mode != "no-load", Publish: true}) ||
				record.Stages.Build.Status != "completed" || record.Stages.Load.Status != wantLoad || record.Stages.Load.ReadableReferenceConfirmed != (mode != "no-load") ||
				record.Stages.Publication != (recordPublication{Status: "published", Reference: result.publication.reference, Digest: f.manifestDigest, ImmutableReference: immutable, Verified: true}) ||
				record.Stages.Signing.Status != "skipped" || record.Stages.Attestation.Status != "skipped" ||
				record.Evidence == nil || record.Evidence.ImageDigest != f.manifestDigest || record.Selection == nil || record.Selection.Version != "17.10-r1" {
				t.Fatalf("record=%+v", record)
			}
			if _, ok := raw["failure"]; ok {
				t.Fatalf("success record has failure: %v", raw)
			}
			if _, err := os.Stat(filepath.Join(f.workspace, "failure.json")); !os.IsNotExist(err) {
				t.Fatalf("unexpected failure record: %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.workspace, "published-manifest.json")); err != nil {
				t.Fatalf("published manifest not retained: %v", err)
			}
			if !bytes.Equal(result.record, mustRead(t, filepath.Join(f.workspace, "result.json"))) {
				t.Fatal("returned record bytes differ from result.json")
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildPublicationTypedPartialFailureAndV6FailureRecord(t *testing.T) {
	for _, tc := range []struct {
		name, local, remote string
		noLoad              bool
		stage, build, load  string
		readable            bool
		publication         string
		captured, verified  bool
	}{
		{"composition", "build", "", false, "build", "failed", "not-attempted", false, "not-attempted", false, false},
		{"no-load composition", "build", "", true, "build", "failed", "skipped", false, "not-attempted", false, false},
		{"load", "load", "", false, "load", "completed", "failed", false, "not-attempted", false, false},
		{"readable alias", "readable ID mismatch", "", false, "readable-tag", "completed", "loaded", false, "not-attempted", false, false},
		{"registry rejection", "", "reject manifest", false, "publication", "completed", "loaded", true, "failed", false, false},
		{"cancel push", "", "cancel push", false, "publication", "completed", "loaded", true, "failed", false, false},
		{"manifest tamper", "", "manifest", false, "publication", "completed", "loaded", true, "failed", true, false},
		{"tag tamper", "", "tag", false, "publication", "completed", "loaded", true, "failed", true, false},
		{"config tamper", "", "config", false, "publication", "completed", "loaded", true, "failed", true, false},
		{"layer tamper", "", "layer", false, "publication", "completed", "loaded", true, "failed", true, false},
		{"no-load layer tamper", "", "layer", true, "publication", "completed", "skipped", false, "failed", true, false},
		{"cancel readback", "", "cancel readback", false, "publication", "completed", "loaded", true, "failed", true, false},
		{"record", "result recording", "", false, "record", "completed", "loaded", true, "published", true, true},
		{"no-load record", "skipped result recording", "", true, "record", "completed", "skipped", false, "published", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, tc.local, cancel)
			registry := addRegistryFixture(t, f, tc.remote, cancel)
			args := append(publicationCLIArgs(registry.host), "--json")
			if tc.noLoad {
				args = append(args, "--no-load")
			}
			var stdout, stderr bytes.Buffer
			var caught error
			code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				result, err := buildLocalWith(ctx, request, f.services)
				caught = err
				return result, err
			})
			var wf *workflowFailure
			if code != 1 || !errors.As(caught, &wf) || wf.stage != tc.stage {
				t.Fatalf("code=%d caught=%v", code, caught)
			}
			r := wf.result
			if r.build != tc.build || r.dockerLoad != tc.load || r.readableConfirmed != tc.readable || r.publication.status != tc.publication || r.publication.verified != tc.verified || (r.publication.pushedDigest != "") != tc.captured || r.signing != "skipped" || r.attestation != "skipped" {
				t.Fatalf("workflow=%+v result=%+v", wf, r)
			}
			if tc.captured && r.publication.pushedDigest != f.manifestDigest {
				t.Fatalf("captured digest %q want local manifest %q", r.publication.pushedDigest, f.manifestDigest)
			}
			if strings.HasPrefix(tc.name, "cancel") && !errors.Is(caught, context.Canceled) {
				t.Fatalf("lost cancellation: %v", caught)
			}
			if strings.Contains(stderr.String(), publicationCanary) || strings.Contains(caught.Error(), publicationCanary) || strings.Contains(stdout.String(), publicationCanary) {
				t.Fatalf("unsafe diagnostics=%q", stderr.String())
			}
			for _, stage := range []string{"build: " + tc.build, "Docker load: " + tc.load, "publication: " + tc.publication, "signing: skipped", "attestation: skipped"} {
				if !strings.Contains(stderr.String(), stage) {
					t.Fatalf("missing %q: %q", stage, stderr.String())
				}
			}
			assertNoSuccessRecord(t, f.workspace)
			data := mustRead(t, filepath.Join(f.workspace, "failure.json"))
			if !bytes.Equal(stdout.Bytes(), data) || !bytes.Equal(wf.record, data) {
				t.Fatalf("--json stdout differs from failure.json:\n%s\n%s", stdout.String(), data)
			}
			record, _ := readRecord(t, filepath.Join(f.workspace, "failure.json"))
			if record.Version != 6 || record.Outcome != "failed" || record.Failure == nil || record.Failure.Stage != tc.stage ||
				record.Stages.Build.Status != tc.build || record.Stages.Load.Status != tc.load || record.Stages.Load.ReadableReferenceConfirmed != tc.readable ||
				record.Stages.Publication.Status != tc.publication || record.Stages.Publication.Verified != tc.verified || (record.Stages.Publication.Digest != "") != tc.captured ||
				record.Stages.Signing.Status != "skipped" || record.Stages.Attestation.Status != "skipped" || (record.Evidence != nil) != (tc.build == "completed") {
				t.Fatalf("record=%+v failure=%+v", record, record.Failure)
			}
			if record.Failure.SideEffectsPossible != (tc.load == "loaded" || tc.load == "failed" || tc.publication != "not-attempted") {
				t.Fatalf("side effects=%v for %+v", record.Failure.SideEffectsPossible, tc)
			}
			if record.Failure.SideEffectsPossible && !strings.Contains(stderr.String(), "no rollback attempted") {
				t.Fatalf("missing uncertainty warning: %q", stderr.String())
			}
			// Publication workflows keep sanitized stage-only messages.
			if !strings.HasPrefix(record.Failure.Error, strings.Split(tc.stage, "-")[0]) && !strings.HasPrefix(record.Failure.Error, "publication") {
				t.Fatalf("unsanitized failure error %q", record.Failure.Error)
			}
			if tc.noLoad {
				for _, event := range f.events {
					if strings.HasPrefix(event, "docker ") {
						t.Fatalf("--no-load invoked Docker: %q", f.events)
					}
				}
			}
		})
	}
}

func TestBuildPublicationNoLoadAccepted(t *testing.T) {
	request := buildRequest{noLoad: true, publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}}
	if err := validateSigningOptions(request.signing, request.publication); err != nil {
		t.Fatalf("--no-load publication rejected: %v", err)
	}
}

func TestBuildPublicationRejectedBeforeExternalBoundaries(t *testing.T) {
	for _, request := range []buildRequest{
		{publication: publicationOptions{registry: "localhost:5000"}},
		{publication: publicationOptions{registry: "https://example.com", repository: "team/images"}},
	} {
		services := buildServices{
			command: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("tool called before validation")
				return nil, nil
			},
			cacheDir: func() (string, error) { t.Fatal("workspace called before validation"); return "", nil },
			publicFile: func(context.Context, string, int64) ([]byte, error) {
				t.Fatal("network called before validation")
				return nil, nil
			},
		}
		if _, err := buildLocalWith(context.Background(), request, services); err == nil {
			t.Fatalf("accepted %+v", request)
		}
	}
}

func TestBuildPublicationEarlyToolFailureIsTypedAndSanitized(t *testing.T) {
	request := buildRequest{publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}}
	services := buildServices{command: func(context.Context, string, ...string) ([]byte, error) {
		return []byte(publicationCanary), errors.New(publicationCanary)
	}}
	_, err := buildLocalWith(context.Background(), request, services)
	var wf *workflowFailure
	if !errors.As(err, &wf) || wf.result.workspace != "" || wf.result.build != "failed" || wf.result.dockerLoad != "not-attempted" || wf.result.publication.status != "not-attempted" || strings.Contains(err.Error(), publicationCanary) || bytes.Contains(wf.record, []byte(publicationCanary)) {
		t.Fatalf("workflow=%+v err=%v", wf, err)
	}
	var record buildRecord
	if err := json.Unmarshal(wf.record, &record); err != nil || record.Workspace != "" || record.Selection != nil || record.Evidence != nil || record.Failure.Error != "build failed" {
		t.Fatalf("record=%s err=%v", wf.record, err)
	}
	var stderr bytes.Buffer
	if !reportWorkflowFailure(&stderr, err) || strings.Contains(stderr.String(), publicationCanary) || strings.Contains(stderr.String(), "could not be retained") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestFailureRecordWriteDoesNotHideCause(t *testing.T) {
	result := initialBuildResult(buildRequest{publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}})
	result.workspace, result.build, result.dockerLoad = t.TempDir(), "completed", "loaded"
	result.publication = publicationOutcome{status: "published", pushedDigest: fixturePushDigest, verified: true}
	if err := os.Mkdir(filepath.Join(result.workspace, "failure.json"), 0700); err != nil {
		t.Fatal(err)
	}
	failure := newWorkflowFailure(result, "record", context.Canceled, true)
	if failure.recordErr == nil || len(failure.record) == 0 || !errors.Is(failure, context.Canceled) || failure.result.publication.status != "published" || !failure.result.publication.verified {
		t.Fatalf("failure=%+v", failure)
	}
	var stderr bytes.Buffer
	if !reportWorkflowFailure(&stderr, failure) || !strings.Contains(stderr.String(), "publication: published") || !strings.Contains(stderr.String(), "could not be retained") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if reportWorkflowFailure(&stderr, errors.New("ordinary")) {
		t.Fatal("consumed an unrelated failure")
	}
	// --json still prints the document that could not be retained.
	var stdout bytes.Buffer
	stderr.Reset()
	code := runWithBuild(context.Background(), []string{"build", "pkg", "1", "--json"}, &stdout, &stderr, func(context.Context, buildRequest) (buildResult, error) {
		return buildResult{}, failure
	})
	if code != 1 || !bytes.Equal(stdout.Bytes(), failure.record) {
		t.Fatalf("code=%d stdout=%q", code, stdout.String())
	}
}
