package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"lupetto/internal/build"
	"lupetto/internal/build/buildtest"
	"lupetto/internal/wolfi"
	"lupetto/internal/wolfi/wolfitest"
)

type cancelOnRecordingWriter struct {
	output *bytes.Buffer
	cancel context.CancelFunc
}

func (w cancelOnRecordingWriter) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	if strings.Contains(string(data), "lupetto: Recording build result\n") {
		w.cancel()
	}
	return n, err
}

type pipelineFixture struct {
	services                                                   build.Services
	events                                                     []string
	workspace, imageID, dockerID, reference, readableReference string
	manifestDigest                                             string
	registry                                                   *buildtest.Registry
	afterBuild                                                 []func(imageDir string)
}

func newPipelineFixture(t *testing.T, failure string, cancel context.CancelFunc) *pipelineFixture {
	t.Helper()
	arch, err := wolfi.TargetArch()
	if err != nil {
		t.Fatal(err)
	}
	ociArch := buildtest.OCIArch(t, arch)
	index, key := wolfitest.MakeSignedIndexFor(t, "P:postgresql-17\nV:17.10-r1\nA:"+arch+"\nC:Q1checksum\n\n")
	data := t.TempDir()
	f := &pipelineFixture{}
	f.readableReference = "lupetto/postgresql-17:17.10-r1-" + ociArch
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.services = build.Services{
		DataDir: func() (string, error) { return data, nil },
		PublicFile: func(ctx context.Context, url string, max int64) ([]byte, error) {
			f.events = append(f.events, "index")
			if failure == "cancel index" {
				cancel()
				return nil, ctx.Err()
			}
			return index, nil
		},
		SigningKey: func(ctx context.Context) ([]byte, error) { return key, nil },
		Command: func(ctx context.Context, executable string, args ...string) ([]byte, error) {
			stage := args[0]
			if executable == "docker" {
				stage = args[1]
			}
			if executable == "docker" && stage == "inspect" && args[len(args)-1] == f.readableReference {
				stage = "readable inspect"
			}
			f.events = append(f.events, executable+" "+stage)
			if failure == "cancel "+stage && stage != "build" {
				cancel()
				return nil, ctx.Err()
			}
			if failure == stage {
				return []byte("stage diagnostic"), errors.New("failed " + stage)
			}
			switch executable + " " + stage {
			case "apko version":
				return []byte("GitVersion:    " + build.ApkoVersion + "\n"), nil
			case "apko lock":
				lockPath := args[4]
				f.workspace = filepath.Dir(lockPath)
				version := "17.10-r1"
				if failure == "lock substitution" {
					version = "17.10-r2"
				}
				write(lockPath, []byte(fmt.Sprintf(`{"contents":{"packages":[{"name":"postgresql-17","version":%q,"architecture":%q,"checksum":"Q1checksum"}]}}`, version, arch)))
			case "apko build":
				imageDir := strings.TrimSuffix(args[len(args)-1], string(os.PathSeparator))
				f.reference = args[len(args)-2]
				version := "17.10-r1"
				if failure == "image package" {
					version = "17.10-r2"
				}
				f.imageID, _, _ = buildtest.MakeLoadOCI(t, imageDir, "postgresql-17", version, arch)
				f.dockerID = f.imageID
				f.manifestDigest = buildtest.ManifestDigest(t, imageDir)
				for _, hook := range f.afterBuild {
					hook(imageDir)
				}
				spdxVersion := "17.10-r1"
				if failure == "SPDX" {
					spdxVersion = "17.10-r2"
				}
				doc := fmt.Sprintf(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Package-apk-postgresql-17","name":"postgresql-17","versionInfo":%q,"externalRefs":[{"referenceType":"purl","referenceLocator":%q}]}]}`, spdxVersion, "pkg:apk/wolfi/postgresql-17@"+spdxVersion+"?arch="+arch+"&distro=wolfi")
				write(filepath.Join(f.workspace, "sbom", "sbom-"+arch+".spdx.json"), []byte(doc))
				if failure == "archive" {
					if err := os.Mkdir(filepath.Join(f.workspace, "docker-image.tar"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "cancel build" || failure == "cancel skipped finalization" {
					cancel()
				}
				if failure == "skipped result recording" {
					if err := os.Mkdir(filepath.Join(f.workspace, "result.json"), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "docker load":
				if !reflect.DeepEqual(args, []string{"image", "load", "--input", filepath.Join(f.workspace, "docker-image.tar")}) {
					t.Fatalf("unexpected load arguments: %q", args)
				}
				if _, err := os.Stat(args[3]); err != nil {
					t.Fatalf("archive missing when loading: %v", err)
				}
				tag, err := name.NewTag(f.reference)
				if err != nil {
					t.Fatal(err)
				}
				image, err := tarball.ImageFromPath(args[3], &tag)
				if err != nil {
					t.Fatalf("export did not retain unique build tag: %v", err)
				}
				config, err := image.ConfigName()
				if err != nil || config.String() != f.imageID {
					t.Fatalf("exported identity=%s want=%s err=%v", config, f.imageID, err)
				}
				return []byte("untrusted human-readable loaded tag"), nil
			case "docker inspect":
				if args[len(args)-1] != f.reference {
					t.Fatalf("inspected %q instead of composed reference %q", args, f.reference)
				}
				if failure == "inspect mismatch" {
					f.dockerID = "not-a-digest"
				}
				if failure == "fallback" || failure == "bad saved config" || failure == "missing tag" || failure == "save" || failure == "malformed archive" || failure == "cancel save" {
					f.dockerID = "sha256:" + strings.Repeat("a", 64)
				}
				if failure == "cancel before tag" {
					cancel()
				}
				return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":%q}`, f.dockerID, ociArch)), nil
			case "docker readable inspect":
				if args[len(args)-1] != f.readableReference {
					t.Fatalf("inspected %q instead of readable reference %q", args, f.readableReference)
				}
				if failure == "result recording" {
					if err := os.Mkdir(filepath.Join(f.workspace, "result.json"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				id, osName, inspectArch := f.dockerID, "linux", ociArch
				switch failure {
				case "readable invalid ID":
					id = "not-a-digest"
				case "readable ID mismatch":
					id = "sha256:" + strings.Repeat("b", 64)
				case "readable OS mismatch":
					osName = "windows"
				case "readable arch mismatch":
					inspectArch = "wrong-arch"
				case "readable malformed":
					return []byte("not identity JSON"), nil
				case "cancel readable inspect after response":
					cancel()
				}
				return []byte(fmt.Sprintf(`{"Id":%q,"Os":%q,"Architecture":%q}`, id, osName, inspectArch)), nil
			case "docker tag":
				if !reflect.DeepEqual(args, []string{"image", "tag", f.dockerID, f.readableReference}) {
					t.Fatalf("tag must use verified ID and readable reference: %q", args)
				}
				if failure == "cancel tag after response" {
					cancel()
				}
			case "docker save":
				wantPath := filepath.Join(f.workspace, "docker-loaded.tar")
				if !reflect.DeepEqual(args, []string{"image", "save", "--output", wantPath, f.reference}) {
					t.Fatalf("unexpected save arguments: %q", args)
				}
				buildtest.WriteSavedDockerFixture(t, filepath.Join(f.workspace, "docker-image.tar"), wantPath, failure)
			default:
				t.Fatalf("unexpected command: %s %q", executable, args)
			}
			return nil, nil
		},
	}
	return f
}

func assertNoSuccessRecord(t *testing.T, workspace string) {
	t.Helper()
	if workspace == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(workspace, "result.json"))
	if err == nil {
		t.Fatalf("unexpected result.json: %s", data)
	}
}

func TestBuildLocalLoadAndSkippedStageOrchestration(t *testing.T) {
	for _, command := range []string{"build", "fallback", "no-load", "sbom"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := ""
			if command == "fallback" {
				failure = "fallback"
			}
			f := newPipelineFixture(t, failure, cancel)
			args := []string{"build", "postgresql-17", "--apk-version", "17.10-r1"}
			if command == "no-load" {
				args = append(args, "--no-load")
			}
			if command == "sbom" {
				args[0] = "sbom"
			}
			var stdout, stderr bytes.Buffer
			runBuild := func(ctx context.Context, request cliRequest) (build.Result, error) {
				return build.RunWith(ctx, request.Request, f.services)
			}
			if code := runWithBuild(ctx, args, &stdout, &stderr, runBuild); code != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			wantEvents := []string{"apko version", "index", "apko lock", "apko build"}
			status, imageID := "skipped", ""
			if command == "build" || command == "fallback" {
				wantEvents = append(wantEvents, "docker load", "docker inspect")
				if command == "fallback" {
					wantEvents = append(wantEvents, "docker save")
				}
				wantEvents = append(wantEvents, "docker tag", "docker readable inspect")
				status, imageID = "loaded", f.dockerID
			}
			if !reflect.DeepEqual(f.events, wantEvents) {
				t.Fatalf("events=%q want=%q", f.events, wantEvents)
			}
			wantRef := "lupetto/local:build-" + strings.TrimPrefix(filepath.Base(f.workspace), "image-")
			wantReadableRef := f.readableReference
			wantProgress := []string{
				"lupetto: Checking build tools",
				"lupetto: Creating build workspace",
				"lupetto: Fetching signed APKINDEX",
				"lupetto: Fetching Wolfi signing key",
				"lupetto: Verifying APKINDEX signature",
				"lupetto: Selecting exact APK",
				"lupetto: Selected postgresql-17@17.10-r1; local reference " + wantReadableRef + "; build reference " + wantRef,
				"lupetto: Locking apko dependencies",
				"lupetto: Composing OCI image with apko",
				"lupetto: Checking installed APK",
				"lupetto: Validating SPDX against apko lock",
			}
			if status == "loaded" {
				wantProgress = append(wantProgress,
					"lupetto: Exporting Docker archive",
					"lupetto: Loading image into Docker",
					"lupetto: Inspecting Docker image identity",
				)
				if command == "fallback" {
					wantProgress = append(wantProgress,
						"lupetto: Saving Docker image for identity fallback",
						"lupetto: Verifying saved Docker image identity",
					)
				}
				wantProgress = append(wantProgress,
					"lupetto: Tagging readable Docker reference",
					"lupetto: Inspecting readable Docker reference",
				)
			} else {
				wantProgress = append(wantProgress, "lupetto: Docker loading skipped")
			}
			wantProgress = append(wantProgress, "lupetto: Recording build result")
			gotProgress := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
			if !reflect.DeepEqual(gotProgress, wantProgress) || strings.ContainsAny(stderr.String(), "\r\x1b") {
				t.Fatalf("progress=%q want=%q", gotProgress, wantProgress)
			}
			if f.reference != wantRef {
				t.Fatalf("reference=%q want=%q", f.reference, wantRef)
			}
			data := mustRead(t, filepath.Join(f.workspace, "result.json"))
			record, raw := readRecord(t, filepath.Join(f.workspace, "result.json"))
			wantCommand := "build"
			if command == "sbom" {
				wantCommand = "sbom"
			}
			load := record.Stages.Load
			if record.Version != 6 || record.Command != wantCommand || record.Outcome != "succeeded" || record.Workspace != f.workspace || load.ImageReference != wantReadableRef || load.BuildReference != wantRef || load.Status != status || load.DockerImageID != imageID || load.ReadableReferenceConfirmed != (status == "loaded") || record.Evidence == nil || !record.Evidence.SPDXValidated || record.Evidence.SPDXSHA256 == "" {
				t.Fatalf("record=%+v", record)
			}
			if record.Request != (build.RecordRequest{Package: "postgresql-17", APKVersion: "17.10-r1", Load: status == "loaded"}) || record.Stages.Build.Status != "completed" || record.Stages.Publication != (build.RecordPublication{Status: "skipped"}) || record.Stages.Signing.Status != "skipped" || record.Stages.Attestation.Status != "skipped" {
				t.Fatalf("request/stages=%+v %+v", record.Request, record.Stages)
			}
			if record.Selection == nil || *record.Selection != (build.RecordSelection{Package: "postgresql-17", Version: "17.10-r1", Architecture: record.Selection.Architecture, IndexSHA256: record.Selection.IndexSHA256}) || record.Selection.IndexSHA256 == "" || record.Selection.Architecture == "" || record.Evidence.ApkoVersion != build.ApkoVersion || record.Evidence.ImageDirectory == "" || record.Evidence.ImageDigest != f.manifestDigest || record.Evidence.LockPath == "" || record.Evidence.SPDXPath == "" {
				t.Fatalf("selected APK/artifact evidence lost: %+v %+v", record.Selection, record.Evidence)
			}
			if _, ok := raw["failure"]; ok {
				t.Fatalf("success record has failure: %s", data)
			}
			if !strings.Contains(stdout.String(), "Validated SPDX:") || !strings.Contains(stdout.String(), "Image reference: "+wantReadableRef+"\n") || !strings.Contains(stdout.String(), "Build reference: "+wantRef+"\n") {
				t.Fatalf("stdout=%q", stdout.String())
			}
			if status == "loaded" {
				if !strings.Contains(stdout.String(), "Docker loaded: "+wantReadableRef+" (image ID: "+imageID+")") {
					t.Fatalf("stdout=%q", stdout.String())
				}
			} else {
				if !strings.Contains(stdout.String(), "Docker loading: skipped") || strings.Contains(string(data), "dockerImageID") {
					t.Fatalf("stdout=%q record=%s", stdout.String(), data)
				}
				if _, err := os.Stat(filepath.Join(f.workspace, "docker-image.tar")); !os.IsNotExist(err) {
					t.Fatalf("no-load created archive: %v", err)
				}
			}
		})
	}
}

func TestBuildLocalFailedStagesNeverReportSuccess(t *testing.T) {
	for _, failure := range []string{"lock substitution", "image package", "SPDX", "archive", "load", "inspect", "inspect mismatch", "bad saved config", "missing tag", "save", "malformed archive", "cancel save", "cancel index", "cancel lock", "cancel build", "cancel load", "cancel inspect", "cancel before tag", "tag", "readable inspect", "readable invalid ID", "readable ID mismatch", "readable OS mismatch", "readable arch mismatch", "readable malformed", "cancel tag", "cancel tag after response", "cancel readable inspect", "cancel readable inspect after response", "cancel finalization", "cancel skipped finalization", "result recording", "skipped result recording"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, failure, cancel)
			args := []string{"build", "postgresql-17", "--apk-version", "17.10-r1"}
			if failure == "skipped result recording" || failure == "cancel skipped finalization" {
				args = append(args, "--no-load")
			}
			var stdout, stderr bytes.Buffer
			var typed *build.WorkflowFailure
			runBuild := func(ctx context.Context, request cliRequest) (build.Result, error) {
				result, err := build.RunWith(ctx, request.Request, f.services)
				if !errors.As(err, &typed) || typed.Result.Workspace == "" {
					t.Fatalf("local failure is not a typed workflow failure with a workspace: %v", err)
				}
				if strings.HasPrefix(failure, "cancel") && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
				return result, err
			}
			stderrWriter := cancelOnRecordingWriter{output: &stderr, cancel: func() {}}
			if failure == "cancel finalization" {
				stderrWriter.cancel = cancel
			}
			if code := runWithBuild(ctx, args, &stdout, stderrWriter, runBuild); code != 1 || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			assertNoSuccessRecord(t, f.workspace)
			if !strings.Contains(stderr.String(), "lupetto: Fetching signed APKINDEX\n") || strings.ContainsAny(stderr.String(), "\r\x1b") || strings.Contains(stderr.String(), "Validated SPDX:") || strings.Contains(stderr.String(), "Docker loaded:") {
				t.Fatalf("missing progress or premature success in stderr: %q", stderr.String())
			}
			blockedStage := map[string]string{
				"lock substitution":                      "Composing OCI image with apko",
				"image package":                          "Validating SPDX against apko lock",
				"SPDX":                                   "Exporting Docker archive",
				"archive":                                "Loading image into Docker",
				"load":                                   "Inspecting Docker image identity",
				"inspect":                                "Recording build result",
				"inspect mismatch":                       "Recording build result",
				"bad saved config":                       "Recording build result",
				"missing tag":                            "Recording build result",
				"save":                                   "Verifying saved Docker image identity",
				"malformed archive":                      "Recording build result",
				"cancel index":                           "Fetching Wolfi signing key",
				"cancel lock":                            "Composing OCI image with apko",
				"cancel build":                           "Checking installed APK",
				"cancel load":                            "Inspecting Docker image identity",
				"cancel inspect":                         "Recording build result",
				"cancel save":                            "Verifying saved Docker image identity",
				"cancel before tag":                      "Tagging readable Docker reference",
				"tag":                                    "Inspecting readable Docker reference",
				"cancel tag":                             "Inspecting readable Docker reference",
				"cancel tag after response":              "Inspecting readable Docker reference",
				"readable inspect":                       "Recording build result",
				"readable invalid ID":                    "Recording build result",
				"readable ID mismatch":                   "Recording build result",
				"readable OS mismatch":                   "Recording build result",
				"readable arch mismatch":                 "Recording build result",
				"readable malformed":                     "Recording build result",
				"cancel readable inspect":                "Recording build result",
				"cancel readable inspect after response": "Recording build result",
			}[failure]
			if blockedStage != "" && strings.Contains(stderr.String(), "lupetto: "+blockedStage+"\n") {
				t.Fatalf("stage ran after failure/cancellation: %q", stderr.String())
			}
			if failure == "bad saved config" || failure == "missing tag" || failure == "save" || failure == "malformed archive" || failure == "cancel save" {
				wantEvents := []string{"apko version", "index", "apko lock", "apko build", "docker load", "docker inspect", "docker save"}
				if !reflect.DeepEqual(f.events, wantEvents) {
					t.Fatalf("fallback events=%q want=%q", f.events, wantEvents)
				}
				if !strings.Contains(stderr.String(), "composition completed but loading was not confirmed") || !strings.Contains(stderr.String(), "may have left an imported image/tag") {
					t.Fatalf("fallback uncertainty missing: %s", stderr.String())
				}
			}
			if f.workspace != "" && !strings.Contains(stderr.String(), "workspace: "+f.workspace) {
				t.Fatalf("workspace missing: %s", stderr.String())
			}
			// Local-only workflows now also leave a version-6 failure record
			// with the same detailed message the CLI prints.
			record, _ := readRecord(t, filepath.Join(typed.Result.Workspace, "failure.json"))
			if record.Version != 6 || record.Outcome != "failed" || record.Failure == nil || record.Failure.Error == "" || !strings.Contains(stderr.String(), record.Failure.Error) || record.Request.Publish || record.Stages.Publication.Status != "skipped" || record.Stages.Signing.Status != "skipped" {
				t.Fatalf("failure record=%+v failure=%+v stderr=%s", record, record.Failure, stderr.String())
			}
			wantStage := map[string]string{"lock substitution": "build", "image package": "build", "SPDX": "build", "cancel index": "build", "cancel lock": "build",
				"archive": "load", "load": "load", "inspect": "load", "bad saved config": "load", "save": "load",
				"tag": "readable-tag", "readable ID mismatch": "readable-tag", "cancel readable inspect after response": "readable-tag",
				"result recording": "record", "cancel finalization": "record", "skipped result recording": "record", "cancel skipped finalization": "record"}[failure]
			if wantStage != "" && record.Failure.Stage != wantStage {
				t.Fatalf("failure stage=%q want %q", record.Failure.Stage, wantStage)
			}
			switch record.Failure.Stage {
			case "build":
				if record.Stages.Build.Status != "failed" || record.Evidence != nil || record.Stages.Load.Status == "loaded" || record.Failure.SideEffectsPossible {
					t.Fatalf("build failure stages=%+v", record.Stages)
				}
			case "load":
				if record.Stages.Build.Status != "completed" || record.Stages.Load.Status != "failed" || record.Evidence == nil || !record.Failure.SideEffectsPossible {
					t.Fatalf("load failure stages=%+v", record.Stages)
				}
			case "readable-tag":
				if record.Stages.Load.Status != "loaded" || record.Stages.Load.ReadableReferenceConfirmed || record.Stages.Load.DockerImageID != f.dockerID {
					t.Fatalf("readable failure stages=%+v", record.Stages)
				}
			case "record":
				if record.Stages.Build.Status != "completed" || record.Failure.SideEffectsPossible != (record.Stages.Load.Status == "loaded") {
					t.Fatalf("record failure stages=%+v", record.Stages)
				}
			default:
				t.Fatalf("unexpected failure stage %q", record.Failure.Stage)
			}
			if failure == "result recording" || failure == "cancel finalization" {
				if !strings.Contains(stderr.String(), "Docker loading confirmed") || !strings.Contains(stderr.String(), "result recording failed") || !strings.Contains(stderr.String(), f.reference) || !strings.Contains(stderr.String(), f.readableReference) || !strings.Contains(stderr.String(), f.dockerID) {
					t.Fatalf("confirmed partial success missing: %s", stderr.String())
				}
			}
			if failure == "cancel before tag" || failure == "tag" || failure == "cancel tag" || failure == "cancel tag after response" || strings.HasPrefix(failure, "readable ") || strings.HasPrefix(failure, "cancel readable ") {
				if !strings.Contains(stderr.String(), "unique image "+f.reference+" was imported and verified") || !strings.Contains(stderr.String(), "readable tagging was not confirmed") || !strings.Contains(stderr.String(), "may already have changed local tags") || !strings.Contains(stderr.String(), f.readableReference) || !strings.Contains(stderr.String(), f.dockerID) {
					t.Fatalf("readable tag partial success/uncertainty missing: %s", stderr.String())
				}
			}
			if failure == "lock substitution" || failure == "image package" || failure == "SPDX" || failure == "archive" || failure == "cancel build" || failure == "cancel skipped finalization" {
				for _, event := range f.events {
					if strings.HasPrefix(event, "docker ") {
						t.Fatalf("Docker ran before validation succeeded: %q", f.events)
					}
				}
			}
		})
	}
}

func TestSBOMRejectsNoLoadWithoutStartingBuild(t *testing.T) {
	for _, args := range [][]string{
		{"sbom", "postgresql-17", "--apk-version", "17.10-r1", "--no-load"},
		{"sbom", "--no-load", "postgresql-17", "--apk-version=17.10-r1"},
		{"sbom", "postgresql-17", "--apk-version=17.10-r1", "--no-load=true"},
	} {
		var stdout, stderr bytes.Buffer
		runBuild := func(context.Context, cliRequest) (build.Result, error) {
			t.Fatal("sbom invalid flags started building")
			return build.Result{}, nil
		}
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, runBuild); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--no-load") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}
