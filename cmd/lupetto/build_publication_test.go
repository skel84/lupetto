package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exportedPublicationBytes(t *testing.T, filename string) ([]byte, []byte) {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	entries := make(map[string][]byte)
	tr := tar.NewReader(file)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name], err = io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
	}
	var manifest []savedManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil || len(manifest) != 1 || len(manifest[0].Layers) != 1 {
		t.Fatalf("exported manifest=%+v err=%v", manifest, err)
	}
	return entries[manifest[0].Config], entries[manifest[0].Layers[0]]
}

func addPublicationFixture(t *testing.T, f *pipelineFixture, failure string, cancel context.CancelFunc) {
	t.Helper()
	f.services.publicationCommand = func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		if executable != "docker" {
			t.Fatalf("unexpected executable %q", executable)
		}
		stage := args[1]
		f.events = append(f.events, "publication "+stage)
		if failure == stage {
			return []byte(publicationCanary), errors.New(publicationCanary)
		}
		if failure == "cancel "+stage {
			cancel()
		}
		switch stage {
		case "tag":
			if args[2] != f.dockerID || !strings.Contains(args[3], "-build-") {
				t.Fatalf("remote tag must use verified ID and unique target: %q", args)
			}
		case "inspect":
			arch, err := targetArch()
			if err != nil {
				t.Fatal(err)
			}
			ociArch, err := ociArchitecture(arch)
			if err != nil {
				t.Fatal(err)
			}
			return []byte(fmt.Sprintf(`{"Id":%q,"Os":"linux","Architecture":%q}`, f.dockerID, ociArch)), nil
		case "push":
			return publicationSummary(remoteTag(args[2])), nil
		case "pull":
			if !strings.HasSuffix(args[2], "@"+fixturePushDigest) {
				t.Fatalf("mutable pull reference %q", args)
			}
		case "save":
			if !strings.HasSuffix(args[4], "@"+fixturePushDigest) {
				t.Fatalf("mutable save reference %q", args)
			}
			config, layer := exportedPublicationBytes(t, filepath.Join(f.workspace, "docker-image.tar"))
			writePublicationArchive(t, args[3], config, layer, failure)
		default:
			t.Fatalf("unexpected publication command %q", args)
		}
		return nil, nil
	}
}

func publicationCLIArgs() []string {
	return []string{"build", "postgresql-17", "--apk-version", "17.10-r1", "--registry", "localhost:5000", "--repository", "team/images"}
}

func TestBuildPublicationSingleCompositionAndV4Evidence(t *testing.T) {
	for _, localFixture := range []string{"", "fallback"} {
		t.Run(localFixture, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, localFixture, cancel)
			addPublicationFixture(t, f, "", cancel)
			var stdout, stderr bytes.Buffer
			var result buildResult
			code := runWithBuild(ctx, publicationCLIArgs(), &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				var err error
				result, err = buildLocalWith(ctx, request, f.services)
				return result, err
			})
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if result.publication.status != "published" || !result.publication.verified || result.publication.pushedDigest != fixturePushDigest || result.publication.immutableReference != "localhost:5000/team/images/postgresql-17@"+fixturePushDigest {
				t.Fatalf("result=%+v", result)
			}
			builds, locks, indexes := 0, 0, 0
			for _, event := range f.events {
				switch event {
				case "apko build":
					builds++
				case "apko lock":
					locks++
				case "index":
					indexes++
				}
			}
			if builds != 1 || locks != 1 || indexes != 1 {
				t.Fatalf("resolved/composed multiple times: %q", f.events)
			}
			if !strings.Contains(stdout.String(), result.publication.immutableReference) || strings.Contains(stdout.String(), publicationCanary) || strings.Contains(stderr.String(), publicationCanary) {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			data, err := os.ReadFile(filepath.Join(f.workspace, "result.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record evidenceResult
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			if record.Version != 4 || record.Publication == nil || !record.Publication.Verified || record.Publication.PushedDigest != fixturePushDigest || record.Build != "completed" || record.Signing != "skipped" || record.Attestation != "skipped" {
				t.Fatalf("record=%+v", record)
			}
			if _, err := os.Stat(filepath.Join(f.workspace, "failure.json")); !os.IsNotExist(err) {
				t.Fatalf("unexpected failure record: %v", err)
			}
		})
	}
}

func TestBuildPublicationTypedPartialFailureAndNoSuccessOutput(t *testing.T) {
	for _, tc := range []struct {
		name, local, remote, stage, build, load, publication string
		captured, verified                                   bool
	}{
		{"composition", "build", "", "build", "failed", "not-attempted", "skipped", false, false},
		{"load", "load", "", "load", "completed", "failed", "skipped", false, false},
		{"readable alias", "readable ID mismatch", "", "readable-tag", "completed", "loaded; readable tag unconfirmed", "skipped", false, false},
		{"tag", "", "tag", "publication", "completed", "loaded", "failed", false, false},
		{"push", "", "push", "publication", "completed", "loaded", "failed", false, false},
		{"pull", "", "pull", "publication", "completed", "loaded", "failed", true, false},
		{"save", "", "save", "publication", "completed", "loaded", "failed", true, false},
		{"content", "", "layer", "publication", "completed", "loaded", "failed", true, false},
		{"cancel", "", "cancel pull", "publication", "completed", "loaded", "failed", true, false},
		{"record", "result recording", "", "record", "completed", "loaded", "published", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, tc.local, cancel)
			addPublicationFixture(t, f, tc.remote, cancel)
			var stdout, stderr bytes.Buffer
			var caught error
			code := runWithBuild(ctx, publicationCLIArgs(), &stdout, &stderr, func(ctx context.Context, request buildRequest) (buildResult, error) {
				result, err := buildLocalWith(ctx, request, f.services)
				caught = err
				return result, err
			})
			var wf *workflowFailure
			if code == 0 || stdout.Len() != 0 || !errors.As(caught, &wf) {
				t.Fatalf("code=%d stdout=%q caught=%v", code, stdout.String(), caught)
			}
			if wf.stage != tc.stage || wf.build != tc.build || wf.load != tc.load || wf.result.publication.status != tc.publication || wf.result.publication.verified != tc.verified || (wf.result.publication.pushedDigest != "") != tc.captured {
				t.Fatalf("workflow=%+v result=%+v", wf, wf.result)
			}
			if tc.name == "readable alias" && (wf.result.dockerImageID == "" || wf.result.dockerLoad != "loaded") {
				t.Fatal("forgot confirmed unique local load")
			}
			if strings.Contains(stderr.String(), publicationCanary) || strings.Contains(caught.Error(), publicationCanary) {
				t.Fatalf("unsafe diagnostics=%q", stderr.String())
			}
			for _, stage := range []string{"build:", "Docker load:", "publication:", "signing: skipped", "attestation: skipped"} {
				if !strings.Contains(stderr.String(), stage) {
					t.Fatalf("missing %q: %q", stage, stderr.String())
				}
			}
			assertNoSuccessRecord(t, f.workspace)
			data, err := os.ReadFile(filepath.Join(f.workspace, "failure.json"))
			if err != nil || bytes.Contains(data, []byte(publicationCanary)) {
				t.Fatalf("record=%q err=%v", data, err)
			}
			var partial struct {
				Stage       string
				Build       string
				Load        string
				Publication publicationEvidence
				Signing     string
				Attestation string
			}
			if err := json.Unmarshal(data, &partial); err != nil {
				t.Fatal(err)
			}
			if partial.Stage != tc.stage || partial.Build != tc.build || partial.Load != tc.load || partial.Publication.Status != tc.publication || partial.Publication.Verified != tc.verified || (partial.Publication.PushedDigest != "") != tc.captured {
				t.Fatalf("partial=%+v", partial)
			}
		})
	}
}

func TestBuildPublicationRejectedBeforeExternalBoundaries(t *testing.T) {
	for _, request := range []buildRequest{
		{publication: publicationOptions{registry: "localhost:5000"}},
		{publication: publicationOptions{registry: "https://example.com", repository: "team/images"}},
		{noLoad: true, publication: publicationOptions{registry: "localhost:5000", repository: "team/images"}},
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
	if !errors.As(err, &wf) || wf.result.workspace != "" || wf.build != "failed" || wf.load != "not-attempted" || strings.Contains(err.Error(), publicationCanary) {
		t.Fatalf("workflow=%+v err=%v", wf, err)
	}
	var stderr bytes.Buffer
	if !reportWorkflowFailure(&stderr, err) || strings.Contains(stderr.String(), publicationCanary) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
