package images

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lupetto/internal/build"
)

func fixtureRecord(t *testing.T, root, suffix, outcome string, id string) string {
	t.Helper()
	workspace := filepath.Join(root, "image-"+suffix)
	if err := os.MkdirAll(filepath.Join(workspace, "sbom"), 0700); err != nil {
		t.Fatal(err)
	}
	spdx := filepath.Join(workspace, "sbom", "sbom-x86_64.spdx.json")
	data := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	os.WriteFile(spdx, data, 0600)
	checksum := sha256.Sum256(data)
	record := build.Record{Version: 6, Command: "build", Outcome: outcome, Workspace: workspace, Request: build.RecordRequest{Package: "busybox-static", Selector: "1", Load: id != ""}, Selection: &build.RecordSelection{Package: "busybox-static", Version: "1.38.0-r2", Architecture: "x86_64"}, Evidence: &build.RecordEvidence{SPDXValidated: true, SPDXPath: spdx, SPDXSHA256: hex.EncodeToString(checksum[:]), ImageDigest: "sha256:" + strings.Repeat("b", 64)}, Stages: build.RecordStages{Build: build.RecordStatus{Status: "completed"}, Load: build.RecordLoad{Status: "loaded", DockerImageID: id, ImageReference: "lupetto/busybox-static:1.38.0-r2-amd64", BuildReference: "lupetto/local:build-" + suffix}, Publication: build.RecordPublication{Status: "skipped"}, Signing: build.RecordStatus{Status: "skipped"}, Attestation: build.RecordStatus{Status: "skipped"}}}
	if id == "" {
		record.Stages.Load.Status = "skipped"
	}
	filename := "result.json"
	if outcome == "failed" {
		filename = "failure.json"
		record.Failure = &build.RecordFailure{Stage: "publication", Error: "publication failed", SideEffectsPossible: true}
		record.Stages.Publication.Status = "failed"
	}
	encoded, _ := json.Marshal(record)
	path := filepath.Join(workspace, filename)
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(workspace, "apko.yaml"), []byte("annotations:\n  org.opencontainers.image.created: 2026-10-01T12:00:00Z\n"), 0600)
	return path
}

func fakeDocker(t *testing.T, script string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "docker"), []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
}

func TestImagesHistoryAndDocker(t *testing.T) {
	root := t.TempDir()
	id := "sha256:" + strings.Repeat("a", 64)
	old := fixtureRecord(t, root, "old", "succeeded", id)
	failure := fixtureRecord(t, root, "failed", "failed", "")
	oldTime := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	os.Chtimes(old, oldTime, oldTime)
	os.Chtimes(failure, newTime, newTime)
	unsupportedWorkspace := filepath.Join(root, "image-unsupported")
	os.Mkdir(unsupportedWorkspace, 0700)
	os.WriteFile(filepath.Join(unsupportedWorkspace, "result.json"), []byte(`{"version":99,"command":{"not":"a v6 string"}}`), 0600)
	newestTime := newTime.Add(time.Hour)
	os.Chtimes(filepath.Join(unsupportedWorkspace, "result.json"), newestTime, newestTime)
	script := fmt.Sprintf(`case "$1 $2" in
 "image ls") [ "$3" = "--filter" ] || exit 12; [ "$4" = "reference=lupetto/*" ] || exit 13; printf '%%s\n%%s\n' '%s' '%s';;
 "image inspect") printf '%%s\n' '[{"Id":"%s","RepoTags":["lupetto/local:build-old","other/not-lupetto:tag","lupetto/busybox-static:1.38.0-r2-amd64"],"Created":"2026-10-01T12:00:00Z","Size":12345}]';;
 *) exit 11;;
esac
`, id, id, id)
	fakeDocker(t, script)
	document, err := RunAt(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if document.Kind != "images" || document.Version != 1 || len(document.Builds) != 3 || !document.Docker.Available || len(document.Docker.Images) != 1 {
		t.Fatalf("document: %+v", document)
	}
	if document.Builds[0].Status != "unsupported" || document.Builds[0].Record != nil || document.Builds[0].RecordVersion != 99 {
		t.Fatalf("unsupported parsed: %+v", document.Builds[0])
	}
	if document.Builds[1].Record.Failure.Stage != "publication" || !document.Builds[1].SPDX.Present || document.Builds[1].BuildTime != "2026-10-01T12:00:00Z" {
		t.Fatalf("failed entry: %+v", document.Builds[1])
	}
	image := document.Docker.Images[0]
	if !image.IdentityKnown || image.IdentitySource != "build-record" || image.Identity.Name != "busybox-static" || len(image.Tags) != 2 || image.Size != 12345 {
		t.Fatalf("image: %+v", image)
	}
}

func TestImagesDockerUnavailableAndEmpty(t *testing.T) {
	root := t.TempDir()
	fixtureRecord(t, root, "noload", "succeeded", "")
	fakeDocker(t, "exit 1\n")
	document, err := RunAt(context.Background(), root)
	if err != nil || document.Docker.Available || document.Docker.Reason == "" || len(document.Builds) != 1 || document.Docker.Images == nil {
		t.Fatalf("unavailable: %+v %v", document, err)
	}
	fakeDocker(t, "[ \"$1 $2\" = \"image ls\" ] || exit 9\nexit 0\n")
	document, err = RunAt(context.Background(), root+"missing")
	if err != nil || !document.Docker.Available || len(document.Docker.Images) != 0 || document.Builds == nil {
		t.Fatalf("empty: %+v %v", document, err)
	}
	t.Setenv("PATH", t.TempDir())
	document, err = RunAt(context.Background(), root)
	if err != nil || document.Docker.Available || !strings.Contains(document.Docker.Reason, "PATH") {
		t.Fatalf("missing CLI: %+v %v", document, err)
	}
}

func TestImagesIdentityInference(t *testing.T) {
	for _, test := range []struct {
		tags   []string
		source string
		name   string
	}{
		{[]string{"lupetto/local:build-1", "lupetto/curl:8.2.0-r1-amd64"}, "readable-tag", "curl"},
		{[]string{"lupetto/curl:8.2.0-r1-arm64"}, "readable-tag", "curl"},
		{[]string{"lupetto/local:build-1"}, "unknown", ""},
		{[]string{"lupetto/apk-sha256-abc:1-r0-amd64"}, "unknown", ""},
		{[]string{"lupetto/curl:_apk-sha256-abc-amd64"}, "unknown", ""},
		{[]string{"lupetto/curl:8.2.0-r1-amd64", "lupetto/curl:8.3.0-r0-amd64"}, "unknown", ""},
	} {
		identity, source := identify("id", test.tags, nil)
		if source != test.source || (identity == nil) != (test.name == "") || (identity != nil && identity.Name != test.name) {
			t.Fatalf("%v => %+v %s", test.tags, identity, source)
		}
	}
	history := []History{{Record: &build.Record{Selection: &build.RecordSelection{Package: "curl", Version: "8.2.0-r1", Architecture: "x86_64"}, Stages: build.RecordStages{Load: build.RecordLoad{DockerImageID: "id"}}}}, {Record: &build.Record{Selection: &build.RecordSelection{Package: "curl", Version: "8.3.0-r0", Architecture: "x86_64"}, Stages: build.RecordStages{Load: build.RecordLoad{DockerImageID: "id"}}}}}
	if identity, source := identify("id", []string{"lupetto/curl:8.2.0-r1-amd64"}, history); identity != nil || source != "unknown" {
		t.Fatalf("ambiguous records: %+v %s", identity, source)
	}
}

func TestImagesSPDXMissingChangedAndUnsafe(t *testing.T) {
	root := t.TempDir()
	path := fixtureRecord(t, root, "spdx", "succeeded", "")
	data, _ := os.ReadFile(path)
	var record build.Record
	json.Unmarshal(data, &record)
	workspace := filepath.Dir(path)
	os.WriteFile(record.Evidence.SPDXPath, []byte("changed"), 0600)
	if spdx := checkSPDX(workspace, record.Evidence); spdx.Present || !strings.Contains(spdx.Reason, "checksum") {
		t.Fatalf("changed: %+v", spdx)
	}
	os.Remove(record.Evidence.SPDXPath)
	if spdx := checkSPDX(workspace, record.Evidence); spdx.Present {
		t.Fatalf("missing: %+v", spdx)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("outside"), 0600)
	os.Symlink(outside, record.Evidence.SPDXPath)
	if spdx := checkSPDX(workspace, record.Evidence); spdx.Present || !strings.Contains(spdx.Reason, "outside") {
		t.Fatalf("symlink escape: %+v", spdx)
	}
}

func TestImagesBoundsMalformedAndCancellation(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "image-invalid")
	os.Mkdir(workspace, 0700)
	os.WriteFile(filepath.Join(workspace, "result.json"), []byte("not JSON"), 0600)
	os.WriteFile(filepath.Join(workspace, "failure.json"), []byte(strings.Repeat(" ", MaxRecordBytes+1)), 0600)
	history, err := scanHistory(context.Background(), root)
	if err != nil || len(history) != 2 {
		t.Fatalf("history: %+v %v", history, err)
	}
	statuses := map[string]bool{}
	for _, item := range history {
		statuses[item.Status] = true
	}
	if !statuses["invalid"] || !statuses["unreadable"] {
		t.Fatalf("statuses: %v", statuses)
	}
	for i := range MaxRecords {
		directory := filepath.Join(root, fmt.Sprintf("record-%d", i))
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "result.json"), []byte(`{"version":99}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scanHistory(context.Background(), root); err == nil || !strings.Contains(err.Error(), "retained records") {
		t.Fatalf("record bound: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunAt(ctx, root); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestImagesDockerMalformedBoundedAndSanitized(t *testing.T) {
	root := t.TempDir()
	id := "sha256:" + strings.Repeat("a", 64)
	for _, script := range []string{
		"printf 'not-an-image-id\\n'\n",
		"printf '%4194305s' ''\n",
		fmt.Sprintf("case \"$1 $2\" in\n'image ls') printf '%%s\\n' '%s';;\n'image inspect') printf 'invalid JSON';;\n*) exit 8;;\nesac\n", id),
		"printf 'DOCKER_CREDENTIAL_CANARY' >&2\nexit 1\n",
	} {
		fakeDocker(t, script)
		document, err := RunAt(context.Background(), root)
		if err != nil || document.Docker.Available || document.Docker.Reason == "" || len(document.Docker.Images) != 0 || strings.Contains(document.Docker.Reason, "CANARY") {
			t.Fatalf("invalid Docker result: %+v %v", document, err)
		}
	}
}
