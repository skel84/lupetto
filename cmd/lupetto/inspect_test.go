package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lupetto/internal/status"
)

func TestInspectCLI(t *testing.T) {
	reference := "127.0.0.1:5000/team/curl@sha256:" + strings.Repeat("a", 64)
	for _, args := range [][]string{{"--json", reference}, {reference, "--json"}} {
		var stdout, stderr bytes.Buffer
		code := runInspectWith(context.Background(), args, &stdout, &stderr, func(_ context.Context, got string) (status.InspectDocument, error) {
			if got != reference {
				t.Fatal(got)
			}
			return status.InspectDocument{Kind: "inspect", Version: 1, Reference: got, Unidentified: true, Packages: []status.Identity{}}, nil
		})
		var document status.InspectDocument
		if code != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &document) != nil || document.Kind != "inspect" || document.Version != 1 || !strings.HasSuffix(stdout.String(), "\n") {
			t.Fatalf("code %d stdout %s stderr %s", code, &stdout, &stderr)
		}
	}
	for _, args := range [][]string{nil, {reference}, {"--json"}, {"--json", reference, reference}, {"--json", "--json", reference}, {"--json", "registry.example.invalid/team/curl:latest"}, {"--json", reference, "--registry=x"}} {
		var stdout, stderr bytes.Buffer
		if code := runInspectWith(context.Background(), args, &stdout, &stderr, func(context.Context, string) (status.InspectDocument, error) {
			t.Fatal("called on invalid invocation")
			return status.InspectDocument{}, nil
		}); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args %v code %d", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runInspectWith(context.Background(), []string{"--json", reference}, &stdout, &stderr, func(context.Context, string) (status.InspectDocument, error) {
		return status.InspectDocument{}, errors.New("inspect manifest failed")
	}); code != 1 || stdout.Len() != 0 {
		t.Fatalf("failure code %d stdout %s", code, &stdout)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"inspect"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "inspect requires") {
		t.Fatalf("dispatch %d %s", code, &stderr)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "lupetto inspect --json") {
		t.Fatalf("help %d %s", code, &stdout)
	}
}
