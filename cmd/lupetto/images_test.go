package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lupetto/internal/images"
)

func TestImagesCLIJSONAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	compute := func(context.Context) (images.Document, error) {
		return images.Document{Kind: "images", Version: 1, Builds: []images.History{}, Docker: images.Docker{Available: false, Reason: "Docker unavailable", Images: []images.Image{}}}, nil
	}
	code := runImagesWith(context.Background(), []string{"--json"}, &stdout, &stderr, compute)
	var document images.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); code != 0 || err != nil || document.Kind != "images" || document.Version != 1 || document.Docker.Available || document.Docker.Reason == "" {
		t.Fatalf("exit %d document %+v err %v", code, document, err)
	}
	for _, args := range [][]string{{"--json", "--json"}, {"--json=true"}, {"busybox"}, {"--products", "products.yaml"}} {
		stdout.Reset()
		stderr.Reset()
		called := false
		code = runImagesWith(context.Background(), args, &stdout, &stderr, func(context.Context) (images.Document, error) { called = true; return images.Document{}, nil })
		if code != 2 || stdout.Len() != 0 || called {
			t.Fatalf("args %v: exit %d stdout=%s called=%v", args, code, &stdout, called)
		}
	}
	stdout.Reset()
	stderr.Reset()
	code = runImagesWith(context.Background(), []string{"--json"}, &stdout, &stderr, func(context.Context) (images.Document, error) {
		return images.Document{}, errors.New("history exceeds bound")
	})
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("failure: exit %d stdout=%s", code, &stdout)
	}
	stdout.Reset()
	stderr.Reset()
	code = runImagesWith(context.Background(), nil, &stdout, &stderr, compute)
	if code != 0 || !strings.Contains(stdout.String(), "Docker unavailable") || !strings.Contains(stdout.String(), "BUILD HISTORY") {
		t.Fatalf("human output: exit %d stdout=%s", code, &stdout)
	}
}
