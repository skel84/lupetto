package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"lupetto/internal/products"
)

func TestProductsCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"products", "add", "curl", "8", "--products", path, "--create", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	var document products.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil || document.Kind != "products" || document.Version != 1 || !document.Changed {
		t.Fatalf("document: %+v %v", document, err)
	}
	for _, args := range [][]string{
		{"list", "--products", path, "--json", "--json"}, {"add", "curl", "8..1", "--products", path, "--json"},
		{"list", "--products", path, "--create"}, {"add", "curl", "--products", path}, {"remove", "--products", path}, {"list", "curl", "--products", path},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runProducts(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("%v: exit %d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := runProducts([]string{"list", "--products", path + "missing", "--json"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("missing file: exit %d %s", code, &stdout)
	}
	os.Chmod(path, 0400)
	stdout.Reset()
	stderr.Reset()
	if code := runProducts([]string{"add", "curl", "9", "--products", path, "--json"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("read-only: exit %d %s", code, &stdout)
	}
}
