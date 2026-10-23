package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpAndInvalidFlags(t *testing.T) {
	for _, test := range []struct {
		args    []string
		code    int
		message string
	}{
		{[]string{"--help"}, 0, "127.0.0.1:8080"},
		{nil, 2, "--products is required"},
		{[]string{"--products", "products.yaml", "--refresh-interval", "0"}, 2, "must be positive"},
		{[]string{"--products", "products.yaml", "--listen", "invalid"}, 2, "invalid --listen"},
		{[]string{"--products", "products.yaml", "--lupetto-binary", "/nonexistent/lupetto"}, 2, "configured lupetto binary"},
		{[]string{"--products", "products.yaml", "--allowed-host", "*"}, 2, "invalid --allowed-host"},
		{[]string{"--products", "products.yaml", "--allowed-host", "example.invalid", "--allowed-host", "[::1]:8080", "--lupetto-binary", "/nonexistent/lupetto"}, 2, "configured lupetto binary"},
		{[]string{"extra"}, 2, "unexpected positional"},
		{[]string{"--registry", "127.0.0.1:5000"}, 2, "flag provided but not defined"},
		{[]string{"--products", "products.yaml", "--scan-max-image-size", "2GB"}, 2, "invalid size"},
		{[]string{"--products", "products.yaml", "--scan-max-image-size", "0"}, 2, "invalid size"},
		{[]string{"--products", "products.yaml", "--scan-interval", "-1h"}, 2, "--scan-interval must not be negative"},
		{[]string{"--help"}, 0, "grype.anchore.io"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), test.args, &stdout, &stderr); code != test.code {
			t.Fatalf("args=%v code=%d stderr=%s", test.args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), test.message) {
			t.Fatalf("args=%v stderr=%s", test.args, stderr.String())
		}
	}
}

func TestParseSize(t *testing.T) {
	for value, want := range map[string]int64{"1": 1, "512KiB": 512 << 10, "100MiB": 100 << 20, "2GiB": 2 << 30} {
		if got, err := parseSize(value); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "GiB", "-1", "1.5GiB", "2GB", "2 GiB", "9999999999GiB"} {
		if _, err := parseSize(value); err == nil {
			t.Errorf("parseSize(%q) accepted", value)
		}
	}
}
