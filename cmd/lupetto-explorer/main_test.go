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
		{[]string{"extra"}, 2, "unexpected positional"},
		{[]string{"--registry", "127.0.0.1:5000"}, 2, "flag provided but not defined"},
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
