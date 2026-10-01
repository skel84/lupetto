package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDiscoverRejectsInvalidArgsBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{nil, {"nginx", "extra"}, {"../../nginx"}, {"--help"}, {"cmd:"}, {":curl"}, {"cmd::curl"}} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), append([]string{"discover"}, args...), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "discover requires one valid") {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q", args, code, stdout.String(), stderr.String())
		}
	}
}
