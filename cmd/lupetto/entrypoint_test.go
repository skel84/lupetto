package main

import (
	"slices"
	"strings"
	"testing"
)

func TestParseBuildEntrypoint(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"kyverno", "1"}, nil},
		{[]string{"kyverno", "1", "--entrypoint", "/usr/bin/kyverno"}, []string{"/usr/bin/kyverno"}},
		{[]string{"--entrypoint=/usr/bin/memcached", "memcached", "--entrypoint=-u", "1", "--entrypoint", "memcached"}, []string{"/usr/bin/memcached", "-u", "memcached"}},
		{[]string{"tool", "--apk-version", "1.0-r0", "--entrypoint=/usr/bin/tool", "--entrypoint=two words"}, []string{"/usr/bin/tool", "two words"}},
	} {
		request, err := parseBuild(tc.args)
		if err != nil || !slices.Equal(request.Image.Entrypoint, tc.want) || (tc.want == nil) != (request.Image.Entrypoint == nil) {
			t.Errorf("parseBuild(%q) entrypoint=%q err=%v; want %q", tc.args, request.Image.Entrypoint, err, tc.want)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"tool", "1", "--entrypoint"}, "requires a value"},
		{[]string{"tool", "1", "--entrypoint", "-u"}, "--entrypoint=<element>"},
		{[]string{"tool", "1", "--entrypoint="}, "non-empty"},
		{[]string{"tool", "1", "--entrypoint", "tool"}, "absolute path"},
		{[]string{"tool", "1", "--entrypoint=/usr/bin/tool", "--entrypoint=it's"}, "single quotes"},
	} {
		if request, err := parseBuild(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseBuild(%q) = %+v err=%v; want %q", tc.args, request, err, tc.want)
		}
	}
}

func TestParseBuildCABundle(t *testing.T) {
	if request, err := parseBuild([]string{"external-dns-0.21", "0"}); err != nil || request.Image.CABundle {
		t.Fatalf("default=%+v err=%v", request.Image, err)
	}
	if request, err := parseBuild([]string{"--ca-bundle", "external-dns-0.21", "--apk-version", "0.21.0-r9"}); err != nil || !request.Image.CABundle {
		t.Fatalf("--ca-bundle=%+v err=%v", request.Image, err)
	}
	for _, args := range [][]string{{"tool", "1", "--ca-bundle", "--ca-bundle"}, {"tool", "1", "--ca-bundle=true"}} {
		if _, err := parseBuild(args); err == nil {
			t.Errorf("parseBuild(%q) accepted", args)
		}
	}
}
