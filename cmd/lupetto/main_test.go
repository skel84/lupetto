package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestParseBuildPreservesExactRevision(t *testing.T) {
	for _, args := range [][]string{
		{"postgresql", "--apk-version", "17.10-r12"},
		{"--apk-version=17.10-r12", "postgresql"},
	} {
		request, err := parseBuild(args)
		if err != nil {
			t.Fatalf("parseBuild(%q): %v", args, err)
		}
		if request.packageName != "postgresql" || request.version != "17.10-r12" || request.selector != "" {
			t.Fatalf("parseBuild(%q) = %+v; want exact revision r12", args, request)
		}
	}
}

func TestParseBuildSelectors(t *testing.T) {
	for _, selector := range []string{"17", "17.1", "17.2", "17.3", "17.10"} {
		request, err := parseBuild([]string{"postgresql", selector})
		if err != nil || request.selector != selector || request.version != "" {
			t.Fatalf("selector %s: request=%+v error=%v", selector, request, err)
		}
	}
}

func TestParseBuildRejectsInvalidRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no revision", []string{"postgresql", "--apk-version", "17.1"}},
		{"missing version", []string{"postgresql", "--apk-version"}},
		{"empty version", []string{"postgresql", "--apk-version="}},
		{"wrong major", []string{"postgresql", "16"}},
		{"no selector", []string{"postgresql"}},
		{"conflicting selectors", []string{"postgresql", "17", "--apk-version", "17.10-r0"}},
		{"duplicate flag", []string{"postgresql", "--apk-version", "17.10-r0", "--apk-version=17.10-r1"}},
		{"unknown flag", []string{"postgresql", "--apk-version", "17.10-r0", "--no-load"}},
		{"unsafe package", []string{"../../pkg", "--apk-version", "17.10-r0"}},
		{"unsupported package", []string{"wolfi-base", "--apk-version", "17.10-r0"}},
		{"unsafe version", []string{"postgresql", "--apk-version", "17.10-r0\nhello"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if request, err := parseBuild(tc.args); err == nil {
				t.Fatalf("parseBuild(%q) accepted %+v", tc.args, request)
			}
		})
	}
}

func TestRunRejectsInvalidBuildWithoutImage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"build", "postgresql", "--apk-version", "17.10"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "exact PostgreSQL 17 APK revision") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestHelpDescribesCurrentCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "lupetto build postgresql 17[.minor]") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
