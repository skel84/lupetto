package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseBuildPreservesExactRevision(t *testing.T) {
	for _, args := range [][]string{
		{"wolfi-base", "--apk-version", "1.2.3-r12"},
		{"--apk-version=1.2.3-r12", "wolfi-base"},
	} {
		request, err := parseBuild(args)
		if err != nil {
			t.Fatalf("parseBuild(%q): %v", args, err)
		}
		if request.packageName != "wolfi-base" || request.version != "1.2.3-r12" {
			t.Fatalf("parseBuild(%q) = %+v; want exact revision r12", args, request)
		}
	}
}

func TestParseBuildRejectsInvalidRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no revision", []string{"pkg", "--apk-version", "1.2.3"}},
		{"missing version", []string{"pkg", "--apk-version"}},
		{"empty version", []string{"pkg", "--apk-version="}},
		{"major selector", []string{"pkg", "12"}},
		{"no selector", []string{"pkg"}},
		{"conflicting selectors", []string{"pkg", "12", "--apk-version", "1.2.3-r0"}},
		{"duplicate flag", []string{"pkg", "--apk-version", "1.2.3-r0", "--apk-version=1.2.3-r1"}},
		{"unknown flag", []string{"pkg", "--apk-version", "1.2.3-r0", "--no-load"}},
		{"unsafe package", []string{"../../pkg", "--apk-version", "1.2.3-r0"}},
		{"unsafe version", []string{"pkg", "--apk-version", "1.2.3-r0\nhello"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if request, err := parseBuild(tc.args); err == nil {
				t.Fatalf("parseBuild(%q) accepted %+v", tc.args, request)
			}
		})
	}
}

func TestRunNeverReportsACompletedBuild(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"build", "pkg", "--apk-version", "1.2.3-r0"}, &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "no image or SBOM was created") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestHelpDescribesCurrentCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "not implemented") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
