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
	for _, tc := range []struct{ name, selector string }{
		{"postgresql", "17"},
		{"nginx", "1.30"},
		{"valkey", "9.1.2"},
		{"other-package", "2.0.10.3"},
		{"cmd:curl", "8.19"},
		{"so:libssl.so.3", "3"},
	} {
		request, err := parseBuild([]string{tc.name, tc.selector})
		if err != nil || request.packageName != tc.name || request.selector != tc.selector || request.version != "" {
			t.Fatalf("selector %s: request=%+v error=%v", tc.selector, request, err)
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
		{"non-numeric selector", []string{"postgresql", "17.rc"}},
		{"no selector", []string{"postgresql"}},
		{"conflicting selectors", []string{"postgresql", "17", "--apk-version", "17.10-r0"}},
		{"duplicate flag", []string{"postgresql", "--apk-version", "17.10-r0", "--apk-version=17.10-r1"}},
		{"unknown flag", []string{"postgresql", "--apk-version", "17.10-r0", "--unknown"}},
		{"unsafe package", []string{"../../pkg", "--apk-version", "17.10-r0"}},
		{"empty provider suffix", []string{"cmd:", "8.19"}},
		{"empty provider namespace", []string{":curl", "8.19"}},
		{"duplicate provider separator", []string{"cmd::curl", "8.19"}},
		{"unsafe version", []string{"postgresql", "--apk-version", "17.10-r0\nhello"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if request, err := parseBuild(tc.args); err == nil {
				t.Fatalf("parseBuild(%q) accepted %+v", tc.args, request)
			}
		})
	}
}

func TestParseBuildNoLoad(t *testing.T) {
	for _, args := range [][]string{
		{"valkey", "9.1", "--no-load"},
		{"--no-load", "valkey", "9.1"},
		{"valkey", "--no-load", "--apk-version=9.1.2-r1"},
		{"--apk-version", "9.1.2-r1", "--no-load", "valkey"},
	} {
		request, err := parseBuild(args)
		if err != nil || !request.noLoad {
			t.Fatalf("args=%q request=%+v err=%v", args, request, err)
		}
	}
	for _, args := range [][]string{
		{"valkey", "9.1", "--no-load", "--no-load"},
		{"valkey", "9.1", "--no-load=true"},
		{"valkey", "9.1", "--no-load=false"},
		{"valkey", "9.1", "--no-load", "false"},
		{"valkey", "--apk-version", "--no-load"},
	} {
		if request, err := parseBuild(args); err == nil {
			t.Fatalf("args=%q accepted %+v", args, request)
		}
	}
}

func TestRunRejectsInvalidBuildWithoutImage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"build", "postgresql", "--apk-version", "17.10"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "exact APK revision") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSBOMRequiresExactVersionBeforeBuilding(t *testing.T) {
	for _, args := range [][]string{
		{"sbom", "valkey", "9.1"},
		{"sbom", "valkey", "--apk-version", "9.1"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "exact APK revision") {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestHelpDescribesCurrentCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "lupetto discover <package-or-provider>") || !strings.Contains(stdout.String(), "lupetto build <package-or-provider>") || !strings.Contains(stdout.String(), "lupetto sbom <package-or-provider>") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, phrase := range []string{"log stages and live tool diagnostics to stderr", "ASCII spinner on interactive terminals"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Fatalf("help missing %q: %s", phrase, stdout.String())
		}
	}
}
