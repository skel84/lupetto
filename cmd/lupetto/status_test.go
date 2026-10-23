package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lupetto/internal/status"
)

func TestParseStatus(t *testing.T) {
	for _, args := range [][]string{
		{"--products", "products.yaml", "--json", "--registry", "127.0.0.1:5000", "--repository", "team/images"},
		{"--repository=team/images", "--products=products.yaml", "--registry=127.0.0.1:5000", "--json"},
	} {
		request, err := parseStatus(args)
		if err != nil || request.products != "products.yaml" || !request.json || !request.publicationFlags.Registry.Set || request.publicationFlags.Registry.Value != "127.0.0.1:5000" || request.publicationFlags.Repository.Value != "team/images" {
			t.Fatalf("parseStatus(%q) = %+v, %v", args, request, err)
		}
	}
	for _, args := range [][]string{
		nil, {"--json"}, {"products.yaml"}, {"--products"}, {"--products="},
		{"--products=p", "--products=q"}, {"--products=p", "--json", "--json"},
		{"--products=p", "--exit-code", "--exit-code"}, {"--products=p", "--exit-code=true"},
		{"--products=p", "--json=true"}, {"--products=p", "--registry"},
		{"--products=p", "--registry="}, {"--products=p", "--repository="},
		{"--products=p", "--registry=a", "--registry=b"},
		{"--products=p", "--repository=a", "--repository=b"},
		{"--products=p", "--cosign-key=x"}, {"--products=p", "--no-load"},
		{"--products=p", "--apk-version=1-r0"}, {"--products=p", "nginx"},
	} {
		if request, err := parseStatus(args); err == nil {
			t.Fatalf("accepted %q: %+v", args, request)
		}
	}
}

func statusProductsFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "products.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nproducts:\n  - package: nginx\n    selectors: [\"1.30\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStatusConfigurationPrecedenceAndTrackErrorExit(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "invalid/environment")
	t.Setenv("LUPETTO_REPOSITORY", "env/team")
	// Signing inputs never influence this read-only command.
	t.Setenv("LUPETTO_COSIGN_KEY", "not-a-key")
	t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "not-a-boolean")
	var stdout, stderr bytes.Buffer
	called := false
	code := runStatusWith(context.Background(), []string{"--products", statusProductsFixture(t), "--registry=127.0.0.1:5000", "--json"}, &stdout, &stderr, func(ctx context.Context, products status.Products, opts status.Options) (status.Document, error) {
		called = true
		if opts.Registry != "127.0.0.1:5000" || opts.Repository != "env/team" || len(products.Products) != 1 {
			t.Fatalf("opts=%+v products=%+v", opts, products)
		}
		return status.Document{Kind: "status", Version: 2, Tracks: []status.Track{{Package: "nginx", Selector: "1.30", State: "error", Error: "selector unavailable"}}}, nil
	})
	if !called || code != 0 || stderr.Len() != 0 {
		t.Fatalf("called=%v code=%d stdout=%q stderr=%q", called, code, stdout.String(), stderr.String())
	}
	var document status.Document
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil || document.Kind != "status" || document.Version != 2 || document.Tracks[0].State != "error" {
		t.Fatalf("document=%+v error=%v", document, err)
	}
}

func TestStatusInvocationErrorsBeforeCompute(t *testing.T) {
	path := statusProductsFixture(t)
	t.Setenv("LUPETTO_REGISTRY", "")
	t.Setenv("LUPETTO_REPOSITORY", "")
	for _, args := range [][]string{
		{"--products", path, "--json"},
		{"--products", path, "--registry=127.0.0.1:5000", "--json"},
		{"--products", path, "--registry=https://example.invalid", "--repository=team", "--json"},
		{"--products", path, "--registry=127.0.0.1:5000", "--repository=../bad", "--json"},
		{"--products", filepath.Join(t.TempDir(), "absent.yaml"), "--registry=127.0.0.1:5000", "--repository=team", "--json"},
	} {
		var stdout, stderr bytes.Buffer
		code := runStatusWith(context.Background(), args, &stdout, &stderr, func(context.Context, status.Products, status.Options) (status.Document, error) {
			t.Fatal("compute called for invalid invocation")
			return status.Document{}, nil
		})
		if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	if err := os.WriteFile(path, []byte("version: 1\nunknown: true\nproducts: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runStatusWith(context.Background(), []string{"--products", path, "--registry=127.0.0.1:5000", "--repository=team", "--json"}, &stdout, &stderr, func(context.Context, status.Products, status.Options) (status.Document, error) {
		t.Fatal("compute called for invalid products")
		return status.Document{}, nil
	}); code != 2 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStatusGlobalFailureAndHumanOutput(t *testing.T) {
	args := []string{"--products", statusProductsFixture(t), "--registry=127.0.0.1:5000", "--repository=team"}
	var stdout, stderr bytes.Buffer
	if code := runStatusWith(context.Background(), append(args, "--json"), &stdout, &stderr, func(context.Context, status.Products, status.Options) (status.Document, error) {
		return status.Document{}, errors.New("signed index verification failed")
	}); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "verification failed") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runStatusWith(context.Background(), args, &stdout, &stderr, func(context.Context, status.Products, status.Options) (status.Document, error) {
		return status.Document{Tracks: []status.Track{{Package: "nginx", Selector: "1.30", State: "not-built"}, {Package: "nginx", Selector: "99", State: "error", Error: "unavailable"}}}, nil
	}); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "PACKAGE") || !strings.Contains(stdout.String(), "not-built") || !strings.Contains(stdout.String(), "nginx 99: unavailable") || !strings.Contains(stdout.String(), "not a vulnerability scan") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestTargetArchFlags(t *testing.T) {
	for value, want := range map[string]string{"arm64": "aarch64", "aarch64": "aarch64", "amd64": "x86_64", "x86_64": "x86_64"} {
		built, err := parseBuild([]string{"busybox", "1", "--arch", value})
		inline, err2 := parseBuild([]string{"--arch=" + value, "busybox", "1"})
		discovered, err3 := parseDiscover([]string{"--arch", value, "busybox"})
		statused, err4 := parseStatus([]string{"--products=p", "--arch=" + value})
		if err != nil || err2 != nil || err3 != nil || err4 != nil || built.Arch != want || inline.Arch != want || discovered.arch != want || statused.arch != want {
			t.Fatalf("%s: %q %q %q %q %v %v %v %v", value, built.Arch, inline.Arch, discovered.arch, statused.arch, err, err2, err3, err4)
		}
	}
	if request, _ := parseBuild([]string{"busybox", "1"}); request.Arch != "" {
		t.Fatalf("default arch=%q, want host default", request.Arch)
	}
	for _, bad := range [][]string{{"--arch", "riscv64"}, {"--arch="}, {"--arch"}, {"--arch=arm64", "--arch=arm64"}} {
		if _, err := parseBuild(append([]string{"busybox", "1"}, bad...)); err == nil {
			t.Fatalf("build accepted %q", bad)
		}
		if _, err := parseDiscover(append([]string{"busybox"}, bad...)); err == nil {
			t.Fatalf("discover accepted %q", bad)
		}
		if _, err := parseStatus(append([]string{"--products=p"}, bad...)); err == nil {
			t.Fatalf("status accepted %q", bad)
		}
	}
}

func TestStatusExitCodeSignalsRebuildAndErrors(t *testing.T) {
	args := []string{"--products", statusProductsFixture(t), "--registry=127.0.0.1:5000", "--repository=team"}
	for _, tc := range []struct {
		states []string
		want   int
	}{
		{[]string{"current", "current"}, 0},
		{nil, 0},
		{[]string{"current", "not-built"}, 3},
		{[]string{"update-available"}, 3},
		{[]string{"fixes-available", "current"}, 3},
		{[]string{"config-changed", "current"}, 3},
		{[]string{"config-changed", "error"}, 4},
		{[]string{"update-available", "error"}, 4},
		{[]string{"error", "current"}, 4},
	} {
		tracks := []status.Track{}
		for _, state := range tc.states {
			tracks = append(tracks, status.Track{Package: "nginx", Selector: "1.30", State: state})
		}
		compute := func(context.Context, status.Products, status.Options) (status.Document, error) {
			return status.Document{Kind: "status", Version: 2, Tracks: tracks}, nil
		}
		for _, extra := range [][]string{{"--exit-code"}, {"--exit-code", "--json"}} {
			var stdout, stderr bytes.Buffer
			if code := runStatusWith(context.Background(), append(append([]string{}, args...), extra...), &stdout, &stderr, compute); code != tc.want || stdout.Len() == 0 || stderr.Len() != 0 {
				t.Fatalf("states=%q args=%q code=%d want=%d stdout=%q stderr=%q", tc.states, extra, code, tc.want, stdout.String(), stderr.String())
			}
		}
		// Without the opt-in, a computed status keeps exit 0 for existing consumers.
		var stdout, stderr bytes.Buffer
		if code := runStatusWith(context.Background(), append(append([]string{}, args...), "--json"), &stdout, &stderr, compute); code != 0 {
			t.Fatalf("states=%q without --exit-code: code=%d", tc.states, code)
		}
	}
}

func TestStatusDispatchAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"status", "--json"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "status requires --products") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, phrase := range []string{"lupetto status --products <file>", "version=2 document", "--severity-budget", "unknown fields are rejected", "unsigned HTTPS", "including track errors/updates", "global failures exit 1", "--exit-code"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Fatalf("help missing %q", phrase)
		}
	}
}

func TestStatusOutputFailure(t *testing.T) {
	args := []string{"--products", statusProductsFixture(t), "--registry=127.0.0.1:5000", "--repository=team"}
	for _, jsonOutput := range []bool{false, true} {
		testArgs := append([]string{}, args...)
		if jsonOutput {
			testArgs = append(testArgs, "--json")
		}
		var stderr bytes.Buffer
		if code := runStatusWith(context.Background(), testArgs, failingWriter{}, &stderr, func(context.Context, status.Products, status.Options) (status.Document, error) {
			return status.Document{Kind: "status", Version: 2, Tracks: []status.Track{}}, nil
		}); code != 1 || !strings.Contains(stderr.String(), "could not write") {
			t.Fatalf("json=%v code=%d stderr=%q", jsonOutput, code, stderr.String())
		}
	}
}

func TestStatusUnevaluatedSecurityWarning(t *testing.T) {
	var stdout bytes.Buffer
	document := status.Document{
		Security: status.SecuritySource{UnevaluatedFixCount: 1, UnevaluatedFixes: []status.UnevaluatedFix{{Name: "opa-envoy", FixedVersion: "1.1.0-r1-r0", IDs: []string{"CVE-2025-1234"}}}},
		Tracks:   []status.Track{{Package: "opa-envoy", Selector: "1", State: "current", UnevaluatedFixes: []status.UnevaluatedFix{{Name: "opa-envoy", FixedVersion: "1.1.0-r1-r0", IDs: []string{"CVE-2025-1234"}}}}},
	}
	if err := writeStatusTable(&stdout, document); err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"UNEVALUATED", "WARNING: 1 security fixed-version entries", "no APK version ordering was guessed", "opa-envoy fixed-version 1.1.0-r1-r0: CVE-2025-1234"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Fatalf("output missing %q: %s", phrase, stdout.String())
		}
	}
}

func TestStatusSeverityBudgetAndCounts(t *testing.T) {
	for _, test := range []struct {
		args []string
		want time.Duration
	}{
		{[]string{"--products=p"}, 20 * time.Second},
		{[]string{"--products=p", "--severity-budget", "0"}, 0},
		{[]string{"--products=p", "--severity-budget=15s"}, 15 * time.Second},
	} {
		request, err := parseStatus(test.args)
		if err != nil || request.severityBudget != test.want {
			t.Fatalf("%v: %+v %v", test.args, request, err)
		}
	}
	for _, value := range []string{"", "-1s", "later", "6m", "20"} {
		if _, err := parseStatus([]string{"--products=p", "--severity-budget=" + value}); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	if _, err := parseStatus([]string{"--products=p", "--severity-budget=0", "--severity-budget=1s"}); err == nil {
		t.Fatal("accepted duplicate budget")
	}
	track := status.Track{State: "current", MissingFixes: []status.MissingFix{
		{Advisories: []status.Advisory{{ID: "a", Severity: "high"}, {ID: "b", Severity: "critical"}}},
		{Advisories: []status.Advisory{{ID: "a", Severity: "high"}, {ID: "c", Severity: "unknown"}}},
	}, UnevaluatedFixes: []status.UnevaluatedFix{{Advisories: []status.Advisory{{ID: "d", Severity: "low"}}}}}
	counts := trackSeverityCounts(track)
	if counts["high"] != 1 || counts["critical"] != 1 || counts["unknown"] != 1 || counts["low"] != 1 {
		t.Fatalf("counts %+v", counts)
	}
	var out bytes.Buffer
	if err := writeStatusTable(&out, status.Document{Tracks: []status.Track{track}}); err != nil || !strings.Contains(out.String(), "CRITICAL") || !strings.Contains(out.String(), "non-fatal") {
		t.Fatalf("human severity output: %v %s", err, &out)
	}
}

func TestStatusTableListsConfigChanges(t *testing.T) {
	var stdout bytes.Buffer
	document := status.Document{Tracks: []status.Track{
		{Package: "metrics-server", Selector: "0", State: status.ConfigChanged, ConfigChanges: []string{status.ChangeBaseLayout}},
		{Package: "curl", Selector: "8", State: status.Current},
	}}
	if err := writeStatusTable(&stdout, document); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "metrics-server 0: newest image configuration differs: baseLayout\n") || strings.Contains(stdout.String(), "curl 8:") {
		t.Fatalf("output: %s", stdout.String())
	}
	if code := statusExitCode(document); code != 3 {
		t.Fatalf("exit code %d", code)
	}
}
