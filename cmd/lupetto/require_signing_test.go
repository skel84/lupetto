package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lupetto/internal/build"
	"lupetto/internal/storage"
)

var warningLine = "lupetto: " + build.UnsignedPublicationWarning + "\n"

// isolateRequireSigning clears publication/signing inputs and points every
// data/cache root at a temporary home so no test touches real user state.
func isolateRequireSigning(t *testing.T) string {
	t.Helper()
	clearSigningFixtureEnvironment(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "xdg-data"))
	t.Setenv("LUPETTO_DATA_DIR", filepath.Join(home, "data"))
	return home
}

func TestParseBuildRequireSigningFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want build.OptionalBool
	}{
		{args: []string{"nginx", "1.30"}},
		{args: []string{"nginx", "1.30", "--require-signing"}, want: build.OptionalBool{Value: true, Set: true}},
		{args: []string{"--require-signing=true", "nginx", "1.30"}, want: build.OptionalBool{Value: true, Set: true}},
		{args: []string{"nginx", "--require-signing=false", "--apk-version=1.30.2-r0"}, want: build.OptionalBool{Set: true}},
	} {
		request, err := parseBuild(tc.args)
		if err != nil || request.signingFlags.Require != tc.want || request.signingFlags.AllowHTTP.Set {
			t.Fatalf("args=%q flags=%+v err=%v want=%+v", tc.args, request.signingFlags, err, tc.want)
		}
	}
	// A valueless boolean never consumes the following positional.
	request, err := parseBuild([]string{"--require-signing", "false", "1"})
	if err != nil || request.PackageName != "false" || request.signingFlags.Require != (build.OptionalBool{Value: true, Set: true}) {
		t.Fatalf("boolean consumed following positional: request=%+v err=%v", request, err)
	}
	for _, flags := range [][]string{
		{"--require-signing="}, {"--require-signing=TRUE"}, {"--require-signing=1"}, {"--require-signing=yes"},
		{"--require-signing", "--require-signing=false"}, {"--require-signing=false", "--require-signing"},
		{"--require-signing", "false"}, {"--require-signing", "true"},
	} {
		args := append([]string{"nginx", "1.30"}, flags...)
		if request, err := parseBuild(args); err == nil {
			t.Fatalf("args=%q accepted %+v", args, request)
		}
	}
}

// failingServices proves that a rejected configuration never reaches tools,
// the network, Cosign, or the data directory.
func failingServices(t *testing.T) build.Services {
	return build.Services{
		Command: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("build tool invoked")
			return nil, nil
		},
		SigningCommand: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("Cosign invoked")
			return nil, nil
		},
		DataDir: func() (string, error) { t.Fatal("workspace used"); return "", nil },
		PublicFile: func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("network used")
			return nil, nil
		},
		SigningKey: func(context.Context) ([]byte, error) { t.Fatal("network used"); return nil, nil },
	}
}

func TestRequireSigningRefusesUnsignedPublicationBeforeWork(t *testing.T) {
	publish := []string{"--registry=registry.example", "--repository=team/images"}
	for _, tc := range []struct {
		name  string
		flags []string
		env   map[string]string
	}{
		{name: "valueless flag", flags: append([]string{"--require-signing"}, publish...)},
		{name: "true flag", flags: append([]string{"--require-signing=true", "--json"}, publish...)},
		{name: "environment", flags: publish, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "true"}},
		{name: "environment publication", flags: []string{"--no-load", "--json"}, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "true", "LUPETTO_REGISTRY": "127.0.0.1:5000", "LUPETTO_REPOSITORY": "test/images"}},
		{name: "flag true overrides environment false", flags: append([]string{"--require-signing"}, publish...), env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "false"}},
		{name: "empty environment key is no key", flags: publish, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "true", "LUPETTO_COSIGN_KEY": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateRequireSigning(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			called := false
			callback := func(ctx context.Context, request cliRequest) (build.Result, error) {
				called = true
				return build.RunWith(ctx, request.Request, failingServices(t))
			}
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "busybox-static", "1"}, tc.flags...)
			code := runWithBuild(context.Background(), args, &stdout, &stderr, callback)
			if code != 2 || called || stdout.Len() != 0 {
				t.Fatalf("code=%d called=%v stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
			}
			if !strings.HasPrefix(stderr.String(), "lupetto: unsigned publication refused: signing is required (--require-signing / LUPETTO_REQUIRE_SIGNING)") || strings.Count(stderr.String(), "\n") != 1 {
				t.Fatalf("stderr=%q", stderr.String())
			}
			if strings.Contains(stderr.String(), "warning:") {
				t.Fatalf("refused build also warned: %q", stderr.String())
			}
			data, err := storage.DataDir()
			if err != nil || !strings.HasPrefix(data, home) {
				t.Fatalf("data dir %q not isolated: %v", data, err)
			}
			if _, err := os.Stat(storage.BuildsDir(data)); !os.IsNotExist(err) {
				t.Fatalf("workspace root created: %v", err)
			}
		})
	}
}

func TestRequireSigningInvalidValuesExitTwo(t *testing.T) {
	isolateRequireSigning(t)
	for _, value := range []string{"TRUE", "False", "1", "yes", " true", "secret-bool-canary"} {
		t.Setenv("LUPETTO_REQUIRE_SIGNING", value)
		for _, flags := range [][]string{nil, {"--registry=registry.example", "--repository=team/images"}} {
			called := false
			callback := func(context.Context, cliRequest) (build.Result, error) { called = true; return build.Result{}, nil }
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "busybox-static", "1"}, flags...)
			if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 2 || called || stdout.Len() != 0 || stderr.String() != "lupetto: LUPETTO_REQUIRE_SIGNING must be true or false\n" {
				t.Fatalf("value=%q flags=%q code=%d called=%v stdout=%q stderr=%q", value, flags, code, called, stdout.String(), stderr.String())
			}
		}
	}
	// An explicit flag overrides (and never reads) an invalid environment value.
	t.Setenv("LUPETTO_REQUIRE_SIGNING", "secret-bool-canary")
	var stdout, stderr bytes.Buffer
	callback := func(context.Context, cliRequest) (build.Result, error) {
		return build.Result{DockerLoad: "skipped"}, nil
	}
	if code := runWithBuild(context.Background(), []string{"build", "busybox-static", "1", "--no-load", "--require-signing=false"}, &stdout, &stderr, callback); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var parseErr bytes.Buffer
	if code := runWithBuild(context.Background(), []string{"build", "busybox-static", "1", "--require-signing=maybe"}, &stdout, &parseErr, callback); code != 2 || !strings.Contains(parseErr.String(), "--require-signing must be true or false") {
		t.Fatalf("code=%d stderr=%q", code, parseErr.String())
	}
}

func TestRequireSigningWithoutPublicationOrWithKeyProceeds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		env   map[string]string
	}{
		{name: "flag without publication", flags: []string{"--require-signing", "--no-load"}},
		{name: "environment without publication", flags: []string{"--no-load"}, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "true"}},
		{name: "flag false overrides environment true", flags: []string{"--require-signing=false", "--registry=registry.example", "--repository=team/images"}, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "true"}},
		{name: "environment false", flags: []string{"--registry=registry.example", "--repository=team/images"}, env: map[string]string{"LUPETTO_REQUIRE_SIGNING": "false"}},
		{name: "with key", flags: []string{"--require-signing", "--cosign-key=synthetic-key", "--registry=registry.example", "--repository=team/images"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateRequireSigning(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			calls := 0
			callback := func(_ context.Context, request cliRequest) (build.Result, error) {
				calls++
				return build.Result{DockerLoad: "skipped"}, nil
			}
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "busybox-static", "1"}, tc.flags...)
			code := runWithBuild(context.Background(), args, &stdout, &stderr, callback)
			wantStderr := ""
			if strings.HasPrefix(tc.name, "flag false") || tc.name == "environment false" {
				wantStderr = warningLine // unsigned publication still warns
			}
			if code != 0 || calls != 1 || stderr.String() != wantStderr || !strings.Contains(stdout.String(), "Build completed") {
				t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
			}
		})
	}
}

func TestSBOMIgnoresRequireSigningEnvironment(t *testing.T) {
	isolateRequireSigning(t)
	t.Setenv("LUPETTO_REGISTRY", "registry.example")
	t.Setenv("LUPETTO_REPOSITORY", "team/images")
	t.Setenv("LUPETTO_REQUIRE_SIGNING", "true")
	calls := 0
	callback := func(_ context.Context, request cliRequest) (build.Result, error) {
		calls++
		if request.Publication.Enabled() || request.signingFlags != (build.SigningFlags{}) {
			t.Fatalf("sbom resolved publication/signing: %+v", request)
		}
		return build.Result{DockerLoad: "skipped"}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := runWithBuild(context.Background(), []string{"sbom", "nginx", "--apk-version=1.30.2-r0"}, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
}

// The warning goes to stderr exactly once, before the first stage log, and
// never changes stdout, the --json document, or the retained record.
func TestUnsignedPublicationWarningPipeline(t *testing.T) {
	for _, mode := range []string{"unsigned json", "unsigned text", "signed json", "local json"} {
		t.Run(mode, func(t *testing.T) {
			clearSigningFixtureEnvironment(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newPipelineFixture(t, "", cancel)
			args := []string{"build", "postgresql-17", "--apk-version", "17.10-r1", "--no-load"}
			switch mode {
			case "unsigned json", "unsigned text":
				registry := addRegistryFixture(t, f, "", cancel)
				args = append(publicationCLIArgs(registry.Host), "--no-load")
			case "signed json":
				registry := addRegistryFixture(t, f, "", cancel)
				addSigningFixture(t, f, "", cancel)
				args = append(signingCLIArgs(registry.Host, false), "--no-load")
			}
			if strings.HasSuffix(mode, "json") {
				args = append(args, "--json")
			}
			var stdout, stderr bytes.Buffer
			code := runWithBuild(ctx, args, &stdout, &stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
				return build.RunWith(ctx, request.Request, f.services)
			})
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			unsigned := strings.HasPrefix(mode, "unsigned")
			if got := strings.Count(stderr.String(), build.UnsignedPublicationWarning); got != map[bool]int{true: 1, false: 0}[unsigned] {
				t.Fatalf("warning count=%d stderr=%q", got, stderr.String())
			}
			if unsigned && !strings.HasPrefix(stderr.String(), warningLine+"lupetto: ") {
				t.Fatalf("warning is not the first stderr line before stage logs: %q", stderr.String())
			}
			if strings.Contains(stdout.String(), "warning") || strings.Contains(stdout.String(), "LUPETTO_REQUIRE_SIGNING") {
				t.Fatalf("warning reached stdout: %q", stdout.String())
			}
			record := mustRead(t, filepath.Join(f.workspace, "result.json"))
			if bytes.Contains(record, []byte("warning")) || bytes.Contains(record, []byte("REQUIRE")) {
				t.Fatalf("record mentions the warning: %s", record)
			}
			if strings.HasSuffix(mode, "json") && !bytes.Equal(stdout.Bytes(), record) {
				t.Fatalf("--json stdout differs from result.json:\n%s\n%s", stdout.String(), record)
			}
		})
	}
}
