package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"lupetto/internal/build"
)

func TestParseBuildSigningFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want build.SigningFlags
	}{
		{args: []string{"nginx", "1.30", "--cosign-key", "key", "--cosign-signing-config", "config", "--cosign-allow-http"}, want: build.SigningFlags{Key: build.OptionalString{Value: "key", Set: true}, Config: build.OptionalString{Value: "config", Set: true}, AllowHTTP: build.OptionalBool{Value: true, Set: true}}},
		{args: []string{"--cosign-signing-config=config", "nginx", "--cosign-key=key", "--apk-version=1.30.2-r0", "--cosign-allow-http=false"}, want: build.SigningFlags{Key: build.OptionalString{Value: "key", Set: true}, Config: build.OptionalString{Value: "config", Set: true}, AllowHTTP: build.OptionalBool{Set: true}}},
		{args: []string{"--cosign-allow-http=true", "nginx", "1.30"}, want: build.SigningFlags{AllowHTTP: build.OptionalBool{Value: true, Set: true}}},
		{args: []string{"nginx", "1.30", "--cosign-key="}, want: build.SigningFlags{Key: build.OptionalString{Set: true}}},
		{args: []string{"nginx", "1.30", "--cosign-signing-config", ""}, want: build.SigningFlags{Config: build.OptionalString{Set: true}}},
	} {
		request, err := parseBuild(tc.args)
		if err != nil || request.signingFlags != tc.want || request.Signing != (build.SigningOptions{}) {
			t.Fatalf("args=%q request=%+v err=%v want flags=%+v", tc.args, request, err, tc.want)
		}
	}
	// A boolean never consumes the following positional, even if it spells false.
	request, err := parseBuild([]string{"--cosign-allow-http", "false", "1"})
	if err != nil || request.PackageName != "false" || request.signingFlags.AllowHTTP != (build.OptionalBool{Value: true, Set: true}) {
		t.Fatalf("boolean consumed following positional: request=%+v err=%v", request, err)
	}
}

func TestParseBuildSigningRejectsInvalidFlags(t *testing.T) {
	for _, flags := range [][]string{
		{"--cosign-key"}, {"--cosign-signing-config"},
		{"--cosign-key", "--no-load"}, {"--cosign-signing-config", "--cosign-key=key"},
		{"--cosign-key=key", "--cosign-key=other"}, {"--cosign-key=", "--cosign-key", "key"},
		{"--cosign-signing-config=config", "--cosign-signing-config=config"}, {"--cosign-signing-config=", "--cosign-signing-config", "config"},
		{"--cosign-allow-http", "--cosign-allow-http=false"}, {"--cosign-allow-http=false", "--cosign-allow-http"},
		{"--cosign-allow-http="}, {"--cosign-allow-http=TRUE"}, {"--cosign-allow-http=1"}, {"--cosign-allow-http=no"},
		{"--cosign-allow-http", "false"}, {"--cosign-allow-http", "true"},
	} {
		args := append([]string{"nginx", "1.30"}, flags...)
		if request, err := parseBuild(args); err == nil {
			t.Fatalf("args=%q accepted %+v", args, request)
		}
	}
}

func TestRunBuildSigningConfigurationBeforeCallback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		env   map[string]string
	}{
		{name: "key without publication", flags: []string{"--cosign-key=secret-key-canary"}},
		{name: "key and partial publication", flags: []string{"--cosign-key=secret-key-canary", "--registry=registry.example"}},
		{name: "config without key", flags: []string{"--cosign-signing-config=secret-config-canary"}},
		{name: "HTTP without key", flags: []string{"--cosign-allow-http"}},
		{name: "nonloopback HTTP", flags: []string{"--cosign-key=secret-key-canary", "--cosign-allow-http", "--registry=registry.example", "--repository=team/images"}},
		{name: "loopback without consent", flags: []string{"--cosign-key=secret-key-canary", "--registry=localhost:5000", "--repository=team/images"}},
		{name: "empty key overrides env", flags: []string{"--cosign-key="}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary", "LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}},
		{name: "empty config overrides env", flags: []string{"--cosign-signing-config="}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary", "LUPETTO_COSIGN_SIGNING_CONFIG": "secret-config-canary", "LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}},
		{name: "invalid HTTP env", env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "secret-bool-canary"}},
		{name: "environment signing with no load", flags: []string{"--no-load"}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP", "LUPETTO_REQUIRE_SIGNING"} {
				t.Setenv(name, tc.env[name])
			}
			called := false
			callback := func(context.Context, cliRequest) (build.Result, error) { called = true; return build.Result{}, nil }
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "nginx", "1.30"}, tc.flags...)
			if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 2 || called || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d called=%v stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
			}
			for _, secret := range []string{"secret-key-canary", "secret-config-canary", "secret-bool-canary"} {
				if strings.Contains(stderr.String(), secret) {
					t.Fatalf("configuration diagnostic leaked %q: %s", secret, stderr.String())
				}
			}
		})
	}
}

func TestRunBuildResolvesSigningInSameCallback(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "registry.example")
	t.Setenv("LUPETTO_REPOSITORY", "team/images")
	t.Setenv("LUPETTO_COSIGN_KEY", "env-key")
	t.Setenv("LUPETTO_COSIGN_SIGNING_CONFIG", "env-config")
	t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "true")
	calls := 0
	callback := func(_ context.Context, request cliRequest) (build.Result, error) {
		calls++
		if request.Signing != (build.SigningOptions{Key: "flag-key", Config: "env-config"}) || request.Publication != (build.PublicationOptions{Registry: "registry.example", Repository: "team/images"}) || request.PackageName != "nginx" || request.Selector != "1.30" || request.NoLoad {
			t.Fatalf("resolved request=%+v", request)
		}
		return build.Result{}, errors.New("synthetic callback failure")
	}
	var stdout, stderr bytes.Buffer
	args := []string{"build", "nginx", "1.30", "--cosign-key=flag-key", "--cosign-allow-http=false"}
	if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || calls != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "synthetic callback failure") {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
}

func TestRunBuildSigningDefaultsRemainDisabled(t *testing.T) {
	for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP", "LUPETTO_REQUIRE_SIGNING"} {
		t.Setenv(name, "")
	}
	for _, flags := range [][]string{nil, {"--no-load"}, {"--cosign-allow-http=false"}} {
		calls := 0
		callback := func(_ context.Context, request cliRequest) (build.Result, error) {
			calls++
			if request.Signing != (build.SigningOptions{}) || request.Publication.Enabled() {
				t.Fatalf("defaults enabled external stages: %+v", request)
			}
			return build.Result{DockerLoad: "skipped", Signing: "skipped", Attestation: "skipped"}, nil
		}
		var stdout, stderr bytes.Buffer
		args := append([]string{"build", "pkg", "1"}, flags...)
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Build completed") || !strings.Contains(stdout.String(), "Image signing: skipped\nSPDX attestation: skipped") {
			t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
		}
	}
}
