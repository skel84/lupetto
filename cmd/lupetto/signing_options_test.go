package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveSigningIndependentPrecedence(t *testing.T) {
	flag := func(value string) optionalString { return optionalString{value: value, set: true} }
	production := publicationOptions{registry: "registry.example", repository: "team/images"}
	loopback := publicationOptions{registry: "127.0.0.1:5000", repository: "team/images"}
	for _, tc := range []struct {
		name      string
		raw       signingFlags
		env       map[string]string
		pub       publicationOptions
		want      signingOptions
		wantError bool
	}{
		{name: "disabled by default"},
		{name: "unset flag values ignored", raw: signingFlags{key: optionalString{value: "ignored"}, config: optionalString{value: "ignored"}, allowHTTP: optionalBool{value: true}}},
		{name: "empty environment absent", env: map[string]string{"LUPETTO_COSIGN_KEY": "", "LUPETTO_COSIGN_SIGNING_CONFIG": "", "LUPETTO_COSIGN_ALLOW_HTTP": ""}},
		{name: "key alone preserves upstream defaults", raw: signingFlags{key: flag("flag-key")}, pub: production, want: signingOptions{key: "flag-key"}},
		{name: "environment key and config together", env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: signingOptions{key: "env-key", config: "env-config"}},
		{name: "flag key and environment config", raw: signingFlags{key: flag("flag-key")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: signingOptions{key: "flag-key", config: "env-config"}},
		{name: "environment key and flag config", raw: signingFlags{config: flag("flag-config")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: signingOptions{key: "env-key", config: "flag-config"}},
		{name: "flag false overrides environment true", raw: signingFlags{key: flag("flag-key"), allowHTTP: optionalBool{value: false, set: true}}, env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: production, want: signingOptions{key: "flag-key"}},
		{name: "flag bool overrides invalid environment", raw: signingFlags{key: flag("flag-key"), allowHTTP: optionalBool{value: false, set: true}}, env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "secret-invalid"}, pub: production, want: signingOptions{key: "flag-key"}},
		{name: "environment loopback consent", env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: loopback, want: signingOptions{key: "env-key", allowHTTP: true}},
		{name: "false override removes loopback consent", raw: signingFlags{allowHTTP: optionalBool{set: true}}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: loopback, wantError: true},
		{name: "environment false no key is noop", env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "false"}},
		{name: "explicit false no key is noop", raw: signingFlags{allowHTTP: optionalBool{set: true}}},
		{name: "empty flag key never revives env", raw: signingFlags{key: flag("")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key"}, pub: production, wantError: true},
		{name: "empty flag config never revives env", raw: signingFlags{config: flag("")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, wantError: true},
		{name: "config alone not keyless", raw: signingFlags{config: flag("flag-config")}, pub: production, wantError: true},
		{name: "HTTP alone not keyless", raw: signingFlags{allowHTTP: optionalBool{value: true, set: true}}, pub: loopback, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) { value, ok := tc.env[name]; return value, ok }
			opts, err := resolveSigning(tc.raw, tc.pub, false, lookup)
			if (err != nil) != tc.wantError || (!tc.wantError && opts != tc.want) {
				t.Fatalf("opts=%+v err=%v want=%+v error=%v", opts, err, tc.want, tc.wantError)
			}
		})
	}
	for _, lookup := range []func(string) (string, bool){nil, func(string) (string, bool) { return "ignored", false }} {
		if opts, err := resolveSigning(signingFlags{}, publicationOptions{}, false, lookup); err != nil || opts != (signingOptions{}) {
			t.Fatalf("absent lookup: opts=%+v err=%v", opts, err)
		}
	}
}

func TestResolveSigningStrictEnvironmentBoolean(t *testing.T) {
	for _, value := range []string{"TRUE", "False", "1", "0", "yes", " true", "false ", "\ntrue", "secret-canary"} {
		lookup := func(name string) (string, bool) { return value, name == "LUPETTO_COSIGN_ALLOW_HTTP" }
		if _, err := resolveSigning(signingFlags{}, publicationOptions{}, false, lookup); err == nil || err.Error() != "LUPETTO_COSIGN_ALLOW_HTTP must be true or false" {
			t.Fatalf("value=%q err=%v; want exact sanitized strict-bool error", value, err)
		}
	}
}

func TestResolveSigningDoesNotInspectSecretsOrOverriddenEnvironment(t *testing.T) {
	lookup := func(name string) (string, bool) {
		t.Fatalf("explicit signing settings unexpectedly read environment %q", name)
		return "", false
	}
	raw := signingFlags{
		key:       optionalString{value: "key", set: true},
		config:    optionalString{value: "config", set: true},
		allowHTTP: optionalBool{set: true},
	}
	if opts, err := resolveSigning(raw, publicationOptions{registry: "registry.example", repository: "team/images"}, false, lookup); err != nil || opts != (signingOptions{key: "key", config: "config"}) {
		t.Fatalf("explicit resolution: opts=%+v err=%v", opts, err)
	}
	var lookedUp []string
	lookup = func(name string) (string, bool) {
		lookedUp = append(lookedUp, name)
		if name == "COSIGN_PASSWORD" {
			t.Fatal("signing resolution read the password")
		}
		return "", false
	}
	if _, err := resolveSigning(signingFlags{}, publicationOptions{}, false, lookup); err != nil {
		t.Fatal(err)
	}
	if strings.Join(lookedUp, ",") != "LUPETTO_COSIGN_KEY,LUPETTO_COSIGN_SIGNING_CONFIG,LUPETTO_COSIGN_ALLOW_HTTP" {
		t.Fatalf("unexpected environment reads: %q", lookedUp)
	}
}

func TestValidateSigningLiteralLoopbackPolicy(t *testing.T) {
	for _, registry := range []string{"localhost", "localhost:5000", "LOCALHOST:5000", "127.0.0.1", "127.12.34.56:5000", "[::1]", "[::1]:5000", "[::ffff:7f00:1]:5000"} {
		pub := publicationOptions{registry: registry, repository: "team/images"}
		if err := validateSigningOptions(signingOptions{key: "key", allowHTTP: true}, pub, false); err != nil {
			t.Fatalf("loopback %q rejected: %v", registry, err)
		}
		if err := validateSigningOptions(signingOptions{key: "key"}, pub, false); err == nil {
			t.Fatalf("loopback %q accepted without HTTP consent", registry)
		}
		if err := validateSigningOptions(signingOptions{}, pub, false); err != nil {
			t.Fatalf("unsigned publication %q required signing consent: %v", registry, err)
		}
	}
	for _, registry := range []string{"registry.example", "registry.example:443", "localhost.example", "loopback.example:5000", "registry:5000", "192.0.2.1:5000", "[2001:db8::1]:5000", "[::ffff:c000:201]:5000"} {
		pub := publicationOptions{registry: registry, repository: "team/images"}
		if err := validateSigningOptions(signingOptions{key: "key"}, pub, false); err != nil {
			t.Fatalf("production default %q rejected: %v", registry, err)
		}
		if err := validateSigningOptions(signingOptions{key: "key", allowHTTP: true}, pub, false); err == nil {
			t.Fatalf("nonloopback %q accepted HTTP allowance", registry)
		}
	}
}

func TestValidateSigningRequiresCompletePublicationAndLoad(t *testing.T) {
	for _, pub := range []publicationOptions{{}, {registry: "registry.example"}, {repository: "team/images"}, {registry: "https://registry.example", repository: "team/images"}, {registry: "registry.example", repository: "INVALID"}} {
		if err := validateSigningOptions(signingOptions{key: "key"}, pub, false); err == nil {
			t.Fatalf("incomplete/invalid publication accepted: %+v", pub)
		}
	}
	if err := validateSigningOptions(signingOptions{key: "key"}, publicationOptions{registry: "registry.example", repository: "team/images"}, true); err == nil {
		t.Fatal("signing accepted --no-load")
	}
	if err := validateSigningOptions(signingOptions{}, publicationOptions{}, true); err != nil {
		t.Fatalf("unsigned local --no-load rejected: %v", err)
	}
}

func TestParseBuildSigningFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want signingFlags
	}{
		{args: []string{"nginx", "1.30", "--cosign-key", "key", "--cosign-signing-config", "config", "--cosign-allow-http"}, want: signingFlags{key: optionalString{value: "key", set: true}, config: optionalString{value: "config", set: true}, allowHTTP: optionalBool{value: true, set: true}}},
		{args: []string{"--cosign-signing-config=config", "nginx", "--cosign-key=key", "--apk-version=1.30.2-r0", "--cosign-allow-http=false"}, want: signingFlags{key: optionalString{value: "key", set: true}, config: optionalString{value: "config", set: true}, allowHTTP: optionalBool{set: true}}},
		{args: []string{"--cosign-allow-http=true", "nginx", "1.30"}, want: signingFlags{allowHTTP: optionalBool{value: true, set: true}}},
		{args: []string{"nginx", "1.30", "--cosign-key="}, want: signingFlags{key: optionalString{set: true}}},
		{args: []string{"nginx", "1.30", "--cosign-signing-config", ""}, want: signingFlags{config: optionalString{set: true}}},
	} {
		request, err := parseBuild(tc.args)
		if err != nil || request.signingFlags != tc.want || request.signing != (signingOptions{}) {
			t.Fatalf("args=%q request=%+v err=%v want flags=%+v", tc.args, request, err, tc.want)
		}
	}
	// A boolean never consumes the following positional, even if it spells false.
	request, err := parseBuild([]string{"--cosign-allow-http", "false", "1"})
	if err != nil || request.packageName != "false" || request.signingFlags.allowHTTP != (optionalBool{value: true, set: true}) {
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
		{name: "no load", flags: []string{"--cosign-key=secret-key-canary", "--no-load", "--registry=registry.example", "--repository=team/images"}},
		{name: "nonloopback HTTP", flags: []string{"--cosign-key=secret-key-canary", "--cosign-allow-http", "--registry=registry.example", "--repository=team/images"}},
		{name: "loopback without consent", flags: []string{"--cosign-key=secret-key-canary", "--registry=localhost:5000", "--repository=team/images"}},
		{name: "empty key overrides env", flags: []string{"--cosign-key="}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary", "LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}},
		{name: "empty config overrides env", flags: []string{"--cosign-signing-config="}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary", "LUPETTO_COSIGN_SIGNING_CONFIG": "secret-config-canary", "LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}},
		{name: "invalid HTTP env", env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "secret-bool-canary"}},
		{name: "environment signing with no load", flags: []string{"--no-load"}, env: map[string]string{"LUPETTO_COSIGN_KEY": "secret-key-canary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
				t.Setenv(name, tc.env[name])
			}
			called := false
			callback := func(context.Context, buildRequest) (buildResult, error) { called = true; return buildResult{}, nil }
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
	callback := func(_ context.Context, request buildRequest) (buildResult, error) {
		calls++
		if request.signing != (signingOptions{key: "flag-key", config: "env-config"}) || request.publication != (publicationOptions{registry: "registry.example", repository: "team/images"}) || request.packageName != "nginx" || request.selector != "1.30" || request.noLoad {
			t.Fatalf("resolved request=%+v", request)
		}
		return buildResult{}, errors.New("synthetic callback failure")
	}
	var stdout, stderr bytes.Buffer
	args := []string{"build", "nginx", "1.30", "--cosign-key=flag-key", "--cosign-allow-http=false"}
	if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || calls != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "synthetic callback failure") {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
}

func TestRunBuildSigningDefaultsRemainDisabled(t *testing.T) {
	for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
		t.Setenv(name, "")
	}
	for _, flags := range [][]string{nil, {"--no-load"}, {"--cosign-allow-http=false"}} {
		calls := 0
		callback := func(_ context.Context, request buildRequest) (buildResult, error) {
			calls++
			if request.signing != (signingOptions{}) || request.publication.enabled() {
				t.Fatalf("defaults enabled external stages: %+v", request)
			}
			return buildResult{dockerLoad: "skipped", signing: "skipped", attestation: "skipped"}, nil
		}
		var stdout, stderr bytes.Buffer
		args := append([]string{"build", "pkg", "1"}, flags...)
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Build completed") || !strings.Contains(stdout.String(), "Image signing: skipped\nSPDX attestation: skipped") {
			t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
		}
	}
}
