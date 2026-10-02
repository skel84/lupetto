package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lupetto/internal/build"
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
		if request.PackageName != "postgresql" || request.Version != "17.10-r12" || request.Selector != "" {
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
		if err != nil || request.PackageName != tc.name || request.Selector != tc.selector || request.Version != "" {
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
		if err != nil || !request.NoLoad {
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
	for _, phrase := range []string{"log stages and live tool diagnostics to stderr", "ASCII spinner on interactive terminals", "--registry / LUPETTO_REGISTRY", "--repository / LUPETTO_REPOSITORY", "nested lower-case prefix", "Docker's credential store", "Cosign v3.1.3", "--cosign-key / LUPETTO_COSIGN_KEY", "--cosign-signing-config / LUPETTO_COSIGN_SIGNING_CONFIG", "--cosign-allow-http / LUPETTO_COSIGN_ALLOW_HTTP", "no implicit keyless path", "COSIGN_PASSWORD only from the process environment", "Cosign tool diagnostics are discarded", "literal loopback requires explicit effective HTTP consent", "cosign signing-config create --out <file>", "ignores publication and signing environment inputs", "[--json]", "--json prints the version-6 result record", "with or without --no-load", "loopback IP registries"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Fatalf("help missing %q: %s", phrase, stdout.String())
		}
	}
	for _, removed := range []string{"Publication requires loading", "cannot be used with --no-load", "publication, and loading", "docker push", "Docker publication"} {
		if strings.Contains(stdout.String(), removed) {
			t.Fatalf("help still contains %q: %s", removed, stdout.String())
		}
	}
}

func TestParseBuildPublicationFlags(t *testing.T) {
	for _, args := range [][]string{
		{"nginx", "1.30", "--registry", "registry.example", "--repository", "team/images"},
		{"--repository=team/images", "nginx", "--registry=registry.example", "--apk-version=1.30.2-r0"},
	} {
		request, err := parseBuild(args)
		if err != nil || request.publicationFlags.Registry != (build.OptionalString{Value: "registry.example", Set: true}) || request.publicationFlags.Repository != (build.OptionalString{Value: "team/images", Set: true}) || request.Publication.Enabled() {
			t.Fatalf("args=%q request=%+v err=%v", args, request, err)
		}
	}
	// Parsing preserves explicit emptiness; resolution rejects it, and SBOM
	// must reject the explicit flag rather than treating it as absent.
	for _, args := range [][]string{
		{"nginx", "1.30", "--registry="},
		{"nginx", "1.30", "--registry", ""},
		{"nginx", "1.30", "--repository="},
		{"nginx", "1.30", "--repository", ""},
	} {
		request, err := parseBuild(args)
		if err != nil || (!request.publicationFlags.Registry.Set && !request.publicationFlags.Repository.Set) {
			t.Fatalf("explicit empty flag not preserved: args=%q request=%+v err=%v", args, request, err)
		}
	}
}

func TestParseBuildPublicationRejectsDuplicatesAndMissingValues(t *testing.T) {
	for _, flags := range [][]string{
		{"--registry"},
		{"--repository"},
		{"--registry", "--repository=team"},
		{"--repository", "--registry=registry.example"},
		{"--registry=registry.example", "--registry=registry.example"},
		{"--registry", "registry.example", "--registry=registry.example"},
		{"--registry=", "--registry=registry.example"},
		{"--repository=team", "--repository=team"},
		{"--repository", "team", "--repository=team"},
		{"--repository=", "--repository=team"},
	} {
		args := append([]string{"nginx", "1.30"}, flags...)
		if request, err := parseBuild(args); err == nil {
			t.Fatalf("args=%q accepted %+v", args, request)
		}
	}
}

func TestRunBuildPublicationConfigurationBeforeCallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		registry   string
		repository string
		flags      []string
	}{
		{name: "environment registry only", registry: "registry.example"},
		{name: "environment repository only", repository: "team/images"},
		{name: "explicit empty registry overrides env", registry: "registry.example", repository: "team/images", flags: []string{"--registry="}},
		{name: "explicit empty repository overrides env", registry: "registry.example", repository: "team/images", flags: []string{"--repository", ""}},
		{name: "flag registry only", flags: []string{"--registry=registry.example"}},
		{name: "flag repository only", flags: []string{"--repository=team/images"}},
		{name: "invalid authority", flags: []string{"--registry=https://registry.example", "--repository=team/images"}},
		{name: "ambiguous authority", flags: []string{"--registry=registry", "--repository=team/images"}},
		{name: "invalid nested prefix", flags: []string{"--registry=registry.example", "--repository=team//images"}},
		{name: "overlong prefix", flags: []string{"--registry=registry.example", "--repository=" + strings.Repeat("a", 255)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LUPETTO_REGISTRY", tc.registry)
			t.Setenv("LUPETTO_REPOSITORY", tc.repository)
			called := false
			callback := func(context.Context, cliRequest) (build.Result, error) {
				called = true
				return build.Result{}, nil
			}
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "nginx", "1.30"}, tc.flags...)
			if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 2 || called || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d called=%v stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunBuildResolvesPublicationBeforeSameBuildCallback(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "registry.example")
	t.Setenv("LUPETTO_REPOSITORY", "env/team")
	for _, tc := range []struct {
		flags []string
		want  build.PublicationOptions
	}{
		{want: build.PublicationOptions{Registry: "registry.example", Repository: "env/team"}},
		{flags: []string{"--registry=localhost:5000"}, want: build.PublicationOptions{Registry: "localhost:5000", Repository: "env/team"}},
		{flags: []string{"--repository=flag/team"}, want: build.PublicationOptions{Registry: "registry.example", Repository: "flag/team"}},
		{flags: []string{"--registry=localhost:5000", "--repository=flag/team"}, want: build.PublicationOptions{Registry: "localhost:5000", Repository: "flag/team"}},
	} {
		calls := 0
		callback := func(_ context.Context, request cliRequest) (build.Result, error) {
			calls++
			if request.Publication != tc.want || request.PackageName != "nginx" || request.Selector != "1.30" || request.NoLoad {
				t.Fatalf("request=%+v want publication=%+v", request, tc.want)
			}
			return build.Result{}, errors.New("synthetic callback failure")
		}
		var stdout, stderr bytes.Buffer
		args := append([]string{"build", "nginx", "1.30"}, tc.flags...)
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || calls != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "synthetic callback failure") {
			t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
		}
	}
}

func TestSBOMRejectsExplicitPublicationBeforeCallback(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "registry.example")
	t.Setenv("LUPETTO_REPOSITORY", "team/images")
	for _, flags := range [][]string{
		{"--registry=registry.example"},
		{"--registry="},
		{"--registry", ""},
		{"--repository=team/images"},
		{"--repository="},
		{"--repository", ""},
		{"--registry=registry.example", "--repository=team/images"},
		{"--cosign-key="},
		{"--cosign-signing-config="},
		{"--cosign-allow-http"},
		{"--cosign-allow-http=false"},
		{"--cosign-allow-http="},
		{"--cosign-key", ""},
		{"--cosign-signing-config", ""},
		{"--cosign-key=/synthetic/key", "--cosign-signing-config=/synthetic/config"},
	} {
		called := false
		callback := func(context.Context, cliRequest) (build.Result, error) {
			called = true
			return build.Result{}, nil
		}
		var stdout, stderr bytes.Buffer
		args := append([]string{"sbom", "nginx", "--apk-version=1.30.2-r0"}, flags...)
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 2 || called || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args=%q code=%d called=%v stdout=%q stderr=%q", args, code, called, stdout.String(), stderr.String())
		}
	}
}

func TestSBOMIgnoresPublicationAndSigningEnvironment(t *testing.T) {
	for _, tc := range []struct{ registry, repository string }{
		{"registry.example", "team/images"},
		{"registry.example", ""},
		{"", "team/images"},
		{"https://invalid.example", "INVALID//PREFIX"},
	} {
		t.Setenv("LUPETTO_REGISTRY", tc.registry)
		t.Setenv("LUPETTO_REPOSITORY", tc.repository)
		t.Setenv("LUPETTO_COSIGN_KEY", "/synthetic/key")
		t.Setenv("LUPETTO_COSIGN_SIGNING_CONFIG", "/synthetic/config")
		t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "invalid")
		calls := 0
		callback := func(_ context.Context, request cliRequest) (build.Result, error) {
			calls++
			if request.Publication.Enabled() || request.publicationFlags.Registry.Set || request.publicationFlags.Repository.Set || request.Signing.Enabled() || request.Signing.Config != "" || request.Signing.AllowHTTP || request.signingFlags != (build.SigningFlags{}) || !request.NoLoad || request.PackageName != "nginx" || request.Version != "1.30.2-r0" {
				t.Fatalf("SBOM lost image-only isolation: %+v", request)
			}
			return build.Result{DockerLoad: "skipped", Publication: build.PublicationOutcome{Status: "skipped"}}, nil
		}
		var stdout, stderr bytes.Buffer
		if code := runWithBuild(context.Background(), []string{"sbom", "nginx", "--apk-version=1.30.2-r0"}, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Registry publication: skipped") {
			t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
		}
	}
}

func TestRunBuildReportsPublicationImmutableIdentity(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "")
	t.Setenv("LUPETTO_REPOSITORY", "")
	immutable := "registry.example/team/images/pkg@sha256:" + strings.Repeat("b", 64)
	callback := func(_ context.Context, request cliRequest) (build.Result, error) {
		if !request.Publication.Enabled() {
			t.Fatal("publication was not requested")
		}
		return build.Result{
			DockerLoad: "loaded", DockerImageID: "sha256:" + strings.Repeat("a", 64),
			Publication: build.PublicationOutcome{Status: "published", Reference: "registry.example/team/images/pkg:1.0-r0-amd64-build-123", PushedDigest: "sha256:" + strings.Repeat("b", 64), ImmutableReference: immutable, Verified: true},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	args := []string{"build", "pkg", "1", "--registry=registry.example", "--repository=team/images"}
	if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Immutable reference: "+immutable) || !strings.Contains(stdout.String(), "Registry published:") || !strings.Contains(stdout.String(), "Image signing: skipped\nSPDX attestation: skipped") || strings.Contains(stdout.String(), "Registry publication: skipped") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunBuildNoPublicationAllowsNoLoad(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "")
	t.Setenv("LUPETTO_REPOSITORY", "")
	calls := 0
	callback := func(_ context.Context, request cliRequest) (build.Result, error) {
		calls++
		if !request.NoLoad || request.Publication.Enabled() {
			t.Fatalf("local-only request=%+v", request)
		}
		return build.Result{DockerLoad: "skipped", Publication: build.PublicationOutcome{Status: "skipped"}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := runWithBuild(context.Background(), []string{"build", "pkg", "1", "--no-load"}, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "Docker loading: skipped") || !strings.Contains(stdout.String(), "Registry publication: skipped") {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
}

func TestRunBuildConsumesTypedWorkflowFailure(t *testing.T) {
	t.Setenv("LUPETTO_REGISTRY", "")
	t.Setenv("LUPETTO_REPOSITORY", "")
	digest := "sha256:" + strings.Repeat("b", 64)
	immutable := "registry.example/team/images/pkg@" + digest
	callback := func(context.Context, cliRequest) (build.Result, error) {
		failure := &build.WorkflowFailure{
			Result: build.Result{
				Workspace: "/synthetic/image-123", Build: "completed", DockerLoad: "loaded", ReadableConfirmed: true, Signing: "skipped", Attestation: "skipped",
				Publication: build.PublicationOutcome{Status: "failed", Reference: "registry.example/team/images/pkg:1.0-r0-amd64-build-123", PushedDigest: digest, ImmutableReference: immutable, Verified: false},
			},
			Stage: "publication", SideEffects: true, Cause: errors.New("publication identity verification failed"),
		}
		return build.Result{}, errors.Join(errors.New("outer wrapper must not be printed"), failure)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"build", "pkg", "1", "--registry=registry.example", "--repository=team/images"}
	if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, phrase := range []string{"build: completed", "Docker load: loaded", "publication: failed", "signing: skipped", "attestation: skipped", "captured pushed digest: " + digest, "immutable reference: " + immutable, "identity verified: false", "workspace: /synthetic/image-123", "no rollback attempted"} {
		if !strings.Contains(stderr.String(), phrase) {
			t.Fatalf("typed failure output missing %q: %s", phrase, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "outer wrapper must not be printed") {
		t.Fatalf("CLI printed the enclosing error instead of consuming typed outcomes: %s", stderr.String())
	}
}

func TestRunBuildReportsSignedAndAttestedImmutableIdentity(t *testing.T) {
	for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
		t.Setenv(name, "")
	}
	immutable := "registry.example/team/images/pkg@sha256:" + strings.Repeat("b", 64)
	calls := 0
	callback := func(_ context.Context, request cliRequest) (build.Result, error) {
		calls++
		if request.Signing != (build.SigningOptions{Key: "/synthetic/key", Config: "/synthetic/config"}) || !request.Publication.Enabled() || request.NoLoad {
			t.Fatalf("lost signing/publication request: %+v", request)
		}
		return build.Result{
			DockerLoad: "loaded", DockerImageID: "sha256:" + strings.Repeat("a", 64),
			ImageReference: "lupetto/pkg:1.0-r0-amd64", BuildReference: "lupetto/local:build-123",
			Publication: build.PublicationOutcome{Status: "published", Reference: "registry.example/team/images/pkg:1.0-r0-amd64-build-123", PushedDigest: "sha256:" + strings.Repeat("b", 64), ImmutableReference: immutable, Verified: true},
			Signing:     "signed", Attestation: "attested",
		}, nil
	}
	var stdout, stderr bytes.Buffer
	args := []string{"build", "pkg", "1", "--registry=registry.example", "--repository=team/images", "--cosign-key=/synthetic/key", "--cosign-signing-config=/synthetic/config"}
	if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 0 || calls != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
	for _, phrase := range []string{"Build completed", "Docker loaded:", "Registry published:", "Immutable reference: " + immutable, "Image signing: signed (" + immutable + ")", "SPDX attestation: attested (" + immutable + ")", "Image reference: lupetto/pkg:1.0-r0-amd64", "Build reference: lupetto/local:build-123"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Fatalf("success output missing %q: %s", phrase, stdout.String())
		}
	}
	for _, forbidden := range []string{"skipped", "/synthetic/key", "/synthetic/config"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("success output contains %q: %s", forbidden, stdout.String())
		}
	}
}

func TestRunBuildConsumesTypedSigningPartialFailures(t *testing.T) {
	for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
		t.Setenv(name, "")
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	immutable := "registry.example/team/images/pkg@" + digest
	for _, tc := range []struct{ stage, signing, attestation string }{
		{"signing", "failed", "not-attempted"},
		{"attestation", "signed", "failed"},
		{"result record", "signed", "attested"},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			callback := func(context.Context, cliRequest) (build.Result, error) {
				failure := &build.WorkflowFailure{
					Result: build.Result{
						Workspace: "/synthetic/image-123", Build: "completed", DockerLoad: "loaded", ReadableConfirmed: true,
						Publication: build.PublicationOutcome{Status: "published", PushedDigest: digest, ImmutableReference: immutable, Verified: true},
						Signing:     tc.signing, Attestation: tc.attestation,
					},
					Stage: tc.stage, SideEffects: true, Cause: errors.New("sanitized stage failure"),
				}
				return build.Result{}, errors.Join(errors.New("secret-outer-wrapper-canary"), failure)
			}
			var stdout, stderr bytes.Buffer
			args := []string{"build", "pkg", "1", "--registry=registry.example", "--repository=team/images", "--cosign-key=secret-key-canary"}
			if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			for _, phrase := range []string{"build: completed", "Docker load: loaded", "publication: published", "signing: " + tc.signing, "attestation: " + tc.attestation, "immutable reference: " + immutable, "identity verified: true", "workspace: /synthetic/image-123", "no rollback attempted"} {
				if !strings.Contains(stderr.String(), phrase) {
					t.Fatalf("typed partial output missing %q: %s", phrase, stderr.String())
				}
			}
			for _, forbidden := range []string{"secret-outer-wrapper-canary", "secret-key-canary", "Build completed"} {
				if strings.Contains(stderr.String(), forbidden) {
					t.Fatalf("typed partial output contains %q: %s", forbidden, stderr.String())
				}
			}
		})
	}
}

func TestRunBuildAllowsNoLoadWithPublication(t *testing.T) {
	for _, tc := range []struct {
		name, registry, repository string
		flags                      []string
	}{
		{name: "explicit publication", flags: []string{"--no-load", "--registry=registry.example", "--repository=team/images"}},
		{name: "environment publication", registry: "registry.example", repository: "team/images", flags: []string{"--no-load"}},
		{name: "signing", flags: []string{"--no-load", "--registry=registry.example", "--repository=team/images", "--cosign-key=/synthetic/key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
				t.Setenv(name, "")
			}
			t.Setenv("LUPETTO_REGISTRY", tc.registry)
			t.Setenv("LUPETTO_REPOSITORY", tc.repository)
			calls := 0
			callback := func(_ context.Context, request cliRequest) (build.Result, error) {
				calls++
				if !request.NoLoad || !request.Publication.Enabled() {
					t.Fatalf("request=%+v", request)
				}
				return build.Result{}, errors.New("synthetic callback failure")
			}
			var stdout, stderr bytes.Buffer
			args := append([]string{"build", "nginx", "1.30"}, tc.flags...)
			if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 1 || calls != 1 {
				t.Fatalf("code=%d calls=%d stderr=%q", code, calls, stderr.String())
			}
		})
	}
}

func TestParseBuildJSON(t *testing.T) {
	for _, args := range [][]string{
		{"valkey", "9.1", "--json"},
		{"--json", "valkey", "--apk-version=9.1.2-r1", "--no-load"},
	} {
		if request, err := parseBuild(args); err != nil || !request.json {
			t.Fatalf("args=%q request=%+v err=%v", args, request, err)
		}
	}
	for _, args := range [][]string{
		{"valkey", "9.1", "--json", "--json"},
		{"valkey", "9.1", "--json=true"},
		{"valkey", "9.1", "--json=false"},
		{"valkey", "--apk-version", "--json"},
	} {
		if request, err := parseBuild(args); err == nil {
			t.Fatalf("args=%q accepted %+v", args, request)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic stdout failure") }

func TestRunJSONOutput(t *testing.T) {
	for _, name := range []string{"LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP"} {
		t.Setenv(name, "")
	}
	record := []byte("{\n  \"version\": 6\n}\n")
	success := func(_ context.Context, request cliRequest) (build.Result, error) {
		if !request.json {
			t.Fatal("--json not passed to the build")
		}
		return build.Result{Record: record}, nil
	}
	for _, command := range [][]string{{"build", "pkg", "1", "--json"}, {"sbom", "pkg", "--apk-version=1.0-r0", "--json"}} {
		var stdout, stderr bytes.Buffer
		if code := runWithBuild(context.Background(), command, &stdout, &stderr, success); code != 0 || !bytes.Equal(stdout.Bytes(), record) {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", command, code, stdout.String(), stderr.String())
		}
	}
	// A typed failure prints its record on stdout; stderr keeps human output.
	failure := build.NewWorkflowFailure(build.InitialResult(build.Request{PackageName: "pkg", Selector: "1"}), "build", errors.New("synthetic local failure"), false)
	var stdout, stderr bytes.Buffer
	code := runWithBuild(context.Background(), []string{"build", "pkg", "1", "--json"}, &stdout, &stderr, func(context.Context, cliRequest) (build.Result, error) {
		return build.Result{}, failure
	})
	var decoded build.Record
	if code != 1 || !bytes.Equal(stdout.Bytes(), failure.Record) || json.Unmarshal(stdout.Bytes(), &decoded) != nil || decoded.Failure == nil || decoded.Failure.Error != "synthetic local failure" || decoded.Request.Package != "pkg" || decoded.Stages.Build.Status != "not-attempted" || decoded.Stages.Load.Status != "not-attempted" || decoded.Stages.Publication.Status != "skipped" || !strings.Contains(stderr.String(), "synthetic local failure") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	// Untyped failures and invocation errors print nothing on stdout.
	stdout.Reset()
	if code := runWithBuild(context.Background(), []string{"build", "pkg", "1", "--json"}, &stdout, &stderr, func(context.Context, cliRequest) (build.Result, error) {
		return build.Result{}, errors.New("untyped")
	}); code != 1 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q", code, stdout.String())
	}
	for _, args := range [][]string{{"build", "pkg", "1", "--json", "--json"}, {"build", "pkg", "--json"}, {"sbom", "pkg", "1", "--json"}, {"build", "pkg", "1", "--json", "--registry=registry.example"}} {
		stdout.Reset()
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, func(context.Context, cliRequest) (build.Result, error) {
			t.Fatal("invalid invocation started a build")
			return build.Result{}, nil
		}); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args=%q code=%d stdout=%q", args, code, stdout.String())
		}
	}
	// A stdout write failure is reported on stderr and fails the command.
	stderr.Reset()
	if code := runWithBuild(context.Background(), []string{"build", "pkg", "1", "--json"}, failingWriter{}, &stderr, success); code != 1 || stderr.String() != "lupetto: could not write JSON result\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunBuildRejectsRelativeDataDirBeforeCallback(t *testing.T) {
	t.Setenv("LUPETTO_DATA_DIR", "relative/data")
	t.Setenv("LUPETTO_REGISTRY", "")
	t.Setenv("LUPETTO_REPOSITORY", "")
	for _, args := range [][]string{{"build", "busybox-static", "1", "--no-load"}, {"sbom", "busybox-static", "--apk-version", "1.38.0-r2"}} {
		called := false
		callback := func(context.Context, cliRequest) (build.Result, error) { called = true; return build.Result{}, nil }
		var stdout, stderr bytes.Buffer
		if code := runWithBuild(context.Background(), args, &stdout, &stderr, callback); code != 2 || called || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid configuration: LUPETTO_DATA_DIR must be an absolute path") {
			t.Fatalf("args=%q code=%d called=%v stdout=%q stderr=%q", args, code, called, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"images", "--json"}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "LUPETTO_DATA_DIR must be an absolute path") {
		t.Fatalf("images: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "<data>/lupetto/builds, where <data> is LUPETTO_DATA_DIR") || !strings.Contains(stdout.String(), "read-only, the legacy <user cache>/lupetto/builds") {
		t.Fatalf("help does not describe the data root: %s", stdout.String())
	}
}
