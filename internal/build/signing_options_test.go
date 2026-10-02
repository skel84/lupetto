package build

import (
	"strings"
	"testing"
)

func TestResolveSigningIndependentPrecedence(t *testing.T) {
	flag := func(value string) OptionalString { return OptionalString{Value: value, Set: true} }
	production := PublicationOptions{Registry: "registry.example", Repository: "team/images"}
	loopback := PublicationOptions{Registry: "127.0.0.1:5000", Repository: "team/images"}
	for _, tc := range []struct {
		name      string
		raw       SigningFlags
		env       map[string]string
		pub       PublicationOptions
		want      SigningOptions
		wantError bool
	}{
		{name: "disabled by default"},
		{name: "unset flag values ignored", raw: SigningFlags{Key: OptionalString{Value: "ignored"}, Config: OptionalString{Value: "ignored"}, AllowHTTP: OptionalBool{Value: true}}},
		{name: "empty environment absent", env: map[string]string{"LUPETTO_COSIGN_KEY": "", "LUPETTO_COSIGN_SIGNING_CONFIG": "", "LUPETTO_COSIGN_ALLOW_HTTP": ""}},
		{name: "key alone preserves upstream defaults", raw: SigningFlags{Key: flag("flag-key")}, pub: production, want: SigningOptions{Key: "flag-key"}},
		{name: "environment key and config together", env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: SigningOptions{Key: "env-key", Config: "env-config"}},
		{name: "flag key and environment config", raw: SigningFlags{Key: flag("flag-key")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: SigningOptions{Key: "flag-key", Config: "env-config"}},
		{name: "environment key and flag config", raw: SigningFlags{Config: flag("flag-config")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, want: SigningOptions{Key: "env-key", Config: "flag-config"}},
		{name: "flag false overrides environment true", raw: SigningFlags{Key: flag("flag-key"), AllowHTTP: OptionalBool{Value: false, Set: true}}, env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: production, want: SigningOptions{Key: "flag-key"}},
		{name: "flag bool overrides invalid environment", raw: SigningFlags{Key: flag("flag-key"), AllowHTTP: OptionalBool{Value: false, Set: true}}, env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "secret-invalid"}, pub: production, want: SigningOptions{Key: "flag-key"}},
		{name: "environment loopback consent", env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: loopback, want: SigningOptions{Key: "env-key", AllowHTTP: true}},
		{name: "false override removes loopback consent", raw: SigningFlags{AllowHTTP: OptionalBool{Set: true}}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_ALLOW_HTTP": "true"}, pub: loopback, wantError: true},
		{name: "environment false no key is noop", env: map[string]string{"LUPETTO_COSIGN_ALLOW_HTTP": "false"}},
		{name: "explicit false no key is noop", raw: SigningFlags{AllowHTTP: OptionalBool{Set: true}}},
		{name: "empty flag key never revives env", raw: SigningFlags{Key: flag("")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key"}, pub: production, wantError: true},
		{name: "empty flag config never revives env", raw: SigningFlags{Config: flag("")}, env: map[string]string{"LUPETTO_COSIGN_KEY": "env-key", "LUPETTO_COSIGN_SIGNING_CONFIG": "env-config"}, pub: production, wantError: true},
		{name: "config alone not keyless", raw: SigningFlags{Config: flag("flag-config")}, pub: production, wantError: true},
		{name: "HTTP alone not keyless", raw: SigningFlags{AllowHTTP: OptionalBool{Value: true, Set: true}}, pub: loopback, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) { value, ok := tc.env[name]; return value, ok }
			opts, err := ResolveSigning(tc.raw, tc.pub, lookup)
			if (err != nil) != tc.wantError || (!tc.wantError && opts != tc.want) {
				t.Fatalf("opts=%+v err=%v want=%+v error=%v", opts, err, tc.want, tc.wantError)
			}
		})
	}
	for _, lookup := range []func(string) (string, bool){nil, func(string) (string, bool) { return "ignored", false }} {
		if opts, err := ResolveSigning(SigningFlags{}, PublicationOptions{}, lookup); err != nil || opts != (SigningOptions{}) {
			t.Fatalf("absent lookup: opts=%+v err=%v", opts, err)
		}
	}
}

func TestResolveSigningStrictEnvironmentBoolean(t *testing.T) {
	for _, value := range []string{"TRUE", "False", "1", "0", "yes", " true", "false ", "\ntrue", "secret-canary"} {
		lookup := func(name string) (string, bool) { return value, name == "LUPETTO_COSIGN_ALLOW_HTTP" }
		if _, err := ResolveSigning(SigningFlags{}, PublicationOptions{}, lookup); err == nil || err.Error() != "LUPETTO_COSIGN_ALLOW_HTTP must be true or false" {
			t.Fatalf("value=%q err=%v; want exact sanitized strict-bool error", value, err)
		}
	}
}

func TestResolveSigningDoesNotInspectSecretsOrOverriddenEnvironment(t *testing.T) {
	lookup := func(name string) (string, bool) {
		t.Fatalf("explicit signing settings unexpectedly read environment %q", name)
		return "", false
	}
	raw := SigningFlags{
		Key:       OptionalString{Value: "key", Set: true},
		Config:    OptionalString{Value: "config", Set: true},
		AllowHTTP: OptionalBool{Set: true},
		Require:   OptionalBool{Value: true, Set: true},
	}
	if opts, err := ResolveSigning(raw, PublicationOptions{Registry: "registry.example", Repository: "team/images"}, lookup); err != nil || opts != (SigningOptions{Key: "key", Config: "config"}) {
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
	if _, err := ResolveSigning(SigningFlags{}, PublicationOptions{}, lookup); err != nil {
		t.Fatal(err)
	}
	if strings.Join(lookedUp, ",") != "LUPETTO_COSIGN_KEY,LUPETTO_COSIGN_SIGNING_CONFIG,LUPETTO_COSIGN_ALLOW_HTTP,LUPETTO_REQUIRE_SIGNING" {
		t.Fatalf("unexpected environment reads: %q", lookedUp)
	}
}

func TestValidateSigningLiteralLoopbackPolicy(t *testing.T) {
	for _, registry := range []string{"localhost", "localhost:5000", "LOCALHOST:5000", "127.0.0.1", "127.12.34.56:5000", "[::1]", "[::1]:5000", "[::ffff:7f00:1]:5000"} {
		pub := PublicationOptions{Registry: registry, Repository: "team/images"}
		if err := validateSigningOptions(SigningOptions{Key: "key", AllowHTTP: true}, pub); err != nil {
			t.Fatalf("loopback %q rejected: %v", registry, err)
		}
		if err := validateSigningOptions(SigningOptions{Key: "key"}, pub); err == nil {
			t.Fatalf("loopback %q accepted without HTTP consent", registry)
		}
		if err := validateSigningOptions(SigningOptions{}, pub); err != nil {
			t.Fatalf("unsigned publication %q required signing consent: %v", registry, err)
		}
	}
	for _, registry := range []string{"registry.example", "registry.example:443", "localhost.example", "loopback.example:5000", "registry:5000", "192.0.2.1:5000", "[2001:db8::1]:5000", "[::ffff:c000:201]:5000"} {
		pub := PublicationOptions{Registry: registry, Repository: "team/images"}
		if err := validateSigningOptions(SigningOptions{Key: "key"}, pub); err != nil {
			t.Fatalf("production default %q rejected: %v", registry, err)
		}
		if err := validateSigningOptions(SigningOptions{Key: "key", AllowHTTP: true}, pub); err == nil {
			t.Fatalf("nonloopback %q accepted HTTP allowance", registry)
		}
	}
}

func TestValidateSigningRequiresCompletePublication(t *testing.T) {
	for _, pub := range []PublicationOptions{{}, {Registry: "registry.example"}, {Repository: "team/images"}, {Registry: "https://registry.example", Repository: "team/images"}, {Registry: "registry.example", Repository: "INVALID"}} {
		if err := validateSigningOptions(SigningOptions{Key: "key"}, pub); err == nil {
			t.Fatalf("incomplete/invalid publication accepted: %+v", pub)
		}
	}
	// Loading is independent of signing: complete publication suffices.
	if err := validateSigningOptions(SigningOptions{Key: "key"}, PublicationOptions{Registry: "registry.example", Repository: "team/images"}); err != nil {
		t.Fatalf("complete publication rejected: %v", err)
	}
	if err := validateSigningOptions(SigningOptions{}, PublicationOptions{}); err != nil {
		t.Fatalf("unsigned local build rejected: %v", err)
	}
}

func TestResolveSigningRequireSigning(t *testing.T) {
	production := PublicationOptions{Registry: "registry.example", Repository: "team/images"}
	on := OptionalBool{Value: true, Set: true}
	off := OptionalBool{Set: true}
	for _, tc := range []struct {
		name      string
		raw       SigningFlags
		env       map[string]string
		pub       PublicationOptions
		want      SigningOptions
		wantError string
	}{
		{name: "flag refuses unsigned publication", raw: SigningFlags{Require: on}, pub: production, wantError: errUnsignedPublicationRefused.Error()},
		{name: "environment refuses unsigned publication", env: map[string]string{RequireSigningEnv: "true"}, pub: production, wantError: errUnsignedPublicationRefused.Error()},
		{name: "flag true overrides environment false", raw: SigningFlags{Require: on}, env: map[string]string{RequireSigningEnv: "false"}, pub: production, wantError: errUnsignedPublicationRefused.Error()},
		{name: "flag false overrides environment true", raw: SigningFlags{Require: off}, env: map[string]string{RequireSigningEnv: "true"}, pub: production},
		{name: "flag false overrides invalid environment", raw: SigningFlags{Require: off}, env: map[string]string{RequireSigningEnv: "secret-invalid"}, pub: production},
		{name: "environment false", env: map[string]string{RequireSigningEnv: "false"}, pub: production},
		{name: "empty environment is unset", env: map[string]string{RequireSigningEnv: ""}, pub: production},
		{name: "empty environment key is no key", env: map[string]string{RequireSigningEnv: "true", "LUPETTO_COSIGN_KEY": ""}, pub: production, wantError: errUnsignedPublicationRefused.Error()},
		{name: "satisfied by key", raw: SigningFlags{Require: on, Key: OptionalString{Value: "flag-key", Set: true}}, pub: production, want: SigningOptions{Key: "flag-key"}},
		{name: "satisfied by environment key", env: map[string]string{RequireSigningEnv: "true", "LUPETTO_COSIGN_KEY": "env-key"}, pub: production, want: SigningOptions{Key: "env-key"}},
		{name: "no effect without publication", raw: SigningFlags{Require: on}},
		{name: "environment no effect without publication", env: map[string]string{RequireSigningEnv: "true"}},
		{name: "invalid environment without publication", env: map[string]string{RequireSigningEnv: "yes"}, wantError: "LUPETTO_REQUIRE_SIGNING must be true or false"},
		{name: "other errors still win", raw: SigningFlags{Require: on, Key: OptionalString{Value: "flag-key", Set: true}}, wantError: "signing requires publication with both registry and repository settings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) { value, ok := tc.env[name]; return value, ok }
			opts, err := ResolveSigning(tc.raw, tc.pub, lookup)
			if tc.wantError != "" {
				if err == nil || err.Error() != tc.wantError {
					t.Fatalf("err=%v want %q", err, tc.wantError)
				}
				return
			}
			if err != nil || opts != tc.want {
				t.Fatalf("opts=%+v err=%v want=%+v", opts, err, tc.want)
			}
		})
	}
	for _, value := range []string{"TRUE", "False", "1", "0", "yes", " true", "false ", "secret-canary"} {
		lookup := func(name string) (string, bool) { return value, name == RequireSigningEnv }
		if _, err := ResolveSigning(SigningFlags{}, production, lookup); err == nil || err.Error() != "LUPETTO_REQUIRE_SIGNING must be true or false" {
			t.Fatalf("value=%q err=%v; want exact sanitized strict-bool error", value, err)
		}
	}
	if !UnsignedPublication(production, SigningOptions{}) || UnsignedPublication(production, SigningOptions{Key: "k"}) || UnsignedPublication(PublicationOptions{}, SigningOptions{}) {
		t.Fatal("UnsignedPublication classification")
	}
	if strings.Contains(UnsignedPublicationWarning, "\n") || !strings.Contains(UnsignedPublicationWarning, "--cosign-key / LUPETTO_COSIGN_KEY") || !strings.Contains(UnsignedPublicationWarning, "--require-signing / LUPETTO_REQUIRE_SIGNING") {
		t.Fatalf("warning must be one line naming both settings: %q", UnsignedPublicationWarning)
	}
}
