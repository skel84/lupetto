package main

import (
	"strings"
	"testing"

	"github.com/distribution/reference"
)

func TestResolvePublicationPrecedence(t *testing.T) {
	flag := func(value string) optionalString { return optionalString{value: value, set: true} }
	for _, tc := range []struct {
		name      string
		raw       publicationFlags
		env       map[string]string
		want      publicationOptions
		wantError bool
	}{
		{name: "absent"},
		{name: "empty environment", env: map[string]string{"LUPETTO_REGISTRY": "", "LUPETTO_REPOSITORY": ""}},
		{name: "environment pair", env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}, want: publicationOptions{"registry.example", "team/images"}},
		{name: "flags pair", raw: publicationFlags{flag("localhost:5000"), flag("dev/images")}, want: publicationOptions{"localhost:5000", "dev/images"}},
		{name: "registry flag independently overrides invalid env", raw: publicationFlags{registry: flag("localhost:5000")}, env: map[string]string{"LUPETTO_REGISTRY": "https://invalid", "LUPETTO_REPOSITORY": "team/images"}, want: publicationOptions{"localhost:5000", "team/images"}},
		{name: "repository flag independently overrides invalid env", raw: publicationFlags{repository: flag("dev/images")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "INVALID"}, want: publicationOptions{"registry.example", "dev/images"}},
		{name: "empty registry flag never revives env", raw: publicationFlags{registry: flag("")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team"}, wantError: true},
		{name: "empty repository flag never revives env", raw: publicationFlags{repository: flag("")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team"}, wantError: true},
		{name: "both empty flags never disable publication", raw: publicationFlags{flag(""), flag("")}, wantError: true},
		{name: "only registry flag", raw: publicationFlags{registry: flag("registry.example")}, wantError: true},
		{name: "only repository flag", raw: publicationFlags{repository: flag("team/images")}, wantError: true},
		{name: "only registry environment", env: map[string]string{"LUPETTO_REGISTRY": "registry.example"}, wantError: true},
		{name: "only repository environment", env: map[string]string{"LUPETTO_REPOSITORY": "team/images"}, wantError: true},
		{name: "invalid environment not ignored", env: map[string]string{"LUPETTO_REGISTRY": "https://registry.example", "LUPETTO_REPOSITORY": "team/images"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) { value, ok := tc.env[name]; return value, ok }
			got, err := resolvePublication(tc.raw, lookup)
			if (err != nil) != tc.wantError {
				t.Fatalf("resolvePublication()=%+v, %v; wantError=%v", got, err, tc.wantError)
			}
			if err == nil && (got != tc.want || got.enabled() != tc.want.enabled()) {
				t.Fatalf("resolved=%+v; want=%+v", got, tc.want)
			}
		})
	}
	if opts, err := resolvePublication(publicationFlags{}, nil); err != nil || opts.enabled() {
		t.Fatalf("nil lookup: opts=%+v err=%v", opts, err)
	}
	if opts, err := resolvePublication(publicationFlags{}, func(string) (string, bool) { return "ignored", false }); err != nil || opts.enabled() {
		t.Fatalf("absent lookup: opts=%+v err=%v", opts, err)
	}
}

func TestValidatePublicationRegistryAuthority(t *testing.T) {
	for _, registry := range []string{
		"registry.example", "registry.example:443", "Registry.EXAMPLE", "localhost", "localhost:1", "registry:5000", "123:5000", "127.0.0.1", "127.0.0.1:65535", "[::1]", "[::1]:5000", "[2001:db8::1]:443", "[::ffff:7f00:1]:5000",
	} {
		t.Run(registry, func(t *testing.T) {
			opts := publicationOptions{registry, "team/lupetto/images"}
			if err := validatePublicationOptions(opts); err != nil {
				t.Fatalf("valid authority %q: %v", registry, err)
			}
		})
	}
	for _, registry := range []string{
		"registry", "docker.io/library", "https://registry.example", "user@registry.example", "registry.example?x=y", "registry.example#fragment", "registry.example/", "registry.example\\path", " registry.example", "registry.example\n", "registry.example:", "registry.example:0", "registry.example:65536", "registry.example:-1", "registry.example:+443", "registry.example:1.5", "registry.example:999999999999999999999", ":5000", "-registry.example", "registry-.example", "registry..example", "registry.example.", "registry_example.test", "999.1.2.3", "127.00.0.1", "::1", "[::1", "[::1]path", "[::1]:", "[::1]:65536", "[127.0.0.1]", "[hostname]", "[fe80::1%lo0]", "[::1]:5000:6000", "[::1]]", "index.docker.io", strings.Repeat("a", 64) + ".example",
	} {
		t.Run("reject "+registry, func(t *testing.T) {
			if err := validatePublicationOptions(publicationOptions{registry, "team/images"}); err == nil {
				t.Fatalf("accepted invalid or normalized authority %q", registry)
			}
		})
	}
}

func TestValidatePublicationNestedRepository(t *testing.T) {
	for _, prefix := range []string{"team", "team/lupetto/images", "team_name/image.name", "team__name/image--name"} {
		if err := validatePublicationOptions(publicationOptions{"registry.example", prefix}); err != nil {
			t.Fatalf("valid prefix %q: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"", "/team", "team/", "team//images", ".", "..", "team/../images", "Team/images", "team/Image", "team/images:latest", "team/images@sha256:abc", "team/ image", "team/.image", "team/image_", "team/a___b", "team/https://images", "team\nimages"} {
		if err := validatePublicationOptions(publicationOptions{"registry.example", prefix}); err == nil {
			t.Fatalf("accepted invalid prefix %q", prefix)
		}
	}
}

func TestPublicationReferencesUseExactSelectedIdentity(t *testing.T) {
	opts := publicationOptions{"registry.example:5000", "team/lupetto/images"}
	selected := indexedPackage{name: "nginx-stable", version: "1.30.2-r0"}
	got, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts)
	wantRepository := "registry.example:5000/team/lupetto/images/nginx-stable"
	if err != nil || got.repository != wantRepository || got.reference != wantRepository+":1.30.2-r0-amd64-build-123" {
		t.Fatalf("target=%+v err=%v", got, err)
	}
	arm, err := publicationReferences(selected, "aarch64", "/cache/image-456", opts)
	if err != nil || arm.reference != wantRepository+":1.30.2-r0-arm64-build-456" {
		t.Fatalf("arm target=%+v err=%v", arm, err)
	}
	other, err := publicationReferences(selected, "x86_64", "/cache/image-456", opts)
	if err != nil || other.reference == got.reference || other.repository != got.repository {
		t.Fatalf("workspace uniqueness: first=%+v second=%+v err=%v", got, other, err)
	}
	if skipped, err := publicationReferences(selected, "unsupported", "", publicationOptions{}); err != nil || skipped != (publicationTarget{}) {
		t.Fatalf("disabled publication: target=%+v err=%v", skipped, err)
	}
	if _, err := publicationReferences(selected, "unsupported", "/cache/image-123", opts); err == nil {
		t.Fatal("accepted unsupported architecture")
	}
	for _, workspace := range []string{"/cache/not-unique", "/cache/image-", "/cache/image-invalid suffix"} {
		if _, err := publicationReferences(selected, "x86_64", workspace, opts); err == nil {
			t.Fatalf("accepted invalid workspace %q", workspace)
		}
	}
}

func TestPublicationReferencesReuseLocalFallbacks(t *testing.T) {
	opts := publicationOptions{"localhost:5000", "team/images"}
	for _, selected := range []indexedPackage{
		{name: "Mixed+Name", version: "1.2+build-r0"},
		{name: "apk-sha256-literal", version: "_literal-r0"},
		{name: strings.Repeat("a", 256), version: "1.0-r0"},
	} {
		local, err := readableImageReference(selected, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		target, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts)
		want := opts.registry + "/" + opts.repository + "/" + strings.TrimPrefix(local, "lupetto/") + "-build-123"
		if err != nil || target.reference != want {
			t.Fatalf("selected=%+v target=%+v want=%q err=%v", selected, target, want, err)
		}
	}
}

func TestPublicationReferencesHashWholeOverlongCombinedTag(t *testing.T) {
	selected := indexedPackage{name: "pkg", version: strings.Repeat("1", 110) + "-r0"}
	opts := publicationOptions{"registry.example", "team/images"}
	local, err := readableImageReference(selected, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	_, localTag, _ := strings.Cut(local, ":")
	suffix := "1234567890"
	combined := localTag + "-build-" + suffix
	if len(localTag) > 128 || len(combined) <= 128 {
		t.Fatalf("fixture must have literal local and overlong remote tags: %q", combined)
	}
	first, err := publicationReferences(selected, "x86_64", "/cache/image-"+suffix, opts)
	want := "registry.example/team/images/pkg:_apk-sha256-" + sha256Hex([]byte(combined))
	if err != nil || first.reference != want {
		t.Fatalf("target=%+v want=%s err=%v", first, want, err)
	}
	repeated, err := publicationReferences(selected, "x86_64", "/other/image-"+suffix, opts)
	if err != nil || repeated != first {
		t.Fatalf("fallback not deterministic: %+v %+v err=%v", first, repeated, err)
	}
	other, err := publicationReferences(selected, "x86_64", "/cache/image-9999999999", opts)
	if err != nil || other.reference == first.reference {
		t.Fatalf("fallback lost unique workspace suffix: %+v %+v err=%v", first, other, err)
	}
}

func TestPublicationReferencesFullRepositoryLength(t *testing.T) {
	selected := indexedPackage{name: "pkg", version: "1.0-r0"}
	for _, registry := range []string{"r.example", strings.Repeat("a", 60) + ".example", "[2001:db8::1]:5000"} {
		prefixLength := reference.RepositoryNameTotalLengthMax - len(registry) - len("//pkg")
		opts := publicationOptions{registry, strings.Repeat("a", prefixLength)}
		target, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts)
		if err != nil || len(target.repository) != reference.RepositoryNameTotalLengthMax {
			t.Fatalf("boundary authority=%q target=%+v err=%v", registry, target, err)
		}
		opts.repository += "a"
		if _, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts); err == nil {
			t.Fatalf("accepted overlong full name including authority %q", registry)
		}
	}
	if err := validatePublicationOptions(publicationOptions{"registry.example", strings.Repeat("a", reference.RepositoryNameTotalLengthMax)}); err == nil {
		t.Fatal("accepted prefix that cannot fit any eventual APK component")
	}
}
