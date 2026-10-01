package build

import (
	"strings"
	"testing"

	"github.com/distribution/reference"
	"lupetto/internal/wolfi"
)

func TestResolvePublicationPrecedence(t *testing.T) {
	flag := func(value string) OptionalString { return OptionalString{Value: value, Set: true} }
	for _, tc := range []struct {
		name      string
		raw       PublicationFlags
		env       map[string]string
		want      PublicationOptions
		wantError bool
	}{
		{name: "absent"},
		{name: "empty environment", env: map[string]string{"LUPETTO_REGISTRY": "", "LUPETTO_REPOSITORY": ""}},
		{name: "environment pair", env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}, want: PublicationOptions{"registry.example", "team/images"}},
		{name: "flags pair", raw: PublicationFlags{flag("localhost:5000"), flag("dev/images")}, want: PublicationOptions{"localhost:5000", "dev/images"}},
		{name: "registry flag independently overrides invalid env", raw: PublicationFlags{Registry: flag("localhost:5000")}, env: map[string]string{"LUPETTO_REGISTRY": "https://invalid", "LUPETTO_REPOSITORY": "team/images"}, want: PublicationOptions{"localhost:5000", "team/images"}},
		{name: "repository flag independently overrides invalid env", raw: PublicationFlags{Repository: flag("dev/images")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "INVALID"}, want: PublicationOptions{"registry.example", "dev/images"}},
		{name: "empty registry flag never revives env", raw: PublicationFlags{Registry: flag("")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team"}, wantError: true},
		{name: "empty repository flag never revives env", raw: PublicationFlags{Repository: flag("")}, env: map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team"}, wantError: true},
		{name: "both empty flags never disable publication", raw: PublicationFlags{flag(""), flag("")}, wantError: true},
		{name: "only registry flag", raw: PublicationFlags{Registry: flag("registry.example")}, wantError: true},
		{name: "only repository flag", raw: PublicationFlags{Repository: flag("team/images")}, wantError: true},
		{name: "only registry environment", env: map[string]string{"LUPETTO_REGISTRY": "registry.example"}, wantError: true},
		{name: "only repository environment", env: map[string]string{"LUPETTO_REPOSITORY": "team/images"}, wantError: true},
		{name: "invalid environment not ignored", env: map[string]string{"LUPETTO_REGISTRY": "https://registry.example", "LUPETTO_REPOSITORY": "team/images"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(name string) (string, bool) { value, ok := tc.env[name]; return value, ok }
			got, err := ResolvePublication(tc.raw, lookup)
			if (err != nil) != tc.wantError {
				t.Fatalf("resolvePublication()=%+v, %v; wantError=%v", got, err, tc.wantError)
			}
			if err == nil && (got != tc.want || got.Enabled() != tc.want.Enabled()) {
				t.Fatalf("resolved=%+v; want=%+v", got, tc.want)
			}
		})
	}
	if opts, err := ResolvePublication(PublicationFlags{}, nil); err != nil || opts.Enabled() {
		t.Fatalf("nil lookup: opts=%+v err=%v", opts, err)
	}
	if opts, err := ResolvePublication(PublicationFlags{}, func(string) (string, bool) { return "ignored", false }); err != nil || opts.Enabled() {
		t.Fatalf("absent lookup: opts=%+v err=%v", opts, err)
	}
}

func TestValidatePublicationRegistryAuthority(t *testing.T) {
	for _, registry := range []string{
		"registry.example", "registry.example:443", "Registry.EXAMPLE", "localhost", "localhost:1", "registry:5000", "123:5000", "127.0.0.1", "127.0.0.1:65535", "[::1]", "[::1]:5000", "[2001:db8::1]:443", "[::ffff:7f00:1]:5000",
	} {
		t.Run(registry, func(t *testing.T) {
			opts := PublicationOptions{registry, "team/lupetto/images"}
			if err := validatePublicationOptions(opts); err != nil {
				t.Fatalf("valid authority %q: %v", registry, err)
			}
		})
	}
	for _, registry := range []string{
		"registry", "docker.io/library", "https://registry.example", "user@registry.example", "registry.example?x=y", "registry.example#fragment", "registry.example/", "registry.example\\path", " registry.example", "registry.example\n", "registry.example:", "registry.example:0", "registry.example:65536", "registry.example:-1", "registry.example:+443", "registry.example:1.5", "registry.example:999999999999999999999", ":5000", "-registry.example", "registry-.example", "registry..example", "registry.example.", "registry_example.test", "999.1.2.3", "127.00.0.1", "::1", "[::1", "[::1]path", "[::1]:", "[::1]:65536", "[127.0.0.1]", "[hostname]", "[fe80::1%lo0]", "[::1]:5000:6000", "[::1]]", "index.docker.io", strings.Repeat("a", 64) + ".example",
	} {
		t.Run("reject "+registry, func(t *testing.T) {
			if err := validatePublicationOptions(PublicationOptions{registry, "team/images"}); err == nil {
				t.Fatalf("accepted invalid or normalized authority %q", registry)
			}
		})
	}
}

func TestValidatePublicationNestedRepository(t *testing.T) {
	for _, prefix := range []string{"team", "team/lupetto/images", "team_name/image.name", "team__name/image--name"} {
		if err := validatePublicationOptions(PublicationOptions{"registry.example", prefix}); err != nil {
			t.Fatalf("valid prefix %q: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"", "/team", "team/", "team//images", ".", "..", "team/../images", "Team/images", "team/Image", "team/images:latest", "team/images@sha256:abc", "team/ image", "team/.image", "team/image_", "team/a___b", "team/https://images", "team\nimages"} {
		if err := validatePublicationOptions(PublicationOptions{"registry.example", prefix}); err == nil {
			t.Fatalf("accepted invalid prefix %q", prefix)
		}
	}
}

func TestPublicationReferencesUseExactSelectedIdentity(t *testing.T) {
	opts := PublicationOptions{"registry.example:5000", "team/lupetto/images"}
	selected := wolfi.Package{Name: "nginx-stable", Version: "1.30.2-r0"}
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
	if skipped, err := publicationReferences(selected, "unsupported", "", PublicationOptions{}); err != nil || skipped != (publicationTarget{}) {
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
	opts := PublicationOptions{"localhost:5000", "team/images"}
	for _, selected := range []wolfi.Package{
		{Name: "Mixed+Name", Version: "1.2+build-r0"},
		{Name: "apk-sha256-literal", Version: "_literal-r0"},
		{Name: strings.Repeat("a", 256), Version: "1.0-r0"},
	} {
		local, err := readableImageReference(selected, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		target, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts)
		want := opts.Registry + "/" + opts.Repository + "/" + strings.TrimPrefix(local, "lupetto/") + "-build-123"
		if err != nil || target.reference != want {
			t.Fatalf("selected=%+v target=%+v want=%q err=%v", selected, target, want, err)
		}
	}
}

func TestPublicationReferencesHashWholeOverlongCombinedTag(t *testing.T) {
	selected := wolfi.Package{Name: "pkg", Version: strings.Repeat("1", 110) + "-r0"}
	opts := PublicationOptions{"registry.example", "team/images"}
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
	want := "registry.example/team/images/pkg:_apk-sha256-" + wolfi.SHA256Hex([]byte(combined))
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
	selected := wolfi.Package{Name: "pkg", Version: "1.0-r0"}
	for _, registry := range []string{"r.example", strings.Repeat("a", 60) + ".example", "[2001:db8::1]:5000"} {
		prefixLength := reference.RepositoryNameTotalLengthMax - len(registry) - len("//pkg")
		opts := PublicationOptions{registry, strings.Repeat("a", prefixLength)}
		target, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts)
		if err != nil || len(target.repository) != reference.RepositoryNameTotalLengthMax {
			t.Fatalf("boundary authority=%q target=%+v err=%v", registry, target, err)
		}
		opts.Repository += "a"
		if _, err := publicationReferences(selected, "x86_64", "/cache/image-123", opts); err == nil {
			t.Fatalf("accepted overlong full name including authority %q", registry)
		}
	}
	if err := validatePublicationOptions(PublicationOptions{"registry.example", strings.Repeat("a", reference.RepositoryNameTotalLengthMax)}); err == nil {
		t.Fatal("accepted prefix that cannot fit any eventual APK component")
	}
}

func TestPublicationReferencesParseUpstreamTagWithoutNormalization(t *testing.T) {
	selected := wolfi.Package{Name: "nginx-stable", Version: "1.30.2-r0"}
	for _, tc := range []struct {
		registry, scheme, registryStr string
		insecure                      bool
	}{
		{"registry.example:5000", "https", "registry.example:5000", false},
		{"registry.example", "https", "registry.example", false},
		{"10.0.0.1:5000", "http", "10.0.0.1:5000", false}, // ggcr heuristic only; the guard refuses plain HTTP
		{"127.0.0.1:5000", "http", "127.0.0.1:5000", true},
		{"127.0.0.2:5000", "http", "127.0.0.2:5000", true},
		{"localhost", "http", "localhost", true},
		{"LOCALHOST:5000", "http", "LOCALHOST:5000", true},
		{"[::1]:5000", "http", "[::1]:5000", true},
		{"docker.io", "https", "index.docker.io", false},
	} {
		target, err := publicationReferences(selected, "x86_64", "/cache/image-123", PublicationOptions{tc.registry, "team/images"})
		if err != nil {
			t.Fatalf("registry %q: %v", tc.registry, err)
		}
		if target.insecure != tc.insecure || target.tag.Scheme() != tc.scheme || target.tag.RegistryStr() != tc.registryStr || target.tag.RepositoryStr() != "team/images/nginx-stable" || target.tag.TagStr() != "1.30.2-r0-amd64-build-123" {
			t.Fatalf("registry %q: target=%+v scheme=%s", tc.registry, target, target.tag.Scheme())
		}
		// The record keeps the operator's authority, including docker.io.
		if target.repository != tc.registry+"/team/images/nginx-stable" {
			t.Fatalf("repository=%q", target.repository)
		}
	}
}
