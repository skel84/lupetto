package build

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"lupetto/internal/imageconfig"
	"lupetto/internal/wolfi"
	"lupetto/internal/wolfi/wolfitest"
)

// v010Config is the apko configuration v0.1.0 and v0.2.0 rendered for these
// inputs without image options, written out literally.
const v010Config = `contents:
  keyring:
    - "/data/builds/image-1/wolfi-signing.rsa.pub"
  repositories:
    - https://packages.wolfi.dev/os
  packages:
    - "busybox-static=1.38.0-r3"
archs:
  - x86_64
annotations:
  org.opencontainers.image.version: "1.38.0-r3"
  org.opencontainers.image.created: "2026-10-01T12:00:00Z"
  lupetto.apk.name: "busybox-static"
  lupetto.apk.version: "1.38.0-r3"
  lupetto.apk.architecture: "x86_64"
  lupetto.index.sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`

// baseConfig is v010Config with the one line every build now adds: the
// unpinned Wolfi base layout after the selected APK.
var baseConfig = strings.Replace(v010Config, "    - \"busybox-static=1.38.0-r3\"\n", "    - \"busybox-static=1.38.0-r3\"\n    - \"wolfi-baselayout\"\n", 1)

func TestApkoConfigAddsOnlyBaseLayoutToV010(t *testing.T) {
	selected := wolfi.Package{Name: "busybox-static", Version: "1.38.0-r3", Arch: "x86_64"}
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, image := range []imageconfig.Options{{}, {Entrypoint: nil}} {
		got := apkoConfig("/data/builds/image-1/wolfi-signing.rsa.pub", selected, "x86_64", created, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", image)
		if got != baseConfig || got == v010Config {
			t.Fatalf("config without image options:\n%s\nwant:\n%s", got, baseConfig)
		}
	}
	// The base layout itself is not listed twice.
	layout := wolfi.Package{Name: "wolfi-baselayout", Version: "20230201-r30", Arch: "x86_64"}
	got := apkoConfig("/k", layout, "x86_64", created, "d", imageconfig.Options{})
	if strings.Count(got, "    - \"wolfi-baselayout") != 1 || !strings.Contains(got, "  packages:\n    - \"wolfi-baselayout=20230201-r30\"\narchs:") {
		t.Fatalf("base layout package config:\n%s", got)
	}
}

func TestApkoConfigEntrypoint(t *testing.T) {
	selected := wolfi.Package{Name: "kyverno", Version: "1.15.2-r0", Arch: "aarch64"}
	entrypoint := []string{"/usr/bin/kyverno", "--flag=two words", `--quote="x"`}
	got := apkoConfig("/k", selected, "aarch64", time.Unix(0, 0).UTC(), "d", imageconfig.Options{Entrypoint: entrypoint})
	var config struct {
		Annotations map[string]string `yaml:"annotations"`
		Entrypoint  struct {
			Command string `yaml:"command"`
		} `yaml:"entrypoint"`
	}
	if err := yaml.Unmarshal([]byte(got), &config); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, got)
	}
	if len(config.Annotations) != 7 || config.Annotations[imageconfig.EntrypointAnnotation] != `["/usr/bin/kyverno","--flag=two words","--quote=\"x\""]` {
		t.Fatalf("annotations=%v", config.Annotations)
	}
	if config.Entrypoint.Command != `'/usr/bin/kyverno' '--flag=two words' '--quote="x"'` {
		t.Fatalf("command=%q", config.Entrypoint.Command)
	}
}

func TestApkoConfigCABundle(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	selected := wolfi.Package{Name: "busybox-static", Version: "1.38.0-r3", Arch: "x86_64"}
	got := apkoConfig("/data/builds/image-1/wolfi-signing.rsa.pub", selected, "x86_64", created, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", imageconfig.Options{CABundle: true})
	want := strings.Replace(baseConfig, "    - \"wolfi-baselayout\"\n", "    - \"wolfi-baselayout\"\n    - \"ca-certificates-bundle\"\n", 1) + "  lupetto.image.ca-bundle: \"true\"\n"
	if got != want {
		t.Fatalf("config:\n%s\nwant:\n%s", got, want)
	}
	// The bundle itself is not listed twice.
	bundle := wolfi.Package{Name: "ca-certificates-bundle", Version: "20260909-r3", Arch: "x86_64"}
	got = apkoConfig("/k", bundle, "x86_64", created, "d", imageconfig.Options{CABundle: true})
	if strings.Count(got, "    - \"ca-certificates-bundle") != 1 || !strings.Contains(got, "    - \"ca-certificates-bundle=20260909-r3\"\n    - \"wolfi-baselayout\"\narchs:") {
		t.Fatalf("bundle package config:\n%s", got)
	}
}

func TestCheckImageCABundle(t *testing.T) {
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	for name, entries := range map[string][]tar.Header{
		"regular file":     {{Name: "etc/ssl/certs/ca-certificates.crt", Typeflag: tar.TypeReg, Mode: 0644}},
		"symlinked parent": {{Name: "etc/ssl", Typeflag: tar.TypeSymlink, Linkname: "../usr/share/ssl"}, {Name: "usr/share/ssl/certs/ca-certificates.crt", Typeflag: tar.TypeReg, Mode: 0644}},
	} {
		dir, _ := makeOCIWith(t, "9.1.2-r1", entries, nil)
		if _, err := checkImage(dir, selected, imageconfig.Options{CABundle: true}); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		entries []tar.Header
		want    string
	}{
		"missing":   {nil, "/etc/ssl does not exist"},
		"directory": {[]tar.Header{{Name: "etc/ssl/certs/ca-certificates.crt/", Typeflag: tar.TypeDir, Mode: 0755}}, "not a regular file"},
		"dangling":  {[]tar.Header{{Name: "etc/ssl/certs/ca-certificates.crt", Typeflag: tar.TypeSymlink, Linkname: "/nowhere"}}, "/nowhere does not exist"},
	} {
		dir, _ := makeOCIWith(t, "9.1.2-r1", tc.entries, nil)
		_, err := checkImage(dir, selected, imageconfig.Options{CABundle: true})
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "CA bundle /etc/ssl/certs/ca-certificates.crt is not usable in the image of valkey-9.1@9.1.2-r1") {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	// Without the option the file is not required.
	dir, _ := makeOCIWith(t, "9.1.2-r1", nil, nil)
	if _, err := checkImage(dir, selected, imageconfig.Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckImageBaseLayout(t *testing.T) {
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	installed := "P:valkey-9.1\nV:9.1.2-r1\nA:x86_64\n\nP:wolfi-baselayout\nV:20230201-r30\nA:x86_64\n\n"
	osRelease := func(body string) fixtureFile {
		return fixtureFile{header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0644}, body: body}
	}
	for name, files := range map[string][]fixtureFile{
		"regular file":     {osRelease(fixtureOSRelease)},
		"unquoted":         {osRelease("# comment\nID=wolfi\nVERSION_ID=20230201\n")},
		"single quotes":    {osRelease("ID='wolfi'\nVERSION_ID='20230201'")},
		"symlink":          {{header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "../usr/lib/os-release"}}, {header: tar.Header{Name: "usr/lib/os-release", Typeflag: tar.TypeReg, Mode: 0644}, body: fixtureOSRelease}},
		"symlinked parent": {{header: tar.Header{Name: "etc", Typeflag: tar.TypeSymlink, Linkname: "usr/etc"}}, {header: tar.Header{Name: "usr/etc/os-release", Typeflag: tar.TypeReg, Mode: 0644}, body: fixtureOSRelease}},
		"hard link":        {{header: tar.Header{Name: "usr/lib/os-release", Typeflag: tar.TypeReg, Mode: 0644}, body: fixtureOSRelease}, {header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeLink, Linkname: "usr/lib/os-release"}}},
	} {
		dir, _ := makeOCILayer(t, installed, files, nil)
		if _, err := checkImage(dir, selected, imageconfig.Options{}); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		files []fixtureFile
		want  string
	}{
		"missing":          {nil, "/etc does not exist"},
		"directory":        {[]fixtureFile{{header: tar.Header{Name: "etc/os-release/", Typeflag: tar.TypeDir, Mode: 0755}}}, "not a regular file"},
		"dangling":         {[]fixtureFile{{header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "/usr/lib/os-release"}}}, "/usr/lib/os-release does not exist"},
		"empty":            {[]fixtureFile{osRelease("")}, `ID is "", not "wolfi"`},
		"other distro":     {[]fixtureFile{osRelease("ID=alpine\nVERSION_ID=3.22\n")}, `ID is "alpine", not "wolfi"`},
		"ID alone":         {[]fixtureFile{osRelease("ID=wolfi\nNAME=Wolfi\n")}, "VERSION_ID is missing"},
		"empty version":    {[]fixtureFile{osRelease("ID=wolfi\nVERSION_ID=\"\"\n")}, "VERSION_ID is missing"},
		"commented ID":     {[]fixtureFile{osRelease("#ID=wolfi\nVERSION_ID=1\n")}, `ID is "", not "wolfi"`},
		"oversized":        {[]fixtureFile{osRelease(fixtureOSRelease + strings.Repeat("#", maxOSReleaseBytes))}, "larger than 65536 bytes"},
		"misnamed content": {[]fixtureFile{{header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "release"}}, {header: tar.Header{Name: "etc/release", Typeflag: tar.TypeReg, Mode: 0644}, body: fixtureOSRelease}}, `ID is "", not "wolfi"`},
	} {
		dir, _ := makeOCILayer(t, installed, tc.files, nil)
		_, err := checkImage(dir, selected, imageconfig.Options{})
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "/etc/os-release does not identify the image of valkey-9.1@9.1.2-r1 as Wolfi to vulnerability scanners") {
			t.Errorf("%s: err=%v want %q", name, err, tc.want)
		}
	}
	// The os-release file alone is not enough: the package must be installed.
	dir, _ := makeOCILayer(t, "P:valkey-9.1\nV:9.1.2-r1\nA:x86_64\n\n", []fixtureFile{osRelease(fixtureOSRelease)}, nil)
	if _, err := checkImage(dir, selected, imageconfig.Options{}); err == nil || err.Error() != "OCI image of valkey-9.1@9.1.2-r1 does not contain wolfi-baselayout" {
		t.Fatalf("image without the base layout package: err=%v", err)
	}
}

func TestCheckImageEntrypoint(t *testing.T) {
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	entries := []tar.Header{
		{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "usr/bin/valkey-server", Typeflag: tar.TypeReg, Mode: 0755},
		{Name: "usr/bin/valkey-alias", Typeflag: tar.TypeSymlink, Linkname: "valkey-server"},
		{Name: "usr/bin/valkey-hard", Typeflag: tar.TypeLink, Linkname: "usr/bin/valkey-server", Mode: 0755},
		{Name: "usr/bin/readme", Typeflag: tar.TypeReg, Mode: 0644},
		{Name: "usr/bin/dangling", Typeflag: tar.TypeSymlink, Linkname: "/nowhere"},
		{Name: "usr/bin/loop", Typeflag: tar.TypeSymlink, Linkname: "loop"},
		{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"},
		{Name: "sbin", Typeflag: tar.TypeSymlink, Linkname: "/usr/../usr/bin"},
		{Name: "opt/tool/run", Typeflag: tar.TypeReg, Mode: 0700},
	}
	for _, valid := range []string{"/usr/bin/valkey-server", "/bin/valkey-server", "/sbin/valkey-alias", "/usr/bin/valkey-hard", "/opt/tool/run"} {
		entrypoint := []string{valid, "--port", "6379"}
		dir, _ := makeOCIWith(t, "9.1.2-r1", entries, entrypoint)
		if _, err := checkImage(dir, selected, imageconfig.Options{Entrypoint: entrypoint}); err != nil {
			t.Errorf("%s rejected: %v", valid, err)
		}
	}
	for invalid, want := range map[string]string{
		"/usr/bin/missing":             "/usr/bin/missing does not exist",
		"/usr/bin":                     "not a regular file",
		"/usr/bin/readme":              "not executable",
		"/usr/bin/dangling":            "/nowhere does not exist",
		"/usr/bin/loop":                "too many levels",
		"/usr/bin/valkey-server/x":     "is not a directory",
		"/usr/local/bin/valkey-server": "/usr/local does not exist",
	} {
		entrypoint := []string{invalid}
		dir, _ := makeOCIWith(t, "9.1.2-r1", entries, entrypoint)
		_, err := checkImage(dir, selected, imageconfig.Options{Entrypoint: entrypoint})
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "entrypoint "+invalid+" is not usable in the image of valkey-9.1@9.1.2-r1") {
			t.Errorf("%s: err=%v want %q", invalid, err, want)
		}
	}
	// The config must carry exactly the requested entrypoint, including none.
	for _, tc := range []struct{ config, requested []string }{
		{nil, []string{"/usr/bin/valkey-server"}},
		{[]string{"/usr/bin/valkey-server"}, nil},
		{[]string{"/usr/bin/valkey-server", "two", "words"}, []string{"/usr/bin/valkey-server", "two words"}},
	} {
		dir, _ := makeOCIWith(t, "9.1.2-r1", entries, tc.config)
		if _, err := checkImage(dir, selected, imageconfig.Options{Entrypoint: tc.requested}); err == nil || !strings.Contains(err.Error(), "OCI image config entrypoint") {
			t.Errorf("config %q requested %q: err=%v", tc.config, tc.requested, err)
		}
	}
}

// TestRunApkoInputs drives the real pipeline up to apko build and checks
// every input apko receives: the configuration bytes (v0.1.0's plus the base
// layout), the build arguments, and the epoch.
func TestRunApkoInputs(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, entrypoint := range [][]string{nil, {"/usr/bin/busybox", "sh"}} {
		index, key := wolfitest.MakeSignedIndexFor(t, "P:busybox-static\nV:1.38.0-r3\nA:x86_64\nC:exact\n\n")
		stopped := errors.New("stop before real composition")
		data := t.TempDir()
		var config []byte
		var buildArgs []string
		result, err := RunWith(context.Background(), Request{PackageName: "busybox-static", Selector: "1", Arch: "x86_64", NoLoad: true, Image: imageconfig.Options{Entrypoint: entrypoint}}, Services{
			DataDir:    func() (string, error) { return data, nil },
			PublicFile: func(context.Context, string, int64) ([]byte, error) { return index, nil },
			SigningKey: func(context.Context) ([]byte, error) { return key, nil },
			Now:        func() time.Time { return created.Add(500 * time.Millisecond) },
			Command: func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				switch args[0] {
				case "version":
					return []byte("GitVersion:    " + ApkoVersion + "\n"), nil
				case "lock":
					data, _ := json.Marshal(map[string]any{"contents": map[string]any{"packages": []any{map[string]string{"name": "busybox-static", "version": "1.38.0-r3", "architecture": "x86_64", "checksum": "exact"}}}})
					return nil, os.WriteFile(args[4], data, 0600)
				case "build":
					buildArgs = args
					var err error
					config, err = os.ReadFile(args[len(args)-3])
					if err != nil {
						t.Fatal(err)
					}
					return nil, stopped
				}
				t.Fatalf("unexpected command %v", args)
				return nil, nil
			},
		})
		if !errors.Is(err, stopped) {
			t.Fatalf("err=%v", err)
		}
		workspace := result.Workspace
		keyPath := filepath.Join(workspace, "wolfi-signing.rsa.pub")
		want := strings.Replace(baseConfig, `"/data/builds/image-1/wolfi-signing.rsa.pub"`, `"`+keyPath+`"`, 1)
		want = strings.Replace(want, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", wolfi.SHA256Hex(index), 1)
		if entrypoint != nil {
			want += "  lupetto.image.entrypoint: \"[\\\"/usr/bin/busybox\\\",\\\"sh\\\"]\"\nentrypoint:\n  command: \"'/usr/bin/busybox' 'sh'\"\n"
		}
		if string(config) != want {
			t.Fatalf("entrypoint=%q config:\n%s\nwant:\n%s", entrypoint, config, want)
		}
		wantArgs := []string{"build", "--build-date", "2026-10-01T12:00:00Z", "--arch", "x86_64"}
		if len(buildArgs) < len(wantArgs) || strings.Join(buildArgs[:len(wantArgs)], " ") != strings.Join(wantArgs, " ") {
			t.Fatalf("build args=%v", buildArgs)
		}
		record, err := EncodeRecord(result.RecordDocument(nil))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(record), `"entrypoint"`) != (entrypoint != nil) {
			t.Fatalf("record entrypoint presence wrong for %q:\n%s", entrypoint, record)
		}
		if strings.Contains(string(record), `"caBundle"`) {
			t.Fatalf("record without a CA bundle request mentions it:\n%s", record)
		}
	}
}

func TestRunRejectsInvalidEntrypointBeforeExternalBoundaries(t *testing.T) {
	_, err := RunWith(context.Background(), Request{PackageName: "x", Selector: "1", Image: imageconfig.Options{Entrypoint: []string{"relative"}}}, Services{
		Command: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("external command invoked")
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("err=%v", err)
	}
}

func TestApkoConfigPackagesAndUser(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	selected := wolfi.Package{Name: "busybox-static", Version: "1.38.0-r3", Arch: "x86_64"}
	extras := []wolfi.Package{{Name: "postgresql-18-contrib", Version: "18.1-r0", Arch: "x86_64"}, {Name: "ca-certificates-bundle", Version: "20260909-r3", Arch: "x86_64"}}
	image := imageconfig.Options{CABundle: true, Packages: []string{"postgresql-18-contrib", "ca-certificates-bundle"}, User: "26:0"}
	got := apkoConfig("/data/builds/image-1/wolfi-signing.rsa.pub", selected, "x86_64", created, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", image, extras...)
	// Additional APKs are pinned after the selected one, and a pinned CA
	// bundle is not listed again unpinned.
	want := strings.Replace(baseConfig, "    - \"wolfi-baselayout\"\n", "    - \"postgresql-18-contrib=18.1-r0\"\n    - \"ca-certificates-bundle=20260909-r3\"\n    - \"wolfi-baselayout\"\n", 1) +
		"  lupetto.image.ca-bundle: \"true\"\n" +
		"  lupetto.image.packages: \"[\\\"ca-certificates-bundle\\\",\\\"postgresql-18-contrib\\\"]\"\n" +
		"  lupetto.image.user: \"26:0\"\n" +
		"accounts:\n  groups:\n    - groupname: nonroot\n      gid: 0\n  users:\n    - username: nonroot\n      uid: 26\n      gid: 0\n  run-as: \"26:0\"\n"
	if got != want {
		t.Fatalf("config:\n%s\nwant:\n%s", got, want)
	}
	var config struct {
		Accounts struct {
			RunAs string `yaml:"run-as"`
			Users []struct {
				UID, GID uint32
			} `yaml:"users"`
		} `yaml:"accounts"`
	}
	if err := yaml.Unmarshal([]byte(got), &config); err != nil || config.Accounts.RunAs != "26:0" || len(config.Accounts.Users) != 1 || config.Accounts.Users[0].UID != 26 {
		t.Fatalf("accounts=%+v err=%v", config.Accounts, err)
	}
	// A uid-only user gets a group with the same ID.
	got = apkoConfig("/k", selected, "x86_64", created, "d", imageconfig.Options{User: "65532"})
	if !strings.HasSuffix(got, "      gid: 65532\n  users:\n    - username: nonroot\n      uid: 65532\n      gid: 65532\n  run-as: \"65532:65532\"\n") {
		t.Fatalf("uid-only config:\n%s", got)
	}
}

func TestCheckImagePackagesAndUser(t *testing.T) {
	selected := wolfi.Package{Name: "valkey-9.1", Version: "9.1.2-r1", Arch: "x86_64"}
	extra := wolfi.Package{Name: "valkey-9.1-cli", Version: "9.1.2-r1", Arch: "x86_64"}
	files := []fixtureFile{{header: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0644}, body: fixtureOSRelease}}
	installed := "P:valkey-9.1\nV:9.1.2-r1\nA:x86_64\n\nP:wolfi-baselayout\nV:20230201-r30\nA:x86_64\n\n"
	// The config always carries an explicit uid:gid, whichever form was requested.
	dir, _ := makeOCIImage(t, installed+"P:valkey-9.1-cli\nV:9.1.2-r1\nA:x86_64\n\n", files, map[string]any{"User": "65532:65532"})
	for _, user := range []string{"65532", "65532:65532"} {
		if _, err := checkImage(dir, selected, imageconfig.Options{Packages: []string{"valkey-9.1-cli"}, User: user}, extra); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkImage(dir, selected, imageconfig.Options{Packages: []string{"valkey-9.1-cli"}, User: "65532:0"}, extra); err == nil || !strings.Contains(err.Error(), `OCI image config user "65532:65532" does not match requested "65532:0"`) {
		t.Fatalf("different user: err=%v", err)
	}
	// A bare uid would take its group from the first passwd entry with that uid.
	dir, _ = makeOCIImage(t, installed+"P:valkey-9.1-cli\nV:9.1.2-r1\nA:x86_64\n\n", files, map[string]any{"User": "65532"})
	if _, err := checkImage(dir, selected, imageconfig.Options{Packages: []string{"valkey-9.1-cli"}, User: "65532"}, extra); err == nil || !strings.Contains(err.Error(), `OCI image config user "65532" does not match requested "65532:65532"`) {
		t.Fatalf("bare uid: err=%v", err)
	}
	dir, _ = makeOCIImage(t, installed+"P:valkey-9.1-cli\nV:9.1.1-r0\nA:x86_64\n\n", files, nil)
	if _, err := checkImage(dir, selected, imageconfig.Options{}, extra); err == nil || !strings.Contains(err.Error(), "different version or architecture of valkey-9.1-cli") {
		t.Fatalf("different additional version: err=%v", err)
	}
	dir, _ = makeOCIImage(t, installed, files, nil)
	if _, err := checkImage(dir, selected, imageconfig.Options{}, extra); err == nil || !strings.Contains(err.Error(), "does not contain selected valkey-9.1-cli@9.1.2-r1") {
		t.Fatalf("missing additional package: err=%v", err)
	}
	// An image without a requested user fails, and one with an unrequested user too.
	if _, err := checkImage(dir, selected, imageconfig.Options{User: "26"}); err == nil || !strings.Contains(err.Error(), "OCI image config user") {
		t.Fatalf("missing user: err=%v", err)
	}
	dir, _ = makeOCIImage(t, installed, files, map[string]any{"User": "26"})
	if _, err := checkImage(dir, selected, imageconfig.Options{}); err == nil || !strings.Contains(err.Error(), "OCI image config user") {
		t.Fatalf("unrequested user: err=%v", err)
	}
}

// TestRunResolvesAdditionalPackages drives the pipeline up to apko build:
// additional packages are pinned to their highest version in the same signed
// index, checked in the lock, and recorded.
func TestRunResolvesAdditionalPackages(t *testing.T) {
	index, key := wolfitest.MakeSignedIndexFor(t, "P:postgresql-18\nV:18.1-r0\nA:x86_64\nC:pg\n\nP:postgresql-18-contrib\nV:18.0-r2\nA:x86_64\nC:old\n\nP:postgresql-18-contrib\nV:18.1-r0\nA:x86_64\nC:contrib\n\nP:psql-18\nV:18.1-r0\nA:x86_64\nC:psql\np:cmd:psql=18.1-r0\n\n")
	run := func(packages []string, lock []map[string]string) (Result, []byte, error) {
		stopped := errors.New("stop before real composition")
		data := t.TempDir()
		var config []byte
		result, err := RunWith(context.Background(), Request{PackageName: "postgresql-18", Selector: "18", Arch: "x86_64", NoLoad: true, Image: imageconfig.Options{Packages: packages, User: "26"}}, Services{
			DataDir:    func() (string, error) { return data, nil },
			PublicFile: func(context.Context, string, int64) ([]byte, error) { return index, nil },
			SigningKey: func(context.Context) ([]byte, error) { return key, nil },
			Command: func(ctx context.Context, executable string, args ...string) ([]byte, error) {
				switch args[0] {
				case "version":
					return []byte("GitVersion:    " + ApkoVersion + "\n"), nil
				case "lock":
					data, _ := json.Marshal(map[string]any{"contents": map[string]any{"packages": lock}})
					return nil, os.WriteFile(args[4], data, 0600)
				case "build":
					config, _ = os.ReadFile(args[len(args)-3])
					return nil, stopped
				}
				t.Fatalf("unexpected command %v", args)
				return nil, nil
			},
		})
		if errors.Is(err, stopped) {
			err = nil
		}
		return result, config, err
	}
	pg := map[string]string{"name": "postgresql-18", "version": "18.1-r0", "architecture": "x86_64", "checksum": "pg"}
	contrib := map[string]string{"name": "postgresql-18-contrib", "version": "18.1-r0", "architecture": "x86_64", "checksum": "contrib"}
	psql := map[string]string{"name": "psql-18", "version": "18.1-r0", "architecture": "x86_64", "checksum": "psql"}
	result, config, err := run([]string{"postgresql-18-contrib", "cmd:psql"}, []map[string]string{pg, contrib, psql})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "    - \"postgresql-18=18.1-r0\"\n    - \"postgresql-18-contrib=18.1-r0\"\n    - \"psql-18=18.1-r0\"\n    - \"wolfi-baselayout\"\n") || !strings.Contains(string(config), "  run-as: \"26:26\"\n") {
		t.Fatalf("config:\n%s", config)
	}
	record, err := json.Marshal(result.RecordDocument(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"packages":["postgresql-18-contrib","cmd:psql"]`, `"user":"26"`, `"packages":[{"name":"postgresql-18-contrib","version":"18.1-r0"},{"name":"psql-18","version":"18.1-r0"}]`} {
		if !strings.Contains(string(record), want) {
			t.Fatalf("record lacks %s:\n%s", want, record)
		}
	}
	// The lock must hold the exact pinned bytes of every additional package.
	if _, _, err := run([]string{"postgresql-18-contrib"}, []map[string]string{pg, {"name": "postgresql-18-contrib", "version": "18.1-r0", "architecture": "x86_64", "checksum": "changed"}}); err == nil || !strings.Contains(err.Error(), "apko lock does not match selected postgresql-18-contrib@18.1-r0") {
		t.Fatalf("substituted additional package: err=%v", err)
	}
	if _, _, err := run([]string{"postgresql-18-contrib"}, []map[string]string{pg}); err == nil || !strings.Contains(err.Error(), "apko lock has 0 entries for selected postgresql-18-contrib@18.1-r0") {
		t.Fatalf("missing additional package in lock: err=%v", err)
	}
	if _, _, err := run([]string{"postgresql-18-dev"}, nil); err == nil || !strings.Contains(err.Error(), "unavailable package: postgresql-18-dev") {
		t.Fatalf("unavailable additional package: err=%v", err)
	}
	if _, _, err := run([]string{"psql-18", "cmd:psql"}, nil); err == nil || !strings.Contains(err.Error(), "package cmd:psql resolves to psql-18, which this build already selects") {
		t.Fatalf("duplicate resolution: err=%v", err)
	}
}
