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

// v010Config is the apko configuration v0.1.0 rendered for these inputs,
// written out literally. apko composes an image only from this file, the
// lock, the build date, and the architecture, so equal bytes here mean a
// track without image options keeps v0.1.0's image and digest.
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

func TestApkoConfigWithoutImageOptionsMatchesV010(t *testing.T) {
	selected := wolfi.Package{Name: "busybox-static", Version: "1.38.0-r3", Arch: "x86_64"}
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, image := range []imageconfig.Options{{}, {Entrypoint: nil}} {
		got := apkoConfig("/data/builds/image-1/wolfi-signing.rsa.pub", selected, "x86_64", created, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", image)
		if got != v010Config {
			t.Fatalf("config without image options changed from v0.1.0:\n%s", got)
		}
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
	want := strings.Replace(v010Config, "    - \"busybox-static=1.38.0-r3\"\n", "    - \"busybox-static=1.38.0-r3\"\n    - \"ca-certificates-bundle\"\n", 1) + "  lupetto.image.ca-bundle: \"true\"\n"
	if got != want {
		t.Fatalf("config:\n%s\nwant:\n%s", got, want)
	}
	// The bundle itself is not listed twice.
	bundle := wolfi.Package{Name: "ca-certificates-bundle", Version: "20260909-r3", Arch: "x86_64"}
	got = apkoConfig("/k", bundle, "x86_64", created, "d", imageconfig.Options{CABundle: true})
	if strings.Count(got, "    - \"ca-certificates-bundle") != 1 || !strings.Contains(got, "    - \"ca-certificates-bundle=20260909-r3\"\narchs:") {
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
		"missing":   {nil, "/etc does not exist"},
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

// TestRunWithoutImageOptionsKeepsV010Inputs drives the real pipeline up to
// apko build and checks every input apko receives against v0.1.0: the
// configuration bytes, the build arguments, and the epoch.
func TestRunWithoutImageOptionsKeepsV010Inputs(t *testing.T) {
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
		want := strings.Replace(v010Config, `"/data/builds/image-1/wolfi-signing.rsa.pub"`, `"`+keyPath+`"`, 1)
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
