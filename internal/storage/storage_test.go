package storage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestDataDirResolution(t *testing.T) {
	for _, test := range []struct {
		name, goos string
		env        map[string]string
		want       string
	}{
		{"override wins on every platform", "darwin", map[string]string{DataDirEnv: "/srv/lupetto/", "HOME": "/home/u"}, "/srv/lupetto"},
		{"override wins over XDG", "linux", map[string]string{DataDirEnv: "/srv/data", "XDG_DATA_HOME": "/xdg", "HOME": "/home/u"}, "/srv/data"},
		{"override wins over LocalAppData", "windows", map[string]string{DataDirEnv: "/srv/data", "LocalAppData": "/appdata"}, "/srv/data"},
		{"macOS Application Support", "darwin", map[string]string{"HOME": "/Users/u", "XDG_DATA_HOME": "/ignored"}, "/Users/u/Library/Application Support"},
		{"iOS follows macOS", "ios", map[string]string{"HOME": "/Users/u"}, "/Users/u/Library/Application Support"},
		{"Windows LocalAppData", "windows", map[string]string{"LocalAppData": "/appdata", "HOME": "/ignored"}, "/appdata"},
		{"absolute XDG_DATA_HOME", "linux", map[string]string{"XDG_DATA_HOME": "/xdg/data", "HOME": "/home/u"}, "/xdg/data"},
		{"relative XDG_DATA_HOME ignored", "linux", map[string]string{"XDG_DATA_HOME": "relative/data", "HOME": "/home/u"}, "/home/u/.local/share"},
		{"HOME fallback", "freebsd", map[string]string{"HOME": "/home/u"}, "/home/u/.local/share"},
		{"empty override is unset", "linux", map[string]string{DataDirEnv: "", "HOME": "/home/u"}, "/home/u/.local/share"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := dataDir(test.goos, env(test.env))
			if err != nil || got != test.want {
				t.Fatalf("dataDir = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestDataDirRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, goos string
		env        map[string]string
		want       string
	}{
		{"relative override", "linux", map[string]string{DataDirEnv: "data", "HOME": "/home/u"}, "LUPETTO_DATA_DIR must be an absolute path"},
		{"dot-relative override", "darwin", map[string]string{DataDirEnv: "./data", "HOME": "/Users/u"}, "LUPETTO_DATA_DIR must be an absolute path"},
		{"no HOME on macOS", "darwin", map[string]string{}, "$HOME is not defined"},
		{"no LocalAppData", "windows", map[string]string{"HOME": "/home/u"}, "LocalAppData"},
		{"no XDG or HOME", "linux", map[string]string{"XDG_DATA_HOME": "relative"}, "$HOME"},
		{"relative HOME", "linux", map[string]string{"HOME": "home"}, "not absolute"},
		{"relative LocalAppData", "windows", map[string]string{"LocalAppData": "appdata"}, "not absolute"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := dataDir(test.goos, env(test.env))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("dataDir = %q, %v; want error containing %q", got, err, test.want)
			}
		})
	}
}

func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "appdata"))
	t.Setenv(DataDirEnv, "")
	return home
}

func TestHistoryRootsFromProcessEnvironment(t *testing.T) {
	home := isolate(t)
	data := filepath.Join(home, "explicit")
	t.Setenv(DataDirEnv, data)
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := HistoryRoots()
	if err != nil || len(roots) != 2 || roots[0] != filepath.Join(data, "lupetto", "builds") || roots[1] != filepath.Join(cache, "lupetto", "builds") {
		t.Fatalf("roots = %q, %v", roots, err)
	}
	t.Setenv(DataDirEnv, cache)
	if roots, err := HistoryRoots(); err != nil || len(roots) != 1 {
		t.Fatalf("data root equal to the cache root must be listed once: %q, %v", roots, err)
	}
	t.Setenv(DataDirEnv, "relative")
	if roots, err := HistoryRoots(); err == nil || roots != nil {
		t.Fatalf("relative override accepted: %q", roots)
	}
}

func TestStorageIsALeafPackage(t *testing.T) {
	data, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "lupetto/internal/storage").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range strings.Fields(string(data)) {
		if strings.HasPrefix(path, "lupetto/") && path != "lupetto/internal/storage" {
			t.Errorf("internal/storage imports module package %s", path)
		}
	}
}
