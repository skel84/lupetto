package status

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"lupetto/internal/wolfi"
	"lupetto/internal/wolfi/wolfitest"
)

type testRegistry struct {
	listings                  map[string]RegistryListing
	installed                 map[string][]wolfi.InstalledPackage
	listError                 error
	installedError            error
	listCalls, installedCalls int
}

func (registry *testRegistry) List(ctx context.Context, repo name.Repository) (RegistryListing, error) {
	registry.listCalls++
	return registry.listings[repo.RepositoryStr()], registry.listError
}
func (registry *testRegistry) Installed(ctx context.Context, repo name.Repository, image Image) ([]wolfi.InstalledPackage, error) {
	registry.installedCalls++
	return registry.installed[image.Digest], registry.installedError
}

type testCache struct {
	sets                  map[string][]wolfi.InstalledPackage
	loadError, storeError error
}

func (cache *testCache) Load(ctx context.Context, digest string) ([]wolfi.InstalledPackage, bool, error) {
	packages, found := cache.sets[digest]
	return packages, found, cache.loadError
}
func (cache *testCache) Store(ctx context.Context, digest string, packages []wolfi.InstalledPackage) error {
	if cache.storeError != nil {
		return cache.storeError
	}
	cache.sets[digest] = packages
	return nil
}

func signedIndexReader(t *testing.T, records string) func(context.Context, string) ([]wolfi.Package, string, error) {
	t.Helper()
	signed, key := wolfitest.MakeSignedIndexFor(t, records)
	return func(ctx context.Context, arch string) ([]wolfi.Package, string, error) {
		verified, err := wolfi.VerifyAPKINDEX(signed, key)
		if err != nil {
			return nil, "", err
		}
		packages, err := wolfi.ParseAPKINDEX(verified, "")
		return packages, wolfi.SHA256Hex(signed), err
	}
}

func testImage(version, digest string, created time.Time) Image {
	return Image{Digest: "sha256:" + strings.Repeat(digest, 64), Name: "curl", Version: version, Architecture: "x86_64", Created: created, Tags: []string{"tag"}}
}

func TestRunStatesSelectorsSecurityAndCache(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	index := signedIndexReader(t, "P:curl\nV:8.2.0-r1\nA:x86_64\nC:Q1a\n\nP:curl\nV:9.1.0-r0\nA:x86_64\nC:Q1b\n\nP:dependency\nV:1.2.0-r2\nA:x86_64\nC:Q1c\n\nP:other\nV:2.0-r0\nA:x86_64\nC:Q1d\n\nP:a\nV:1.0-r0\nA:x86_64\nC:Q1e\np:ambiguous=1.0-r0\n\nP:b\nV:1.0-r0\nA:x86_64\nC:Q1f\np:ambiguous=1.0-r0\n\n")
	security := func(context.Context) (SecurityFeed, string, error) {
		return SecurityFeed{"dependency": {"0": {"CVE-2024-0001"}, "1.2.0-r1": {"CVE-2024-0002", "GHSA-aaaa-bbbb-cccc", "GO-2024-1234"}, "1.3.0-r0": {"CVE-2024-0003"}}}, strings.Repeat("a", 64), nil
	}
	for _, scenario := range []struct {
		name, version, want string
		dependency          string
		images              bool
	}{
		{"not built", "", NotBuilt, "", false},
		{"top level update precedence", "8.1.0-r0", UpdateAvailable, "1.1.0-r0", true},
		{"same top level fixes", "8.2.0-r1", FixesAvailable, "1.1.0-r0", true},
		{"dependency outdated without missing fixes", "8.2.0-r1", Current, "1.2.0-r1", true},
		{"current", "8.2.0-r1", Current, "1.2.0-r2", true},
		{"index regressed", "8.3.0-r0", Error, "1.1.0-r0", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			image := testImage(scenario.version, "a", now)
			listing := RegistryListing{Images: []Image{}, ArtifactCount: 2, UnidentifiedCount: 3}
			if scenario.images {
				listing.Images = []Image{image, testImage("9.1.0-r0", "b", now.Add(time.Hour)), testImage("8.0.0-r0", "c", now.Add(time.Hour))}
			}
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": listing}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: scenario.version, Arch: "x86_64"}, {Name: "dependency", Version: scenario.dependency, Arch: "x86_64"}}}}
			cache := &testCache{sets: map[string][]wolfi.InstalledPackage{}}
			products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8", "8.2"}}, {Package: "missing", Selectors: []string{"1"}}, {Package: "ambiguous", Selectors: []string{"1"}}, {Package: "other", Selectors: []string{"2"}}}}
			services := Services{Architecture: "x86_64", ReadIndex: index, ReadSecurity: security, Registry: registry, Cache: cache, Now: func() time.Time { return now }}
			document, err := RunWith(context.Background(), products, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services)
			if err != nil || document.Version != 1 || document.Kind != "status" || len(document.Tracks) != 5 {
				t.Fatalf("document: %+v, %v", document, err)
			}
			track := document.Tracks[0]
			if track.State != scenario.want {
				t.Fatalf("state: %+v, want %s", track, scenario.want)
			}
			if track.ArtifactCount != 2 || track.UnidentifiedCount != 3 || registry.listCalls != 2 {
				t.Fatalf("listing/counts: %+v, calls %d", track, registry.listCalls)
			}
			if scenario.images {
				if track.Newest.Version != scenario.version || len(track.Images) != 2 || len(track.Installed) != 2 {
					t.Fatalf("newest/images: %+v", track)
				}
				if registry.installedCalls != 1 {
					t.Fatalf("cache failed; reads=%d", registry.installedCalls)
				}
				if scenario.dependency == "1.1.0-r0" && (len(track.MissingFixes) != 1 || len(track.MissingFixes[0].IDs) != 3) {
					t.Fatalf("missing fixes: %+v", track.MissingFixes)
				}
				if _, err := RunWith(context.Background(), products, Options{Registry: "registry.example.invalid", Repository: "team/images"}, services); err != nil || registry.installedCalls != 1 {
					t.Fatalf("cache second run: reads=%d err=%v", registry.installedCalls, err)
				}
			}
			if document.Tracks[2].State != Error || !strings.Contains(document.Tracks[3].Error, "ambiguous") || document.Tracks[4].State != NotBuilt {
				t.Fatalf("isolated errors: %+v", document.Tracks)
			}
			data, _ := json.Marshal(document)
			if strings.Contains(string(data), `"Name"`) || !strings.Contains(string(data), `"computedAt"`) || !document.Security.Unsigned || !document.Security.FixedOnly || !document.Security.WolfiOnly {
				t.Fatalf("schema: %s", data)
			}
		})
	}
}

func TestNewestAPKRevisionCreatedAndDigestOrder(t *testing.T) {
	now := time.Now().UTC()
	images := []Image{testImage("8.2-r2", "b", now), testImage("8.2-r10", "c", now.Add(-time.Hour)), testImage("8.2-r10", "b", now), testImage("8.2-r10", "a", now)}
	for i := 1; i < len(images); i++ {
		if !imageNewer(images[i], images[i-1]) {
			t.Fatalf("not newer: %+v %+v", images[i], images[i-1])
		}
	}
	if matchesSelector("18.0-r0", "8") || !matchesSelector("8.20.1-r0", "8.20") || matchesSelector("8.20.1-r0", "8.2") {
		t.Fatal("numeric component selector matching failed")
	}
}

func TestMissingFixRequiresSameNameArchitectureAndAvailableVersion(t *testing.T) {
	installed := []wolfi.InstalledPackage{{Name: "curl", Version: "8.1-r0", Arch: "x86_64"}}
	feed := SecurityFeed{"curl": {"0": {"CVE-2024-0001"}, "8.2-r1": {"CVE-2024-0002"}}}
	for _, available := range []wolfi.Package{{Name: "curl", Version: "8.2-r0", Arch: "x86_64"}, {Name: "curl", Version: "8.2-r1", Arch: "aarch64"}, {Name: "other", Version: "8.2-r1", Arch: "x86_64"}} {
		latest, _ := latestPackages([]wolfi.Package{available})
		_, fixes := compareInstalled(installed, latest, feed)
		if len(fixes) != 0 {
			t.Fatalf("unavailable fix included: %+v", fixes)
		}
	}
	latest, _ := latestPackages([]wolfi.Package{{Name: "curl", Version: "8.2-r3", Arch: "x86_64"}})
	_, fixes := compareInstalled(installed, latest, feed)
	if len(fixes) != 1 || fixes[0].FixedVersion != "8.2-r1" || fixes[0].AvailableVersion != "8.2-r3" {
		t.Fatalf("available fix missing: %+v", fixes)
	}
}

func TestFileCachePrivacyDigestAndCorruption(t *testing.T) {
	cache, err := NewFileCache(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	packages := []wolfi.InstalledPackage{{Name: "curl", Version: "8.1-r0", Arch: "x86_64"}}
	if _, found, err := cache.Load(context.Background(), digest); err != nil || found {
		t.Fatalf("miss: %v %v", found, err)
	}
	if err := cache.Store(context.Background(), digest, packages); err != nil {
		t.Fatal(err)
	}
	got, found, err := cache.Load(context.Background(), digest)
	if err != nil || !found || len(got) != 1 || got[0] != packages[0] {
		t.Fatalf("hit: %+v %v %v", got, found, err)
	}
	file, _ := cache.file(digest)
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cache permissions: %v", info.Mode())
	}
	data, _ := os.ReadFile(file)
	data = []byte(strings.Replace(string(data), "8.1-r0", "8.1-r1", 1))
	os.WriteFile(file, data, 0600)
	if _, _, err := cache.Load(context.Background(), digest); err == nil {
		t.Fatal("corrupt cache silently accepted")
	}
	if _, _, err := cache.Load(context.Background(), "../../escape"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if err := cache.Store(context.Background(), digest, packages); err != nil {
		t.Fatal(err)
	}
	os.Chmod(file, 0644)
	if _, _, err := cache.Load(context.Background(), digest); err == nil {
		t.Fatal("public cache accepted")
	}
	os.Remove(file)
	os.Symlink(filepath.Join(t.TempDir(), "missing"), file)
	if _, _, err := cache.Load(context.Background(), digest); err == nil {
		t.Fatal("cache symlink accepted")
	}
}

func TestTrackFailuresDoNotLeakErrorsOrDiscardCacheFailures(t *testing.T) {
	image := testImage("8.1-r0", "a", time.Now().UTC())
	products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}}}}
	options := Options{Registry: "registry.example.invalid", Repository: "team/images"}
	for _, failure := range []string{"registry", "installed", "cache load", "cache store"} {
		t.Run(failure, func(t *testing.T) {
			canary := errors.New("secretcanary https://token@invalid")
			registry := &testRegistry{listings: map[string]RegistryListing{"team/images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: image.Version, Arch: "x86_64"}}}}
			cache := &testCache{sets: map[string][]wolfi.InstalledPackage{}}
			switch failure {
			case "registry":
				registry.listError = canary
			case "installed":
				registry.installedError = canary
			case "cache load":
				cache.loadError = canary
			case "cache store":
				cache.storeError = canary
			}
			services := Services{Architecture: "x86_64", Registry: registry, Cache: cache, ReadIndex: func(context.Context, string) ([]wolfi.Package, string, error) {
				return []wolfi.Package{{Name: "curl", Version: "8.1-r0", Arch: "x86_64", Checksum: "Q1a"}}, "index", nil
			}, ReadSecurity: func(context.Context) (SecurityFeed, string, error) { return SecurityFeed{}, "feed", nil }}
			document, err := RunWith(context.Background(), products, options, services)
			if err != nil || document.Tracks[0].State != Error || document.Tracks[0].Error == "" {
				t.Fatalf("track failure: %+v %v", document, err)
			}
			data, _ := json.Marshal(document)
			if strings.Contains(string(data), "secretcanary") || strings.Contains(string(data), "token@") {
				t.Fatalf("leaked error: %s", data)
			}
		})
	}
}
