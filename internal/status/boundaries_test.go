package status

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

func TestMetadataLimitsFollowOriginalRequestAcrossRedirects(t *testing.T) {
	payload := strings.Repeat("x", registry.MaxMetadataBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/object" {
			io.WriteString(w, payload)
			return
		}
		http.Redirect(w, r, "/storage/object", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := &http.Client{Transport: metadataTransport{http.DefaultTransport}}
	for _, test := range []struct {
		path    string
		limited bool
	}{{"/v2/repo/blobs/sha256:abc", false}, {"/v2/repo/manifests/tag", true}, {"/v2/repo/tags/list", true}, {"/v2/x/blobs/y/manifests/tag", true}, {"/v2/x/blobs/y/tags/list", true}, {"/v2/x/blobs/y/blobs/sha256:abc", false}} {
		response, err := client.Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if test.limited {
			if err == nil {
				t.Fatalf("redirected metadata uncapped at %d", len(data))
			}
		} else if err != nil || len(data) != len(payload) {
			t.Fatalf("redirected blob truncated at %d: %v", len(data), err)
		}
	}
	body := &boundedBody{ReadCloser: io.NopCloser(strings.NewReader("too long")), remaining: 1}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("bound not enforced")
	}
	if _, err := body.Read(make([]byte, 10)); err == nil {
		t.Fatal("exceeded body did not retain error")
	}
}

func TestRunPreservesSanitizedHTTPDetails(t *testing.T) {
	raw := &transport.Error{StatusCode: http.StatusUnauthorized}
	safe := registry.SafeError(context.Background(), "registry tag listing", raw)
	wrapped := errors.Join(errors.New("unsafe injected wrapper"), safe)
	if got := safeRegistryError(context.Background(), "registry listing", wrapped).Error(); got != safe.Error() || !strings.Contains(got, "HTTP 401") {
		t.Fatalf("sanitized detail lost: %s", got)
	}
	products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}}}}
	services := simpleServices(&testRegistry{listError: safe}, &testCache{sets: map[string][]wolfi.InstalledPackage{}}, []wolfi.Package{{Name: "curl", Version: "8.1-r0", Arch: "x86_64", Checksum: "Q1a"}}, SecurityFeed{})
	document, err := RunWith(context.Background(), products, Options{Registry: "r.invalid", Repository: "images"}, services)
	if err != nil || document.Tracks[0].Error != safe.Error() {
		t.Fatalf("Run detail: %+v %v", document, err)
	}
}

func simpleServices(reader RegistryReader, cache InstalledCache, packages []wolfi.Package, feed SecurityFeed) Services {
	return Services{Architecture: "x86_64", Registry: reader, Cache: cache, ReadIndex: func(context.Context, string) ([]wolfi.Package, string, error) { return packages, "index", nil }, ReadSecurity: func(context.Context) (SecurityFeed, string, error) { return feed, "feed", nil }}
}

func TestTopLevelSecurityFixOutsideSelectorRemainsVisibleNotReachable(t *testing.T) {
	image := testImage("8.1-r0", "a", time.Now().UTC())
	reader := &testRegistry{listings: map[string]RegistryListing{"images/curl": {Images: []Image{image}}}, installed: map[string][]wolfi.InstalledPackage{image.Digest: {{Name: "curl", Version: image.Version, Arch: "x86_64"}, {Name: "dependency", Version: "1.0-r0", Arch: "x86_64"}}}}
	packages := []wolfi.Package{{Name: "curl", Version: "8.1-r0", Arch: "x86_64", Checksum: "Q1a"}, {Name: "curl", Version: "9.0-r0", Arch: "x86_64", Checksum: "Q1b"}, {Name: "dependency", Version: "1.1-r0", Arch: "x86_64", Checksum: "Q1c"}}
	feed := SecurityFeed{"curl": {"9.0-r0": {"CVE-2024-0001"}}}
	products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}}}}
	for _, dependencyFix := range []bool{false, true} {
		if dependencyFix {
			feed["dependency"] = map[string][]string{"1.1-r0": {"CVE-2024-0002"}}
		}
		services := simpleServices(reader, &testCache{sets: map[string][]wolfi.InstalledPackage{}}, packages, feed)
		document, err := RunWith(context.Background(), products, Options{Registry: "r.invalid", Repository: "images"}, services)
		if err != nil {
			t.Fatal(err)
		}
		track := document.Tracks[0]
		want := Current
		if dependencyFix {
			want = FixesAvailable
		}
		if track.State != want {
			t.Fatalf("state=%s want=%s", track.State, want)
		}
		if len(track.Outdated) != 2 {
			t.Fatalf("outdated facts omitted %+v", track.Outdated)
		}
		for _, fix := range track.MissingFixes {
			if fix.Name == "curl" && fix.ReachableByTrack {
				t.Fatal("outside-selector top-level fix marked reachable")
			}
			if fix.Name == "dependency" && !fix.ReachableByTrack {
				t.Fatal("available dependency fix marked unreachable")
			}
		}
		if len(track.MissingFixes) == 0 || track.MissingFixes[0].Name != "curl" {
			t.Fatalf("outside-selector fix omitted %+v", track.MissingFixes)
		}
	}
}

func TestRepositoryDerivationFailureIsTrackLocal(t *testing.T) {
	prefix := strings.Repeat("a", 240)
	options := Options{Registry: "r.invalid", Repository: prefix}
	if err := ValidateOptions(options); err != nil {
		t.Fatal(err)
	}
	products := Products{Version: 1, Products: []Product{{Package: "longname", Selectors: []string{"1"}}, {Package: "x", Selectors: []string{"1"}}}}
	packages := []wolfi.Package{{Name: "longname", Version: "1.0-r0", Arch: "x86_64", Checksum: "Q1a"}, {Name: "x", Version: "1.0-r0", Arch: "x86_64", Checksum: "Q1b"}}
	services := simpleServices(&testRegistry{}, &testCache{sets: map[string][]wolfi.InstalledPackage{}}, packages, SecurityFeed{})
	document, err := RunWith(context.Background(), products, options, services)
	if err != nil || len(document.Tracks) != 2 || document.Tracks[0].State != Error || document.Tracks[1].State != NotBuilt {
		t.Fatalf("isolated repository errors: %+v %v", document, err)
	}
}

func TestGlobalFailuresAndCancellationDoNotReturnComputedDocuments(t *testing.T) {
	products := Products{Version: 1, Products: []Product{{Package: "curl", Selectors: []string{"8"}}}}
	options := Options{Registry: "r.invalid", Repository: "images"}
	for _, source := range []string{"index", "security", "cancel"} {
		services := simpleServices(&testRegistry{}, &testCache{sets: map[string][]wolfi.InstalledPackage{}}, nil, SecurityFeed{})
		ctx, cancel := context.WithCancel(context.Background())
		switch source {
		case "index":
			services.ReadIndex = func(context.Context, string) ([]wolfi.Package, string, error) {
				return nil, "", errors.New("secretcanary")
			}
		case "security":
			services.ReadSecurity = func(context.Context) (SecurityFeed, string, error) { return nil, "", errors.New("secretcanary") }
		case "cancel":
			cancel()
		}
		document, err := RunWith(ctx, products, options, services)
		cancel()
		if err == nil || document.Version != 0 || strings.Contains(err.Error(), "secretcanary") {
			t.Fatalf("global error: %+v %v", document, err)
		}
	}
}
