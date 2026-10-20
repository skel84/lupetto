package explorer

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	unsignedNotice = "Published images will be unsigned."
	refusedNotice  = "Publishing will be refused."
)

func TestPublishSigningState(t *testing.T) {
	publication := map[string]string{"LUPETTO_REGISTRY": "registry.example", "LUPETTO_REPOSITORY": "team/images"}
	with := func(extra map[string]string) func(string) string {
		return func(name string) string {
			if value, ok := extra[name]; ok {
				return value
			}
			return publication[name]
		}
	}
	for _, tc := range []struct {
		name   string
		builds bool
		getenv func(string) string
		want   string
	}{
		{"builds disabled", false, with(map[string]string{"LUPETTO_REQUIRE_SIGNING": "true"}), ""},
		{"publication not configured", true, with(map[string]string{"LUPETTO_REPOSITORY": ""}), ""},
		{"key set", true, with(map[string]string{"LUPETTO_COSIGN_KEY": "/synthetic/key"}), "key"},
		{"key set and required", true, with(map[string]string{"LUPETTO_COSIGN_KEY": "/synthetic/key", "LUPETTO_REQUIRE_SIGNING": "true"}), "key"},
		{"identity token set", true, with(map[string]string{"LUPETTO_COSIGN_IDENTITY_TOKEN_FILE": "/synthetic/token"}), "key"},
		{"identity token set and required", true, with(map[string]string{"LUPETTO_COSIGN_IDENTITY_TOKEN_FILE": "/synthetic/token", "LUPETTO_REQUIRE_SIGNING": "true"}), "key"},
		{"identity token empty", true, with(map[string]string{"LUPETTO_COSIGN_IDENTITY_TOKEN_FILE": ""}), "unsigned"},
		{"key unset", true, with(nil), "unsigned"},
		{"key empty", true, with(map[string]string{"LUPETTO_COSIGN_KEY": ""}), "unsigned"},
		{"required false", true, with(map[string]string{"LUPETTO_REQUIRE_SIGNING": "false"}), "unsigned"},
		{"key unset and required", true, with(map[string]string{"LUPETTO_REQUIRE_SIGNING": "true"}), "refused"},
	} {
		if got := publishSigningState(tc.builds, tc.getenv); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
	// The key is decided from presence only; the key file is never read.
	reads := map[string]bool{}
	publishSigningState(true, func(name string) string { reads[name] = true; return "/nonexistent/key-file" })
	for name := range reads {
		if !strings.HasPrefix(name, "LUPETTO_") {
			t.Fatalf("read unexpected input %q", name)
		}
	}
}

// The notice is computed from the server's own environment and rendered with
// the build controls; disabled builds never show it.
func TestPublishSigningNoticeOnDashboard(t *testing.T) {
	for _, tc := range []struct {
		name          string
		builds        bool
		key, require  string
		want, present string
	}{
		{name: "key set", builds: true, key: "/synthetic/cosign.key", want: "key"},
		{name: "key unset", builds: true, want: "unsigned", present: unsignedNotice},
		{name: "key unset and required", builds: true, require: "true", want: "refused", present: refusedNotice},
		{name: "builds disabled", builds: false, require: "true", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedCache(t)
			t.Setenv("LUPETTO_REGISTRY", "127.0.0.1:5000")
			t.Setenv("LUPETTO_REPOSITORY", "test/images")
			t.Setenv("LUPETTO_COSIGN_KEY", tc.key)
			t.Setenv("LUPETTO_REQUIRE_SIGNING", tc.require)
			server, _, _ := testServer(t, goodFake(), tc.builds)
			if got := server.shell().PublishSigning; got != tc.want {
				t.Fatalf("PublishSigning=%q want %q", got, tc.want)
			}
			w := request(server, "GET", "/", nil)
			if w.Code != 200 {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			html := w.Body.String()
			for _, notice := range []string{unsignedNotice, refusedNotice} {
				if strings.Contains(html, notice) != (notice == tc.present) {
					t.Errorf("notice %q shown=%t; want only %q", notice, strings.Contains(html, notice), tc.present)
				}
			}
			if strings.Contains(html, "/synthetic/cosign.key") {
				t.Fatal("page shows the key path")
			}
			w = request(server, "GET", "/?format=json", nil)
			var view struct {
				Shell struct {
					PublishSigning *string `json:"publishSigning"`
				} `json:"shell"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Shell.PublishSigning == nil || *view.Shell.PublishSigning != tc.want {
				t.Fatalf("JSON publishSigning: %s err=%v", w.Body.String(), err)
			}
		})
	}
}

func TestPublishSigningNoticeTemplates(t *testing.T) {
	shell := func(state string) ShellView {
		return ShellView{RegistryState: "ready", DockerState: "available", PublishLoad: true, PublishSigning: state}
	}
	base := func(state string) BaseView {
		return BaseView{CSRFToken: "tok-123", BuildsEnabled: true, Shell: shell(state)}
	}
	publish := ProductRow{Package: "busybox-static", Selector: "1", DetailURL: "/images/busybox-static/1", Verdict: "Not in registry", VerdictKind: "notbuilt",
		Track:  Track{Package: "busybox-static", Selector: "1", State: "not-built"},
		Action: PrimaryAction{Label: "Build 1.38.0-r2", Kind: "build", Package: "busybox-static", Selector: "1", Mode: "publish"}}
	local := publish
	local.Action.Mode, local.Action.Label = "local", "Build locally"
	catalog := func(state string) PackageView {
		return PackageView{BaseView: base(state), Name: "busybox-static", Document: &DiscoverDocument{Packages: []DiscoveredPackage{{Name: "busybox-static", Version: "1.38.0-r2"}}}}
	}
	renderCases(t, []templateCase{
		{"image unsigned", "image", ImageView{BaseView: base("unsigned"), Product: publish, Tab: "overview"}, []string{unsignedNotice, `data-publish-signing="unsigned"`, "LUPETTO_REQUIRE_SIGNING=true", `name="mode" value="publish"`}, []string{refusedNotice}},
		{"image refused", "image", ImageView{BaseView: base("refused"), Product: publish, Tab: "builds"}, []string{refusedNotice, `data-publish-signing="refused"`}, []string{unsignedNotice}},
		{"image key", "image", ImageView{BaseView: base("key"), Product: publish, Tab: "overview"}, nil, []string{"data-publish-signing"}},
		{"image local action", "image", ImageView{BaseView: base("unsigned"), Product: local, Tab: "overview"}, nil, []string{"data-publish-signing"}},
		{"catalog unsigned", "package", catalog("unsigned"), []string{unsignedNotice, `name="mode" value="publish"`}, []string{refusedNotice}},
		{"catalog refused", "package", catalog("refused"), []string{refusedNotice}, []string{unsignedNotice}},
		{"catalog key", "package", catalog("key"), []string{`name="mode" value="publish"`}, []string{"data-publish-signing"}},
		{"catalog disabled", "package", PackageView{BaseView: BaseView{CSRFToken: "tok-123", Shell: shell("")}, Name: "x", Document: &DiscoverDocument{Packages: []DiscoveredPackage{{Name: "x", Version: "1-r0"}}}}, []string{"Builds are disabled"}, []string{"data-publish-signing"}},
		{"images unsigned", "images", ImagesView{BaseView: base("unsigned"), Status: StatusView{Refreshing: true}}, []string{unsignedNotice}, []string{refusedNotice}},
		{"images refused", "images", ImagesView{BaseView: base("refused"), Status: StatusView{Refreshing: true}}, []string{refusedNotice}, []string{unsignedNotice}},
	})
}
