package explorer

import (
	"os"
	"strings"
	"testing"
)

func TestHTTPBuildUsesTrackedProductEntrypoint(t *testing.T) {
	config := goodFake()
	config.Products = `{"kind":"products","version":1,"products":[{"package":"cmd:curl","selectors":["1"],"entrypoint":["/usr/bin/curl","-s","two words"],"caBundle":true}],"changed":false,"message":"synthetic"}`
	server, _, calls := testServer(t, config, true)
	form := buildForm(server)
	// Form fields cannot choose image options; only the products file does.
	form.Set("entrypoint", "/bin/sh")
	form.Set("caBundle", "false")
	if w := request(server, "POST", "/builds", form); w.Code != 303 {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	eventually(t, func() bool { _, log, ok := server.jobs.detail("1", 0); return ok && log.Done })
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "build|cmd:curl|1.2|--no-load|--entrypoint=/usr/bin/curl|--entrypoint=-s|--entrypoint=two words|--ca-bundle|--json\n") || strings.Contains(string(data), "/bin/sh") {
		t.Fatal(string(data))
	}
	view, _, _ := server.jobs.detail("1", 0)
	if strings.Join(view.Request.Entrypoint, "|") != "/usr/bin/curl|-s|two words" || !view.Request.CABundle {
		t.Fatalf("job request = %#v", view.Request)
	}

	// An untracked package builds without one.
	form = buildForm(server)
	form.Set("package", "busybox-static")
	if w := request(server, "POST", "/builds", form); w.Code != 303 {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	eventually(t, func() bool { _, log, ok := server.jobs.detail("2", 0); return ok && log.Done })
	data, _ = os.ReadFile(calls)
	if !strings.Contains(string(data), "build|busybox-static|1.2|--no-load|--json\n") {
		t.Fatal(string(data))
	}
}

func TestHTTPBuildRefusedWithoutReadableProducts(t *testing.T) {
	config := goodFake()
	config.ProductsExit = 1
	server, _, _ := testServer(t, config, true)
	if w := request(server, "POST", "/builds", buildForm(server)); w.Code != 503 || !strings.Contains(w.Body.String(), "products file") {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	if _, _, ok := server.jobs.detail("1", 0); ok {
		t.Fatal("build started without the products file")
	}
}

func TestValidateBuildEntrypoint(t *testing.T) {
	for _, entrypoint := range [][]string{{"relative"}, {"/usr/bin/x", ""}, {"/usr/bin/x", "a\x00b"}, make([]string, 33)} {
		if err := ValidateBuild(BuildRequest{Package: "curl", Selector: "1", Entrypoint: entrypoint}); err == nil {
			t.Errorf("accepted %q", entrypoint)
		}
	}
}

func TestHTTPBuildUsesTrackedProductPackagesAndUser(t *testing.T) {
	config := goodFake()
	config.Products = `{"kind":"products","version":1,"products":[{"package":"cmd:curl","selectors":["1"],"packages":["postgresql-18-contrib","-x"],"user":"26:26"}],"changed":false,"message":"synthetic"}`
	server, _, calls := testServer(t, config, true)
	if w := request(server, "POST", "/builds", buildForm(server)); w.Code != 400 {
		t.Fatalf("flag-like package: response = %d %s", w.Code, w.Body.String())
	}
	config.Products = strings.Replace(config.Products, `,"-x"`, "", 1)
	server, _, calls = testServer(t, config, true)
	if w := request(server, "POST", "/builds", buildForm(server)); w.Code != 303 {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	eventually(t, func() bool { _, log, ok := server.jobs.detail("1", 0); return ok && log.Done })
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "build|cmd:curl|1.2|--no-load|--package=postgresql-18-contrib|--user=26:26|--json\n") {
		t.Fatal(string(data))
	}
}

func TestValidateBuildPackagesAndUser(t *testing.T) {
	for _, request := range []BuildRequest{{Packages: []string{"-x"}}, {Packages: make([]string, 33)}, {User: "root"}, {User: "1 2"}, {User: "--user"}} {
		request.Package, request.Selector = "curl", "1"
		if err := ValidateBuild(request); err == nil {
			t.Errorf("accepted %+v", request)
		}
	}
}
