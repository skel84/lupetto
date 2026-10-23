package products

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lupetto/internal/status"
)

func TestProductsRoundTripCommentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	original := "# inventory\nversion: 1 # format\nproducts:\n  # database\n  - package: postgresql # keep package comment\n    selectors: [\"16\", \"17\"] # versions\n  - package: nginx\n    selectors: [\"1.30\"]\n"
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	document, err := Run(path, "add", "postgresql", []string{"17", "18", "18"}, false)
	if err != nil || !document.Changed {
		t.Fatalf("add: %+v %v", document, err)
	}
	data, _ := os.ReadFile(path)
	for _, comment := range []string{"# inventory", "# format", "# database", "# keep package comment", "# versions"} {
		if !bytes.Contains(data, []byte(comment)) {
			t.Fatalf("lost %s: %s", comment, data)
		}
	}
	if strings.Index(string(data), "postgresql") > strings.Index(string(data), "nginx") {
		t.Fatal("reordered products")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	parsed, err := status.ParseProducts(bytes.NewReader(data))
	if err != nil || len(parsed.Products[0].Selectors) != 3 {
		t.Fatalf("parse: %+v %v", parsed, err)
	}
	document, err = Run(path, "add", "postgresql", []string{"18"}, false)
	unchanged, _ := os.ReadFile(path)
	if err != nil || document.Changed || !bytes.Equal(data, unchanged) || !strings.Contains(document.Message, "Already tracked") {
		t.Fatalf("idempotence: %+v %v", document, err)
	}
	document, err = Run(path, "remove", "postgresql", []string{"16"}, false)
	if err != nil || len(document.Products[0].Selectors) != 2 {
		t.Fatalf("remove selector: %+v %v", document, err)
	}
	if _, err := Run(path, "remove", "postgresql", nil, false); err != nil {
		t.Fatal(err)
	}
	document, err = Run(path, "remove", "nginx", nil, false)
	if err != nil || len(document.Products) != 0 {
		t.Fatalf("remove last: %+v %v", document, err)
	}
	document, err = Run(path, "list", "", nil, false)
	if err != nil || document.Products == nil {
		t.Fatalf("empty list: %+v %v", document, err)
	}
}

func TestProductsSeparateEntriesNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	original := "version: 1\nproducts:\n  - package: nginx\n    selectors: [\"1\"]\n  - package: nginx # second\n    selectors: [\"2\"]\n"
	os.WriteFile(path, []byte(original), 0600)
	document, err := Run(path, "add", "nginx", []string{"2"}, false)
	data, _ := os.ReadFile(path)
	if err != nil || document.Changed || string(data) != original {
		t.Fatalf("no-op: %+v %v %s", document, err, data)
	}
}

func TestProductsCreationValidationAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	if _, err := Run(path, "add", "cmd:curl", []string{"8.2"}, false); err == nil {
		t.Fatal("created without --create")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected file: %v", err)
	}
	if _, err := Run(path, "add", "cmd:curl", []string{"8.2"}, true); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	for _, input := range []struct {
		name      string
		selectors []string
	}{{"bad/name", []string{"1"}}, {"cmd::curl", []string{"1"}}, {"curl", []string{"1..2"}}, {"curl", []string{"1-r0"}}, {"curl", nil}} {
		if _, err := Run(path, "add", input.name, input.selectors, false); err == nil {
			t.Fatalf("accepted %+v", input)
		}
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(original, data) {
		t.Fatal("invalid input changed file")
	}
	os.Chmod(path, 0400)
	if _, err := Run(path, "add", "curl", []string{"8"}, false); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only file: %v", err)
	}
	os.Chmod(path, 0600)
	directory := filepath.Dir(path)
	os.Chmod(directory, 0500)
	defer os.Chmod(directory, 0700)
	if _, err := Run(path, "add", "curl", []string{"8"}, false); err == nil || !strings.Contains(err.Error(), "directory is read-only") {
		t.Fatalf("read-only directory: %v", err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.Equal(original, data) {
		t.Fatal("failed atomic write changed file")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatalf("temporary file left: %v", entries)
	}
}

func TestProductsRejectMalformedFiles(t *testing.T) {
	for _, data := range []string{
		"version: 2\nproducts: []\n", "version: 1\nproducts: []\nextra: true\n", "version: 1\nproducts: null\n",
		"version: 1\nproducts:\n - package: curl\n   selectors: [8]\n", "version: 1\nproducts:\n - package: curl\n   selectors: [\"8\", \"8\"]\n",
		"version: 1\nproducts: []\n---\nversion: 1\nproducts: []\n",
	} {
		path := filepath.Join(t.TempDir(), "products.yaml")
		os.WriteFile(path, []byte(data), 0600)
		_, err := Run(path, "list", "", nil, false)
		var invalidError *InvalidError
		if !errors.As(err, &invalidError) {
			t.Fatalf("expected invalid YAML: %q: %v", data, err)
		}
	}
}

func TestProductsKeepEntrypointAcrossMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nproducts:\n  - package: kyverno\n    selectors: [\"1\"]\n    entrypoint: [/usr/bin/kyverno, \"--v=2\"]\n"), 0640); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		action, name, selector string
	}{{"add", "kyverno", "2"}, {"add", "curl", "8"}, {"remove", "kyverno", "1"}} {
		if _, err := Run(path, step.action, step.name, []string{step.selector}, false); err != nil {
			t.Fatalf("%s %s %s: %v", step.action, step.name, step.selector, err)
		}
	}
	document, err := Run(path, "list", "", nil, false)
	if err != nil || len(document.Products) != 2 || strings.Join(document.Products[0].Entrypoint, " ") != "/usr/bin/kyverno --v=2" || strings.Join(document.Products[0].Selectors, ",") != "2" || document.Products[1].Entrypoint != nil {
		t.Fatalf("products=%+v err=%v", document.Products, err)
	}
	if err := os.WriteFile(path, []byte("version: 1\nproducts:\n  - package: kyverno\n    selectors: [\"1\"]\n    entrypoint: [kyverno]\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(path, "add", "kyverno", []string{"2"}, false); err == nil {
		t.Fatal("invalid entrypoint accepted by a mutation")
	}
}

func TestProductsKeepCABundleAcrossMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nproducts:\n  - package: external-dns-0.21\n    selectors: [\"0\"]\n    caBundle: true\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(path, "add", "external-dns-0.21", []string{"1"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(path, "remove", "external-dns-0.21", []string{"0"}, false); err != nil {
		t.Fatal(err)
	}
	document, err := Run(path, "list", "", nil, false)
	if err != nil || len(document.Products) != 1 || !document.Products[0].CABundle || strings.Join(document.Products[0].Selectors, ",") != "1" {
		t.Fatalf("products=%+v err=%v", document.Products, err)
	}
}

func TestProductsUpstreamFollowsSelectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "products.yaml")
	original := "version: 1\nproducts:\n  - package: metrics-server\n    selectors: [\"0\", \"1\"]\n    upstream:\n      \"0\": registry.k8s.io/metrics-server/metrics-server:v0.8.0 # pinned\n      \"1\": registry.k8s.io/metrics-server/metrics-server:v1.0.0\n"
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	document, err := Run(path, "add", "metrics-server", []string{"2"}, false)
	if err != nil || len(document.Products[0].Upstream) != 2 {
		t.Fatalf("add kept upstream: %+v %v", document.Products, err)
	}
	document, err = Run(path, "remove", "metrics-server", []string{"1"}, false)
	if err != nil || len(document.Products[0].Upstream) != 1 || document.Products[0].Upstream["0"] != "registry.k8s.io/metrics-server/metrics-server:v0.8.0" {
		t.Fatalf("remove one selector: %+v %v", document.Products, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte("# pinned")) || bytes.Contains(data, []byte("v1.0.0")) {
		t.Fatalf("upstream after remove:\n%s", data)
	}
	document, err = Run(path, "remove", "metrics-server", []string{"0"}, false)
	if err != nil || document.Products[0].Upstream != nil || strings.Join(document.Products[0].Selectors, ",") != "2" {
		t.Fatalf("remove last upstream selector: %+v %v", document.Products, err)
	}
	if data, _ := os.ReadFile(path); bytes.Contains(data, []byte("upstream")) {
		t.Fatalf("empty upstream mapping left behind:\n%s", data)
	}
	if _, err := Run(path, "remove", "metrics-server", nil, false); err != nil {
		t.Fatal(err)
	}
}

// configMapVolume lays out a products file the way a Kubernetes ConfigMap
// volume mounts it: products.yaml -> ..data/products.yaml, with ..data a
// symlink to a timestamped directory holding the regular file.
func configMapVolume(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "..2026_10_23_12_00_00.000000001"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..2026_10_23_12_00_00.000000001", "products.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_10_23_12_00_00.000000001", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "products.yaml")
	if err := os.Symlink("..data/products.yaml", path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListFollowsConfigMapSymlinks(t *testing.T) {
	original := "version: 1\nproducts:\n  - package: metrics-server\n    selectors: [\"0\"]\n    upstream:\n      \"0\": registry.k8s.io/metrics-server/metrics-server:v0.8.0\n"
	path := configMapVolume(t, original)
	document, err := Run(path, "list", "", nil, false)
	if err != nil || len(document.Products) != 1 || document.Products[0].Upstream["0"] != "registry.k8s.io/metrics-server/metrics-server:v0.8.0" || document.Changed {
		t.Fatalf("list through ConfigMap symlinks: %+v %v", document, err)
	}
	// Edits replace the file by rename, which would replace the symlink, so
	// they still refuse it and leave the volume untouched.
	for _, action := range []string{"add", "remove"} {
		if _, err := Run(path, action, "metrics-server", []string{"1"}, false); err == nil || !strings.Contains(err.Error(), "not a directory or symlink") {
			t.Errorf("%s through a symlink: %v", action, err)
		}
	}
	if target, err := os.Readlink(path); err != nil || target != "..data/products.yaml" {
		t.Fatalf("symlink changed: %q %v", target, err)
	}
	if data, _ := os.ReadFile(path); string(data) != original {
		t.Fatalf("target changed:\n%s", data)
	}
}

func TestListRejectsWhatIsNotAFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Run(dir, "list", "", nil, false); err == nil || !strings.Contains(err.Error(), "regular file or a symlink to one") {
		t.Fatalf("directory: %v", err)
	}
	link := filepath.Join(t.TempDir(), "products.yaml")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(link, "list", "", nil, false); err == nil || !strings.Contains(err.Error(), "regular file or a symlink to one") {
		t.Fatalf("symlink to a directory: %v", err)
	}
	dangling := filepath.Join(t.TempDir(), "products.yaml")
	if err := os.Symlink(filepath.Join(dir, "missing.yaml"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(dangling, "list", "", nil, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink: %v", err)
	}
}
