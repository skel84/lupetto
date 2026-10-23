package status

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductsStrictContract(t *testing.T) {
	valid := "version: 1\nproducts:\n- package: cmd:curl\n  selectors: [\"8\", \"8.2\"]\n"
	products, err := ParseProducts(strings.NewReader(valid))
	if err != nil || len(products.Products) != 1 || products.Products[0].Selectors[1] != "8.2" {
		t.Fatalf("valid products: %+v, %v", products, err)
	}
	for name, data := range map[string]string{
		"unknown root":     valid + "registry: bad\n",
		"unknown nested":   strings.Replace(valid, "  selectors:", "  extra: x\n  selectors:", 1),
		"duplicate key":    "version: 1\nversion: 1\nproducts: []\n",
		"version":          strings.Replace(valid, "version: 1", "version: 2", 1),
		"numeric":          strings.Replace(valid, "\"8\"", "8", 1),
		"empty products":   "version: 1\nproducts: []\n",
		"empty selectors":  "version: 1\nproducts:\n- package: curl\n  selectors: []\n",
		"duplicate track":  strings.Replace(valid, "\"8.2\"", "\"8\"", 1),
		"invalid package":  strings.Replace(valid, "cmd:curl", "cmd::curl", 1),
		"invalid selector": strings.Replace(valid, "\"8.2\"", "\"8.x\"", 1),
		"multiple docs":    valid + "---\n" + valid,
		"aliases":          "version: 1\nproducts:\n- package: curl\n  selectors: &selectors [\"8\"]\n- package: curl\n  selectors: *selectors\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProducts(strings.NewReader(data)); err == nil {
				t.Fatal("invalid products accepted")
			}
		})
	}
	if _, err := ParseProducts(strings.NewReader(strings.Repeat(" ", MaxProductsBytes+1))); err == nil {
		t.Fatal("products byte limit not enforced")
	}
}

func TestSecurityFeedFixedOnlyAndHTTPS(t *testing.T) {
	data := `{"packages":[{"pkg":{"name":"curl","secfixes":{"0":["CVE-2024-0001"],"8.2.0-r1":["CVE-2024-0002","GHSA-aaaa-bbbb-cccc","GO-1234-1234","secretcanary"]}}}]}`
	feed, err := ParseSecurity([]byte(data))
	if err != nil || len(feed["curl"]) != 1 || len(feed["curl"]["8.2.0-r1"]) != 3 {
		t.Fatalf("parsed security: %+v, %v", feed, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, data) }))
	defer server.Close()
	got, sha, err := readSecurityURL(context.Background(), server.Client(), server.URL)
	if err != nil || len(sha) != 64 || len(got["curl"]) != 1 {
		t.Fatalf("HTTPS feed: %+v, %s, %v", got, sha, err)
	}
	if _, _, err := readSecurityURL(context.Background(), server.Client(), "http://127.0.0.1/security.json"); err == nil {
		t.Fatal("HTTP security feed accepted")
	}
	for _, invalid := range []string{`{}`, `{"packages":null}`, `{"packages":[{"pkg":{"name":"../bad"}}]}`, `{"packages":[{"pkg":{"name":"curl"}},{"pkg":{"name":"curl"}}]}`} {
		if _, err := ParseSecurity([]byte(invalid)); err == nil {
			t.Fatalf("invalid feed accepted: %s", invalid)
		}
	}
}

func TestProductsUpstream(t *testing.T) {
	legacy := "version: 1\nproducts:\n- package: metrics-server\n  selectors: [\"0\"]\n  caBundle: true\n"
	products, err := ParseProducts(strings.NewReader(legacy))
	if err != nil || products.Products[0].Upstream != nil {
		t.Fatalf("products without upstream must keep working: %+v, %v", products, err)
	}
	valid := legacy + "  upstream:\n    \"0\": registry.k8s.io/metrics-server/metrics-server:v0.8.0\n"
	products, err = ParseProducts(strings.NewReader(valid))
	if err != nil || products.Products[0].Upstream["0"] != "registry.k8s.io/metrics-server/metrics-server:v0.8.0" {
		t.Fatalf("valid upstream: %+v, %v", products, err)
	}
	digest := strings.Replace(valid, ":v0.8.0", "@sha256:"+strings.Repeat("a", 64), 1)
	if _, err := ParseProducts(strings.NewReader(digest)); err != nil {
		t.Fatalf("digest upstream rejected: %v", err)
	}
	if _, err := ParseProducts(strings.NewReader(strings.Replace(valid, "registry.k8s.io/metrics-server/metrics-server:v0.8.0", "busybox:1.37", 1))); err != nil {
		t.Fatalf("Docker Hub short name rejected: %v", err)
	}
	for name, data := range map[string]string{
		"unknown selector": strings.Replace(valid, "    \"0\":", "    \"1\":", 1),
		"numeric selector": strings.Replace(valid, "    \"0\":", "    0:", 1),
		"no tag":           strings.Replace(valid, ":v0.8.0", "", 1),
		"bad reference":    strings.Replace(valid, "metrics-server:v0.8.0", "Metrics Server:v0.8.0", 1),
		"too long":         strings.Replace(valid, ":v0.8.0", "/"+strings.Repeat("a", MaxUpstreamReferenceBytes)+":v1", 1),
		"duplicate key":    valid + "    \"0\": busybox:1.37\n",
		"list":             legacy + "  upstream: [busybox:1.37]\n",
		"scalar":           legacy + "  upstream: busybox:1.37\n",
		"nested":           legacy + "  upstream:\n    \"0\": {image: busybox:1.37}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProducts(strings.NewReader(data)); err == nil {
				t.Fatal("invalid upstream accepted")
			}
		})
	}
}
