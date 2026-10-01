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
	if err != nil || len(feed["curl"]) != 1 || len(feed["curl"]["8.2.0-r1"]) != 2 {
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
