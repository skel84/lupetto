package explorer

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowedHostsForEveryListener(t *testing.T) {
	binary, _, _ := fakeCLI(t, goodFake())
	for _, listen := range []string{"0.0.0.0:8080", "127.0.0.1:8080", "[::]:8080"} {
		t.Run(listen, func(t *testing.T) {
			config := DefaultConfig()
			config.Listen = listen
			config.Products = "products.yaml"
			config.LupettoBinary = binary
			server, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close(context.Background())
			for _, host := range []string{"localhost", "localhost:8080", "LOCALHOST:443", "127.0.0.1:49123", "[::1]", "[::1]:8080", "[0:0:0:0:0:0:0:1]:8443"} {
				r := httptest.NewRequest("GET", "http://127.0.0.1/healthz", nil)
				r.Host = host
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, r)
				if w.Code != 200 {
					t.Errorf("host %q code=%d", host, w.Code)
				}
			}
			for _, path := range []string{"/?format=json", "/healthz", "/static/app.css"} {
				r := httptest.NewRequest("GET", "http://rebound.example.invalid"+path, nil)
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, r)
				if w.Code != 403 || strings.Contains(w.Body.String(), server.token) {
					t.Errorf("rebound GET %s response=%d %s", path, w.Code, w.Body.String())
				}
			}
			// Even a known valid token and Origin matching the rebound Host cannot bypass the allowlist.
			form := url.Values{"csrfToken": {server.token}, "package": {"busybox-static"}, "selector": {"1"}}
			r := httptest.NewRequest("POST", "http://rebound.example.invalid/builds", strings.NewReader(form.Encode()))
			r.Header.Set("Origin", "http://rebound.example.invalid")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			if w.Code != 403 {
				t.Errorf("rebound POST code=%d", w.Code)
			}
		})
	}
}

func TestExplicitAllowedHostsAndPorts(t *testing.T) {
	rules, err := parseAllowedHosts([]string{"dashboard.example.invalid", "restricted.example.invalid:8443", "[2001:db8::1]:9443", "[2001:db8::2]"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{allowedHosts: rules}
	for _, host := range []string{"dashboard.example.invalid", "DASHBOARD.EXAMPLE.INVALID:443", "dashboard.example.invalid:8080", "restricted.example.invalid:8443", "[2001:db8::1]:9443", "[2001:0db8:0:0:0:0:0:1]:9443", "[2001:db8::2]", "[2001:db8::2]:8080"} {
		if !server.hostAllowed(host) {
			t.Errorf("allowed host %q rejected", host)
		}
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "restricted.example.invalid", "restricted.example.invalid:443", "restricted.example.invalid:08443", "[2001:db8::1]", "[2001:db8::1]:443", "dashboard.example.invalid.evil:443", "evil.invalid", "dashboard.example.invalid:0", "dashboard.example.invalid:65536", "dashboard.example.invalid:"} {
		if server.hostAllowed(host) {
			t.Errorf("unlisted host %q accepted", host)
		}
	}
	binary, _, _ := fakeCLI(t, goodFake())
	config := DefaultConfig()
	config.Listen = "0.0.0.0:8080"
	config.Products = "p"
	config.LupettoBinary = binary
	config.AllowedHosts = []string{"dashboard.example.invalid"}
	instance, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close(context.Background())
	form := url.Values{"csrfToken": {instance.token}}
	r := httptest.NewRequest("POST", "http://dashboard.example.invalid/status/refresh", strings.NewReader(form.Encode()))
	r.Header.Set("Origin", "https://dashboard.example.invalid")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	instance.Handler().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("allowed ingress POST=%d %s", w.Code, w.Body.String())
	}
}

func TestInvalidAllowedHostConfiguration(t *testing.T) {
	for _, value := range []string{"", "*", "https://example.invalid", "user@example.invalid", "example.invalid/path", "example.invalid:", "example.invalid:http", "example.invalid:0", "example.invalid:65536", "::1", "[::1", "[::1]suffix", "[127.0.0.1]", "-example.invalid", "example..invalid", "host name"} {
		if _, err := parseAllowedHosts([]string{value}); err == nil {
			t.Errorf("invalid allowed-host %q accepted", value)
		}
	}
}
