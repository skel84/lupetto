package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lupetto/internal/wolfi"
)

func TestParseDiscoverJSON(t *testing.T) {
	for _, args := range [][]string{{"--json"}, {"--json", "cmd:curl"}, {"cmd:curl", "--json"}, {"nginx"}} {
		request, err := parseDiscover(args)
		if err != nil || request.json != strings.Contains(strings.Join(args, " "), "--json") {
			t.Fatalf("args=%v request=%+v err=%v", args, request, err)
		}
	}
	for _, args := range [][]string{{"--json", "--json"}, {"--json=false"}, {"--json", "nginx", "extra"}, {"--json", "../nginx"}, {"--unknown"}} {
		var stdout, stderr bytes.Buffer
		code := runDiscoverWith(context.Background(), args, &stdout, &stderr,
			func() (string, error) { t.Fatal("architecture called for invalid args"); return "", nil },
			func(context.Context, string, string) ([]wolfi.Package, string, error) {
				t.Fatal("network called for invalid args")
				return nil, "", nil
			})
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("args=%v code=%d stdout=%q", args, code, stdout.String())
		}
	}
}

func TestDiscoverJSONAndUnchangedHuman(t *testing.T) {
	packages := []wolfi.Package{{Name: "nginx-stable", Version: "1.30-r10", Arch: "x86_64", Description: "new <description>"}, {Name: "nginx-stable", Version: "1.30-r2", Arch: "x86_64", Description: "old"}, {Name: "nginx-mainline", Version: "1.29-r0", Arch: "x86_64"}}
	for _, tc := range []struct {
		args  []string
		name  string
		json  bool
		count int
	}{
		{[]string{"nginx"}, "nginx", false, 3},
		{[]string{"--json", "nginx"}, "nginx", true, 3},
		{[]string{"--json"}, "", true, 2},
	} {
		var stdout, stderr bytes.Buffer
		code := runDiscoverWith(context.Background(), tc.args, &stdout, &stderr, func() (string, error) { return "x86_64", nil },
			func(_ context.Context, name, arch string) ([]wolfi.Package, string, error) {
				if name != tc.name || arch != "x86_64" {
					t.Fatalf("name=%q arch=%q", name, arch)
				}
				return packages, "fixture-sha256", nil
			})
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v code=%d stderr=%q", tc.args, code, stderr.String())
		}
		if !tc.json {
			want := "Wolfi APKINDEX sha256:fixture-sha256 (x86_64)\nIndexed versions for nginx (not verified buildable):\n  nginx-stable@1.30-r10\n  nginx-stable@1.30-r2\n  nginx-mainline@1.29-r0\n"
			if stdout.String() != want {
				t.Fatalf("human changed: %q", stdout.String())
			}
			continue
		}
		if !strings.HasSuffix(stdout.String(), "\n") {
			t.Fatal("JSON document must end with a newline")
		}
		var document discoverDocument
		decoder := json.NewDecoder(&stdout)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			t.Fatal(err)
		}
		if document.Kind != "discover" || document.Version != 1 || document.Package != tc.name || document.Architecture != "x86_64" || document.IndexSHA256 != "fixture-sha256" || len(document.Packages) != tc.count {
			t.Fatalf("document=%+v", document)
		}
		if tc.name == "" && (document.Packages[0].Name != "nginx-mainline" || document.Packages[1].Version != "1.30-r10" || document.Packages[1].Description != "new <description>") {
			t.Fatalf("all packages=%+v", document.Packages)
		}
	}
}

func TestDiscoverJSONFailureNoDocument(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"missing", nil}, {"fetch", errors.New("index unavailable")}} {
		var stdout, stderr bytes.Buffer
		code := runDiscoverWith(context.Background(), []string{"--json", tc.name}, &stdout, &stderr,
			func() (string, error) { return "x86_64", nil },
			func(context.Context, string, string) ([]wolfi.Package, string, error) { return nil, "", tc.err })
		if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}
