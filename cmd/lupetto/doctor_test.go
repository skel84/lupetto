package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDoctorReportsMissingTools(t *testing.T) {
	var out bytes.Buffer
	code := doctor(&out, "darwin", func(name string) (string, error) {
		if name == "docker" {
			return "/usr/local/bin/docker", nil
		}
		return "", errors.New("not on PATH")
	})
	if code != 1 || !strings.Contains(out.String(), "apko: missing (required") ||
		!strings.Contains(out.String(), "brew install apko") ||
		!strings.Contains(out.String(), "docker: found (required") ||
		!strings.Contains(out.String(), "cosign: missing (optional") ||
		!strings.Contains(out.String(), "brew install cosign") {
		t.Fatalf("code=%d output=%q", code, out.String())
	}
}

func TestDoctorOptionalToolDoesNotBlock(t *testing.T) {
	var out bytes.Buffer
	code := doctor(&out, "linux", func(name string) (string, error) {
		if name == "cosign" {
			return "", errors.New("not on PATH")
		}
		return "/usr/bin/" + name, nil
	})
	if code != 0 || !strings.Contains(out.String(), "cosign: missing (optional") ||
		!strings.Contains(out.String(), "go install github.com/sigstore/cosign/v3/cmd/cosign@latest") {
		t.Fatalf("code=%d output=%q", code, out.String())
	}
}

func TestInstallHintsByOS(t *testing.T) {
	for _, tc := range []struct {
		goos, name, want string
	}{
		{"darwin", "docker", "mac-install"},
		{"linux", "apko", "chainguard.dev/apko@latest"},
		{"linux", "docker", "engine/install"},
		{"windows", "apko", "run Lupetto and doctor inside WSL/Linux"},
		{"windows", "docker", "windows-install"},
		{"windows", "cosign", "sigstore.dev"},
		{"plan9", "apko", "upstream installation"},
	} {
		t.Run(tc.goos+"/"+tc.name, func(t *testing.T) {
			if got := installHint(tc.goos, tc.name); !strings.Contains(got, tc.want) {
				t.Fatalf("installHint(%q, %q) = %q; want %q", tc.goos, tc.name, got, tc.want)
			}
		})
	}
}

func TestDoctorUsesActualPATHAndRejectsArguments(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var out, errOut bytes.Buffer
	if code := runDoctor(&out, &errOut, nil); code != 1 ||
		!strings.Contains(out.String(), "apko: missing") ||
		!strings.Contains(out.String(), "docker: missing") ||
		!strings.Contains(out.String(), "cosign: missing") {
		t.Fatalf("code=%d output=%q error=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := runDoctor(&out, &errOut, []string{"unexpected"}); code != 2 || out.Len() != 0 {
		t.Fatalf("code=%d output=%q error=%q", code, out.String(), errOut.String())
	}
}
