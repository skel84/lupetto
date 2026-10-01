package main

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
)

type requiredTool struct {
	name     string
	purpose  string
	optional bool
}

var tools = []requiredTool{
	{name: "apko", purpose: "image composition"},
	{name: "docker", purpose: "default image loading"},
	{name: "cosign", purpose: "signing and attestation", optional: true},
}

func doctor(out io.Writer, goos string, lookPath func(string) (string, error)) int {
	fmt.Fprintln(out, "External tools on PATH (versions and Docker daemon not checked):")
	missingRequired := false
	for _, tool := range tools {
		_, err := lookPath(tool.name)
		label := "required"
		if tool.optional {
			label = "optional"
		}
		if err == nil {
			fmt.Fprintf(out, "  %s: found (%s for %s)\n", tool.name, label, tool.purpose)
			continue
		}
		fmt.Fprintf(out, "  %s: missing (%s for %s)\n", tool.name, label, tool.purpose)
		fmt.Fprintf(out, "    Install: %s\n", installHint(goos, tool.name))
		if !tool.optional {
			missingRequired = true
		}
	}
	if missingRequired {
		return 1
	}
	return 0
}

func installHint(goos, name string) string {
	switch goos {
	case "darwin":
		switch name {
		case "apko":
			return "brew install apko (Homebrew: https://brew.sh/)"
		case "docker":
			return "Docker Desktop for Mac: https://docs.docker.com/desktop/setup/install/mac-install/"
		case "cosign":
			return "brew install cosign (Homebrew: https://brew.sh/)"
		}
	case "linux":
		switch name {
		case "apko":
			return "with Go: go install chainguard.dev/apko@latest; add Go's bin directory to PATH (https://github.com/chainguard-dev/apko#installation)"
		case "docker":
			return "Docker Engine installation by distribution: https://docs.docker.com/engine/install/"
		case "cosign":
			return "with Go: go install github.com/sigstore/cosign/v3/cmd/cosign@latest; add Go's bin directory to PATH (https://docs.sigstore.dev/cosign/system_config/installation/)"
		}
	case "windows":
		switch name {
		case "apko":
			return "run Lupetto and doctor inside WSL/Linux after installing apko there; a WSL executable is not on Windows PATH (https://github.com/chainguard-dev/apko#installation)"
		case "docker":
			return "Docker Desktop for Windows: https://docs.docker.com/desktop/setup/install/windows-install/"
		case "cosign":
			return "Cosign Windows binaries: https://docs.sigstore.dev/cosign/system_config/installation/"
		}
	}
	return "check upstream installation instructions for " + name
}

func runDoctor(out, errOut io.Writer, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(errOut, "lupetto: doctor accepts no arguments")
		return 2
	}
	return doctor(out, runtime.GOOS, exec.LookPath)
}
