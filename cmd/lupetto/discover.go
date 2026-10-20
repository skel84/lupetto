package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"lupetto/internal/wolfi"
)

type discoverRequest struct {
	name string
	json bool
	arch string
}

type discoverDocument struct {
	Kind         string            `json:"kind"`
	Version      int               `json:"version"`
	Package      string            `json:"package,omitempty"`
	Architecture string            `json:"architecture"`
	IndexSHA256  string            `json:"indexSHA256"`
	Packages     []discoverPackage `json:"packages"`
}

type discoverPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

func parseDiscover(args []string) (discoverRequest, error) {
	var request discoverRequest
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if value, inline := strings.CutPrefix(arg, "--arch="); (inline || arg == "--arch") && request.arch == "" {
			if !inline {
				if i++; i == len(args) {
					return discoverRequest{}, fmt.Errorf("--arch requires a value")
				}
				value = args[i]
			}
			arch, err := wolfi.ParseArch(value)
			if err != nil {
				return discoverRequest{}, err
			}
			request.arch = arch
		} else if arg == "--json" && !request.json {
			request.json = true
		} else if request.name == "" && wolfi.RequestedNamePattern.MatchString(arg) {
			request.name = arg
		} else {
			return discoverRequest{}, fmt.Errorf("discover requires one valid package or provider name, or --json with an optional name")
		}
	}
	if request.name == "" && !request.json {
		return discoverRequest{}, fmt.Errorf("discover requires one valid package or provider name, or --json with an optional name")
	}
	return request, nil
}

func runDiscover(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runDiscoverWith(ctx, args, stdout, stderr, wolfi.TargetArch, wolfi.ReadIndexedPackages)
}

func runDiscoverWith(ctx context.Context, args []string, stdout, stderr io.Writer, targetArch func() (string, error), readIndex func(context.Context, string, string) ([]wolfi.Package, string, error)) int {
	request, err := parseDiscover(args)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 2
	}
	arch, err := request.arch, error(nil)
	if arch == "" {
		arch, err = targetArch()
	}
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	packages, digest, err := readIndex(ctx, request.name, arch)
	if err == nil && request.name == "" {
		packages, err = wolfi.LatestIndexedPackages(packages, arch)
	}
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	if len(packages) == 0 && request.name != "" {
		fmt.Fprintf(stderr, "lupetto: no indexed versions for %s on %s in current Wolfi APKINDEX\n", request.name, arch)
		return 1
	}
	if request.json {
		document := discoverDocument{Kind: "discover", Version: 1, Package: request.name, Architecture: arch, IndexSHA256: digest, Packages: make([]discoverPackage, 0, len(packages))}
		for _, pkg := range packages {
			document.Packages = append(document.Packages, discoverPackage{Name: pkg.Name, Version: pkg.Version, Description: pkg.Description})
		}
		data, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: encode discovery: %v\n", err)
			return 1
		}
		if !writeJSONRecord(stdout, stderr, append(data, '\n')) {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Wolfi APKINDEX sha256:%s (%s)\nIndexed versions for %s (not verified buildable):\n", digest, arch, request.name)
	for _, pkg := range packages {
		fmt.Fprintf(stdout, "  %s@%s\n", pkg.Name, pkg.Version)
	}
	return 0
}
