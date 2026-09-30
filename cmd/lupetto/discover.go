package main

import (
	apkcompare "chainguard.dev/apko/pkg/apk/apk"

	"context"
	"fmt"
	"io"
	"sort"
)

type discoveredPackage struct {
	indexedPackage
	parsedVersion apkcompare.Version
}

func orderedIndexedPackages(packages []indexedPackage, arch string) ([]indexedPackage, error) {
	ordered := make([]discoveredPackage, 0, len(packages))
	for _, pkg := range packages {
		if pkg.arch != arch {
			continue
		}
		if !packageName.MatchString(pkg.name) {
			return nil, fmt.Errorf("invalid APKINDEX package name %q", pkg.name)
		}
		parsed, err := apkcompare.ParseVersion(pkg.version)
		if err != nil {
			return nil, fmt.Errorf("cannot order APK version %q for %s: %w", pkg.version, pkg.name, err)
		}
		ordered = append(ordered, discoveredPackage{indexedPackage: pkg, parsedVersion: parsed})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if comparison := apkcompare.CompareVersions(ordered[i].parsedVersion, ordered[j].parsedVersion); comparison != 0 {
			return comparison > 0
		}
		if ordered[i].name != ordered[j].name {
			return ordered[i].name < ordered[j].name
		}
		if ordered[i].version != ordered[j].version {
			return ordered[i].version > ordered[j].version
		}
		return ordered[i].checksum < ordered[j].checksum
	})
	result := make([]indexedPackage, len(ordered))
	for i, pkg := range ordered {
		result[i] = pkg.indexedPackage
	}
	return result, nil
}

func readIndexedPackages(ctx context.Context, requested, arch string) ([]indexedPackage, string, error) {
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", wolfiRepository, arch)
	index, err := getPublicFile(ctx, indexURL, 32<<20)
	if err != nil {
		return nil, "", err
	}
	key, err := getWolfiSigningKey(ctx)
	if err != nil {
		return nil, "", err
	}
	verified, err := verifyAPKINDEX(index, key)
	if err != nil {
		return nil, "", err
	}
	packages, err := parseAPKINDEX(verified, requested)
	if err != nil {
		return nil, "", err
	}
	ordered, err := orderedIndexedPackages(packages, arch)
	if err != nil {
		return nil, "", err
	}
	return ordered, sha256Hex(index), nil
}

func runDiscover(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !requestedName.MatchString(args[0]) {
		fmt.Fprintln(stderr, "lupetto: discover requires one valid package or provider name")
		return 2
	}
	arch, err := targetArch()
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	packages, digest, err := readIndexedPackages(ctx, args[0], arch)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	if len(packages) == 0 {
		fmt.Fprintf(stderr, "lupetto: no indexed versions for %s on %s in current Wolfi APKINDEX\n", args[0], arch)
		return 1
	}
	fmt.Fprintf(stdout, "Wolfi APKINDEX sha256:%s (%s)\nIndexed versions for %s (not verified buildable):\n", digest, arch, args[0])
	for _, pkg := range packages {
		fmt.Fprintf(stdout, "  %s@%s\n", pkg.name, pkg.version)
	}
	return 0
}
