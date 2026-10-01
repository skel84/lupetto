package wolfi

import (
	"context"
	"fmt"
	"sort"

	apkcompare "chainguard.dev/apko/pkg/apk/apk"
)

type discoveredPackage struct {
	Package
	parsedVersion apkcompare.Version
}

func orderedIndexedPackages(packages []Package, arch string) ([]Package, error) {
	ordered := make([]discoveredPackage, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Arch != arch {
			continue
		}
		if !PackageNamePattern.MatchString(pkg.Name) {
			return nil, fmt.Errorf("invalid APKINDEX package name %q", pkg.Name)
		}
		parsed, err := apkcompare.ParseVersion(pkg.Version)
		if err != nil {
			return nil, fmt.Errorf("cannot order APK version %q for %s: %w", pkg.Version, pkg.Name, err)
		}
		ordered = append(ordered, discoveredPackage{Package: pkg, parsedVersion: parsed})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if comparison := apkcompare.CompareVersions(ordered[i].parsedVersion, ordered[j].parsedVersion); comparison != 0 {
			return comparison > 0
		}
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		if ordered[i].Version != ordered[j].Version {
			return ordered[i].Version > ordered[j].Version
		}
		return ordered[i].Checksum < ordered[j].Checksum
	})
	result := make([]Package, len(ordered))
	for i, pkg := range ordered {
		result[i] = pkg.Package
	}
	return result, nil
}

// ReadIndexedPackages fetches and verifies the current APKINDEX for arch and
// returns the matching entries in descending APK version order, plus the
// index's SHA-256.
func ReadIndexedPackages(ctx context.Context, requested, arch string) ([]Package, string, error) {
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", Repository, arch)
	index, err := GetPublicFile(ctx, indexURL, 32<<20)
	if err != nil {
		return nil, "", err
	}
	key, err := GetSigningKey(ctx)
	if err != nil {
		return nil, "", err
	}
	verified, err := VerifyAPKINDEX(index, key)
	if err != nil {
		return nil, "", err
	}
	packages, err := ParseAPKINDEX(verified, requested)
	if err != nil {
		return nil, "", err
	}
	ordered, err := orderedIndexedPackages(packages, arch)
	if err != nil {
		return nil, "", err
	}
	return ordered, SHA256Hex(index), nil
}
