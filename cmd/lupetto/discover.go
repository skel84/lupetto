package main

import (
	"context"
	"fmt"
	"io"

	"lupetto/internal/wolfi"
)

func runDiscover(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || !wolfi.RequestedNamePattern.MatchString(args[0]) {
		fmt.Fprintln(stderr, "lupetto: discover requires one valid package or provider name")
		return 2
	}
	arch, err := wolfi.TargetArch()
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	packages, digest, err := wolfi.ReadIndexedPackages(ctx, args[0], arch)
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
		fmt.Fprintf(stdout, "  %s@%s\n", pkg.Name, pkg.Version)
	}
	return 0
}
