package wolfi

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// MaxInstalledDatabaseBytes bounds installed APK database extraction.
const MaxInstalledDatabaseBytes = 8 << 20

// InstalledPackage is an APK identity from an image's installed database.
// Records retain database order; this reader does not validate them against a lock.
type InstalledPackage struct {
	Name, Version, Arch string
}

// ParseInstalledPackages reads the full installed APK identity set, not just
// the selected top-level package. Other database fields are ignored.
func ParseInstalledPackages(data []byte) []InstalledPackage {
	packages := make([]InstalledPackage, 0)
	for _, record := range strings.Split(string(data), "\n\n") {
		var pkg InstalledPackage
		for _, line := range strings.Split(record, "\n") {
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				pkg.Name = line[2:]
			case 'V':
				pkg.Version = line[2:]
			case 'A':
				pkg.Arch = line[2:]
			}
		}
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}
	return packages
}

// ReadInstalledPackages reads the installed APK database from a gzip-compressed
// OCI layer. Callers own digest verification and image/layer selection. The
// database is bounded to 8 MiB, as in the build pipeline's original reader.
func ReadInstalledPackages(layer io.Reader) ([]InstalledPackage, error) {
	gz, err := gzip.NewReader(layer)
	if err != nil {
		return nil, fmt.Errorf("open OCI layer gzip: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("installed APK database missing from OCI image")
		}
		if err != nil {
			return nil, fmt.Errorf("read OCI layer tar: %w", err)
		}
		if header.Name != "usr/lib/apk/db/installed" {
			continue
		}
		if header.Size > MaxInstalledDatabaseBytes {
			return nil, fmt.Errorf("installed APK database exceeds 8 MiB")
		}
		data, err := io.ReadAll(io.LimitReader(archive, MaxInstalledDatabaseBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read installed APK database: %w", err)
		}
		return ParseInstalledPackages(data), nil
	}
}
