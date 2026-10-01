package build

import (
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

func readableImageReference(selected wolfi.Package, arch string) (string, error) {
	return registry.ReadableImageReference(selected.Name, selected.Version, arch)
}
