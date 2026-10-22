package build

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"lupetto/internal/imageconfig"
	"lupetto/internal/wolfi"
)

// apkoConfig renders the build's apko configuration. Image options only
// append lines, so a build without them renders exactly the configuration of
// earlier releases and apko composes the same image and digest from the same
// lock and build date.
func apkoConfig(keyPath string, selected wolfi.Package, arch string, created time.Time, indexDigest string, image imageconfig.Options) string {
	var config strings.Builder
	fmt.Fprintf(&config, "contents:\n  keyring:\n    - %s\n  repositories:\n    - %s\n  packages:\n    - %s\n", strconv.Quote(keyPath), wolfi.Repository, strconv.Quote(selected.Name+"="+selected.Version))
	if image.CABundle && selected.Name != imageconfig.CABundlePackage {
		fmt.Fprintf(&config, "    - %s\n", strconv.Quote(imageconfig.CABundlePackage))
	}
	fmt.Fprintf(&config, "archs:\n  - %s\nannotations:\n  org.opencontainers.image.version: %s\n  org.opencontainers.image.created: %s\n  lupetto.apk.name: %s\n  lupetto.apk.version: %s\n  lupetto.apk.architecture: %s\n  lupetto.index.sha256: %s\n", arch, strconv.Quote(selected.Version), strconv.Quote(created.Format(time.RFC3339)), strconv.Quote(selected.Name), strconv.Quote(selected.Version), strconv.Quote(selected.Arch), strconv.Quote(indexDigest))
	annotations := image.Annotations()
	for _, name := range slices.Sorted(maps.Keys(annotations)) {
		fmt.Fprintf(&config, "  %s: %s\n", name, strconv.Quote(annotations[name]))
	}
	if image.Entrypoint != nil {
		fmt.Fprintf(&config, "entrypoint:\n  command: %s\n", strconv.Quote(imageconfig.ApkoCommand(image.Entrypoint)))
	}
	return config.String()
}

// checkImageConfig requires the OCI config to carry exactly the requested
// entrypoint (none when none was requested), so apko's command splitting can
// never silently change it.
func checkImageConfig(dir, digest string, image imageconfig.Options) error {
	data, err := readOCIBlob(dir, digest, 4<<20)
	if err != nil {
		return fmt.Errorf("read OCI config: %w", err)
	}
	var config struct {
		Config struct{ Entrypoint []string }
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("decode OCI config: %w", err)
	}
	if !slices.Equal(config.Config.Entrypoint, image.Entrypoint) {
		return fmt.Errorf("OCI image config entrypoint %q does not match requested %q", config.Config.Entrypoint, image.Entrypoint)
	}
	return nil
}

const maxLayerEntries = 1 << 20

type layerEntry struct {
	typeflag byte
	mode     int64
	linkname string
}

// checkImageFiles checks the files image options require in the
// gzip-compressed layer: the entrypoint executable and the CA bundle.
func checkImageFiles(layer io.Reader, selected wolfi.Package, image imageconfig.Options) error {
	entries, err := readLayerEntries(layer)
	if err != nil {
		return err
	}
	if image.Entrypoint != nil {
		if err := checkExecutable(entries, image.Entrypoint[0]); err != nil {
			return fmt.Errorf("entrypoint %s is not usable in the image of %s@%s and its dependency closure: %w", image.Entrypoint[0], selected.Name, selected.Version, err)
		}
	}
	if image.CABundle {
		entry, err := resolveLayerPath(entries, imageconfig.CABundlePath)
		if err == nil && entry.typeflag != tar.TypeReg && entry.typeflag != tar.TypeLink {
			err = errors.New("not a regular file")
		}
		if err != nil {
			return fmt.Errorf("CA bundle %s is not usable in the image of %s@%s: %w", imageconfig.CABundlePath, selected.Name, selected.Version, err)
		}
	}
	return nil
}

// checkExecutable requires target, resolved through the layer's own
// symlinks, to be an executable regular file.
func checkExecutable(entries map[string]layerEntry, target string) error {
	entry, err := resolveLayerPath(entries, target)
	if err != nil {
		return err
	}
	if entry.typeflag != tar.TypeReg && entry.typeflag != tar.TypeLink {
		return errors.New("not a regular file")
	}
	if entry.mode&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
}

func layerName(name string) string {
	name = strings.Trim(strings.TrimPrefix(name, "./"), "/")
	if name == "" {
		return ""
	}
	return path.Clean(name)
}

func readLayerEntries(layer io.Reader) (map[string]layerEntry, error) {
	gz, err := gzip.NewReader(layer)
	if err != nil {
		return nil, fmt.Errorf("open OCI layer gzip: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	entries := map[string]layerEntry{}
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read OCI layer tar: %w", err)
		}
		if len(entries) >= maxLayerEntries {
			return nil, fmt.Errorf("OCI layer has more than %d entries", maxLayerEntries)
		}
		name := layerName(header.Name)
		if name == "" {
			continue
		}
		entries[name] = layerEntry{typeflag: header.Typeflag, mode: header.Mode, linkname: header.Linkname}
		// Parent directories may be implicit in a tar stream.
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, ok := entries[parent]; ok {
				break
			}
			entries[parent] = layerEntry{typeflag: tar.TypeDir}
		}
	}
	return entries, nil
}

// resolveLayerPath walks target component by component from the image root,
// following symlinks in any component as the kernel would.
func resolveLayerPath(entries map[string]layerEntry, target string) (layerEntry, error) {
	pending := strings.Split(target, "/")
	current := ""
	entry := layerEntry{typeflag: tar.TypeDir}
	for links := 0; len(pending) > 0; {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case "", ".":
			continue
		case "..":
			if current = path.Dir(current); current == "." {
				current = ""
			}
			continue
		}
		candidate := path.Join(current, component)
		next, ok := entries[candidate]
		if !ok {
			return layerEntry{}, fmt.Errorf("/%s does not exist", candidate)
		}
		if next.typeflag == tar.TypeSymlink {
			if links++; links > 40 {
				return layerEntry{}, errors.New("too many levels of symbolic links")
			}
			if strings.HasPrefix(next.linkname, "/") {
				current = ""
			}
			pending = append(strings.Split(next.linkname, "/"), pending...)
			continue
		}
		if len(pending) > 0 && next.typeflag != tar.TypeDir {
			return layerEntry{}, fmt.Errorf("/%s is not a directory", candidate)
		}
		current, entry = candidate, next
	}
	return entry, nil
}
