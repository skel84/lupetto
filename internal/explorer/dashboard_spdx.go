package explorer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Paths originate only in a CLI inventory record, never an HTTP parameter.
// Root confines the actual open, including concurrent symlink replacement.
func readValidatedSPDX(build InventoryBuild) ([]byte, error) {
	if !build.SPDX.Present || build.Record == nil || build.Record.Version != 6 || build.Record.Evidence == nil || !build.Record.Evidence.SPDXValidated {
		return nil, errors.New("validated SPDX is not available for this build")
	}
	if build.SPDX.Path != build.Record.Evidence.SPDXPath || build.SPDX.SHA256 != build.Record.Evidence.SPDXSHA256 {
		return nil, errors.New("SPDX inventory does not match validated record")
	}
	roots, err := buildsRoots()
	if err != nil {
		return nil, err
	}
	// The record's workspace selects one root (durable data first, then the
	// legacy cache); every later check is confined to that root alone.
	builds := ""
	for _, root := range roots {
		if workspace, err := filepath.Rel(root, build.Workspace); err == nil && filepath.IsLocal(workspace) && workspace != "." {
			builds = root
			break
		}
	}
	if builds == "" {
		return nil, errors.New("build workspace is outside the Lupetto builds directories")
	}
	info, err := os.Lstat(builds)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Lupetto builds directory must not be a symlink")
	}
	relative, err := filepath.Rel(builds, build.SPDX.Path)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return nil, errors.New("SPDX path is outside the Lupetto builds directory")
	}
	inside, err := filepath.Rel(build.Workspace, build.SPDX.Path)
	if err != nil || !filepath.IsLocal(inside) || inside == "." {
		return nil, errors.New("SPDX path is outside build workspace")
	}
	root, err := os.OpenRoot(builds)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("Lupetto builds directory changed while opening")
	}
	components := strings.Split(relative, string(filepath.Separator))
	current := ""
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("SPDX path must not contain symlinks")
		}
		if current == relative && !info.Mode().IsRegular() {
			return nil, errors.New("SPDX must be a regular file")
		}
	}
	// A file replaced by a FIFO between Lstat and open must not hold an
	// HTTP worker indefinitely. Stat below checks the actual opened object.
	f, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxDocumentBytes {
		return nil, errors.New("SPDX must be a regular file no larger than 32 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocumentBytes {
		return nil, errOutputLimit
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != build.SPDX.SHA256 {
		return nil, errors.New("SPDX checksum no longer matches validated build evidence")
	}
	return data, nil
}
func spdxPackages(data []byte) ([]PackageIdentity, error) {
	var document struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.SPDXVersion != "SPDX-2.3" {
		return nil, errors.New("unsupported SPDX version")
	}
	packages := []PackageIdentity{}
	seen := map[PackageIdentity]bool{}
	for _, p := range document.Packages {
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType != "purl" || !strings.HasPrefix(ref.ReferenceLocator, "pkg:apk/wolfi/") {
				continue
			}
			body, query, _ := strings.Cut(strings.TrimPrefix(ref.ReferenceLocator, "pkg:apk/wolfi/"), "?")
			name, version, ok := strings.Cut(body, "@")
			if !ok {
				return nil, errors.New("malformed APK purl")
			}
			qualifiers, err := url.ParseQuery(query)
			if err != nil {
				return nil, err
			}
			if qualifiers.Get("distro") != "wolfi" {
				continue
			}
			name, err = url.PathUnescape(name)
			if err != nil {
				return nil, err
			}
			version, err = url.PathUnescape(version)
			if err != nil {
				return nil, err
			}
			identity := PackageIdentity{name, version, qualifiers.Get("arch")}
			if identity.Name == "" || identity.Version == "" || identity.Architecture == "" {
				return nil, fmt.Errorf("incomplete APK purl")
			}
			if !seen[identity] {
				packages = append(packages, identity)
				seen[identity] = true
			}
		}
	}
	if len(packages) == 0 {
		return nil, errors.New("validated SPDX has no Wolfi distro APK packages")
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	return packages, nil
}
