package status

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

const (
	MaxLayers                       = 128
	MaxCompressedLayerBytes   int64 = 512 << 20
	MaxUncompressedLayerBytes int64 = 2 << 30
	MaxImageCompressedBytes   int64 = 2 << 30
	MaxImageUncompressedBytes int64 = 8 << 30
)

const installedPath = "usr/lib/apk/db/installed"

func (reader RemoteRegistry) Installed(ctx context.Context, repository name.Repository, image Image) ([]wolfi.InstalledPackage, error) {
	if !digestPattern.MatchString(image.Digest) {
		return nil, errors.New("invalid image digest")
	}
	descriptor, err := remote.Get(repository.Digest(image.Digest), reader.options(ctx)...)
	if err != nil {
		return nil, registry.SafeError(ctx, "installed manifest", err)
	}
	if !verifyDigest(descriptor.Manifest, image.Digest) {
		return nil, errors.New("installed manifest digest mismatch")
	}
	identified, classification := classifyManifest(descriptor.Manifest, image.Digest)
	if classification != "image" || identified.Name != image.Name || identified.Version != image.Version || identified.Architecture != image.Architecture {
		return nil, errors.New("installed image identity mismatch")
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(descriptor.Manifest, &manifest); err != nil {
		return nil, errors.New("invalid installed manifest")
	}
	if len(manifest.Layers) > MaxLayers {
		return nil, errors.New("installed image layer limit exceeded")
	}
	configData, err := reader.readBlob(ctx, repository, manifest.Config.Digest.String(), registry.MaxMetadataBytes)
	if err != nil {
		return nil, err
	}
	var config v1.ConfigFile
	if json.Unmarshal(configData, &config) != nil {
		return nil, errors.New("invalid installed image config")
	}
	ociArch := "amd64"
	if image.Architecture == "aarch64" {
		ociArch = "arm64"
	}
	if config.OS != "linux" || config.Architecture != ociArch || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return nil, errors.New("installed image platform or layer configuration mismatch")
	}
	var database []byte
	var compressedTotal, uncompressedTotal int64
	for i, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest.String()) || !digestPattern.MatchString(config.RootFS.DiffIDs[i].String()) {
			return nil, errors.New("invalid installed layer digest")
		}
		remoteLayer, err := remote.Layer(repository.Digest(layer.Digest.String()), reader.options(ctx)...)
		if err != nil {
			return nil, registry.SafeError(ctx, "installed layer", err)
		}
		stream, err := remoteLayer.Compressed()
		if err != nil {
			return nil, registry.SafeError(ctx, "installed layer", err)
		}
		data, removed, compressed, uncompressed, readErr := readInstalledLayerBounded(ctx, stream, layer.MediaType, layer.Digest.String(), config.RootFS.DiffIDs[i].String(), min(MaxCompressedLayerBytes, MaxImageCompressedBytes-compressedTotal), min(MaxUncompressedLayerBytes, MaxImageUncompressedBytes-uncompressedTotal))
		closeErr := stream.Close()
		if readErr != nil {
			return nil, registry.SafeError(ctx, "installed layer validation", readErr)
		}
		if closeErr != nil {
			return nil, registry.SafeError(ctx, "installed layer close", closeErr)
		}
		compressedTotal += compressed
		uncompressedTotal += uncompressed
		if compressedTotal > MaxImageCompressedBytes || uncompressedTotal > MaxImageUncompressedBytes {
			return nil, errors.New("installed image byte limit exceeded")
		}
		if removed {
			database = nil
		}
		if data != nil {
			database = data
		}
	}
	if database == nil {
		return nil, errors.New("installed APK database missing from image")
	}
	packages, err := parseInstalledStrict(database, image.Architecture)
	if err != nil {
		return nil, err
	}
	selected := false
	for _, pkg := range packages {
		if pkg.Name == image.Name && pkg.Version == image.Version && pkg.Arch == image.Architecture {
			selected = true
		}
	}
	if !selected {
		return nil, errors.New("installed top-level APK does not match image annotations")
	}
	return packages, nil
}

func (reader RemoteRegistry) readBlob(ctx context.Context, repository name.Repository, digest string, limit int64) ([]byte, error) {
	if !digestPattern.MatchString(digest) {
		return nil, errors.New("invalid installed config digest")
	}
	blob, err := remote.Layer(repository.Digest(digest), reader.options(ctx)...)
	if err != nil {
		return nil, registry.SafeError(ctx, "installed config", err)
	}
	stream, err := blob.Compressed()
	if err != nil {
		return nil, registry.SafeError(ctx, "installed config", err)
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, limit+1))
	if err != nil {
		return nil, registry.SafeError(ctx, "installed config", err)
	}
	if int64(len(data)) > limit || !verifyDigest(data, digest) {
		return nil, errors.New("installed config size or digest mismatch")
	}
	return data, nil
}

type countedReader struct {
	reader       io.Reader
	ctx          context.Context
	count, limit int64
}

func (reader *countedReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.count > reader.limit {
		return 0, errors.New("installed layer byte limit exceeded")
	}
	if int64(len(data)) > reader.limit-reader.count+1 {
		data = data[:reader.limit-reader.count+1]
	}
	n, err := reader.reader.Read(data)
	reader.count += int64(n)
	if reader.count > reader.limit {
		return n, errors.New("installed layer byte limit exceeded")
	}
	return n, err
}

// Whiteouts affect only lower layers, so a DB in the same layer wins regardless
// of whiteout ordering. Only the DB bytes are retained; every layer is streamed
// to completion and both compressed digests and ordered rootfs diffIDs verified.
func readInstalledLayer(ctx context.Context, stream io.Reader, mediaType types.MediaType, digest, diffID string) ([]byte, bool, int64, int64, error) {
	return readInstalledLayerBounded(ctx, stream, mediaType, digest, diffID, MaxCompressedLayerBytes, MaxUncompressedLayerBytes)
}

func readInstalledLayerBounded(ctx context.Context, stream io.Reader, mediaType types.MediaType, digest, diffID string, compressedLimit, uncompressedLimit int64) ([]byte, bool, int64, int64, error) {
	compressedHash, uncompressedHash := sha256.New(), sha256.New()
	compressed := &countedReader{reader: io.TeeReader(stream, compressedHash), ctx: ctx, limit: compressedLimit}
	var decoded io.Reader = compressed
	var gz *gzip.Reader
	switch mediaType {
	case types.OCILayer, types.OCIRestrictedLayer, types.DockerLayer, types.DockerForeignLayer:
		var err error
		gz, err = gzip.NewReader(compressed)
		if err != nil {
			return nil, false, compressed.count, 0, err
		}
		defer gz.Close()
		decoded = gz
	case types.OCIUncompressedLayer, types.OCIUncompressedRestrictedLayer, types.DockerUncompressedLayer:
	default:
		return nil, false, 0, 0, errors.New("unsupported installed layer media type")
	}
	uncompressed := &countedReader{reader: io.TeeReader(decoded, uncompressedHash), ctx: ctx, limit: uncompressedLimit}
	archive := tar.NewReader(uncompressed)
	var database []byte
	removed := false
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, compressed.count, uncompressed.count, err
		}
		entry := strings.TrimPrefix(header.Name, "./")
		if (entry == "" || entry == "." || entry == "/") && header.Typeflag == tar.TypeDir {
			continue
		}
		if strings.HasPrefix(entry, "/") || path.Clean(entry) != strings.TrimSuffix(entry, "/") || entry == ".." || strings.HasPrefix(entry, "../") {
			return nil, false, compressed.count, uncompressed.count, errors.New("invalid installed layer path")
		}
		entry = strings.TrimSuffix(entry, "/")
		if whiteoutRemovesDatabase(entry) {
			removed = true
			continue
		}
		if entry == installedPath {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				return nil, false, compressed.count, uncompressed.count, errors.New("installed database is not a regular file")
			}
			if header.Size > wolfi.MaxInstalledDatabaseBytes {
				return nil, false, compressed.count, uncompressed.count, errors.New("installed database exceeds 8 MiB")
			}
			data, err := io.ReadAll(io.LimitReader(archive, wolfi.MaxInstalledDatabaseBytes+1))
			if err != nil || len(data) > wolfi.MaxInstalledDatabaseBytes {
				return nil, false, compressed.count, uncompressed.count, errors.New("installed database read failed")
			}
			database = append([]byte{}, data...)
		} else if strings.HasPrefix(installedPath, entry+"/") && header.Typeflag != tar.TypeDir {
			removed = true
			database = nil
		}
	}
	if _, err := io.Copy(io.Discard, uncompressed); err != nil {
		return nil, false, compressed.count, uncompressed.count, err
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return nil, false, compressed.count, uncompressed.count, err
	}
	if "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != digest || "sha256:"+hex.EncodeToString(uncompressedHash.Sum(nil)) != diffID {
		return nil, false, compressed.count, uncompressed.count, errors.New("installed layer digest or diffID mismatch")
	}
	return database, removed, compressed.count, uncompressed.count, nil
}

func whiteoutRemovesDatabase(entry string) bool {
	base, directory := path.Base(entry), path.Dir(entry)
	if base == ".wh..wh..opq" {
		return directory == "." || strings.HasPrefix(installedPath, directory+"/")
	}
	if !strings.HasPrefix(base, ".wh.") {
		return false
	}
	target := path.Join(directory, strings.TrimPrefix(base, ".wh."))
	return target == installedPath || strings.HasPrefix(installedPath, target+"/")
}

func validateInstalled(packages []wolfi.InstalledPackage, arch string) error {
	if len(packages) == 0 {
		return errors.New("installed APK identity set is empty")
	}
	seen := map[string]bool{}
	for _, pkg := range packages {
		if !wolfi.PackageNamePattern.MatchString(pkg.Name) || !validExactVersion(pkg.Version) || (pkg.Arch != arch && pkg.Arch != "noarch") {
			return errors.New("invalid installed APK identity")
		}
		key := pkg.Name + "\x00" + pkg.Arch
		if seen[key] {
			return errors.New("duplicate installed APK identity")
		}
		seen[key] = true
	}
	return nil
}

// The shared parser preserves historical build tolerance. Status needs a full
// identity set: reject records it would otherwise drop or silently overwrite.
func parseInstalledStrict(data []byte, arch string) ([]wolfi.InstalledPackage, error) {
	for _, record := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		if strings.TrimSpace(record) == "" {
			continue
		}
		fields := map[byte]bool{}
		for _, line := range strings.Split(record, "\n") {
			if len(line) < 2 || line[1] != ':' {
				return nil, errors.New("malformed installed APK record")
			}
			if line[0] == 'P' || line[0] == 'V' || line[0] == 'A' {
				if fields[line[0]] || len(line) < 3 {
					return nil, errors.New("duplicate or empty installed APK identity field")
				}
				fields[line[0]] = true
			}
		}
		if !fields['P'] || !fields['V'] || !fields['A'] {
			return nil, errors.New("incomplete installed APK identity record")
		}
	}
	packages := wolfi.ParseInstalledPackages(data)
	if err := validateInstalled(packages, arch); err != nil {
		return nil, err
	}
	return packages, nil
}
