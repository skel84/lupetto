package status

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"lupetto/internal/wolfi"
)

const MaxCacheBytes = 16 << 20

type InstalledCache interface {
	Load(context.Context, string) ([]wolfi.InstalledPackage, bool, error)
	Store(context.Context, string, []wolfi.InstalledPackage) error
}

type FileCache struct{ Directory string }

type cachedInstalled struct {
	Version  int                      `json:"version"`
	Digest   string                   `json:"digest"`
	SHA256   string                   `json:"sha256"`
	Packages []wolfi.InstalledPackage `json:"packages"`
}

func NewFileCache(directory string) (*FileCache, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("installed cache directory unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("installed cache directory must be private")
	}
	return &FileCache{Directory: directory}, nil
}

func defaultCache() (*FileCache, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return nil, errors.New("user cache directory unavailable")
	}
	return NewFileCache(filepath.Join(root, "lupetto", "status", "installed"))
}

func (cache *FileCache) file(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", errors.New("invalid installed cache digest")
	}
	return filepath.Join(cache.Directory, digest[len("sha256:"):]+".json"), nil
}

func (cache *FileCache) Load(ctx context.Context, digest string) ([]wolfi.InstalledPackage, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	path, err := cache.file(digest)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, false, errors.New("installed cache file is not private and regular")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, errors.New("installed cache read failed")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxCacheBytes+1))
	if err != nil || len(data) > MaxCacheBytes {
		return nil, false, errors.New("installed cache size or read failure")
	}
	var record cachedInstalled
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || record.Digest != digest {
		return nil, false, errors.New("invalid installed cache record")
	}
	packagesData, err := json.Marshal(record.Packages)
	if err != nil || wolfi.SHA256Hex(packagesData) != record.SHA256 {
		return nil, false, errors.New("installed cache checksum mismatch")
	}
	return record.Packages, true, nil
}

func (cache *FileCache) Store(ctx context.Context, digest string, packages []wolfi.InstalledPackage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := cache.file(digest)
	if err != nil {
		return err
	}
	packagesData, err := json.Marshal(packages)
	if err != nil {
		return errors.New("installed cache encoding failed")
	}
	data, err := json.Marshal(cachedInstalled{Version: 1, Digest: digest, SHA256: wolfi.SHA256Hex(packagesData), Packages: packages})
	if err != nil || len(data) > MaxCacheBytes {
		return errors.New("installed cache encoding or size failure")
	}
	file, err := os.CreateTemp(cache.Directory, ".installed-*")
	if err != nil {
		return errors.New("installed cache write failed")
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return errors.New("installed cache write failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("installed cache close failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return errors.New("installed cache replacement failed")
	}
	return nil
}
