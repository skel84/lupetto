// Package storage resolves where Lupetto keeps build workspaces. It imports no
// other module package, so the build pipeline (the only writer) and the images
// history (a reader) share one rule. Explorer keeps its own copy because it
// must not import CLI packages; both read the same inherited environment.
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DataDirEnv overrides the durable data base directory. It must be absolute.
const DataDirEnv = "LUPETTO_DATA_DIR"

// BuildsDir returns the builds root below a base directory:
// <base>/lupetto/builds.
func BuildsDir(base string) string {
	return filepath.Join(base, "lupetto", "builds")
}

// DataDir returns the durable data base directory from the process
// environment. New build workspaces are created under BuildsDir(DataDir()).
func DataDir() (string, error) {
	return dataDir(runtime.GOOS, os.Getenv)
}

// dataDir is DataDir with an injectable platform and environment:
// LUPETTO_DATA_DIR when non-empty (must be absolute); otherwise macOS
// $HOME/Library/Application Support, Windows %LocalAppData%, and other
// systems $XDG_DATA_HOME when absolute, else $HOME/.local/share. A relative
// result is rejected so retained records never contain relative paths.
func dataDir(goos string, getenv func(string) string) (string, error) {
	if dir := getenv(DataDirEnv); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("invalid configuration: %s must be an absolute path, got %q", DataDirEnv, dir)
		}
		return filepath.Clean(dir), nil
	}
	var dir string
	switch goos {
	case "windows":
		dir = getenv("LocalAppData")
		if dir == "" {
			return "", errors.New("%LocalAppData% is not defined; set " + DataDirEnv)
		}
	case "darwin", "ios":
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("$HOME is not defined; set " + DataDirEnv)
		}
		dir = filepath.Join(home, "Library", "Application Support")
	default:
		if xdg := getenv("XDG_DATA_HOME"); filepath.IsAbs(xdg) {
			return filepath.Clean(xdg), nil
		}
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("neither an absolute $XDG_DATA_HOME nor $HOME is defined; set " + DataDirEnv)
		}
		dir = filepath.Join(home, ".local", "share")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("user data directory %q is not absolute; set %s", dir, DataDirEnv)
	}
	return filepath.Clean(dir), nil
}

// LegacyBuildsDir returns the pre-2026-10-02 builds root below the OS user
// cache. It is only read, never written.
func LegacyBuildsDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return BuildsDir(cache), nil
}

// HistoryRoots returns the builds roots that hold retained records, durable
// data root first. An invalid data configuration is an error. The legacy
// cache root is omitted when the user cache cannot be resolved (no builds can
// be read from it) or when it is lexically the same directory as the data
// root.
func HistoryRoots() ([]string, error) {
	data, err := DataDir()
	if err != nil {
		return nil, err
	}
	roots := []string{BuildsDir(data)}
	if legacy, err := LegacyBuildsDir(); err == nil && legacy != roots[0] {
		roots = append(roots, legacy)
	}
	return roots, nil
}
