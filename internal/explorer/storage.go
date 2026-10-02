package explorer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Explorer must not import CLI packages, so this is its own copy of the CLI's
// internal/storage rule; both read the same inherited environment. The
// durable data builds root comes first, then the legacy user-cache root that
// older CLI builds wrote to (read-only).
func buildsRoots() ([]string, error) {
	data, err := dataDir(runtime.GOOS, os.Getenv)
	if err != nil {
		return nil, err
	}
	roots := []string{filepath.Join(data, "lupetto", "builds")}
	if cache, err := os.UserCacheDir(); err == nil {
		if legacy := filepath.Join(cache, "lupetto", "builds"); legacy != roots[0] {
			roots = append(roots, legacy)
		}
	}
	return roots, nil
}

// dataDir: LUPETTO_DATA_DIR when non-empty (must be absolute); otherwise macOS
// $HOME/Library/Application Support, Windows %LocalAppData%, and other systems
// $XDG_DATA_HOME when absolute, else $HOME/.local/share.
func dataDir(goos string, getenv func(string) string) (string, error) {
	if dir := getenv("LUPETTO_DATA_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("invalid configuration: LUPETTO_DATA_DIR must be an absolute path, got %q", dir)
		}
		return filepath.Clean(dir), nil
	}
	var dir string
	switch goos {
	case "windows":
		dir = getenv("LocalAppData")
		if dir == "" {
			return "", errors.New("%LocalAppData% is not defined; set LUPETTO_DATA_DIR")
		}
	case "darwin", "ios":
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("$HOME is not defined; set LUPETTO_DATA_DIR")
		}
		dir = filepath.Join(home, "Library", "Application Support")
	default:
		if xdg := getenv("XDG_DATA_HOME"); filepath.IsAbs(xdg) {
			return filepath.Clean(xdg), nil
		}
		home := getenv("HOME")
		if home == "" {
			return "", errors.New("neither an absolute $XDG_DATA_HOME nor $HOME is defined; set LUPETTO_DATA_DIR")
		}
		dir = filepath.Join(home, ".local", "share")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("user data directory %q is not absolute; set LUPETTO_DATA_DIR", dir)
	}
	return filepath.Clean(dir), nil
}
