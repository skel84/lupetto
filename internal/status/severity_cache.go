package status

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type severityCache struct{ directory string }

type cachedSeverity struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	FetchedAt time.Time `json:"fetchedAt"`
	SeverityResult
}

func (cache severityCache) privateDirectory() bool {
	if cache.directory == "" || os.MkdirAll(cache.directory, 0700) != nil {
		return false
	}
	info, err := os.Lstat(cache.directory)
	return err == nil && info.IsDir() && info.Mode().Perm() == 0700
}

func (cache severityCache) file(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(cache.directory, hex.EncodeToString(sum[:])+".json")
}

func validCachedSeverity(result SeverityResult) bool {
	if result.Severity == "unknown" {
		return result.SeveritySource == "none"
	}
	if !knownSeverity(result) || result.Severity != normalizeSeverity(result.Severity) {
		return false
	}
	switch result.SeveritySource {
	case "nvd-cvss-v4.0", "nvd-cvss-v3.1", "nvd-cvss-v3.0", "nvd-cvss-v2", "osv", "ghsa":
		return true
	default:
		alias := strings.TrimPrefix(result.SeveritySource, "osv-alias:")
		if alias != result.SeveritySource {
			return severityIDPattern.MatchString(alias) && (strings.HasPrefix(alias, "CVE-") || strings.HasPrefix(alias, "GHSA-"))
		}
		alias = strings.TrimPrefix(result.SeveritySource, "ghsa-alias:")
		return alias != result.SeveritySource && strings.HasPrefix(alias, "CVE-") && severityIDPattern.MatchString(alias)
	}
}

func validCachedSeverityID(id string, result SeverityResult) bool {
	if !validCachedSeverity(result) {
		return false
	}
	// Previously cached direct Go severities are not valid for alias-only Go
	// enrichment. Legacy grouped \"alias:\" sources are rejected above.
	return !strings.HasPrefix(id, "GO-") || result.Severity == "unknown" || strings.HasPrefix(result.SeveritySource, "osv-alias:")
}

func (cache severityCache) load(id string, now time.Time) (SeverityResult, bool) {
	if !severityIDPattern.MatchString(id) || !cache.privateDirectory() {
		return SeverityResult{}, false
	}
	path := cache.file(id)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return SeverityResult{}, false
	}
	file, err := os.Open(path)
	if err != nil {
		return SeverityResult{}, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return SeverityResult{}, false
	}
	var record cachedSeverity
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || record.ID != id || !validCachedSeverityID(id, record.SeverityResult) {
		return SeverityResult{}, false
	}
	ttl := 7 * 24 * time.Hour
	if record.Severity == "unknown" {
		ttl = time.Hour
	}
	age := now.Sub(record.FetchedAt)
	if record.FetchedAt.IsZero() || age < 0 || age >= ttl {
		return SeverityResult{}, false
	}
	return record.SeverityResult, true
}

func (cache severityCache) store(id string, result SeverityResult, fetchedAt time.Time) {
	if !severityIDPattern.MatchString(id) || !validCachedSeverityID(id, result) || !cache.privateDirectory() {
		return
	}
	data, err := json.Marshal(cachedSeverity{Version: 1, ID: id, FetchedAt: fetchedAt.UTC(), SeverityResult: result})
	if err != nil {
		return
	}
	file, err := os.CreateTemp(cache.directory, ".severity-*")
	if err != nil {
		return
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return
	}
	if file.Sync() != nil {
		file.Close()
		return
	}
	if file.Close() != nil {
		return
	}
	// Atomic replacement cannot follow an existing advisory-file symlink.
	_ = os.Rename(file.Name(), cache.file(id))
}
