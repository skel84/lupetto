package build

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"lupetto/internal/wolfi"
)

type apkIdentity struct {
	name, version, arch string
}

// validateSPDX checks the complete APK identity set, not apko's non-APK
// image, operating-system, or build-recipe entries. The latter are retained
// but are not evidence of additional installed APKs.
func validateSPDX(lockPath, spdxPath, arch string) (string, error) {
	lockBytes, err := readEvidenceFile(lockPath, 16<<20)
	if err != nil {
		return "", fmt.Errorf("read apko lock: %w", err)
	}
	var lock struct {
		Contents struct {
			Packages []struct{ Name, Version, Architecture string } `json:"packages"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		return "", fmt.Errorf("decode apko lock: %w", err)
	}
	if len(lock.Contents.Packages) == 0 {
		return "", fmt.Errorf("apko lock contains no APK packages")
	}
	want := make(map[apkIdentity]bool, len(lock.Contents.Packages))
	for _, pkg := range lock.Contents.Packages {
		id := apkIdentity{pkg.Name, pkg.Version, pkg.Architecture}
		if !wolfi.PackageNamePattern.MatchString(id.name) || id.version == "" || id.arch != arch || want[id] {
			return "", fmt.Errorf("invalid, duplicate, or wrong-architecture apko lock APK %q@%q (%q)", id.name, id.version, id.arch)
		}
		want[id] = true
	}

	data, err := readEvidenceFile(spdxPath, 32<<20)
	if err != nil {
		return "", fmt.Errorf("read SPDX document: %w", err)
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
		Packages    []struct {
			SPDXID       string `json:"SPDXID"`
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType, ReferenceLocator string
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("decode SPDX document: %w", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.SPDXID != "SPDXRef-DOCUMENT" || len(doc.Packages) == 0 {
		return "", fmt.Errorf("unexpected or empty SPDX document")
	}
	seenIDs := map[string]bool{}
	seen := map[string]map[apkIdentity]bool{"distro": {}, "origin": {}}
	for _, pkg := range doc.Packages {
		if pkg.SPDXID == "" || seenIDs[pkg.SPDXID] {
			return "", fmt.Errorf("missing or duplicate SPDX package ID %q", pkg.SPDXID)
		}
		seenIDs[pkg.SPDXID] = true
		isAPK := strings.HasPrefix(pkg.SPDXID, "SPDXRef-Package-apk-")
		var apkRef string
		for _, ref := range pkg.ExternalRefs {
			if !strings.HasPrefix(ref.ReferenceLocator, "pkg:apk/") {
				continue
			}
			isAPK = true
			if ref.ReferenceType != "purl" || apkRef != "" {
				return "", fmt.Errorf("ambiguous APK references for SPDX package %q", pkg.SPDXID)
			}
			apkRef = ref.ReferenceLocator
		}
		if !isAPK {
			continue
		}
		id, kind, err := parseAPKRef(apkRef, arch)
		if err != nil || id.name != pkg.Name || id.version != pkg.VersionInfo {
			return "", fmt.Errorf("invalid SPDX APK %q@%q reference: %v", pkg.Name, pkg.VersionInfo, err)
		}
		if seen[kind][id] || !want[id] {
			return "", fmt.Errorf("extra or duplicate SPDX APK %s@%s (%s, %s)", id.name, id.version, id.arch, kind)
		}
		seen[kind][id] = true
	}
	// apko copies every APK entry from the SBOM each package ships. Each
	// locked APK must appear exactly once as a distro entry. Only newer
	// package SBOMs add an origin entry, so origin entries are optional per
	// package; any that appear must still name a locked APK, once (above).
	for id := range want {
		if !seen["distro"][id] {
			return "", fmt.Errorf("SPDX missing locked APK %s@%s (%s)", id.name, id.version, id.arch)
		}
	}
	return wolfi.SHA256Hex(data), nil
}

func parseAPKRef(ref, arch string) (apkIdentity, string, error) {
	body, ok := strings.CutPrefix(ref, "pkg:apk/")
	if !ok {
		return apkIdentity{}, "", fmt.Errorf("not a Wolfi APK purl")
	}
	rawNamespace, body, found := strings.Cut(body, "/")
	namespace, err := url.PathUnescape(rawNamespace)
	if !found || err != nil || namespace != "wolfi" {
		return apkIdentity{}, "", fmt.Errorf("not a Wolfi APK purl")
	}
	path, query, ok := strings.Cut(body, "?")
	rawName, rawVersion, found := strings.Cut(path, "@")
	name, nameErr := url.PathUnescape(rawName)
	version, versionErr := url.PathUnescape(rawVersion)
	if !ok || !found || nameErr != nil || versionErr != nil || !wolfi.PackageNamePattern.MatchString(name) || version == "" || strings.ContainsAny(version, "/@#?") {
		return apkIdentity{}, "", fmt.Errorf("malformed Wolfi APK purl")
	}
	if strings.Contains(query, ";") {
		return apkIdentity{}, "", fmt.Errorf("malformed APK purl qualifiers: %q", ref)
	}
	// Purl percent-encoding is not HTML form encoding: a literal '+' must
	// remain '+', including in qualifier values. Split before decoding so
	// encoded delimiters cannot change the component boundaries.
	values := url.Values{}
	for _, qualifier := range strings.Split(query, "&") {
		key, rawValue, found := strings.Cut(qualifier, "=")
		value, err := url.PathUnescape(rawValue)
		if !found || err != nil {
			return apkIdentity{}, "", fmt.Errorf("malformed APK purl qualifiers: %q", ref)
		}
		values[key] = append(values[key], value)
	}
	if len(values) != 2 || len(values["arch"]) != 1 || values.Get("arch") != arch {
		return apkIdentity{}, "", fmt.Errorf("APK purl architecture mismatch: %q (target %s)", ref, arch)
	}
	kind := "distro"
	switch {
	case len(values["distro"]) == 1 && values.Get("distro") == "wolfi":
	case len(values["origin"]) == 1 && values.Get("origin") != "":
		kind = "origin"
	default:
		return apkIdentity{}, "", fmt.Errorf("unsupported APK purl qualifiers: %q", ref)
	}
	return apkIdentity{name, version, arch}, kind, nil
}

func readEvidenceFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
