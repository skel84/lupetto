// Package wolfi resolves exact APKs from the signed public Wolfi APKINDEX:
// trust inputs, public file and key fetch, signature verification, index
// parsing, exact selection, and discovery ordering. It knows nothing about
// builds or the CLI.
package wolfi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"

	apkcompare "chainguard.dev/apko/pkg/apk/apk"
)

// PackageNamePattern matches a literal APK name; RequestedNamePattern also
// allows namespaced provider names such as cmd:curl.
var (
	PackageNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	RequestedNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$`)
)

// Trust inputs for the public Wolfi repository. Package names and versions
// are resolved from the signed index, not from a source-level allowlist.
const (
	Repository     = "https://packages.wolfi.dev/os"
	wolfiKeyURL    = Repository + "/wolfi-signing.rsa.pub"
	wolfiKeySHA256 = "f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc"
)

var upstreamNumbers = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)`)

// Package is one APKINDEX entry.
type Package struct {
	Name, Version, Arch, Checksum, Provides, Description string
}

// TargetArch returns the Wolfi architecture of the host.
func TargetArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported host architecture %q for Wolfi image build", runtime.GOARCH)
	}
}

// ParseArch maps an explicit --arch value, in Wolfi or OCI spelling, to the
// Wolfi architecture. Callers keep an empty value meaning the host.
func ParseArch(value string) (string, error) {
	switch value {
	case "x86_64", "amd64":
		return "x86_64", nil
	case "aarch64", "arm64":
		return "aarch64", nil
	}
	return "", fmt.Errorf("--arch must be x86_64 (amd64) or aarch64 (arm64)")
}

// GetPublicFile fetches a public URL, refusing bodies over maxBytes.
func GetPublicFile(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", url, maxBytes)
	}
	return data, nil
}

// GetSigningKey fetches the Wolfi signing key and checks its pinned
// fingerprint.
func GetSigningKey(ctx context.Context) ([]byte, error) {
	key, err := GetPublicFile(ctx, wolfiKeyURL, 16<<10)
	if err != nil {
		return nil, err
	}
	if SHA256Hex(key) != wolfiKeySHA256 {
		return nil, fmt.Errorf("Wolfi signing key fingerprint changed; refusing to use untrusted key")
	}
	return key, nil
}

// Wolfi signs the second gzip member (the index tarball) with a signature
// stored in the first gzip member. Match apko's APKINDEX verification framing
// before treating an index as a source for "latest" or "unavailable" claims.
func VerifyAPKINDEX(compressed, publicKey []byte) ([]byte, error) {
	input := bytes.NewReader(compressed)
	gz, err := gzip.NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("open signed APKINDEX: %w", err)
	}
	defer gz.Close()
	gz.Multistream(false)
	archive := tar.NewReader(gz)
	var signature []byte
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read APKINDEX signature: %w", err)
		}
		if header.Name != ".SIGN.RSA256.wolfi-signing.rsa.pub" || signature != nil || header.Size > 4096 {
			return nil, fmt.Errorf("unexpected or missing Wolfi APKINDEX signature")
		}
		signature, err = io.ReadAll(archive)
		if err != nil {
			return nil, fmt.Errorf("read Wolfi APKINDEX signature bytes: %w", err)
		}
	}
	if len(signature) == 0 || input.Len() == 0 {
		return nil, fmt.Errorf("Wolfi APKINDEX signature or signed data is missing")
	}
	pemBlock, _ := pem.Decode(publicKey)
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid Wolfi public key PEM")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Wolfi public key: %w", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Wolfi signing key is not RSA")
	}
	// bytes.Reader implements io.ByteReader, so gzip does not read ahead into
	// the next gzip member; input.Len() identifies the exact signed suffix.
	indexMember := compressed[len(compressed)-input.Len():]
	digest := sha256.Sum256(indexMember)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("Wolfi APKINDEX signature verification failed: %w", err)
	}
	return indexMember, nil
}

// ParseAPKINDEX returns the complete entries that match requested by name or
// by a provider of the entry's own exact version. An empty request returns all
// complete named entries, retaining every version for index comparisons.
func ParseAPKINDEX(compressed []byte, requested string) ([]Package, error) {
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open APKINDEX gzip: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("APKINDEX member not found")
		}
		if err != nil {
			return nil, fmt.Errorf("read APKINDEX tar: %w", err)
		}
		if header.Name != "APKINDEX" {
			continue
		}
		if header.Size > 96<<20 {
			return nil, fmt.Errorf("APKINDEX member exceeds 96 MiB")
		}
		data, err := io.ReadAll(io.LimitReader(archive, (96<<20)+1))
		if err != nil {
			return nil, fmt.Errorf("read APKINDEX member: %w", err)
		}
		if len(data) > 96<<20 {
			return nil, fmt.Errorf("APKINDEX member exceeds 96 MiB")
		}
		var packages []Package
		var current Package
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				if (requested == "" && current.Name != "" || requested != "" && matchesRequestedPackage(current, requested)) && current.Version != "" && current.Arch != "" && current.Checksum != "" {
					packages = append(packages, current)
				}
				current = Package{}
				continue
			}
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				current.Name = line[2:]
			case 'V':
				current.Version = line[2:]
			case 'A':
				current.Arch = line[2:]
			case 'C':
				current.Checksum = line[2:]
			case 'p':
				current.Provides = line[2:]
			case 'T':
				current.Description = line[2:]
			}
		}
		if (requested == "" && current.Name != "" || requested != "" && matchesRequestedPackage(current, requested)) && current.Version != "" && current.Arch != "" && current.Checksum != "" {
			packages = append(packages, current)
		}
		return packages, nil
	}
}

// A provided name is usable only when it advertises the APK's own exact
// version. This keeps selection tied to the package that apko will lock.
func matchesRequestedPackage(pkg Package, requested string) bool {
	if pkg.Name == requested {
		return true
	}
	for _, provided := range strings.Fields(pkg.Provides) {
		if provided == requested+"="+pkg.Version {
			return true
		}
	}
	return false
}

// SelectPackage resolves requested (an APK name or version-matched provider)
// to one exact APK: the exact version when given, otherwise the highest APK
// version whose upstream numbers match the dotted numeric selector.
func SelectPackage(packages []Package, requested, selector, version, arch string) (Package, error) {
	var best Package
	var bestVersion apkcompare.Version
	ambiguous := false
	for _, pkg := range packages {
		if pkg.Arch != arch || !matchesRequestedPackage(pkg, requested) {
			continue
		}
		if !PackageNamePattern.MatchString(pkg.Name) {
			return Package{}, fmt.Errorf("invalid APKINDEX package name %q", pkg.Name)
		}
		if version != "" {
			if pkg.Version != version {
				continue
			}
			if best.Version != "" && (best.Name != pkg.Name || best.Checksum != pkg.Checksum) {
				return Package{}, fmt.Errorf("ambiguous package providers for %s@%s", requested, pkg.Version)
			}
			best = pkg
			continue
		}
		upstream := upstreamNumbers.FindString(pkg.Version)
		if upstream != selector && !strings.HasPrefix(upstream, selector+".") {
			continue
		}
		parsed, err := apkcompare.ParseVersion(pkg.Version)
		if err != nil {
			return Package{}, fmt.Errorf("cannot order APK version %q for %s: %w", pkg.Version, pkg.Name, err)
		}
		if best.Version == "" {
			best, bestVersion = pkg, parsed
			continue
		}
		comparison := apkcompare.CompareVersions(parsed, bestVersion)
		if comparison > 0 {
			best, bestVersion = pkg, parsed
			ambiguous = false
		} else if comparison == 0 && (best.Name != pkg.Name || best.Version != pkg.Version || best.Checksum != pkg.Checksum) {
			ambiguous = true
		}
	}
	if best.Version == "" {
		if version != "" {
			selector = version
		}
		return Package{}, fmt.Errorf("unavailable version: %s %s for %s in current Wolfi APKINDEX", requested, selector, arch)
	}
	if ambiguous {
		return Package{}, fmt.Errorf("ambiguous package providers for %s at %s", requested, best.Version)
	}
	return best, nil
}

// SHA256Hex returns the lower-case hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
