package main

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
	"strconv"
	"strings"
	"time"
)

// These are the trust and package-family inputs for the first local image workflow.
// Versions are discovered from APKINDEX, never listed here.
const (
	wolfiRepository = "https://packages.wolfi.dev/os"
	wolfiKeyURL     = wolfiRepository + "/wolfi-signing.rsa.pub"
	wolfiKeySHA256  = "f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc"
	postgresAPK     = "postgresql-17"
)

var (
	pgSelector = regexp.MustCompile(`^17(?:\.[0-9]+)?$`)
	pgVersion  = regexp.MustCompile(`^17\.([0-9]+)-r([0-9]+)$`)
)

type indexedPackage struct {
	name, version, arch, checksum string
}

func targetArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported host architecture %q for Wolfi image build", runtime.GOARCH)
	}
}

func getPublicFile(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
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

// Wolfi signs the second gzip member (the index tarball) with a signature
// stored in the first gzip member. Match apko's APKINDEX verification framing
// before treating an index as a source for "latest" or "unavailable" claims.
func verifyAPKINDEX(compressed, publicKey []byte) ([]byte, error) {
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

func parseAPKINDEX(compressed []byte) ([]indexedPackage, error) {
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
		var packages []indexedPackage
		var current indexedPackage
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				if current.name == postgresAPK && current.version != "" && current.arch != "" && current.checksum != "" {
					packages = append(packages, current)
				}
				current = indexedPackage{}
				continue
			}
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				current.name = line[2:]
			case 'V':
				current.version = line[2:]
			case 'A':
				current.arch = line[2:]
			case 'C':
				current.checksum = line[2:]
			}
		}
		if current.name == postgresAPK && current.version != "" && current.arch != "" && current.checksum != "" {
			packages = append(packages, current)
		}
		return packages, nil
	}
}

func selectPostgres(packages []indexedPackage, request buildRequest, arch string) (indexedPackage, error) {
	var best indexedPackage
	var bestMinor, bestRevision uint64
	for _, pkg := range packages {
		if pkg.name != postgresAPK || pkg.arch != arch {
			continue
		}
		if request.version != "" {
			if pkg.version == request.version {
				if best.version != "" && best.checksum != pkg.checksum {
					return indexedPackage{}, fmt.Errorf("ambiguous APKINDEX entries for %s@%s", pkg.name, pkg.version)
				}
				best = pkg
			}
			continue
		}
		match := pgVersion.FindStringSubmatch(pkg.version)
		if match == nil {
			continue
		}
		if request.selector != "17" && "17."+match[1] != request.selector {
			continue
		}
		minor, minorErr := strconv.ParseUint(match[1], 10, 64)
		revision, revisionErr := strconv.ParseUint(match[2], 10, 64)
		if minorErr != nil || revisionErr != nil {
			return indexedPackage{}, fmt.Errorf("unsupported PostgreSQL APK version %q", pkg.version)
		}
		if best.version == "" || minor > bestMinor || (minor == bestMinor && revision > bestRevision) {
			best, bestMinor, bestRevision = pkg, minor, revision
		} else if minor == bestMinor && revision == bestRevision && best.checksum != pkg.checksum {
			return indexedPackage{}, fmt.Errorf("ambiguous APKINDEX entries for %s@%s", pkg.name, pkg.version)
		}
	}
	if best.version == "" {
		selector := request.selector
		if request.version != "" {
			selector = request.version
		}
		return indexedPackage{}, fmt.Errorf("unavailable version: postgresql %s for %s in current Wolfi APKINDEX", selector, arch)
	}
	return best, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
