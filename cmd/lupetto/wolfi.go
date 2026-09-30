package main

import (
	apkcompare "chainguard.dev/apko/pkg/apk/apk"

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
)

// Trust inputs for the public Wolfi repository. Package names and versions
// are resolved from the signed index, not from a source-level allowlist.
const (
	wolfiRepository = "https://packages.wolfi.dev/os"
	wolfiKeyURL     = wolfiRepository + "/wolfi-signing.rsa.pub"
	wolfiKeySHA256  = "f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc"
)

var upstreamNumbers = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)`)

type indexedPackage struct {
	name, version, arch, checksum, provides string
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

func getWolfiSigningKey(ctx context.Context) ([]byte, error) {
	key, err := getPublicFile(ctx, wolfiKeyURL, 16<<10)
	if err != nil {
		return nil, err
	}
	if sha256Hex(key) != wolfiKeySHA256 {
		return nil, fmt.Errorf("Wolfi signing key fingerprint changed; refusing to use untrusted key")
	}
	return key, nil
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

func parseAPKINDEX(compressed []byte, requested string) ([]indexedPackage, error) {
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
				if matchesRequestedPackage(current, requested) && current.version != "" && current.arch != "" && current.checksum != "" {
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
			case 'p':
				current.provides = line[2:]
			}
		}
		if matchesRequestedPackage(current, requested) && current.version != "" && current.arch != "" && current.checksum != "" {
			packages = append(packages, current)
		}
		return packages, nil
	}
}

// A provided name is usable only when it advertises the APK's own exact
// version. This keeps selection tied to the package that apko will lock.
func matchesRequestedPackage(pkg indexedPackage, requested string) bool {
	if pkg.name == requested {
		return true
	}
	for _, provided := range strings.Fields(pkg.provides) {
		if provided == requested+"="+pkg.version {
			return true
		}
	}
	return false
}

func selectPackage(packages []indexedPackage, request buildRequest, arch string) (indexedPackage, error) {
	var best indexedPackage
	var bestVersion apkcompare.Version
	ambiguous := false
	for _, pkg := range packages {
		if pkg.arch != arch || !matchesRequestedPackage(pkg, request.packageName) {
			continue
		}
		if !packageName.MatchString(pkg.name) {
			return indexedPackage{}, fmt.Errorf("invalid APKINDEX package name %q", pkg.name)
		}
		if request.version != "" {
			if pkg.version != request.version {
				continue
			}
			if best.version != "" && (best.name != pkg.name || best.checksum != pkg.checksum) {
				return indexedPackage{}, fmt.Errorf("ambiguous package providers for %s@%s", request.packageName, pkg.version)
			}
			best = pkg
			continue
		}
		upstream := upstreamNumbers.FindString(pkg.version)
		if upstream != request.selector && !strings.HasPrefix(upstream, request.selector+".") {
			continue
		}
		parsed, err := apkcompare.ParseVersion(pkg.version)
		if err != nil {
			return indexedPackage{}, fmt.Errorf("cannot order APK version %q for %s: %w", pkg.version, pkg.name, err)
		}
		if best.version == "" {
			best, bestVersion = pkg, parsed
			continue
		}
		comparison := apkcompare.CompareVersions(parsed, bestVersion)
		if comparison > 0 {
			best, bestVersion = pkg, parsed
			ambiguous = false
		} else if comparison == 0 && (best.name != pkg.name || best.version != pkg.version || best.checksum != pkg.checksum) {
			ambiguous = true
		}
	}
	if best.version == "" {
		selector := request.selector
		if request.version != "" {
			selector = request.version
		}
		return indexedPackage{}, fmt.Errorf("unavailable version: %s %s for %s in current Wolfi APKINDEX", request.packageName, selector, arch)
	}
	if ambiguous {
		return indexedPackage{}, fmt.Errorf("ambiguous package providers for %s at %s", request.packageName, best.version)
	}
	return best, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
