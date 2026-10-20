package explorer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	digestReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-:\[\]]*/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$`)
	imageDigestPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	hexSHA256Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (c *CLI) document(ctx context.Context, args []string, kind string, version int, target any) error {
	stderr := newLogBuffer(maxErrorBytes)
	data, exit, err := c.execute(ctx, args, stderr)
	if err != nil {
		if errors.Is(err, errOutputLimit) {
			return err
		}
		return cliError(kind, exit, stderr)
	}
	var header struct {
		Kind    string `json:"kind"`
		Version int    `json:"version"`
	}
	if err := decodeDocument(data, &header); err != nil {
		return fmt.Errorf("incompatible lupetto CLI: %s JSON: %w", kind, err)
	}
	if header.Kind != kind || header.Version != version {
		return incompatible(kind, header.Kind, header.Version, version)
	}
	if err := decodeDocument(data, target); err != nil {
		return fmt.Errorf("incompatible lupetto CLI: %s JSON: %w", kind, err)
	}
	return nil
}
func (c *CLI) Images(ctx context.Context) (*ImagesDocument, error) {
	var d ImagesDocument
	if err := c.document(ctx, []string{"images", "--json"}, "images", 1, &d); err != nil {
		return nil, err
	}
	for _, b := range d.Builds {
		if b.Status == "supported" && (b.RecordVersion != 6 || b.Record == nil || b.Record.Version != 6 || (b.Record.Command != "build" && b.Record.Command != "sbom")) {
			return nil, errors.New("incompatible lupetto CLI: supported inventory record must be version 6 build or sbom")
		}
	}
	return &d, nil
}
func (c *CLI) Inspect(ctx context.Context, reference string) (*InspectDocument, error) {
	if len(reference) > 1024 || !digestReferencePattern.MatchString(reference) {
		return nil, errors.New("inspect requires an explicit registry sha256 digest reference")
	}
	var d InspectDocument
	if err := c.document(ctx, []string{"inspect", "--json", reference}, "inspect", 1, &d); err != nil {
		return nil, err
	}
	if d.Reference != reference || d.Digest != reference[len(reference)-71:] {
		return nil, errors.New("incompatible lupetto CLI: inspect reference or digest mismatch")
	}
	return &d, nil
}
func (c *CLI) Products(ctx context.Context, products, action, name string, selectors []string) (*ProductsDocument, error) {
	if action != "list" && action != "add" && action != "remove" {
		return nil, errors.New("invalid products action")
	}
	args := []string{"products", action}
	if action != "list" {
		if !validPackage(name) {
			return nil, errors.New("invalid package name")
		}
		if action == "add" && len(selectors) == 0 {
			return nil, errors.New("provide at least one numeric selector")
		}
		args = append(args, name)
		for _, selector := range selectors {
			if len(selector) > 128 || !selectorPattern.MatchString(selector) {
				return nil, errors.New("invalid selector: expected dotted numeric components")
			}
			args = append(args, selector)
		}
	}
	args = append(args, "--products", products, "--json")
	var d ProductsDocument
	if err := c.document(ctx, args, "products", 1, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Verify runs `lupetto verify --json [--cosign-allow-http] [--sbom-out <new
// file>] <reference>`. Trust reaches the CLI only through the inherited
// LUPETTO_COSIGN_PUBLIC_KEY or LUPETTO_COSIGN_CERTIFICATE_* environment
// variables, never as an argument.
// allowHTTP adds the local-only flag, and only for a literal loopback registry.
func (c *CLI) Verify(ctx context.Context, reference, sbomOut string, allowHTTP bool) (*VerifyDocument, error) {
	if len(reference) > 1024 || !digestReferencePattern.MatchString(reference) {
		return nil, errors.New("verify requires an explicit registry sha256 digest reference")
	}
	args := []string{"verify", "--json"}
	if allowHTTP && loopbackReference(reference) {
		args = append(args, "--cosign-allow-http")
	}
	if sbomOut != "" {
		if !filepath.IsAbs(sbomOut) {
			return nil, errors.New("verify --sbom-out requires an absolute path")
		}
		args = append(args, "--sbom-out", sbomOut)
	}
	args = append(args, reference)
	var d VerifyDocument
	if err := c.document(ctx, args, "verify", 1, &d); err != nil {
		return nil, err
	}
	if d.Reference != reference || d.Digest != reference[len(reference)-71:] {
		return nil, errors.New("incompatible lupetto CLI: verify reference or digest mismatch")
	}
	switch d.Signature.State {
	case "signed", "unsigned", "invalid", "error":
	default:
		return nil, fmt.Errorf("incompatible lupetto CLI: unknown verify signature state %q", d.Signature.State)
	}
	switch d.Attestation.State {
	case "attested", "absent", "invalid", "error":
	default:
		return nil, fmt.Errorf("incompatible lupetto CLI: unknown verify attestation state %q", d.Attestation.State)
	}
	if d.TransparencyLog != "verified" && d.TransparencyLog != "skipped-local" {
		return nil, fmt.Errorf("incompatible lupetto CLI: unknown verify transparencyLog %q", d.TransparencyLog)
	}
	if d.Attestation.State == "attested" {
		if d.Attestation.SBOM == nil || !hexSHA256Pattern.MatchString(d.Attestation.SBOM.SHA256) {
			return nil, errors.New("incompatible lupetto CLI: attested verify result without an SBOM SHA-256")
		}
		if sbomOut != "" && filepath.Clean(d.Attestation.SBOM.Path) != filepath.Clean(sbomOut) {
			return nil, errors.New("incompatible lupetto CLI: verify did not report writing the requested --sbom-out file")
		}
	}
	return &d, nil
}

// loopbackReference reports whether the reference's registry authority is a
// literal localhost or loopback IP, the only scope of the CLI's HTTP exception.
func loopbackReference(reference string) bool {
	authority, _, _ := strings.Cut(reference, "/")
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
