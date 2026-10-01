package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// MaxMetadataBytes bounds registry manifests and configuration metadata.
const MaxMetadataBytes = 4 << 20

// Only safe, stage-specific text enters this type. Registry bodies, URLs,
// subprocess output, argument strings, and credential-helper diagnostics are
// never wrapped; detail is a fixed classification chosen by Lupetto.
type StageError struct {
	stage, detail string
	cause         error
}

func (e *StageError) Error() string {
	if e.cause != nil {
		return e.stage + " canceled: " + e.cause.Error()
	}
	if e.detail != "" {
		return e.stage + " failed (" + e.detail + ")"
	}
	return e.stage + " failed"
}

func (e *StageError) Unwrap() error { return e.cause }

func StageCancellation(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func SafeStageError(ctx context.Context, stage string, err error) error {
	return &StageError{stage: stage, cause: StageCancellation(ctx, err)}
}

var (
	ErrPlainHTTPRefused = errors.New("plain HTTP refused for non-loopback registry")
	ErrSchemeRefused    = errors.New("unsupported registry URL scheme")
	ErrContentMismatch  = errors.New("registry content mismatch")
	ErrUnsupportedLayer = errors.New("unsupported layer compression")
	// Registry-supplied codes are arbitrary strings; only these known OCI
	// distribution error constants are ever reported.
	knownRegistryCodes = map[transport.ErrorCode]bool{
		transport.BlobUnknownErrorCode: true, transport.BlobUploadInvalidErrorCode: true,
		transport.BlobUploadUnknownErrorCode: true, transport.DigestInvalidErrorCode: true,
		transport.ManifestBlobUnknownErrorCode: true, transport.ManifestInvalidErrorCode: true,
		transport.ManifestUnknownErrorCode: true, transport.ManifestUnverifiedErrorCode: true,
		transport.NameInvalidErrorCode: true, transport.NameUnknownErrorCode: true,
		transport.SizeInvalidErrorCode: true, transport.TagInvalidErrorCode: true,
		transport.UnauthorizedErrorCode: true, transport.DeniedErrorCode: true,
		transport.UnsupportedErrorCode: true, transport.TooManyRequestsErrorCode: true,
		transport.UnknownErrorCode: true, transport.UnavailableErrorCode: true,
	}
)

// SafeError reports the stage plus, at most, a fixed classification,
// an HTTP status, and registry error codes from the known OCI constants.
func SafeError(ctx context.Context, stage string, err error) error {
	if cause := StageCancellation(ctx, err); cause != nil {
		return &StageError{stage: stage, cause: cause}
	}
	return &StageError{stage: stage, detail: ErrorDetail(err)}
}

func ErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrPlainHTTPRefused) {
		return "plain HTTP refused for non-loopback registry"
	}
	if errors.Is(err, ErrSchemeRefused) {
		return "unsupported registry URL scheme refused"
	}
	if errors.Is(err, ErrContentMismatch) {
		return "content mismatch"
	}
	if errors.Is(err, ErrUnsupportedLayer) {
		return "unsupported layer compression"
	}
	var registryErr *transport.Error
	if errors.As(err, &registryErr) {
		detail := fmt.Sprintf("HTTP %d", registryErr.StatusCode)
		var codes []string
		seen := make(map[string]bool)
		for _, diagnostic := range registryErr.Errors {
			code := string(diagnostic.Code)
			if !knownRegistryCodes[diagnostic.Code] || seen[code] || len(codes) == 8 {
				continue
			}
			seen[code] = true
			codes = append(codes, code)
		}
		if len(codes) != 0 {
			detail += "; " + strings.Join(codes, ",")
		}
		return detail
	}
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "TLS verification failed"
	}
	var dns *net.DNSError
	var op *net.OpError
	if errors.As(err, &dns) || errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &op) && op.Op == "dial") {
		return "registry unreachable"
	}
	return ""
}
