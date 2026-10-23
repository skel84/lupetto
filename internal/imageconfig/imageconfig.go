// Package imageconfig owns the image configuration that a build applies beyond
// its selected APK and dependency closure. Every image gets the Wolfi base
// layout. The optional per-track settings are the OCI entrypoint and the CA
// certificate bundle; the build writes them into the image and its manifest
// annotations, and status reads those annotations back to detect a changed
// track.
package imageconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// EntrypointAnnotation records the image entrypoint as a compact JSON array.
// It is present only when an entrypoint was requested.
const EntrypointAnnotation = "lupetto.image.entrypoint"

// CABundleAnnotation is "true" when the build added the CA certificate
// bundle; it is absent otherwise.
const CABundleAnnotation = "lupetto.image.ca-bundle"

// CABundlePackage is the Wolfi APK that provides CABundlePath. It is added
// unpinned; apko's lock records the exact version installed.
const (
	CABundlePackage = "ca-certificates-bundle"
	CABundlePath    = "/etc/ssl/certs/ca-certificates.crt"
)

// BaseLayoutPackage is the Wolfi APK every build adds, unpinned like the CA
// bundle, so vulnerability scanners can identify the image: it provides
// OSReleasePath, without which Trivy reports no findings and Grype ignores the
// APK database. In Wolfi it also depends on CABundlePackage.
const (
	BaseLayoutPackage = "wolfi-baselayout"
	OSReleasePath     = "/etc/os-release"
	OSReleaseID       = "wolfi"
)

const (
	maxEntrypointElements = 32
	maxElementBytes       = 1024
)

// Options is the non-package image configuration of one build or track.
type Options struct {
	// Entrypoint is the OCI config Entrypoint: an absolute executable path in
	// the image followed by fixed leading arguments. Nil means none.
	Entrypoint []string
	// CABundle adds CABundlePackage to the image so TLS clients find system
	// roots at CABundlePath. The base layout normally brings the bundle in
	// already; the option records and checks that the track requires it rather
	// than relying on Wolfi's dependency graph.
	CABundle bool
}

// ValidateEntrypoint checks a requested entrypoint. The executable must be a
// clean absolute path so it can be checked against the built image; elements
// exclude control characters and single quotes, which apko's command
// splitting could not round-trip.
func ValidateEntrypoint(entrypoint []string) error {
	if len(entrypoint) == 0 {
		return errors.New("entrypoint must name an executable")
	}
	if len(entrypoint) > maxEntrypointElements {
		return fmt.Errorf("entrypoint has more than %d elements", maxEntrypointElements)
	}
	for _, element := range entrypoint {
		if element == "" || len(element) > maxElementBytes || !utf8.ValidString(element) {
			return fmt.Errorf("entrypoint elements must be non-empty UTF-8 of at most %d bytes", maxElementBytes)
		}
		if strings.ContainsRune(element, '\'') || strings.IndexFunc(element, unicode.IsControl) >= 0 {
			return errors.New("entrypoint elements must not contain single quotes or control characters")
		}
	}
	if executable := entrypoint[0]; !strings.HasPrefix(executable, "/") || executable == "/" || path.Clean(executable) != executable {
		return errors.New("entrypoint executable must be a clean absolute path such as /usr/bin/example")
	}
	return nil
}

// Validate checks every set option.
func (o Options) Validate() error {
	if o.Entrypoint != nil {
		return ValidateEntrypoint(o.Entrypoint)
	}
	return nil
}

// Annotations returns the manifest annotations recording o; none when o is
// empty.
func (o Options) Annotations() map[string]string {
	annotations := map[string]string{}
	if o.Entrypoint != nil {
		data, _ := json.Marshal(o.Entrypoint)
		annotations[EntrypointAnnotation] = string(data)
	}
	if o.CABundle {
		annotations[CABundleAnnotation] = "true"
	}
	return annotations
}

// FromAnnotations reads the options an image was built with. A missing
// annotation means the option was not set; a malformed one is an error, never
// a guess.
func FromAnnotations(annotations map[string]string) (Options, error) {
	var options Options
	if value, ok := annotations[EntrypointAnnotation]; ok {
		var entrypoint []string
		if err := json.Unmarshal([]byte(value), &entrypoint); err != nil || ValidateEntrypoint(entrypoint) != nil {
			return Options{}, errors.New("invalid " + EntrypointAnnotation + " annotation")
		}
		options.Entrypoint = entrypoint
	}
	if value, ok := annotations[CABundleAnnotation]; ok {
		if value != "true" {
			return Options{}, errors.New("invalid " + CABundleAnnotation + " annotation")
		}
		options.CABundle = true
	}
	return options, nil
}

// Equal reports whether a and b configure the same image.
func (o Options) Equal(other Options) bool {
	return slices.Equal(o.Entrypoint, other.Entrypoint) && o.CABundle == other.CABundle
}

// ApkoCommand renders the entrypoint as apko's entrypoint.command string.
// apko splits it with shell-like rules; single-quoting every element (which
// ValidateEntrypoint guarantees contains no single quote) keeps each element,
// including spaces, intact.
func ApkoCommand(entrypoint []string) string {
	quoted := make([]string, len(entrypoint))
	for i, element := range entrypoint {
		quoted[i] = "'" + element + "'"
	}
	return strings.Join(quoted, " ")
}
