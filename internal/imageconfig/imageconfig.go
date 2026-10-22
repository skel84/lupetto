// Package imageconfig owns the optional per-track image configuration that a
// build applies beyond its selected APK and dependency closure: the OCI
// entrypoint. The build writes it into the image config and a manifest
// annotation; status reads that annotation back to detect a changed track.
// An empty Options adds nothing, so such images match earlier releases.
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

const (
	maxEntrypointElements = 32
	maxElementBytes       = 1024
)

// Options is the non-package image configuration of one build or track.
type Options struct {
	// Entrypoint is the OCI config Entrypoint: an absolute executable path in
	// the image followed by fixed leading arguments. Nil means none.
	Entrypoint []string
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
	return options, nil
}

// Equal reports whether a and b configure the same image.
func (o Options) Equal(other Options) bool {
	return slices.Equal(o.Entrypoint, other.Entrypoint)
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
