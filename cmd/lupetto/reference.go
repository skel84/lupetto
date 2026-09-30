package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// The pinned name parser checks allowed characters and length, but not Docker's
// separator grammar. Keep each literal APK name a single valid path component.
var dockerRepositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
var dockerTagComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func readableImageReference(selected indexedPackage, arch string) (string, error) {
	ociArch, err := ociArchitecture(arch)
	if err != nil {
		return "", err
	}
	repository := selected.name
	// Docker normalizes these plain references with docker.io/ before enforcing
	// its repository length limit; reserve that prefix without displaying it.
	if strings.HasPrefix(repository, "apk-sha256-") || !dockerRepositoryComponent.MatchString(repository) || len("docker.io/lupetto/"+repository) > 255 {
		repository = "apk-sha256-" + sha256Hex([]byte(selected.name))
	}
	tag := selected.version + "-" + ociArch
	if strings.HasPrefix(selected.version, "_") || !dockerTagComponent.MatchString(tag) {
		tag = "_apk-sha256-" + sha256Hex([]byte(selected.version)) + "-" + ociArch
	}
	reference := "lupetto/" + repository + ":" + tag
	parsed, err := name.NewTag(reference)
	if err != nil {
		return "", fmt.Errorf("validate readable local image reference: %w", err)
	}
	if parsed.RepositoryStr() != "lupetto/"+repository || parsed.TagStr() != tag {
		return "", fmt.Errorf("readable local image reference parsed as a different repository or tag")
	}
	return reference, nil
}
