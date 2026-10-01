package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// The pinned name parser checks allowed characters and length, but not Docker's
// separator grammar. Keep each literal APK name a single valid path component.
var dockerRepositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)

var dockerTagComponent = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// APKComponent preserves Docker-compatible APK names literally and uses the
// reserved collision-resistant fallback for all other names.
func APKComponent(apkName string) string {
	if strings.HasPrefix(apkName, "apk-sha256-") || !dockerRepositoryComponent.MatchString(apkName) || len("docker.io/lupetto/"+apkName) > 255 {
		return "apk-sha256-" + sha256Hex([]byte(apkName))
	}
	return apkName
}

func ReadableImageReference(apkName, apkVersion, arch string) (string, error) {
	ociArch, err := ociArchitecture(arch)
	if err != nil {
		return "", err
	}
	repository := APKComponent(apkName)
	tag := apkVersion + "-" + ociArch
	if strings.HasPrefix(apkVersion, "_") || !dockerTagComponent.MatchString(tag) {
		tag = "_apk-sha256-" + sha256Hex([]byte(apkVersion)) + "-" + ociArch
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

func ociArchitecture(arch string) (string, error) {
	switch arch {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Docker target architecture %q", arch)
	}
}
