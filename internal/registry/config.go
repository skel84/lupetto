package registry

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
)

type OptionalString struct {
	Value string
	Set   bool
}

// The authority is validated before this check, so only bracket/port syntax
// needs removal. The same literal-loopback rule governs Cosign HTTP consent,
// ggcr's HTTP fallback, and the registry transport guard.
func AuthorityIsLoopback(authority string) bool {
	host := authority
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return false
		}
		host = host[1:end]
	} else if before, _, hasPort := strings.Cut(host, ":"); hasPort {
		host = before
	}
	return loopbackHost(host)
}

func loopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

type PublicationFlags struct {
	Registry, Repository OptionalString
}

type PublicationOptions struct {
	Registry, Repository string
}

func (opts PublicationOptions) Enabled() bool {
	return opts.Registry != "" || opts.Repository != ""
}

func ResolvePublication(raw PublicationFlags, lookupEnv func(string) (string, bool)) (PublicationOptions, error) {
	resolve := func(flag OptionalString, envName, flagName string) (string, error) {
		if flag.Set {
			if flag.Value == "" {
				return "", fmt.Errorf("%s must not be empty", flagName)
			}
			return flag.Value, nil
		}
		if lookupEnv != nil {
			if value, present := lookupEnv(envName); present {
				return value, nil
			}
		}
		return "", nil
	}
	registry, err := resolve(raw.Registry, "LUPETTO_REGISTRY", "--registry")
	if err != nil {
		return PublicationOptions{}, err
	}
	repository, err := resolve(raw.Repository, "LUPETTO_REPOSITORY", "--repository")
	if err != nil {
		return PublicationOptions{}, err
	}
	opts := PublicationOptions{Registry: registry, Repository: repository}
	if err := ValidatePublicationOptions(opts); err != nil {
		return PublicationOptions{}, err
	}
	return opts, nil
}

var registryDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)

var registryPort = regexp.MustCompile(`^[0-9]+$`)

var registryNumericHost = regexp.MustCompile(`^[0-9.]+$`)

var publicationWorkspaceSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func ValidatePublicationOptions(opts PublicationOptions) error {
	if !opts.Enabled() {
		return nil
	}
	if opts.Registry == "" || opts.Repository == "" {
		return fmt.Errorf("publication requires both --registry / LUPETTO_REGISTRY and --repository / LUPETTO_REPOSITORY")
	}
	if err := ValidateRegistryAuthority(opts.Registry); err != nil {
		return err
	}
	for _, component := range strings.Split(opts.Repository, "/") {
		if !dockerRepositoryComponent.MatchString(component) {
			return fmt.Errorf("repository must be a nested lower-case OCI prefix without tags, digests, or empty components")
		}
	}
	// Even the shortest APK component must fit; the selected exact component
	// is checked again when the final unique reference can be derived.
	return ValidatePublicationReference(opts.Registry, opts.Repository+"/x", "validation")
}

func ValidateRegistryAuthority(authority string) error {
	if authority == "" || strings.ContainsAny(authority, "/@?#\\ \t\r\n") {
		return fmt.Errorf("registry must be a DNS/IP authority with an optional port, not a URL")
	}
	host, port := authority, ""
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return fmt.Errorf("registry IPv6 address must be bracketed")
		}
		host = authority[1:end]
		ip := net.ParseIP(host)
		if ip == nil || !strings.Contains(host, ":") {
			return fmt.Errorf("registry bracketed host must be an IPv6 address")
		}
		if rest := authority[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return fmt.Errorf("registry must contain only an authority")
			}
			hasPort, port = true, rest[1:]
		}
	} else {
		if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
			return fmt.Errorf("registry IPv6 address must be bracketed")
		}
		if before, after, found := strings.Cut(authority, ":"); found {
			host, port, hasPort = before, after, true
		}
		if net.ParseIP(host) == nil {
			if host == "" || len(host) > 253 || (strings.Contains(host, ".") && registryNumericHost.MatchString(host)) {
				return fmt.Errorf("registry has an invalid DNS name or IP address")
			}
			for _, label := range strings.Split(host, ".") {
				if len(label) > 63 || !registryDNSLabel.MatchString(label) {
					return fmt.Errorf("registry has an invalid DNS name")
				}
			}
			if host != "localhost" && !strings.Contains(host, ".") && !hasPort {
				return fmt.Errorf("registry must be unambiguous: use a dotted DNS name, localhost, an IP address, or an explicit port")
			}
		}
	}
	if hasPort {
		value, err := strconv.Atoi(port)
		if !registryPort.MatchString(port) || err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("registry port must be a decimal number from 1 to 65535")
		}
	}
	return nil
}

func ValidatePublicationReference(registry, path, tag string) error {
	repository := registry + "/" + path
	// The upstream parser bounds the path. Apply its advertised total-name
	// bound to the whole operator-selected repository, including authority.
	if len(repository) > reference.RepositoryNameTotalLengthMax {
		return fmt.Errorf("publication repository exceeds the OCI repository name length limit")
	}
	full := repository + ":" + tag
	parsed, err := reference.ParseNormalizedNamed(full)
	if err != nil {
		return fmt.Errorf("invalid publication image reference")
	}
	tagged, ok := parsed.(reference.NamedTagged)
	if !ok || parsed.Name() != repository || reference.Domain(parsed) != registry || reference.Path(parsed) != path || tagged.Tag() != tag || parsed.String() != full {
		return fmt.Errorf("publication image reference normalizes to a different registry, repository, or tag")
	}
	return nil
}

type Target struct {
	Repository, Reference string
	// tag is the parsed upstream reference used for the push and tag readback;
	// insecure records whether ggcr may attempt its loopback HTTP fallback.
	Tag      name.Tag
	Insecure bool
}

func (t Target) NameOptions() []name.Option {
	if t.Insecure {
		return []name.Option{name.StrictValidation, name.Insecure}
	}
	return []name.Option{name.StrictValidation}
}

func PublicationReferences(apkName, apkVersion, arch, workspace string, opts PublicationOptions) (Target, error) {
	if err := ValidatePublicationOptions(opts); err != nil {
		return Target{}, err
	}
	if !opts.Enabled() {
		return Target{}, nil
	}
	local, err := ReadableImageReference(apkName, apkVersion, arch)
	if err != nil {
		return Target{}, err
	}
	component, tag, ok := strings.Cut(strings.TrimPrefix(local, "lupetto/"), ":")
	if !ok {
		return Target{}, fmt.Errorf("readable image reference has no exact tag")
	}
	base := filepath.Base(workspace)
	suffix := strings.TrimPrefix(base, "image-")
	if base == suffix || !publicationWorkspaceSuffix.MatchString(suffix) {
		return Target{}, fmt.Errorf("publication requires a unique image workspace suffix")
	}
	tag += "-build-" + suffix
	if !dockerTagComponent.MatchString(tag) {
		tag = "_apk-sha256-" + sha256Hex([]byte(tag))
	}
	path := opts.Repository + "/" + component
	if err := ValidatePublicationReference(opts.Registry, path, tag); err != nil {
		return Target{}, err
	}
	repository := opts.Registry + "/" + path
	target := Target{Repository: repository, Reference: repository + ":" + tag, Insecure: AuthorityIsLoopback(opts.Registry)}
	// Parse once with the client that pushes, before any build side effect, and
	// reject any registry, repository, or tag normalization. Only Docker Hub's
	// documented docker.io -> index.docker.io authority alias is accepted.
	parsed, err := name.NewTag(target.Reference, target.NameOptions()...)
	if err != nil {
		return Target{}, fmt.Errorf("invalid publication image reference")
	}
	registryMatches := parsed.RegistryStr() == opts.Registry || (opts.Registry == "docker.io" && parsed.RegistryStr() == name.DefaultRegistry)
	if !registryMatches || parsed.RepositoryStr() != path || parsed.TagStr() != tag {
		return Target{}, fmt.Errorf("publication image reference normalizes to a different registry, repository, or tag")
	}
	target.Tag = parsed
	return target, nil
}

// Repository resolves the same APK component used for publication and rejects
// registry or repository normalization by either pinned reference parser.
func Repository(opts PublicationOptions, apkName string) (name.Repository, error) {
	if err := ValidatePublicationOptions(opts); err != nil {
		return name.Repository{}, err
	}
	if !opts.Enabled() {
		return name.Repository{}, fmt.Errorf("registry reads require both registry and repository settings")
	}
	path := opts.Repository + "/" + APKComponent(apkName)
	if err := ValidatePublicationReference(opts.Registry, path, "validation"); err != nil {
		return name.Repository{}, err
	}
	options := []name.Option{name.StrictValidation}
	if AuthorityIsLoopback(opts.Registry) {
		options = append(options, name.Insecure)
	}
	parsed, err := name.NewRepository(opts.Registry+"/"+path, options...)
	if err != nil {
		return name.Repository{}, fmt.Errorf("invalid publication image reference")
	}
	registryMatches := parsed.RegistryStr() == opts.Registry || (opts.Registry == "docker.io" && parsed.RegistryStr() == name.DefaultRegistry)
	if !registryMatches || parsed.RepositoryStr() != path {
		return name.Repository{}, fmt.Errorf("publication image reference normalizes to a different registry, repository, or tag")
	}
	return parsed, nil
}
