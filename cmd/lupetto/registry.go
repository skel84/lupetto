package main

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/distribution/reference"
)

type optionalString struct {
	value string
	set   bool
}

type optionalBool struct {
	value bool
	set   bool
}

type signingFlags struct {
	key, config optionalString
	allowHTTP   optionalBool
}

type signingOptions struct {
	key, config string
	allowHTTP   bool
}

func (opts signingOptions) enabled() bool {
	return opts.key != ""
}

func resolveSigning(raw signingFlags, pub publicationOptions, noLoad bool, lookupEnv func(string) (string, bool)) (signingOptions, error) {
	resolveString := func(flag optionalString, envName, flagName string) (string, error) {
		if flag.set {
			if flag.value == "" {
				return "", fmt.Errorf("%s must not be empty", flagName)
			}
			return flag.value, nil
		}
		if lookupEnv != nil {
			if value, present := lookupEnv(envName); present {
				return value, nil
			}
		}
		return "", nil
	}
	key, err := resolveString(raw.key, "LUPETTO_COSIGN_KEY", "--cosign-key")
	if err != nil {
		return signingOptions{}, err
	}
	config, err := resolveString(raw.config, "LUPETTO_COSIGN_SIGNING_CONFIG", "--cosign-signing-config")
	if err != nil {
		return signingOptions{}, err
	}
	allowHTTP := raw.allowHTTP.set && raw.allowHTTP.value
	if !raw.allowHTTP.set && lookupEnv != nil {
		if value, present := lookupEnv("LUPETTO_COSIGN_ALLOW_HTTP"); present && value != "" {
			switch value {
			case "true":
				allowHTTP = true
			case "false":
				allowHTTP = false
			default:
				return signingOptions{}, fmt.Errorf("LUPETTO_COSIGN_ALLOW_HTTP must be true or false")
			}
		}
	}
	opts := signingOptions{key: key, config: config, allowHTTP: allowHTTP}
	if err := validateSigningOptions(opts, pub, noLoad); err != nil {
		return signingOptions{}, err
	}
	return opts, nil
}

func validateSigningOptions(opts signingOptions, pub publicationOptions, noLoad bool) error {
	if err := validatePublicationOptions(pub); err != nil {
		return err
	}
	if !opts.enabled() {
		if opts.config != "" || opts.allowHTTP {
			return fmt.Errorf("Cosign signing config and enabled HTTP allowance require --cosign-key / LUPETTO_COSIGN_KEY")
		}
		return nil
	}
	if noLoad {
		return fmt.Errorf("signing cannot be used with --no-load")
	}
	if !pub.enabled() {
		return fmt.Errorf("signing requires publication with both registry and repository settings")
	}
	host := pub.registry
	if strings.HasPrefix(host, "[") {
		host = host[1:strings.IndexByte(host, ']')]
	} else if before, _, hasPort := strings.Cut(host, ":"); hasPort {
		host = before
	}
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if opts.allowHTTP && !loopback {
		return fmt.Errorf("--cosign-allow-http is restricted to literal-loopback registries")
	}
	if loopback && !opts.allowHTTP {
		return fmt.Errorf("signing against a literal-loopback registry requires --cosign-allow-http=true")
	}
	return nil
}

type publicationFlags struct {
	registry, repository optionalString
}

type publicationOptions struct {
	registry, repository string
}

func (opts publicationOptions) enabled() bool {
	return opts.registry != "" || opts.repository != ""
}

func resolvePublication(raw publicationFlags, lookupEnv func(string) (string, bool)) (publicationOptions, error) {
	resolve := func(flag optionalString, envName, flagName string) (string, error) {
		if flag.set {
			if flag.value == "" {
				return "", fmt.Errorf("%s must not be empty", flagName)
			}
			return flag.value, nil
		}
		if lookupEnv != nil {
			if value, present := lookupEnv(envName); present {
				return value, nil
			}
		}
		return "", nil
	}
	registry, err := resolve(raw.registry, "LUPETTO_REGISTRY", "--registry")
	if err != nil {
		return publicationOptions{}, err
	}
	repository, err := resolve(raw.repository, "LUPETTO_REPOSITORY", "--repository")
	if err != nil {
		return publicationOptions{}, err
	}
	opts := publicationOptions{registry: registry, repository: repository}
	if err := validatePublicationOptions(opts); err != nil {
		return publicationOptions{}, err
	}
	return opts, nil
}

var registryDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
var registryPort = regexp.MustCompile(`^[0-9]+$`)
var registryNumericHost = regexp.MustCompile(`^[0-9.]+$`)
var publicationWorkspaceSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validatePublicationOptions(opts publicationOptions) error {
	if !opts.enabled() {
		return nil
	}
	if opts.registry == "" || opts.repository == "" {
		return fmt.Errorf("publication requires both --registry / LUPETTO_REGISTRY and --repository / LUPETTO_REPOSITORY")
	}
	if err := validateRegistryAuthority(opts.registry); err != nil {
		return err
	}
	for _, component := range strings.Split(opts.repository, "/") {
		if !dockerRepositoryComponent.MatchString(component) {
			return fmt.Errorf("repository must be a nested lower-case OCI prefix without tags, digests, or empty components")
		}
	}
	// Even the shortest APK component must fit; the selected exact component
	// is checked again when the final unique reference can be derived.
	return validatePublicationReference(opts.registry, opts.repository+"/x", "validation")
}

func validateRegistryAuthority(authority string) error {
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

func validatePublicationReference(registry, path, tag string) error {
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

type publicationTarget struct {
	repository, reference string
}

func publicationReferences(selected indexedPackage, arch, workspace string, opts publicationOptions) (publicationTarget, error) {
	if err := validatePublicationOptions(opts); err != nil {
		return publicationTarget{}, err
	}
	if !opts.enabled() {
		return publicationTarget{}, nil
	}
	local, err := readableImageReference(selected, arch)
	if err != nil {
		return publicationTarget{}, err
	}
	component, tag, ok := strings.Cut(strings.TrimPrefix(local, "lupetto/"), ":")
	if !ok {
		return publicationTarget{}, fmt.Errorf("readable image reference has no exact tag")
	}
	base := filepath.Base(workspace)
	suffix := strings.TrimPrefix(base, "image-")
	if base == suffix || !publicationWorkspaceSuffix.MatchString(suffix) {
		return publicationTarget{}, fmt.Errorf("publication requires a unique image workspace suffix")
	}
	tag += "-build-" + suffix
	if !dockerTagComponent.MatchString(tag) {
		tag = "_apk-sha256-" + sha256Hex([]byte(tag))
	}
	path := opts.repository + "/" + component
	if err := validatePublicationReference(opts.registry, path, tag); err != nil {
		return publicationTarget{}, err
	}
	repository := opts.registry + "/" + path
	return publicationTarget{repository: repository, reference: repository + ":" + tag}, nil
}
