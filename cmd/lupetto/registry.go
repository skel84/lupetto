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
