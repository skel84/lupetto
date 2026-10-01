package build

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

type OptionalString = registry.OptionalString

type OptionalBool struct {
	Value bool
	Set   bool
}

type SigningFlags struct {
	Key, Config OptionalString
	AllowHTTP   OptionalBool
}

type SigningOptions struct {
	Key, Config string
	AllowHTTP   bool
}

func (opts SigningOptions) Enabled() bool {
	return opts.Key != ""
}

func ResolveSigning(raw SigningFlags, pub PublicationOptions, lookupEnv func(string) (string, bool)) (SigningOptions, error) {
	resolveString := func(flag OptionalString, envName, flagName string) (string, error) {
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
	key, err := resolveString(raw.Key, "LUPETTO_COSIGN_KEY", "--cosign-key")
	if err != nil {
		return SigningOptions{}, err
	}
	config, err := resolveString(raw.Config, "LUPETTO_COSIGN_SIGNING_CONFIG", "--cosign-signing-config")
	if err != nil {
		return SigningOptions{}, err
	}
	allowHTTP := raw.AllowHTTP.Set && raw.AllowHTTP.Value
	if !raw.AllowHTTP.Set && lookupEnv != nil {
		if value, present := lookupEnv("LUPETTO_COSIGN_ALLOW_HTTP"); present && value != "" {
			switch value {
			case "true":
				allowHTTP = true
			case "false":
				allowHTTP = false
			default:
				return SigningOptions{}, fmt.Errorf("LUPETTO_COSIGN_ALLOW_HTTP must be true or false")
			}
		}
	}
	opts := SigningOptions{Key: key, Config: config, AllowHTTP: allowHTTP}
	if err := validateSigningOptions(opts, pub); err != nil {
		return SigningOptions{}, err
	}
	return opts, nil
}

func validateSigningOptions(opts SigningOptions, pub PublicationOptions) error {
	if err := validatePublicationOptions(pub); err != nil {
		return err
	}
	if !opts.Enabled() {
		if opts.Config != "" || opts.AllowHTTP {
			return fmt.Errorf("Cosign signing config and enabled HTTP allowance require --cosign-key / LUPETTO_COSIGN_KEY")
		}
		return nil
	}
	if !pub.Enabled() {
		return fmt.Errorf("signing requires publication with both registry and repository settings")
	}
	loopback := registryAuthorityIsLoopback(pub.Registry)
	if opts.AllowHTTP && !loopback {
		return fmt.Errorf("--cosign-allow-http is restricted to literal-loopback registries")
	}
	if loopback && !opts.AllowHTTP {
		return fmt.Errorf("signing against a literal-loopback registry requires --cosign-allow-http=true")
	}
	return nil
}

type PublicationFlags = registry.PublicationFlags

type PublicationOptions = registry.PublicationOptions

func ResolvePublication(raw PublicationFlags, lookupEnv func(string) (string, bool)) (PublicationOptions, error) {
	return registry.ResolvePublication(raw, lookupEnv)
}

func validatePublicationOptions(opts PublicationOptions) error {
	return registry.ValidatePublicationOptions(opts)
}

func validateRegistryAuthority(authority string) error {
	return registry.ValidateRegistryAuthority(authority)
}

func validatePublicationReference(authority, path, tag string) error {
	return registry.ValidatePublicationReference(authority, path, tag)
}

func registryAuthorityIsLoopback(authority string) bool {
	return registry.AuthorityIsLoopback(authority)
}

type publicationTarget struct {
	repository, reference string
	tag                   name.Tag
	insecure              bool
}

func (t publicationTarget) nameOptions() []name.Option {
	return (registry.Target{Insecure: t.insecure}).NameOptions()
}

func publicationReferences(selected wolfi.Package, arch, workspace string, opts PublicationOptions) (publicationTarget, error) {
	target, err := registry.PublicationReferences(selected.Name, selected.Version, arch, workspace, opts)
	if err != nil {
		return publicationTarget{}, err
	}
	return publicationTarget{repository: target.Repository, reference: target.Reference, tag: target.Tag, insecure: target.Insecure}, nil
}
