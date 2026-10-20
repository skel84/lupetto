package build

import (
	"fmt"
	"os"

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
	// IdentityTokenFile is --cosign-identity-token: a file holding an OIDC
	// token for keyless (Fulcio) signing. Mutually exclusive with Key.
	IdentityTokenFile OptionalString
	AllowHTTP         OptionalBool
	// Require is --require-signing. It is resolved and enforced here and is not
	// part of SigningOptions: it only rejects unsigned publication.
	Require OptionalBool
}

type SigningOptions struct {
	Key, Config string
	// IdentityTokenFile selects keyless signing: Cosign receives the path,
	// never the token, and obtains a short-lived Fulcio certificate.
	IdentityTokenFile string
	AllowHTTP         bool
}

func (opts SigningOptions) Enabled() bool {
	return opts.Key != "" || opts.Keyless()
}

func (opts SigningOptions) Keyless() bool {
	return opts.IdentityTokenFile != ""
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
	tokenFile, err := resolveString(raw.IdentityTokenFile, IdentityTokenFileEnv, "--cosign-identity-token")
	if err != nil {
		return SigningOptions{}, err
	}
	allowHTTP, err := resolveBool(raw.AllowHTTP, "LUPETTO_COSIGN_ALLOW_HTTP", lookupEnv)
	if err != nil {
		return SigningOptions{}, err
	}
	require, err := resolveBool(raw.Require, RequireSigningEnv, lookupEnv)
	if err != nil {
		return SigningOptions{}, err
	}
	opts := SigningOptions{Key: key, Config: config, IdentityTokenFile: tokenFile, AllowHTTP: allowHTTP}
	if err := validateSigningOptions(opts, pub); err != nil {
		return SigningOptions{}, err
	}
	if require && pub.Enabled() && !opts.Enabled() {
		return SigningOptions{}, errUnsignedPublicationRefused
	}
	return opts, nil
}

// RequireSigningEnv is the environment input of --require-signing.
const RequireSigningEnv = "LUPETTO_REQUIRE_SIGNING"

// IdentityTokenFileEnv is the environment input of --cosign-identity-token.
const IdentityTokenFileEnv = "LUPETTO_COSIGN_IDENTITY_TOKEN_FILE"

var errUnsignedPublicationRefused = fmt.Errorf("unsigned publication refused: signing is required (--require-signing / %s) but neither a Cosign key (--cosign-key / LUPETTO_COSIGN_KEY) nor an identity token file (--cosign-identity-token / %s) is set", RequireSigningEnv, IdentityTokenFileEnv)

// UnsignedPublicationWarning is printed once on stderr before a build that
// publishes without a Cosign key. It is not part of the build record.
const UnsignedPublicationWarning = "warning: publishing without signing: the image will be pushed with no Cosign signature or SPDX attestation; set --cosign-key / LUPETTO_COSIGN_KEY or --cosign-identity-token / " + IdentityTokenFileEnv + " to sign, or --require-signing / " + RequireSigningEnv + "=true to refuse unsigned publication"

// UnsignedPublication reports whether a resolved build publishes without
// signing, which also means no SPDX attestation reaches the registry.
func UnsignedPublication(pub PublicationOptions, signing SigningOptions) bool {
	return pub.Enabled() && !signing.Enabled()
}

// resolveBool resolves a strict true/false setting: an explicit flag wins;
// otherwise a non-empty environment value must be exactly true or false.
func resolveBool(flag OptionalBool, envName string, lookupEnv func(string) (string, bool)) (bool, error) {
	if flag.Set {
		return flag.Value, nil
	}
	if lookupEnv == nil {
		return false, nil
	}
	value, present := lookupEnv(envName)
	if !present || value == "" {
		return false, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", envName)
}

func validateSigningOptions(opts SigningOptions, pub PublicationOptions) error {
	if err := validatePublicationOptions(pub); err != nil {
		return err
	}
	if !opts.Enabled() {
		if opts.Config != "" || opts.AllowHTTP {
			return fmt.Errorf("Cosign signing config and enabled HTTP allowance require --cosign-key / LUPETTO_COSIGN_KEY or --cosign-identity-token / %s", IdentityTokenFileEnv)
		}
		return nil
	}
	if opts.Key != "" && opts.Keyless() {
		return fmt.Errorf("--cosign-key and --cosign-identity-token are mutually exclusive")
	}
	if opts.Keyless() {
		// Cosign treats a nonexistent path as the literal token; insist on a
		// regular file so a typo cannot become a bogus token sent to Fulcio.
		// Only metadata is read, never the token.
		info, err := os.Stat(opts.IdentityTokenFile)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("--cosign-identity-token / %s must name a readable regular file", IdentityTokenFileEnv)
		}
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
