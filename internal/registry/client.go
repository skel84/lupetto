package registry

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/docker/cli/cli/config"
	dockercredentials "github.com/docker/cli/cli/config/credentials"
	dockertypes "github.com/docker/cli/cli/config/types"
	helpercredentials "github.com/docker/docker-credential-helpers/credentials"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// loopbackHTTPOnly is the innermost registry transport. It applies to every
// request, including ping fallbacks, token-realm requests, and redirects:
// plain HTTP is sent only to localhost or a loopback IP literal.
type loopbackHTTPOnly struct{ base http.RoundTripper }

func (t loopbackHTTPOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	refuse := func(err error) (*http.Response, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if req.URL == nil {
		return refuse(ErrSchemeRefused)
	}
	switch {
	case strings.EqualFold(req.URL.Scheme, "https"):
	case strings.EqualFold(req.URL.Scheme, "http"):
		if !loopbackHost(req.URL.Hostname()) {
			return refuse(ErrPlainHTTPRefused)
		}
	default:
		return refuse(ErrSchemeRefused)
	}
	return t.base.RoundTrip(req)
}

// DockerConfigKeychain reads only Docker's client configuration (DOCKER_CONFIG
// or ~/.docker/config.json, including credsStore/credHelpers). Unlike
// authn.DefaultKeychain it never falls back to Podman/containers auth files.
// The lookup mirrors go-containerregistry v0.22.1 authn/keychain.go.
type DockerConfigKeychain struct{}

var _ authn.ContextKeychain = DockerConfigKeychain{}

var credentialHelperName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

const maxCredentialHelperBytes = 64 << 10

type boundedCredentialOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedCredentialOutput) Write(data []byte) (int, error) {
	if !w.overflow {
		if len(data) > maxCredentialHelperBytes-len(w.data) {
			w.data = nil
			w.overflow = true
		} else {
			w.data = append(w.data, data...)
		}
	}
	return len(data), nil
}

func credentialHelperAuth(ctx context.Context, helper, key string) (dockertypes.AuthConfig, bool, error) {
	var cfg dockertypes.AuthConfig
	if !credentialHelperName.MatchString(helper) {
		return cfg, false, errors.New("Docker credential helper name is invalid")
	}
	cmd := exec.CommandContext(ctx, "docker-credential-"+helper, "get")
	cmd.Stdin = strings.NewReader(key)
	// A nil Stderr discards diagnostics; never inherit or replace os.Stderr.
	var stdout boundedCredentialOutput
	cmd.Stdout = &stdout
	err := cmd.Run()
	if ctx.Err() != nil {
		return cfg, false, ctx.Err()
	}
	if stdout.overflow {
		return cfg, false, errors.New("Docker credential helper output exceeded limit")
	}
	if err != nil {
		if helpercredentials.IsErrCredentialsNotFoundMessage(string(stdout.data)) {
			return cfg, false, nil
		}
		return cfg, false, errors.New("Docker credential helper failed")
	}
	var creds helpercredentials.Credentials
	if err := json.NewDecoder(bytes.NewReader(stdout.data)).Decode(&creds); err != nil {
		return cfg, false, errors.New("Docker credential helper response is invalid")
	}
	if creds.Username == "<token>" {
		cfg.IdentityToken = creds.Secret
	} else {
		cfg.Username, cfg.Password = creds.Username, creds.Secret
	}
	cfg.ServerAddress = key
	return cfg, true, nil
}

func (k DockerConfigKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), target)
}

func (DockerConfigKeychain) ResolveContext(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return nil, err
	}
	// Construct the file store explicitly: GetAuthConfig can select the unsafe
	// native helper store (and can print DOCKER_AUTH_CONFIG diagnostics).
	fileStore := dockercredentials.NewFileStore(cf)
	var cfg, empty dockertypes.AuthConfig
	for _, key := range []string{target.String(), target.RegistryStr()} {
		if key == name.DefaultRegistry {
			key = authn.DefaultAuthKey
		}
		helper := cf.CredentialsStore
		if key != "" {
			if configured, present := cf.CredentialHelpers[key]; present {
				helper = configured
			}
		}
		cfg, err = fileStore.Get(key)
		if helper != "" {
			var helperCfg dockertypes.AuthConfig
			var found bool
			helperCfg, found, err = credentialHelperAuth(ctx, helper, key)
			if err == nil && !found {
				cfg = empty
				continue
			}
			// Like Docker's native store, start with the file entry and replace
			// the helper-owned fields. Auth and RegistryToken affect authn and
			// must survive; Email is harmless and ignored by authn.
			cfg.Username, cfg.Password = helperCfg.Username, helperCfg.Password
			cfg.IdentityToken, cfg.ServerAddress = helperCfg.IdentityToken, helperCfg.ServerAddress
		}
		if err != nil {
			return nil, err
		}
		cfg.ServerAddress = ""
		if cfg != empty {
			break
		}
	}
	if cfg == empty {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

// GuardTransport enforces the loopback-only plain-HTTP rule on every request,
// including token realms and redirects, even when a transport is injected.
func GuardTransport(base http.RoundTripper) http.RoundTripper {
	return loopbackHTTPOnly{base: cmp.Or(base, remote.DefaultTransport)}
}

// RemoteOptions uses Docker-only credentials and the guarded default transport.
func RemoteOptions(ctx context.Context) []remote.Option {
	return ClientOptions(ctx, nil, nil)
}

// ClientOptions supports injected transports and keychains for isolated tests;
// injected transports are still guarded against non-loopback plain HTTP.
func ClientOptions(ctx context.Context, transport http.RoundTripper, keychain authn.Keychain) []remote.Option {
	if keychain == nil {
		keychain = DockerConfigKeychain{}
	}
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(keychain),
		remote.WithTransport(GuardTransport(transport)),
		remote.WithUserAgent("lupetto"),
	}
}
