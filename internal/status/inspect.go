package status

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"lupetto/internal/registry"
)

// InspectDocument is immutable package evidence, not a security or signature scan.
type InspectDocument struct {
	Kind         string     `json:"kind"`
	Version      int        `json:"version"`
	Reference    string     `json:"reference"`
	Digest       string     `json:"digest"`
	Identity     *Identity  `json:"identity,omitempty"`
	Unidentified bool       `json:"unidentified"`
	Created      *time.Time `json:"created,omitempty"`
	Packages     []Identity `json:"packages"`
}

// ParseInspectReference rejects tags, implicit Docker Hub names, credentials,
// URLs and normalized references before any registry request is made.
func ParseInspectReference(reference string) (name.Digest, error) {
	authority, rest, found := strings.Cut(reference, "/")
	repository, digest, hasDigest := strings.Cut(rest, "@")
	if !found || !hasDigest || !digestPattern.MatchString(digest) || registry.ValidateRegistryAuthority(authority) != nil {
		return name.Digest{}, errors.New("inspect requires an explicit registry repository@sha256:digest reference")
	}
	options := []name.Option{name.StrictValidation}
	if registry.AuthorityIsLoopback(authority) {
		options = append(options, name.Insecure)
	}
	parsed, err := name.NewDigest(reference, options...)
	if err != nil || parsed.Name() != reference || parsed.Context().RepositoryStr() != repository {
		return name.Digest{}, errors.New("invalid inspect digest reference")
	}
	return parsed, nil
}

func Inspect(ctx context.Context, reference string) (InspectDocument, error) {
	return InspectWith(ctx, reference, RemoteRegistry{}, nil)
}

func InspectWith(ctx context.Context, reference string, reader RemoteRegistry, cache InstalledCache) (InspectDocument, error) {
	ref, err := ParseInspectReference(reference)
	if err != nil {
		return InspectDocument{}, err
	}
	descriptor, err := remote.Get(ref, reader.options(ctx)...)
	if err != nil {
		return InspectDocument{}, registry.SafeError(ctx, "inspect manifest", err)
	}
	if !verifyDigest(descriptor.Manifest, ref.DigestStr()) {
		return InspectDocument{}, errors.New("inspect manifest digest mismatch")
	}
	image, classification := classifyManifest(descriptor.Manifest, ref.DigestStr())
	if classification == "artifact" {
		return InspectDocument{}, errors.New("inspect requires a single package image, not an artifact or image index")
	}
	document := InspectDocument{Kind: "inspect", Version: 1, Reference: ref.Name(), Digest: ref.DigestStr(), Unidentified: classification != "image", Packages: []Identity{}}
	if classification == "image" {
		document.Identity = &Identity{Name: image.Name, Version: image.Version, Architecture: image.Architecture}
		document.Created = &image.Created
	} else {
		image = Image{Digest: ref.DigestStr()}
		var metadata struct {
			Annotations map[string]string `json:"annotations"`
		}
		if json.Unmarshal(descriptor.Manifest, &metadata) == nil {
			if created, parseErr := time.Parse(time.RFC3339Nano, metadata.Annotations["org.opencontainers.image.created"]); parseErr == nil {
				utc := created.UTC()
				document.Created = &utc
			}
		}
	}
	if cache == nil {
		cache, err = defaultCache()
		if err != nil {
			return InspectDocument{}, err
		}
	}
	packages, cached, err := cache.Load(ctx, image.Digest)
	if err != nil {
		return InspectDocument{}, errors.New("installed cache read failed")
	}
	if !cached {
		packages, err = reader.Installed(ctx, ref.Context(), image)
		if err != nil {
			return InspectDocument{}, err
		}
	}
	arch := image.Architecture
	if arch == "" {
		for _, pkg := range packages {
			if pkg.Arch != "noarch" {
				arch = pkg.Arch
				break
			}
		}
		if arch == "" {
			arch = "noarch"
		}
	}
	if (arch != "x86_64" && arch != "aarch64" && arch != "noarch") || validateInstalled(packages, arch) != nil {
		return InspectDocument{}, errors.New("invalid installed APK identity set")
	}
	if image.Name != "" && !hasTopLevel(packages, image) {
		return InspectDocument{}, errors.New("installed top-level APK does not match image annotations")
	}
	if !cached {
		if err := cache.Store(ctx, image.Digest, packages); err != nil {
			return InspectDocument{}, errors.New("installed cache write failed")
		}
	}
	for _, pkg := range packages {
		document.Packages = append(document.Packages, Identity{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Arch})
	}
	sort.Slice(document.Packages, func(i, j int) bool { return document.Packages[i].Name < document.Packages[j].Name })
	if err := ctx.Err(); err != nil {
		return InspectDocument{}, err
	}
	return document, nil
}
