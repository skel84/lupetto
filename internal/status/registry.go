package status

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"time"

	apkcompare "chainguard.dev/apko/pkg/apk/apk"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

const MaxTags = 10000

var exactVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type RegistryListing struct {
	Images            []Image
	ArtifactCount     int
	UnidentifiedCount int
}

type RegistryReader interface {
	List(context.Context, name.Repository) (RegistryListing, error)
	Installed(context.Context, name.Repository, Image) ([]wolfi.InstalledPackage, error)
}

// RemoteRegistry always uses the shared Docker-only keychain and loopback HTTP
// guard, including when a transport/keychain is injected by hermetic tests.
type RemoteRegistry struct {
	Transport http.RoundTripper
	Keychain  authn.Keychain
}

func (reader RemoteRegistry) options(ctx context.Context) []remote.Option {
	transport := reader.Transport
	if transport == nil {
		transport = remote.DefaultTransport
	}
	return registry.ClientOptions(ctx, metadataTransport{transport}, reader.Keychain)
}

// RemoteOptions exposes the same guarded, metadata-bounded client options to
// other read-only registry commands.
func (reader RemoteRegistry) RemoteOptions(ctx context.Context) []remote.Option {
	return reader.options(ctx)
}

type metadataTransport struct{ base http.RoundTripper }

var blobEndpointPattern = regexp.MustCompile(`/blobs/sha256:[0-9a-f]+$`)

func (transport metadataTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	original := request
	for redirects := 0; original.Response != nil && original.Response.Request != nil && redirects < 10; redirects++ {
		original = original.Response.Request
	}
	if !blobEndpointPattern.MatchString(original.URL.Path) {
		response.Body = &boundedBody{ReadCloser: response.Body, remaining: registry.MaxMetadataBytes}
	}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (body *boundedBody) Read(data []byte) (int, error) {
	if body.remaining < 0 {
		return 0, errors.New("registry metadata size limit exceeded")
	}
	if int64(len(data)) > body.remaining+1 {
		data = data[:body.remaining+1]
	}
	n, err := body.ReadCloser.Read(data)
	body.remaining -= int64(n)
	if body.remaining < 0 {
		return n, errors.New("registry metadata size limit exceeded")
	}
	return n, err
}

func (reader RemoteRegistry) List(ctx context.Context, repository name.Repository) (RegistryListing, error) {
	listing := RegistryListing{Images: []Image{}}
	puller, err := remote.NewPuller(reader.options(ctx)...)
	if err != nil {
		return listing, registry.SafeError(ctx, "registry client", err)
	}
	lister, err := puller.Lister(ctx, repository)
	if err != nil {
		// A repository not yet published is a normal not-built track.
		if isMissingRepository(err) {
			return listing, nil
		}
		return listing, registry.SafeError(ctx, "registry tag listing", err)
	}
	var tags []string
	for pages := 0; lister.HasNext(); pages++ {
		if pages >= MaxTags {
			return listing, errors.New("registry tag page limit exceeded")
		}
		page, err := lister.Next(ctx)
		if err != nil {
			return listing, registry.SafeError(ctx, "registry tag listing", err)
		}
		tags = append(tags, page.Tags...)
		if len(tags) > MaxTags {
			return listing, errors.New("registry tag limit exceeded")
		}
	}
	sort.Strings(tags)
	seen := map[string]int{}
	for _, tag := range tags {
		descriptor, err := remote.Get(repository.Tag(tag), reader.options(ctx)...)
		if err != nil {
			return listing, registry.SafeError(ctx, "registry tag manifest", err)
		}
		digest := descriptor.Digest.String()
		if !digestPattern.MatchString(digest) || !verifyDigest(descriptor.Manifest, digest) {
			return listing, errors.New("registry tag manifest digest mismatch")
		}
		if index, exists := seen[digest]; exists {
			if index >= 0 {
				listing.Images[index].Tags = append(listing.Images[index].Tags, tag)
			}
			continue
		}
		// Read again by immutable digest; never derive installed evidence from a tag.
		immutable, err := remote.Get(repository.Digest(digest), reader.options(ctx)...)
		if err != nil {
			return listing, registry.SafeError(ctx, "registry digest manifest", err)
		}
		if !verifyDigest(immutable.Manifest, digest) {
			return listing, errors.New("registry digest manifest mismatch")
		}
		image, classification := classifyManifest(immutable.Manifest, digest)
		seen[digest] = -1
		switch classification {
		case "artifact":
			listing.ArtifactCount++
		case "unidentified":
			listing.UnidentifiedCount++
		default:
			image.Tags = []string{tag}
			seen[digest] = len(listing.Images)
			listing.Images = append(listing.Images, image)
		}
	}
	return listing, nil
}

func classifyManifest(data []byte, digest string) (Image, string) {
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     types.MediaType   `json:"mediaType"`
		ArtifactType  string            `json:"artifactType"`
		Subject       json.RawMessage   `json:"subject"`
		Config        v1.Descriptor     `json:"config"`
		Layers        []v1.Descriptor   `json:"layers"`
		Annotations   map[string]string `json:"annotations"`
	}
	if len(data) > registry.MaxMetadataBytes || json.Unmarshal(data, &manifest) != nil {
		return Image{}, "unidentified"
	}
	if manifest.ArtifactType != "" || (len(manifest.Subject) > 0 && string(manifest.Subject) != "null") {
		return Image{}, "artifact"
	}
	if manifest.MediaType != types.OCIManifestSchema1 && manifest.MediaType != types.DockerManifestSchema2 {
		return Image{}, "artifact"
	}
	if manifest.Config.MediaType != types.OCIConfigJSON && manifest.Config.MediaType != types.DockerConfigJSON {
		return Image{}, "artifact"
	}
	for _, layer := range manifest.Layers {
		if !imageLayerType(layer.MediaType) {
			return Image{}, "artifact"
		}
	}
	annotations := manifest.Annotations
	image := Image{Digest: digest, Name: annotations["lupetto.apk.name"], Version: annotations["lupetto.apk.version"], Architecture: annotations["lupetto.apk.architecture"], Annotations: annotations}
	created, err := time.Parse(time.RFC3339Nano, annotations["org.opencontainers.image.created"])
	_, offset := created.Zone()
	if manifest.SchemaVersion != 2 || !wolfi.PackageNamePattern.MatchString(image.Name) || !validExactVersion(image.Version) ||
		(image.Architecture != "x86_64" && image.Architecture != "aarch64") || !shaPattern.MatchString(annotations["lupetto.index.sha256"]) ||
		annotations["org.opencontainers.image.version"] != image.Version || err != nil || offset != 0 {
		return Image{}, "unidentified"
	}
	image.Created = created.UTC()
	return image, "image"
}

func validExactVersion(version string) bool {
	if !exactVersionPattern.MatchString(version) {
		return false
	}
	_, err := apkcompare.ParseVersion(version)
	return err == nil
}

func imageLayerType(mediaType types.MediaType) bool {
	return mediaType == types.OCILayer || mediaType == types.OCILayerZStd || mediaType == types.OCIUncompressedLayer || mediaType == types.DockerLayer || mediaType == types.DockerUncompressedLayer || mediaType == types.OCIRestrictedLayer || mediaType == types.OCIUncompressedRestrictedLayer || mediaType == types.DockerForeignLayer
}

func verifyDigest(data []byte, digest string) bool { return digest == "sha256:"+wolfi.SHA256Hex(data) }

func isMissingRepository(err error) bool {
	var failure *transport.Error
	return errors.As(err, &failure) && failure.StatusCode == http.StatusNotFound
}

func safeRegistryError(ctx context.Context, stage string, err error) error {
	var sanitized *registry.StageError
	if errors.As(err, &sanitized) {
		return sanitized
	}
	return registry.SafeError(ctx, stage, err)
}
