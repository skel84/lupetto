package registry

import (
	"strings"
	"testing"

	"github.com/distribution/reference"
)

func TestRepositoryMatchesPublicationComponent(t *testing.T) {
	for _, authority := range []string{"registry.example.invalid", "docker.io", "localhost:5000", "127.0.0.2:5000", "[::1]:5000"} {
		for _, apkName := range []string{"nginx-stable", "Package+extra", "apk-sha256-literal", strings.Repeat("p", 238)} {
			t.Run(authority+"/"+apkName, func(t *testing.T) {
				opts := PublicationOptions{Registry: authority, Repository: "team/nested/images"}
				repository, err := Repository(opts, apkName)
				if err != nil {
					t.Fatal(err)
				}
				target, err := PublicationReferences(apkName, "1.2-r3", "x86_64", "/cache/image-123", opts)
				if err != nil {
					t.Fatal(err)
				}
				if repository.Name() != target.Tag.Context().Name() || repository.RepositoryStr() != opts.Repository+"/"+APKComponent(apkName) {
					t.Fatalf("read repository %q differs from publication %q", repository.Name(), target.Repository)
				}
				if AuthorityIsLoopback(authority) && repository.Registry.Scheme() != "http" {
					t.Fatal("loopback repository lost publication HTTP fallback")
				}
			})
		}
	}
}

func TestRepositoryRejectsInvalidSettingsAndNormalization(t *testing.T) {
	for _, opts := range []PublicationOptions{
		{},
		{Registry: "registry.example.invalid"},
		{Repository: "team/images"},
		{Registry: "https://registry.example.invalid", Repository: "team/images"},
		{Registry: "registry.example.invalid", Repository: "Team/images"},
		{Registry: "registry.example.invalid", Repository: "team//images"},
		{Registry: "index.docker.io", Repository: "team/images"},
		{Registry: "registry.example.invalid", Repository: strings.Repeat("p", reference.RepositoryNameTotalLengthMax-30)},
	} {
		if _, err := Repository(opts, "nginx-stable"); err == nil {
			t.Fatalf("accepted invalid or normalized repository: %+v", opts)
		}
	}
}
