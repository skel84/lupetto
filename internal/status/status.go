package status

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	apkcompare "chainguard.dev/apko/pkg/apk/apk"
	"lupetto/internal/registry"
	"lupetto/internal/wolfi"
)

type Options = registry.PublicationOptions

type Services struct {
	ReadIndex    func(context.Context, string) ([]wolfi.Package, string, error)
	ReadSecurity func(context.Context) (SecurityFeed, string, error)
	Registry     RegistryReader
	Now          func() time.Time
	Cache        InstalledCache
	Architecture string
}

func ValidateOptions(options Options) error {
	if err := registry.ValidatePublicationOptions(options); err != nil {
		return err
	}
	if !options.Enabled() {
		return errors.New("status requires registry and repository")
	}
	return nil
}

func Run(ctx context.Context, products Products, options Options) (Document, error) {
	return RunWith(ctx, products, options, Services{})
}

// RunWith returns a computed document even when individual tracks fail. Only
// global prerequisites/cancellation return an error; CLI invocation validation
// remains separate, allowing its exit-2/no-document contract.
func RunWith(ctx context.Context, products Products, options Options, services Services) (Document, error) {
	if err := ValidateProducts(products); err != nil {
		return Document{}, err
	}
	if err := ValidateOptions(options); err != nil {
		return Document{}, err
	}
	if services.Architecture == "" {
		arch, err := wolfi.TargetArch()
		if err != nil {
			return Document{}, err
		}
		services.Architecture = arch
	}
	if services.Architecture != "x86_64" && services.Architecture != "aarch64" {
		return Document{}, errors.New("unsupported status architecture")
	}
	if services.ReadIndex == nil {
		services.ReadIndex = wolfi.ReadIndex
	}
	if services.ReadSecurity == nil {
		services.ReadSecurity = ReadSecurity
	}
	if services.Registry == nil {
		services.Registry = RemoteRegistry{}
	}
	if services.Now == nil {
		services.Now = time.Now
	}
	if services.Cache == nil {
		cache, err := defaultCache()
		if err != nil {
			return Document{}, err
		}
		services.Cache = cache
	}
	packages, indexSHA, err := services.ReadIndex(ctx, services.Architecture)
	if err != nil {
		return Document{}, globalError(ctx, "signed index read failed")
	}
	feed, securitySHA, err := services.ReadSecurity(ctx)
	if err != nil {
		return Document{}, globalError(ctx, "security feed read failed")
	}
	latestByIdentity, err := latestPackages(packages)
	if err != nil {
		return Document{}, err
	}
	document := Document{Version: Version, Kind: "status", ComputedAt: services.Now().UTC(), Architecture: services.Architecture,
		Registry: options.Registry, Repository: options.Repository, IndexSHA256: indexSHA,
		Security: SecuritySource{URL: SecurityURL, SHA256: securitySHA, Unsigned: true, FixedOnly: true, WolfiOnly: true}, Tracks: []Track{}}
	document.Security.UnevaluatedFixes = unevaluatedSecurity(feed)
	document.Security.UnevaluatedFixCount = len(document.Security.UnevaluatedFixes)
	listings := map[string]RegistryListing{}
	listingErrors := map[string]error{}
	installedSets := map[string][]wolfi.InstalledPackage{}
	for _, product := range products.Products {
		for _, selector := range product.Selectors {
			track := Track{Package: product.Package, Selector: selector, State: NotBuilt, Images: []Image{}, Installed: []Identity{}, Outdated: []OutdatedPackage{}, MissingFixes: []MissingFix{}, UnevaluatedFixes: []UnevaluatedFix{}}
			selected, err := wolfi.SelectPackage(packages, product.Package, selector, "", services.Architecture)
			if err != nil {
				track.State, track.Error = Error, "unavailable index version for track"
				if strings.Contains(err.Error(), "ambiguous") {
					track.Error = "ambiguous index providers for track"
				}
				document.Tracks = append(document.Tracks, track)
				continue
			}
			track.Latest = &Identity{Name: selected.Name, Version: selected.Version, Architecture: selected.Arch}
			repository, err := registry.Repository(options, selected.Name)
			if err != nil {
				track.State, track.Error = Error, "invalid status repository for track"
				document.Tracks = append(document.Tracks, track)
				continue
			}
			track.Repository = repository.Name()
			listing, known := listings[repository.Name()]
			if !known {
				listing, err = services.Registry.List(ctx, repository)
				listings[repository.Name()], listingErrors[repository.Name()] = listing, err
			}
			track.ArtifactCount, track.UnidentifiedCount = listing.ArtifactCount, listing.UnidentifiedCount
			if err := listingErrors[repository.Name()]; err != nil {
				track.State, track.Error = Error, safeRegistryError(ctx, "registry listing", err).Error()
				document.Tracks = append(document.Tracks, track)
				continue
			}
			for _, image := range listing.Images {
				if image.Name == selected.Name && image.Architecture == services.Architecture && matchesSelector(image.Version, selector) {
					track.Images = append(track.Images, image)
				}
			}
			sort.Slice(track.Images, func(i, j int) bool { return imageNewer(track.Images[i], track.Images[j]) })
			if len(track.Images) == 0 {
				document.Tracks = append(document.Tracks, track)
				continue
			}
			track.Newest = &track.Images[0]
			installed, known := installedSets[track.Newest.Digest]
			if !known {
				var cached bool
				installed, cached, err = services.Cache.Load(ctx, track.Newest.Digest)
				if err != nil {
					track.State, track.Error = Error, "installed cache read failed"
				} else {
					if !cached {
						installed, err = services.Registry.Installed(ctx, repository, *track.Newest)
					}
					if err != nil {
						track.State, track.Error = Error, safeRegistryError(ctx, "installed image read", err).Error()
					} else if err = validateInstalled(installed, services.Architecture); err != nil {
						track.State, track.Error = Error, "invalid installed APK identity set"
					} else if !hasTopLevel(installed, *track.Newest) {
						track.State, track.Error = Error, "installed top-level APK does not match image annotations"
					} else {
						if !cached {
							err = services.Cache.Store(ctx, track.Newest.Digest, installed)
						}
						if err != nil {
							track.State, track.Error = Error, "installed cache write failed"
						} else {
							installedSets[track.Newest.Digest] = installed
						}
					}
				}
			}
			if track.State == Error {
				document.Tracks = append(document.Tracks, track)
				continue
			}
			for _, pkg := range installed {
				track.Installed = append(track.Installed, Identity{Name: pkg.Name, Version: pkg.Version, Architecture: pkg.Arch})
			}
			sort.Slice(track.Installed, func(i, j int) bool {
				if track.Installed[i].Name != track.Installed[j].Name {
					return track.Installed[i].Name < track.Installed[j].Name
				}
				return track.Installed[i].Architecture < track.Installed[j].Architecture
			})
			track.Outdated, track.MissingFixes = compareInstalled(installed, latestByIdentity, feed)
			for _, issue := range document.Security.UnevaluatedFixes {
				for _, pkg := range track.Installed {
					if issue.Name != pkg.Name {
						continue
					}
					installedIssue := issue
					installedIssue.InstalledVersion, installedIssue.Architecture = pkg.Version, pkg.Architecture
					track.UnevaluatedFixes = append(track.UnevaluatedFixes, installedIssue)
				}
			}
			reachableFix := false
			for i := range track.MissingFixes {
				fix := &track.MissingFixes[i]
				fix.ReachableByTrack = fix.Name != selected.Name || compareVersion(fix.FixedVersion, selected.Version) <= 0
				reachableFix = reachableFix || fix.ReachableByTrack
			}
			track.State = Current
			comparison := compareVersion(selected.Version, track.Newest.Version)
			if comparison > 0 {
				track.State = UpdateAvailable
			} else if comparison < 0 {
				track.State, track.Error = Error, "newest image top-level version is newer than current index selection"
			} else if reachableFix {
				track.State = FixesAvailable
			}
			document.Tracks = append(document.Tracks, track)
		}
	}
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func globalError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}

func hasTopLevel(packages []wolfi.InstalledPackage, image Image) bool {
	for _, pkg := range packages {
		if pkg.Name == image.Name && pkg.Version == image.Version && pkg.Arch == image.Architecture {
			return true
		}
	}
	return false
}

func matchesSelector(version, selector string) bool {
	// Reuse the build resolver's leading upstream numeric component matching.
	_, err := wolfi.SelectPackage([]wolfi.Package{{Name: "selected", Version: version, Arch: "x86_64", Checksum: "image"}}, "selected", selector, "", "x86_64")
	return err == nil
}

func compareVersion(left, right string) int {
	a, _ := apkcompare.ParseVersion(left)
	b, _ := apkcompare.ParseVersion(right)
	return apkcompare.CompareVersions(a, b)
}

func imageNewer(left, right Image) bool {
	if comparison := compareVersion(left.Version, right.Version); comparison != 0 {
		return comparison > 0
	}
	if !left.Created.Equal(right.Created) {
		return left.Created.After(right.Created)
	}
	return left.Digest < right.Digest
}

func latestPackages(packages []wolfi.Package) (map[string]wolfi.Package, error) {
	latest := map[string]wolfi.Package{}
	for _, pkg := range packages {
		if _, err := apkcompare.ParseVersion(pkg.Version); err != nil {
			return nil, errors.New("invalid index APK version")
		}
		key := pkg.Name + "\x00" + pkg.Arch
		previous, exists := latest[key]
		if !exists || compareVersion(pkg.Version, previous.Version) > 0 {
			latest[key] = pkg
		}
	}
	return latest, nil
}

func compareInstalled(installed []wolfi.InstalledPackage, latest map[string]wolfi.Package, feed SecurityFeed) ([]OutdatedPackage, []MissingFix) {
	outdated, fixes := []OutdatedPackage{}, []MissingFix{}
	for _, pkg := range installed {
		available, exists := latest[pkg.Name+"\x00"+pkg.Arch]
		if !exists {
			continue
		}
		if compareVersion(available.Version, pkg.Version) > 0 {
			outdated = append(outdated, OutdatedPackage{Name: pkg.Name, Architecture: pkg.Arch, InstalledVersion: pkg.Version, LatestVersion: available.Version})
		}
		for fixed, identifiers := range feed[pkg.Name] {
			if fixed == "0" {
				continue
			}
			if _, err := apkcompare.ParseVersion(fixed); err != nil {
				continue
			}
			if compareVersion(fixed, pkg.Version) <= 0 || compareVersion(available.Version, fixed) < 0 {
				continue
			}
			unique := map[string]bool{}
			ids := []string{}
			for _, id := range identifiers {
				if advisoryPattern.MatchString(id) && !unique[id] {
					unique[id] = true
					ids = append(ids, id)
				}
			}
			if len(ids) == 0 {
				continue
			}
			sort.Strings(ids)
			fixes = append(fixes, MissingFix{Name: pkg.Name, Architecture: pkg.Arch, InstalledVersion: pkg.Version, FixedVersion: fixed, AvailableVersion: available.Version, IDs: ids})
		}
	}
	sort.Slice(outdated, func(i, j int) bool {
		if outdated[i].Name != outdated[j].Name {
			return outdated[i].Name < outdated[j].Name
		}
		return outdated[i].Architecture < outdated[j].Architecture
	})
	sort.Slice(fixes, func(i, j int) bool {
		if fixes[i].Name != fixes[j].Name {
			return fixes[i].Name < fixes[j].Name
		}
		if fixes[i].Architecture != fixes[j].Architecture {
			return fixes[i].Architecture < fixes[j].Architecture
		}
		return compareVersion(fixes[i].FixedVersion, fixes[j].FixedVersion) < 0
	})
	return outdated, fixes
}
