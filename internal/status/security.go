package status

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	apkcompare "chainguard.dev/apko/pkg/apk/apk"
	"lupetto/internal/wolfi"
)

const (
	SecurityURL         = "https://packages.wolfi.dev/os/security.json"
	MaxSecurityBytes    = 64 << 20
	MaxSecurityPackages = 100000
	MaxSecurityFixes    = 1000000
)

// SecurityFeed maps exact APK names to fixed APK versions and advisory IDs.
type SecurityFeed map[string]map[string][]string

var advisoryPattern = regexp.MustCompile(`^(?:CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-[0-9]{4}-[0-9]+)$`)

func ReadSecurity(ctx context.Context) (SecurityFeed, string, error) {
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return errors.New("security feed requires HTTPS")
		}
		return nil
	}}
	return readSecurityURL(ctx, client, SecurityURL)
}

func readSecurityURL(ctx context.Context, client *http.Client, url string) (SecurityFeed, string, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, "", errors.New("security feed requires HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", errors.New("security feed request failed")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", errors.New("security feed fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", errors.New("security feed fetch failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxSecurityBytes+1))
	if err != nil {
		return nil, "", errors.New("security feed read failed")
	}
	if len(data) > MaxSecurityBytes {
		return nil, "", errors.New("security feed exceeds 64 MiB")
	}
	feed, err := ParseSecurity(data)
	if err != nil {
		return nil, "", err
	}
	return feed, wolfi.SHA256Hex(data), nil
}

func ParseSecurity(data []byte) (SecurityFeed, error) {
	if len(data) > MaxSecurityBytes {
		return nil, errors.New("security feed exceeds 64 MiB")
	}
	var document struct {
		Packages []struct {
			Pkg struct {
				Name     string              `json:"name"`
				Secfixes map[string][]string `json:"secfixes"`
			} `json:"pkg"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &document); err != nil || document.Packages == nil {
		return nil, errors.New("invalid Wolfi security feed")
	}
	if len(document.Packages) > MaxSecurityPackages {
		return nil, errors.New("security feed package limit exceeded")
	}
	feed := SecurityFeed{}
	fixes := 0
	for _, entry := range document.Packages {
		pkg := entry.Pkg
		if !wolfi.PackageNamePattern.MatchString(pkg.Name) {
			return nil, errors.New("invalid security package name")
		}
		if _, exists := feed[pkg.Name]; exists {
			return nil, errors.New("duplicate security package")
		}
		feed[pkg.Name] = map[string][]string{}
		for version, ids := range pkg.Secfixes {
			fixes += 1 + len(ids)
			if fixes > MaxSecurityFixes {
				return nil, errors.New("security feed fix limit exceeded")
			}
			// secdb key 0 means not affected, not a fixed release.
			if version == "0" {
				continue
			}
			// Preserve unparseable versions and unrecognised-only advisory
			// entries for explicit unevaluated evidence, never silent omission.
			recognised := securityIDs(ids)
			if len(recognised) == 0 {
				feed[pkg.Name][version] = append([]string{}, ids...)
			} else {
				feed[pkg.Name][version] = recognised
			}
		}
	}
	return feed, nil
}

func securityIDs(ids []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if advisoryPattern.MatchString(id) && !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

func unevaluatedSecurity(feed SecurityFeed) []UnevaluatedFix {
	issues := []UnevaluatedFix{}
	for name, fixes := range feed {
		for version, ids := range fixes {
			if version == "0" {
				continue
			}
			recognised := securityIDs(ids)
			if _, err := apkcompare.ParseVersion(version); err != nil || len(recognised) == 0 {
				if len(recognised) == 0 {
					recognised = append([]string{}, ids...)
					sort.Strings(recognised)
					recognised = slices.Compact(recognised)
				}
				issues = append(issues, UnevaluatedFix{Name: name, FixedVersion: version, IDs: recognised})
			}
		}
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Name != issues[j].Name {
			return issues[i].Name < issues[j].Name
		}
		return issues[i].FixedVersion < issues[j].FixedVersion
	})
	return issues
}
