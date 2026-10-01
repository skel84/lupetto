package status

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const maxSeverityResponseBytes = 2 << 20

var severityIDPattern = regexp.MustCompile(`^(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-[0-9]{4}-[0-9]{4,})$`)

// SeverityResult is advisory metadata, not a vulnerability scan or a status verdict.
type SeverityResult struct {
	Severity       string `json:"severity"`
	SeveritySource string `json:"severitySource"`
}

// SeverityResolverStats describes the last completed Resolve call, without
// retaining upstream errors, response bodies, request URLs or credentials.
type SeverityResolverStats struct {
	FetchFailureCount int
}

// SeverityResolverOptions permits hermetic endpoint, clock and rate-limit tests.
// Empty fields select production defaults. CacheDirectory is the private cache
// directory itself. A negative NVDInterval disables spacing for fake endpoints;
// production NVD requests always retain the minimum spacing for their key mode.
type SeverityResolverOptions struct {
	HTTPClient     *http.Client
	NVDURL         string
	OSVURL         string
	GitHubURL      string
	CacheDirectory string
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
	NVDInterval    time.Duration
}

// SeverityResolver performs best-effort, bounded enrichment. Reuse it to retain
// NVD request spacing between calls. Its options are fixed at construction.
type SeverityResolver struct {
	client                    *http.Client
	nvdURL, osvURL, githubURL string
	cache                     severityCache
	now                       func() time.Time
	wait                      func(context.Context, time.Duration) error
	interval                  time.Duration
	apiKey                    string
	nvdGate                   chan struct{}
	nextNVD                   time.Time
	fetchFailures             atomic.Int64
}

func NewSeverityResolver() *SeverityResolver {
	return NewSeverityResolverWithOptions(SeverityResolverOptions{})
}

// Stats reports failed HTTP exchanges, excluding budget/context cancellation
// and skipped requests. Cache misses and rate-limit waits are not failures.
func (resolver *SeverityResolver) Stats() SeverityResolverStats {
	if resolver == nil {
		return SeverityResolverStats{}
	}
	return SeverityResolverStats{FetchFailureCount: int(resolver.fetchFailures.Load())}
}

func NewSeverityResolverWithOptions(options SeverityResolverOptions) *SeverityResolver {
	nvdURL := options.NVDURL
	if nvdURL == "" {
		nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	osvURL := options.OSVURL
	if osvURL == "" {
		osvURL = "https://api.osv.dev/v1/vulns"
	}
	githubURL := options.GitHubURL
	if githubURL == "" {
		githubURL = "https://api.github.com/advisories"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if options.HTTPClient != nil {
		copy := *options.HTTPClient
		client = &copy
	}
	// Do not forward the optional NVD key to a redirect destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout <= 0 || client.Timeout > 10*time.Second {
		client.Timeout = 10 * time.Second
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	wait := options.Wait
	if wait == nil {
		wait = severityWait
	}
	key := os.Getenv("NVD_API_KEY")
	interval := 6100 * time.Millisecond
	if key != "" {
		interval = 600 * time.Millisecond
	}
	if options.NVDInterval != 0 && options.NVDURL != "" && nvdURL != "https://services.nvd.nist.gov/rest/json/cves/2.0" {
		interval = options.NVDInterval
		if interval < 0 {
			interval = 0
		}
	} else if options.NVDInterval > interval {
		interval = options.NVDInterval
	}
	directory := options.CacheDirectory
	if directory == "" {
		if root, err := os.UserCacheDir(); err == nil {
			directory = filepath.Join(root, "lupetto", "status", "severity")
		}
	}
	return &SeverityResolver{client: client, nvdURL: nvdURL, osvURL: osvURL, githubURL: githubURL,
		cache: severityCache{directory: directory}, now: now, wait: wait, interval: interval,
		apiKey: key, nvdGate: make(chan struct{}, 1)}
}

func severityWait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func unknownSeverity() SeverityResult { return SeverityResult{"unknown", "none"} }
func pendingSeverity() SeverityResult { return SeverityResult{"unknown", "pending"} }
func knownSeverity(result SeverityResult) bool {
	return result.Severity != "unknown" && normalizeSeverity(result.Severity) != ""
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}

type severityRun struct {
	resolver      *SeverityResolver
	ctx           context.Context
	results       map[string]SeverityResult
	resolved      map[string]bool
	nvdStopped    bool
	fetchFailures int
	nvdResults    map[string]SeverityResult
	nvdComplete   map[string]bool
}

// Resolve returns every supplied ID. Unsupported IDs are unknown/none; supported
// uncached IDs that cannot be completed in budget are unknown/pending. A zero
// (or negative) budget reads the cache without network access. Groups provide
// IDs to deduplicate only: co-listed secdb fixes are not evidence of aliases.
// Network and cache failures never escape into the status comparison.
func (resolver *SeverityResolver) Resolve(ctx context.Context, groups [][]string, budget time.Duration) map[string]SeverityResult {
	if resolver == nil {
		resolver = NewSeverityResolver()
	}
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	results := make(map[string]SeverityResult)
	resolved := make(map[string]bool)
	for _, group := range groups {
		for _, id := range group {
			if _, exists := results[id]; !exists {
				results[id] = unknownSeverity()
				if severityIDPattern.MatchString(id) {
					results[id] = pendingSeverity()
					if cached, ok := resolver.cache.load(id, resolver.now()); ok {
						results[id], resolved[id] = cached, true
					}
				} else {
					resolved[id] = true
				}
			}
		}
	}
	run := &severityRun{resolver: resolver, ctx: ctx, results: results, resolved: resolved}
	defer func() { resolver.fetchFailures.Store(int64(run.fetchFailures)) }()
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	// Resolve advisory-owned sources before standalone NVD requests so the
	// NVD spacing does not consume the entire budget before GHSA enrichment.
	sort.Slice(ids, func(i, j int) bool {
		ci, cj := strings.HasPrefix(ids[i], "CVE-"), strings.HasPrefix(ids[j], "CVE-")
		if ci != cj {
			return !ci
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids {
		if !resolved[id] && budget > 0 && ctx.Err() == nil {
			run.resolve(id)
		}
	}
	// OSV aliases may be fetched internally but are not extra output IDs.
	output := make(map[string]SeverityResult, len(ids))
	for _, id := range ids {
		output[id] = results[id]
	}
	return output
}

func (run *severityRun) record(id string, result SeverityResult) SeverityResult {
	// Preserve fetchedAt when reusing a resolved result.
	if run.resolved[id] && run.results[id] == result {
		return result
	}
	run.results[id], run.resolved[id] = result, true
	if result.SeveritySource != "pending" {
		run.resolver.cache.store(id, result, run.resolver.now())
	}
	return result
}

func (run *severityRun) resolve(id string) SeverityResult {
	if run.resolved[id] {
		return run.results[id]
	}
	if run.ctx.Err() != nil {
		return pendingSeverity()
	}
	if cached, ok := run.resolver.cache.load(id, run.resolver.now()); ok {
		run.results[id], run.resolved[id] = cached, true
		return cached
	}
	if strings.HasPrefix(id, "CVE-") {
		result, nvdOK := run.nvd(id)
		if knownSeverity(result) {
			return run.record(id, result)
		}
		advisory, osvOK := run.osv(id)
		if severity := normalizeSeverity(advisory.DatabaseSpecific.Severity); severity != "" {
			return run.record(id, SeverityResult{severity, "osv"})
		}
		if nvdOK && osvOK {
			return run.record(id, unknownSeverity())
		}
		return run.record(id, pendingSeverity())
	}
	advisory, osvOK := run.osv(id)
	ownSeverity := normalizeSeverity(advisory.DatabaseSpecific.Severity)
	if strings.HasPrefix(id, "GHSA-") {
		// The advisory's own severity takes precedence over a true CVE alias.
		if ownSeverity != "" {
			return run.record(id, SeverityResult{ownSeverity, "osv"})
		}
		github, githubOK := run.github(id)
		if severity := normalizeSeverity(github.Severity); severity != "" {
			return run.record(id, SeverityResult{severity, "ghsa"})
		}
		result, osvAliasesOK := run.cveAliases(advisory.Aliases, "osv-alias")
		if knownSeverity(result) {
			return run.record(id, result)
		}
		result, githubAliasesOK := run.cveAliases([]string{github.CVEID}, "ghsa-alias")
		if knownSeverity(result) {
			return run.record(id, result)
		}
		if osvOK && githubOK && osvAliasesOK && githubAliasesOK && run.ctx.Err() == nil {
			return run.record(id, unknownSeverity())
		}
		return run.record(id, pendingSeverity())
	}
	// Go advisories use only true aliases from their OSV record. Resolve
	// CVEs first, then GHSA advisories through their own severity sources.
	result, aliasesOK := run.cveAliases(advisory.Aliases, "osv-alias")
	if knownSeverity(result) {
		return run.record(id, result)
	}
	sort.Strings(advisory.Aliases)
	for _, alias := range advisory.Aliases {
		if !strings.HasPrefix(alias, "GHSA-") || !severityIDPattern.MatchString(alias) {
			continue
		}
		aliased := run.resolve(alias)
		aliasesOK = aliasesOK && aliased.SeveritySource != "pending"
		if knownSeverity(aliased) {
			return run.record(id, SeverityResult{aliased.Severity, "osv-alias:" + alias})
		}
	}
	if osvOK && aliasesOK && run.ctx.Err() == nil {
		return run.record(id, unknownSeverity())
	}
	return run.record(id, pendingSeverity())
}

func (run *severityRun) cveAliases(aliases []string, source string) (SeverityResult, bool) {
	sort.Strings(aliases)
	complete := true
	for _, alias := range aliases {
		if !strings.HasPrefix(alias, "CVE-") || !severityIDPattern.MatchString(alias) {
			continue
		}
		result, resolved := run.nvdAlias(alias)
		complete = complete && resolved
		if knownSeverity(result) {
			return SeverityResult{result.Severity, source + ":" + alias}, true
		}
	}
	return SeverityResult{}, complete
}

func (run *severityRun) nvdAlias(id string) (SeverityResult, bool) {
	// CVE alias inheritance is specifically an NVD path. A direct CVE's OSV
	// fallback must not silently become an advisory's NVD-alias severity.
	if result, ok := run.resolver.cache.load(id, run.resolver.now()); ok {
		if result.Severity == "unknown" || strings.HasPrefix(result.SeveritySource, "nvd-cvss-") {
			return result, true
		}
	}
	result, complete := run.nvd(id)
	if knownSeverity(result) {
		run.record(id, result)
	}
	return result, complete
}

type githubSeverityAdvisory struct {
	GHSAID   string `json:"ghsa_id"`
	CVEID    string `json:"cve_id"`
	Severity string `json:"severity"`
}

func (run *severityRun) github(id string) (githubSeverityAdvisory, bool) {
	var advisory githubSeverityAdvisory
	ok, _ := run.fetch(run.resolver.githubURL+"/"+url.PathEscape(id), false, &advisory)
	if !ok || (advisory.GHSAID != "" && advisory.GHSAID != id) {
		return githubSeverityAdvisory{}, false
	}
	return advisory, true
}

type osvSeverityAdvisory struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (run *severityRun) osv(id string) (osvSeverityAdvisory, bool) {
	var advisory osvSeverityAdvisory
	ok, _ := run.fetch(run.resolver.osvURL+"/"+url.PathEscape(id), false, &advisory)
	if !ok {
		return osvSeverityAdvisory{}, false
	}
	if advisory.ID != "" && advisory.ID != id {
		return osvSeverityAdvisory{}, false
	}
	return advisory, ok
}

type nvdSeverityMetric struct {
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssData"`
}

func (run *severityRun) nvd(id string) (result SeverityResult, complete bool) {
	if previous, exists := run.nvdResults[id]; exists {
		return previous, run.nvdComplete[id]
	}
	if run.nvdResults == nil {
		run.nvdResults = make(map[string]SeverityResult)
		run.nvdComplete = make(map[string]bool)
	}
	defer func() { run.nvdResults[id], run.nvdComplete[id] = result, complete }()
	resolver := run.resolver
	if run.nvdStopped || run.ctx.Err() != nil {
		return unknownSeverity(), false
	}
	select {
	case resolver.nvdGate <- struct{}{}:
	case <-run.ctx.Done():
		return unknownSeverity(), false
	}
	defer func() { <-resolver.nvdGate }()
	if delay := resolver.nextNVD.Sub(resolver.now()); delay > 0 {
		if resolver.wait(run.ctx, delay) != nil {
			return unknownSeverity(), false
		}
	}
	if run.ctx.Err() != nil {
		return unknownSeverity(), false
	}
	endpoint, err := url.Parse(resolver.nvdURL)
	if err != nil {
		return unknownSeverity(), false
	}
	query := endpoint.Query()
	query.Set("cveId", id)
	endpoint.RawQuery = query.Encode()
	resolver.nextNVD = resolver.now().Add(resolver.interval)
	var response struct {
		Vulnerabilities []struct {
			CVE struct {
				ID      string                         `json:"id"`
				Metrics map[string][]nvdSeverityMetric `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	ok, code := run.fetch(endpoint.String(), true, &response)
	if code == http.StatusForbidden || code == http.StatusTooManyRequests {
		run.nvdStopped = true
	}
	if !ok {
		return unknownSeverity(), false
	}
	for _, entry := range response.Vulnerabilities {
		if entry.CVE.ID != id {
			continue
		}
		for _, version := range []struct{ key, source string }{
			{"cvssMetricV40", "nvd-cvss-v4.0"}, {"cvssMetricV31", "nvd-cvss-v3.1"},
			{"cvssMetricV30", "nvd-cvss-v3.0"}, {"cvssMetricV2", "nvd-cvss-v2"},
		} {
			for _, primary := range []bool{true, false} {
				for _, metric := range entry.CVE.Metrics[version.key] {
					if (metric.Type == "Primary") != primary {
						continue
					}
					value := metric.CVSSData.BaseSeverity
					if version.key == "cvssMetricV2" {
						value = metric.BaseSeverity
					}
					if severity := normalizeSeverity(value); severity != "" {
						return SeverityResult{severity, version.source}, true
					}
				}
			}
		}
	}
	return unknownSeverity(), true
}

func (run *severityRun) fetch(endpoint string, nvd bool, target any) (bool, int) {
	if run.ctx.Err() != nil {
		return false, 0
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false, 0
	}
	if parsed.Scheme != "https" {
		// Only explicitly configured loopback fake endpoints may use HTTP.
		ip := net.ParseIP(parsed.Hostname())
		if parsed.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return false, 0
		}
	}
	request, err := http.NewRequestWithContext(run.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, 0
	}
	request.Header.Set("Accept", "application/json")
	if nvd && run.resolver.apiKey != "" {
		request.Header.Set("apiKey", run.resolver.apiKey)
	}
	response, err := run.resolver.client.Do(request)
	if err != nil {
		if run.ctx.Err() == nil {
			run.fetchFailures++
		}
		return false, 0
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return true, response.StatusCode
	}
	if response.StatusCode != http.StatusOK {
		run.fetchFailures++
		return false, response.StatusCode
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSeverityResponseBytes+1))
	if err != nil || len(data) > maxSeverityResponseBytes || json.Unmarshal(data, target) != nil {
		if run.ctx.Err() == nil {
			run.fetchFailures++
		}
		return false, response.StatusCode
	}
	return true, response.StatusCode
}
