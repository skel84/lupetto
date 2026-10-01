package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"lupetto/internal/build"
	"lupetto/internal/registry"
	"lupetto/internal/status"
)

const statusUsage = "\n\nRead-only registry comparison:\n  lupetto status --products <file> [--registry <authority> --repository <prefix>] [--json] [--severity-budget <duration>]\nStatus requires both registry/repository settings, reusing independent flag/LUPETTO_* environment precedence.\nProducts YAML version 1 lists package names/providers and dotted numeric selectors; unknown fields are rejected.\nStatus --json prints a kind=status, version=2 document with index, image, installed-package, and severity-enriched security-fix facts.\nSeverity fetching defaults to 20s; --severity-budget 0 uses cache only (otherwise use a Go duration, e.g. 10s).\nStatus reads only; it never builds, publishes, signs, or loads Docker.\nThe Wolfi security feed is unsigned HTTPS and lists fixed vulnerabilities only, not a vulnerability scan.\nStatus exit 0 means computed (including track errors/updates); invocation errors exit 2, global failures exit 1."

type statusRequest struct {
	products         string
	json             bool
	publicationFlags registry.PublicationFlags
	severityBudget   time.Duration
	severitySet      bool
}

func parseStatus(args []string) (statusRequest, error) {
	request := statusRequest{severityBudget: status.DefaultSeverityBudget}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" {
			if request.json {
				return statusRequest{}, fmt.Errorf("--json may be specified only once")
			}
			request.json = true
			continue
		}
		flag, value, inline := strings.Cut(arg, "=")
		switch flag {
		case "--products", "--registry", "--repository", "--severity-budget":
			if (flag == "--products" && request.products != "") || (flag == "--registry" && request.publicationFlags.Registry.Set) || (flag == "--repository" && request.publicationFlags.Repository.Set) || (flag == "--severity-budget" && request.severitySet) {
				return statusRequest{}, fmt.Errorf("%s may be specified only once", flag)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return statusRequest{}, fmt.Errorf("%s requires a value", flag)
				}
				value = args[i]
			}
			if value == "" {
				return statusRequest{}, fmt.Errorf("%s must not be empty", flag)
			}
			switch flag {
			case "--products":
				request.products = value
			case "--registry":
				request.publicationFlags.Registry = registry.OptionalString{Value: value, Set: true}
			case "--repository":
				request.publicationFlags.Repository = registry.OptionalString{Value: value, Set: true}
			case "--severity-budget":
				budget, err := time.ParseDuration(value)
				if err != nil || budget < 0 || budget > 5*time.Minute {
					return statusRequest{}, fmt.Errorf("--severity-budget must be a duration from 0 to 5m")
				}
				request.severityBudget, request.severitySet = budget, true
			}
		default:
			return statusRequest{}, fmt.Errorf("status accepts only --products, --registry, --repository, --severity-budget, and --json")
		}
	}
	if request.products == "" {
		return statusRequest{}, fmt.Errorf("status requires --products <file>")
	}
	return request, nil
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runStatusWith(ctx, args, stdout, stderr, status.Run)
}

func runStatusWith(ctx context.Context, args []string, stdout, stderr io.Writer, compute func(context.Context, status.Products, status.Options) (status.Document, error)) int {
	request, err := parseStatus(args)
	var publication registry.PublicationOptions
	if err == nil {
		publication, err = registry.ResolvePublication(request.publicationFlags, os.LookupEnv)
	}
	options := status.Options{Registry: publication.Registry, Repository: publication.Repository}
	if err == nil {
		err = status.ValidateOptions(options)
	}
	var products status.Products
	if err == nil {
		products, err = status.LoadProducts(request.products)
	}
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(err.Error()))
		return 2
	}
	document, err := compute(status.WithSeverityBudget(ctx, request.severityBudget), products, options)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(err.Error()))
		return 1
	}
	if request.json {
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "lupetto: could not write JSON status")
			return 1
		}
		if !writeJSONRecord(stdout, stderr, append(encoded, '\n')) {
			return 1
		}
		return 0
	}
	if err := writeStatusTable(stdout, document); err != nil {
		fmt.Fprintln(stderr, "lupetto: could not write status")
		return 1
	}
	return 0
}

func writeStatusTable(out io.Writer, document status.Document) error {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "PACKAGE\tSELECTOR\tSTATE\tINDEX\tBUILT\tOUTDATED\tFIXES\tUNEVALUATED\tCRITICAL\tHIGH\tMEDIUM\tLOW\tUNKNOWN"); err != nil {
		return err
	}
	for _, track := range document.Tracks {
		latest, built := "-", "-"
		if track.Latest != nil {
			latest = track.Latest.Version
		}
		if track.Newest != nil {
			built = track.Newest.Version
		}
		counts := trackSeverityCounts(track)
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", build.PlainText(track.Package), build.PlainText(track.Selector), build.PlainText(track.State), build.PlainText(latest), build.PlainText(built), len(track.Outdated), len(track.MissingFixes), len(track.UnevaluatedFixes), counts["critical"], counts["high"], counts["medium"], counts["low"], counts["unknown"]); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	for _, track := range document.Tracks {
		if track.Error != "" {
			if _, err := fmt.Fprintf(out, "%s %s: %s\n", build.PlainText(track.Package), build.PlainText(track.Selector), build.PlainText(track.Error)); err != nil {
				return err
			}
		}
	}
	if document.Security.UnevaluatedFixCount > 0 {
		if _, err := fmt.Fprintf(out, "WARNING: %d security fixed-version entries could not be evaluated; no APK version ordering was guessed.\n", document.Security.UnevaluatedFixCount); err != nil {
			return err
		}
		for _, fix := range document.Security.UnevaluatedFixes {
			if _, err := fmt.Fprintf(out, "  %s fixed-version %s: %s\n", build.PlainText(fix.Name), build.PlainText(fix.FixedVersion), build.PlainText(strings.Join(fix.IDs, ", "))); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(out, "Severity: %d resolved / %d advisory IDs; %d unknown (%d pending); %d fetch failures (non-fatal).\n", document.Security.Severity.ResolvedCount, document.Security.Severity.IDCount, document.Security.Severity.UnknownCount, document.Security.Severity.PendingCount, document.Security.Severity.FetchFailureCount); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "Computed: %s; APKINDEX sha256:%s (%s)\nSecurity feed sha256:%s (unsigned HTTPS; fixed Wolfi vulnerabilities only, not a vulnerability scan)\n", document.ComputedAt, document.IndexSHA256, document.Architecture, document.Security.SHA256)
	return err
}

func trackSeverityCounts(track status.Track) map[string]int {
	seen := map[string]string{}
	for _, fix := range track.MissingFixes {
		for _, advisory := range fix.Advisories {
			seen[advisory.ID] = advisory.Severity
		}
	}
	for _, fix := range track.UnevaluatedFixes {
		for _, advisory := range fix.Advisories {
			seen[advisory.ID] = advisory.Severity
		}
	}
	counts := map[string]int{}
	for _, severity := range seen {
		counts[severity]++
	}
	return counts
}
