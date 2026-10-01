package status

import (
	"context"
	"time"
)

const DefaultSeverityBudget = 20 * time.Second

type severityBudgetKey struct{}

// WithSeverityBudget changes only optional advisory enrichment, never comparison.
func WithSeverityBudget(ctx context.Context, budget time.Duration) context.Context {
	return context.WithValue(ctx, severityBudgetKey{}, budget)
}

func enrichSeverity(ctx context.Context, document *Document, resolver *SeverityResolver, budget time.Duration) {
	groups := [][]string{}
	for _, fix := range document.Security.UnevaluatedFixes {
		groups = append(groups, fix.IDs)
	}
	for _, track := range document.Tracks {
		for _, fix := range track.MissingFixes {
			groups = append(groups, fix.IDs)
		}
		for _, fix := range track.UnevaluatedFixes {
			groups = append(groups, fix.IDs)
		}
	}
	results := resolver.Resolve(ctx, groups, budget)
	summary := SeveritySummary{IDCount: len(results), SourceCounts: map[string]int{}, FetchFailureCount: resolver.Stats().FetchFailureCount}
	for _, result := range results {
		summary.SourceCounts[result.SeveritySource]++
		if result.Severity == "unknown" {
			summary.UnknownCount++
		} else {
			summary.ResolvedCount++
		}
		if result.SeveritySource == "pending" {
			summary.PendingCount++
		}
	}
	document.Security.Severity = summary
	for i := range document.Security.UnevaluatedFixes {
		fix := &document.Security.UnevaluatedFixes[i]
		fix.Advisories, fix.MaxSeverity = severityAdvisories(fix.IDs, results)
	}
	for i := range document.Tracks {
		track := &document.Tracks[i]
		for j := range track.MissingFixes {
			fix := &track.MissingFixes[j]
			fix.Advisories, fix.MaxSeverity = severityAdvisories(fix.IDs, results)
		}
		for j := range track.UnevaluatedFixes {
			fix := &track.UnevaluatedFixes[j]
			fix.Advisories, fix.MaxSeverity = severityAdvisories(fix.IDs, results)
		}
	}
}

func severityAdvisories(ids []string, results map[string]SeverityResult) ([]Advisory, string) {
	advisories := make([]Advisory, 0, len(ids))
	maxSeverity := "unknown"
	for _, id := range ids {
		result, ok := results[id]
		if !ok {
			result = SeverityResult{Severity: "unknown", SeveritySource: "none"}
		}
		advisories = append(advisories, Advisory{ID: id, Severity: result.Severity, SeveritySource: result.SeveritySource})
		if severityOrder(result.Severity) > severityOrder(maxSeverity) {
			maxSeverity = result.Severity
		}
	}
	return advisories, maxSeverity
}

func severityOrder(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
