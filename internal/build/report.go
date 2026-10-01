package build

import (
	"context"
	"fmt"
)

// Reporter receives pipeline stage names and live tool diagnostics. The CLI's
// terminal renderer implements it; the pipeline never depends on presentation.
type Reporter interface {
	Stage(stage string)
	// Write receives live diagnostics; a failing reporter must not fail a tool.
	Write(data []byte) (int, error)
}

type reporterKey struct{}

// WithReporter attaches a reporter to the pipeline context.
func WithReporter(ctx context.Context, reporter Reporter) context.Context {
	return context.WithValue(ctx, reporterKey{}, reporter)
}

// ReporterFrom returns the context's reporter, or nil. Presentation stays in
// the CLI context; direct pipeline callers need no reporter.
func ReporterFrom(ctx context.Context) Reporter {
	reporter, _ := ctx.Value(reporterKey{}).(Reporter)
	return reporter
}

func buildStage(ctx context.Context, stage string) {
	if reporter := ReporterFrom(ctx); reporter != nil {
		reporter.Stage(stage)
	}
}

func buildMessage(ctx context.Context, format string, args ...any) {
	if reporter := ReporterFrom(ctx); reporter != nil {
		reporter.Write([]byte("lupetto: " + fmt.Sprintf(format, args...) + "\n"))
	}
}
