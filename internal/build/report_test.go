package build

import "io"

// lineReporter renders stages and diagnostics as plain log lines, like the
// CLI renderer on a non-terminal, for pipeline tests without the CLI.
type lineReporter struct{ output io.Writer }

func (r lineReporter) Stage(stage string) { r.output.Write([]byte("lupetto: " + stage + "\n")) }

func (r lineReporter) Write(data []byte) (int, error) {
	r.output.Write(data)
	return len(data), nil
}
