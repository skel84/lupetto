package explorer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxDocumentBytes = 32 << 20
	maxErrorBytes    = 64 << 10
	defaultLogBytes  = 1 << 20
)

var (
	packagePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$`)
	selectorPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)
	versionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
)

func ValidateBuild(request BuildRequest) error {
	if !validPackage(request.Package) {
		return errors.New("invalid package: use an APK name or provider, not a flag")
	}
	if (request.Selector == "") == (request.APKVersion == "") {
		return errors.New("provide exactly one selector or apkVersion")
	}
	if request.Selector != "" && (len(request.Selector) > 128 || !selectorPattern.MatchString(request.Selector)) {
		return errors.New("invalid selector: expected dotted numeric components")
	}
	if request.APKVersion != "" && (len(request.APKVersion) > 256 || !versionPattern.MatchString(request.APKVersion)) {
		return errors.New("invalid apkVersion: expected an exact APK version ending in -r<digits>")
	}
	if request.Mode != "" && request.Mode != "local" && request.Mode != "publish" {
		return errors.New("invalid build mode: choose local or publish")
	}
	return nil
}
func validPackage(name string) bool { return len(name) <= 256 && packagePattern.MatchString(name) }
func buildArgs(request BuildRequest) []string {
	args := []string{"build", request.Package}
	if request.Selector != "" {
		args = append(args, request.Selector)
	} else {
		args = append(args, "--apk-version", request.APKVersion)
	}
	if request.Mode != "local" {
		args = append(args, "--no-load")
	}
	return append(args, "--json")
}

type CLI struct {
	binary string
	grace  time.Duration
}

var errOutputLimit = errors.New("CLI JSON document exceeds 32 MiB limit")

func NewCLI(binary string) (*CLI, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("find configured lupetto binary: %w", err)
	}
	return &CLI{binary: path, grace: 5 * time.Second}, nil
}

// Lupetto main uses signal.NotifyContext for SIGINT and SIGTERM. SIGTERM lets
// it retain a failure record and cancel child commands; WaitDelay bounds grace.
func (c *CLI) execute(ctx context.Context, args []string, stderr io.Writer) ([]byte, int, error) {
	return c.executeMode(ctx, args, stderr, false)
}
func (c *CLI) executeMode(ctx context.Context, args []string, stderr io.Writer, local bool) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = c.grace
	stdout := &limitedOutput{limit: maxDocumentBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Local-only builds explicitly exclude publication/signing settings while
	// retaining Docker configuration and credentials. Never log environment.
	if local {
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			switch key {
			case "LUPETTO_REGISTRY", "LUPETTO_REPOSITORY", "LUPETTO_COSIGN_KEY", "LUPETTO_COSIGN_SIGNING_CONFIG", "LUPETTO_COSIGN_ALLOW_HTTP":
				continue
			}
			cmd.Env = append(cmd.Env, entry)
		}
	}
	err := cmd.Run()
	exit := -1
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	if stdout.exceeded {
		return nil, exit, errOutputLimit
	}
	return stdout.Bytes(), exit, err
}
func (c *CLI) Status(ctx context.Context, products string) (*StatusDocument, error) {
	stderr := newLogBuffer(maxErrorBytes)
	data, exit, err := c.execute(ctx, []string{"status", "--products", products, "--json"}, stderr)
	if err != nil {
		if errors.Is(err, errOutputLimit) {
			return nil, err
		}
		return nil, cliError("status", exit, stderr)
	}
	var document StatusDocument
	if err := decodeDocument(data, &document); err != nil {
		return nil, fmt.Errorf("incompatible lupetto CLI: status JSON: %w", err)
	}
	if document.Kind != "status" || document.Version != 2 {
		return nil, incompatible("status", document.Kind, document.Version, 2)
	}
	return &document, nil
}
func (c *CLI) Discover(ctx context.Context, name string) (*DiscoverDocument, error) {
	if name != "" && !validPackage(name) {
		return nil, errors.New("invalid package name")
	}
	args := []string{"discover", "--json"}
	if name != "" {
		args = append(args, name)
	}
	stderr := newLogBuffer(maxErrorBytes)
	data, exit, err := c.execute(ctx, args, stderr)
	if err != nil {
		if errors.Is(err, errOutputLimit) {
			return nil, err
		}
		return nil, cliError("discover", exit, stderr)
	}
	var document DiscoverDocument
	if err := decodeDocument(data, &document); err != nil {
		return nil, fmt.Errorf("incompatible lupetto CLI: discover JSON: %w", err)
	}
	if document.Kind != "discover" || document.Version != 1 {
		return nil, incompatible("discover", document.Kind, document.Version, 1)
	}
	return &document, nil
}
func incompatible(expected, kind string, version, wanted int) error {
	return fmt.Errorf("incompatible lupetto CLI: expected kind %q version %d; received kind %q version %d", expected, wanted, kind, version)
}
func decodeDocument(data []byte, document any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(document); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}
func parseRecord(data []byte) (*BuildRecord, error) {
	var header struct {
		Kind    string `json:"kind"`
		Version int    `json:"version"`
	}
	if err := decodeDocument(data, &header); err != nil {
		return nil, fmt.Errorf("incompatible lupetto CLI: build record JSON: %w", err)
	}
	if header.Kind != "" || header.Version != 6 {
		return nil, incompatible("build record (no kind)", header.Kind, header.Version, 6)
	}
	var record BuildRecord
	if err := decodeDocument(data, &record); err != nil {
		return nil, fmt.Errorf("incompatible lupetto CLI: build record: %w", err)
	}
	if record.Command != "build" || (record.Outcome != "succeeded" && record.Outcome != "failed") {
		return nil, errors.New("incompatible lupetto CLI: expected build command with succeeded or failed outcome")
	}
	return &record, nil
}
func cliError(command string, exit int, stderr *logBuffer) error {
	chunk := stderr.chunk(0)
	message := strings.TrimSpace(chunk.Text)
	if chunk.Truncated {
		message = "[stderr truncated] " + message
	}
	if message == "" {
		message = "no stderr diagnostic"
	}
	return fmt.Errorf("lupetto %s failed (exit %d): %s", command, exit, message)
}

// Do not embed bytes.Buffer: its promoted ReadFrom would let io.Copy bypass
// Write and the bound when os/exec drains the child's stdout pipe.
type limitedOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return n, nil // Drain pipes without retaining unbounded stdout.
}

type logBuffer struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	total     int64
	stage     int
	stageTail string
}

func newLogBuffer(limit int) *logBuffer { return &logBuffer{limit: limit} }
func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	b.total += int64(n)
	progress := b.stageTail + string(p)
	b.stage = max(b.stage, livePhase(progress))
	if len(progress) > 128 {
		progress = progress[len(progress)-128:]
	}
	b.stageTail = progress
	if n >= b.limit {
		b.data = append(b.data[:0], p[n-b.limit:]...)
	} else {
		if drop := len(b.data) + n - b.limit; drop > 0 {
			copy(b.data, b.data[drop:])
			b.data = b.data[:len(b.data)-drop]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *logBuffer) stages(mode string) []BuildStage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return liveStagesAt(b.stage, mode)
}
func (b *logBuffer) chunk(offset int64) LogChunk {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := b.total - int64(len(b.data))
	truncated := offset < start
	if offset < start {
		offset = start
	}
	if offset > b.total {
		offset = b.total
	}
	return LogChunk{Offset: offset, NextOffset: b.total, Text: string(b.data[offset-start:]), Truncated: truncated}
}
