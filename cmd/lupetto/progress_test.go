package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const helperLiveOutput = "\x1b[31mstdout diagnostic\x1b[0m\r\nstderr diagnostic\n"

// The helper writes diagnostics, then blocks on a parent-controlled socket.
// Receiving logs while that gate is shut proves delivery before process exit.
func TestMain(m *testing.M) {
	if os.Getenv("LUPETTO_PROGRESS_TEST_HELPER") == "1" {
		before, after := progressHelperOutput(filepath.Base(os.Args[0]), os.Args[1:])
		if before == helperLiveOutput {
			fmt.Fprint(os.Stdout, "\x1b[31mstdout diagnostic\x1b[0m\r\n")
			fmt.Fprint(os.Stderr, "stderr diagnostic\n")
		} else {
			fmt.Fprint(os.Stdout, before)
		}
		gate, err := net.Dial("tcp", os.Getenv("LUPETTO_PROGRESS_TEST_GATE"))
		if err != nil {
			os.Exit(90)
		}
		var release [1]byte
		if _, err := io.ReadFull(gate, release[:]); err != nil {
			os.Exit(91)
		}
		gate.Close()
		fmt.Fprint(os.Stdout, after)
		if os.Getenv("LUPETTO_PROGRESS_TEST_FAILURE") == "1" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func progressHelperOutput(executable string, args []string) (string, string) {
	if executable == "apko" && len(args) > 0 && args[0] == "version" {
		return "GitVersion:    " + apkoBuildVersion + "\n", ""
	}
	if executable == "docker" && len(args) > 1 && args[1] == "inspect" {
		return `{"Id":"sha256:` + strings.Repeat("a", 64) + `","Os":"linux","Architecture":"amd64"}` + "\n", ""
	}
	if executable == "docker" && len(args) > 1 && args[1] == "save" {
		return "internal save output\n", ""
	}
	return helperLiveOutput, "command completed\n"
}

type progressTestWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func newProgressTestWriter() *progressTestWriter {
	return &progressTestWriter{changed: make(chan struct{}, 1)}
}

func (w *progressTestWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(data)
	w.mu.Unlock()
	select {
	case w.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (w *progressTestWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func waitForProgress(t *testing.T, w *progressTestWriter, predicate func(string) bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !predicate(w.String()) {
		select {
		case <-w.changed:
		case <-deadline.C:
			t.Fatalf("timed out waiting for live progress: %q", w.String())
		}
	}
}

type progressCommandResult struct {
	output []byte
	err    error
}

type progressCommandFixture struct {
	cancel   context.CancelFunc
	progress *buildProgress
	gate     net.Conn
	result   <-chan progressCommandResult
}

func startProgressCommand(t *testing.T, executable string, args []string, output io.Writer, fail bool) *progressCommandFixture {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), executable)
	if err := os.Symlink(binary, tool); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUPETTO_PROGRESS_TEST_HELPER", "1")
	t.Setenv("LUPETTO_PROGRESS_TEST_GATE", listener.Addr().String())
	failure := "0"
	if fail {
		failure = "1"
	}
	t.Setenv("LUPETTO_PROGRESS_TEST_FAILURE", failure)
	ctx, cancel := context.WithCancel(context.Background())
	progress := newBuildProgress(ctx, output, false)
	ctx = context.WithValue(ctx, buildProgressKey{}, progress)
	result := make(chan progressCommandResult, 1)
	completed := make(chan struct{})
	go func() {
		captured, err := executeLocalCommand(ctx, tool, args...)
		result <- progressCommandResult{captured, err}
		close(completed)
	}()
	t.Cleanup(func() {
		cancel()
		progress.Close()
		select {
		case <-completed:
		case <-time.After(5 * time.Second):
			t.Error("helper command did not stop after cancellation")
		}
	})
	gate, err := listener.Accept()
	if err != nil {
		t.Fatalf("helper did not reach its completion gate: %v", err)
	}
	t.Cleanup(func() { gate.Close() })
	return &progressCommandFixture{cancel: cancel, progress: progress, gate: gate, result: result}
}

func (f *progressCommandFixture) release(t *testing.T) {
	t.Helper()
	if _, err := f.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
}

func (f *progressCommandFixture) completed(t *testing.T) progressCommandResult {
	t.Helper()
	select {
	case result := <-f.result:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("helper command did not complete")
		return progressCommandResult{}
	}
}

func TestLiveCommandDiagnosticsBeforeCompletion(t *testing.T) {
	for _, tc := range []struct {
		executable string
		args       []string
	}{
		{"apko", []string{"lock"}},
		{"apko", []string{"build"}},
		{"docker", []string{"image", "load"}},
	} {
		t.Run(tc.executable+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			logs := newProgressTestWriter()
			f := startProgressCommand(t, tc.executable, tc.args, logs, false)
			waitForProgress(t, logs, func(text string) bool { return strings.Contains(text, "stderr diagnostic\n") })
			select {
			case result := <-f.result:
				t.Fatalf("process completed before gate release: %+v", result)
			default:
			}
			if logs.String() != "stdout diagnostic\nstderr diagnostic\n" {
				t.Fatalf("unfiltered or incomplete live logs: %q", logs.String())
			}
			f.release(t)
			result := f.completed(t)
			f.progress.Close()
			if result.err != nil || string(result.output) != helperLiveOutput+"command completed\n" {
				t.Fatalf("captured output changed: %q, err=%v", result.output, result.err)
			}
			if logs.String() != "stdout diagnostic\nstderr diagnostic\ncommand completed\n" {
				t.Fatalf("logs=%q", logs.String())
			}
		})
	}
}

func TestCommandParsingOutputStaysInternal(t *testing.T) {
	for _, tc := range []struct {
		executable string
		args       []string
	}{
		{"apko", []string{"version"}},
		{"docker", []string{"image", "inspect"}},
		{"docker", []string{"image", "save"}},
	} {
		t.Run(tc.executable+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			logs := newProgressTestWriter()
			f := startProgressCommand(t, tc.executable, tc.args, logs, false)
			if logs.String() != "" {
				t.Fatalf("internal output streamed before completion: %q", logs.String())
			}
			f.release(t)
			result := f.completed(t)
			f.progress.Close()
			before, after := progressHelperOutput(tc.executable, tc.args)
			if result.err != nil || string(result.output) != before+after || logs.String() != "" {
				t.Fatalf("output=%q err=%v logs=%q", result.output, result.err, logs.String())
			}
			if tc.executable == "apko" {
				command := func(context.Context, string, ...string) ([]byte, error) { return result.output, nil }
				if err := requireApkoVersion(context.Background(), command); err != nil {
					t.Fatalf("version parser lost captured output: %v", err)
				}
			} else if tc.args[1] == "inspect" {
				var identity struct{ Id, Os, Architecture string }
				if err := json.Unmarshal(result.output, &identity); err != nil || identity.Os != "linux" || identity.Architecture != "amd64" {
					t.Fatalf("inspect parser lost captured output: %+v, err=%v", identity, err)
				}
			}
		})
	}
}

type failedProgressWriter struct{ short bool }

func (w failedProgressWriter) Write(data []byte) (int, error) {
	if w.short {
		return len(data) - 1, nil
	}
	return 0, errors.New("stderr unavailable")
}

func TestCommandRendererFailureIsNonfatal(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprintf("short=%t", short), func(t *testing.T) {
			f := startProgressCommand(t, "apko", []string{"build"}, failedProgressWriter{short: short}, false)
			f.release(t)
			result := f.completed(t)
			f.progress.Close()
			if result.err != nil || string(result.output) != helperLiveOutput+"command completed\n" {
				t.Fatalf("render failure affected tool: output=%q err=%v", result.output, result.err)
			}
		})
	}
}

func TestLiveCommandFailureAndCancellationCloseProgress(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled=%t", canceled), func(t *testing.T) {
			logs := newProgressTestWriter()
			f := startProgressCommand(t, "apko", []string{"lock"}, logs, !canceled)
			waitForProgress(t, logs, func(text string) bool { return strings.Contains(text, "stderr diagnostic\n") })
			if canceled {
				f.cancel()
			} else {
				f.release(t)
			}
			result := f.completed(t)
			if result.err == nil || (canceled && !errors.Is(result.err, context.Canceled)) || !bytes.Contains(result.output, []byte("stderr diagnostic")) {
				t.Fatalf("lost failure/cancellation diagnostics: output=%q err=%v", result.output, result.err)
			}
			f.progress.Close()
			select {
			case <-f.progress.done:
			default:
				t.Fatal("renderer worker not joined")
			}
			before := logs.String()
			f.progress.Stage("late stage")
			f.progress.Write([]byte("late diagnostic\n"))
			if logs.String() != before {
				t.Fatalf("writes after close: %q", logs.String())
			}
		})
	}
}

func TestProgressPlainLogsStripSplitControls(t *testing.T) {
	logs := newProgressTestWriter()
	p := newBuildProgress(context.Background(), logs, false)
	p.Stage("Locking apko dependencies")
	for _, chunk := range []string{"\x1b[3", "1mcolored\x1b[0m\r\n", "\x1b]0;private title", "\x1b", "\\plain\ttext\b\n", "partial"} {
		if n, err := p.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("Write=(%d, %v)", n, err)
		}
	}
	p.Stage("Composing OCI image with apko")
	p.Write([]byte("last partial"))
	p.Close()
	want := "lupetto: Locking apko dependencies\ncolored\nplain\ttext\npartial\nlupetto: Composing OCI image with apko\nlast partial\n"
	if logs.String() != want || strings.ContainsAny(logs.String(), "\r\x1b") {
		t.Fatalf("plain logs=%q want=%q", logs.String(), want)
	}
	p.Close()
}

func TestProgressTerminalFramesLogInterleavingAndCleanup(t *testing.T) {
	logs := newProgressTestWriter()
	p := newBuildProgress(context.Background(), logs, true)
	t.Cleanup(p.Close)
	p.Stage("Locking apko dependencies")
	waitForProgress(t, logs, func(text string) bool { return strings.Contains(text, "/ Locking apko dependencies [") })
	p.Write([]byte("tool diagnostic\n"))
	p.Write([]byte("partial diagnostic"))
	p.Stage("Composing OCI image with apko")
	p.Close()
	text := logs.String()
	for _, want := range []string{
		"lupetto: Locking apko dependencies\n\r\x1b[2K| Locking apko dependencies [0s]",
		"\r\x1b[2Ktool diagnostic\n\r\x1b[2K",
		"\r\x1b[2Kpartial diagnostic\nlupetto: Composing OCI image with apko\n\r\x1b[2K",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing terminal interleaving %q in %q", want, text)
		}
	}
	if !strings.HasSuffix(text, "\r\x1b[2K") || strings.Contains(text, "%") {
		t.Fatalf("spinner not cleared or invented percentage: %q", text)
	}
}

func TestProgressFrameFitsNarrowAndTinyTerminals(t *testing.T) {
	stage := "Composing OCI image with apko"
	for _, tc := range []struct {
		columns int
		want    string
	}{
		{80, "| Composing OCI image with apko [3s]"},
		{20, "| Composing OC [3s]"},
		{8, "| Compo"},
		{3, "| "},
		{2, "|"},
		{1, ""},
		{0, ""},
		{-1, ""},
	} {
		t.Run(fmt.Sprintf("columns=%d", tc.columns), func(t *testing.T) {
			got := progressFrame(stage, 0, 3*time.Second, tc.columns)
			if got != tc.want || len(got) > max(0, tc.columns-1) || strings.ContainsAny(got, "\r\n\x1b") {
				t.Fatalf("frame=%q want=%q columns=%d", got, tc.want, tc.columns)
			}
		})
	}
	longElapsed := progressFrame(stage, 5, time.Hour+2*time.Minute+3*time.Second, 20)
	if longElapsed != "/ Composin [1h2m3s]" || len(longElapsed) != 19 {
		t.Fatalf("elapsed/frame lost or last column used: %q", longElapsed)
	}
	// Each frame derives its bounds anew; resizing requires no mutable callback.
	for _, columns := range []int{80, 20, 1, 30} {
		got := progressFrame(stage, 2, 3*time.Second, columns)
		if len(got) > max(0, columns-1) {
			t.Fatalf("resized frame exceeds safe columns: %q columns=%d", got, columns)
		}
	}
}

func TestProgressCancellationStopsAndJoinsTerminalWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := newProgressTestWriter()
	p := newBuildProgress(ctx, logs, true)
	t.Cleanup(p.Close)
	p.Stage("Loading image into Docker")
	cancel()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not join renderer worker")
	}
	before := logs.String()
	if !strings.HasSuffix(before, "\r\x1b[2K") {
		t.Fatalf("canceled spinner not cleared: %q", before)
	}
	p.Stage("late stage")
	p.Write([]byte("late output\n"))
	var closers sync.WaitGroup
	for range 4 {
		closers.Add(1)
		go func() { defer closers.Done(); p.Close() }()
	}
	closers.Wait()
	if logs.String() != before {
		t.Fatalf("output after cancellation: %q", logs.String())
	}
}

type progressWriterFunc func([]byte) (int, error)

func (fn progressWriterFunc) Write(data []byte) (int, error) { return fn(data) }

func TestCLIClosesProgressBeforeFinalSuccessFailureOrCancellation(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "cancellation"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var p *buildProgress
			var stdout, stderr bytes.Buffer
			assertClosed := func() {
				t.Helper()
				select {
				case <-p.done:
				default:
					t.Error("final CLI output preceded renderer cleanup")
				}
			}
			out := progressWriterFunc(func(data []byte) (int, error) {
				assertClosed()
				return stdout.Write(data)
			})
			errOut := progressWriterFunc(func(data []byte) (int, error) {
				if bytes.Contains(data, []byte("final failure")) || bytes.Contains(data, []byte("context canceled")) {
					assertClosed()
				}
				return stderr.Write(data)
			})
			build := func(buildCtx context.Context, _ buildRequest) (buildResult, error) {
				p = progressFromContext(buildCtx)
				if p == nil {
					t.Fatal("CLI did not install progress reporter")
				}
				buildStage(buildCtx, "Composing OCI image with apko")
				p.Write([]byte("partial diagnostic"))
				if outcome == "failure" {
					return buildResult{}, errors.New("\x1b[31mfinal failure\x1b[0m\r")
				}
				if outcome == "cancellation" {
					cancel()
					return buildResult{}, buildCtx.Err()
				}
				return buildResult{packageName: "busybox", version: "1.0-r0", imageDir: "image", workspace: "workspace", spdxPath: "sbom", imageReference: "lupetto/busybox:1.0-r0-amd64", buildReference: "lupetto/local:build-fixture", dockerLoad: "skipped"}, nil
			}
			code := runWithBuild(ctx, []string{"build", "busybox", "--apk-version", "1.0-r0", "--no-load"}, out, errOut, build)
			if outcome == "success" {
				want := "Selected busybox@1.0-r0 (APKINDEX sha256:)\nOCI image: image\nValidated SPDX: sbom (sha256:)\nBuild evidence: workspace\nImage reference: lupetto/busybox:1.0-r0-amd64\nBuild reference: lupetto/local:build-fixture\nDocker loading: skipped\nRegistry publication: skipped\nImage signing: skipped\nSPDX attestation: skipped\n"
				if code != 0 || stdout.String() != want {
					t.Fatalf("success stdout changed: code=%d stdout=%q", code, stdout.String())
				}
			} else if code != 1 || stdout.Len() != 0 {
				t.Fatalf("failed build printed success: code=%d stdout=%q", code, stdout.String())
			}
			if strings.ContainsAny(stderr.String(), "\r\x1b") {
				t.Fatalf("plain failure output has terminal controls: %q", stderr.String())
			}
			before := stderr.String()
			p.Write([]byte("late diagnostic"))
			if stderr.String() != before {
				t.Fatal("CLI left reporter open")
			}
		})
	}
}

func TestProgressTerminalDetectionRejectsPlainWritersAndDumb(t *testing.T) {
	if progressTerminal(&bytes.Buffer{}) {
		t.Fatal("buffer treated as terminal")
	}
	if columns := progressColumns(&bytes.Buffer{}); columns != 80 {
		t.Fatalf("unknown dimensions fallback=%d want=80", columns)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if progressTerminal(writer) {
		t.Fatal("redirected file treated as terminal")
	}
	if columns := progressColumns(writer); columns != 80 {
		t.Fatalf("GetSize failure fallback=%d want=80", columns)
	}
	t.Setenv("TERM", "dumb")
	if progressTerminal(os.Stderr) {
		t.Fatal("TERM=dumb enabled animation")
	}
}
