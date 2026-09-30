package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

type buildProgressKey struct{}

// Presentation stays in the CLI context; direct pipeline callers need no reporter.
func progressFromContext(ctx context.Context) *buildProgress {
	progress, _ := ctx.Value(buildProgressKey{}).(*buildProgress)
	return progress
}

func buildStage(ctx context.Context, stage string) {
	progressFromContext(ctx).Stage(stage)
}

func buildMessage(ctx context.Context, format string, args ...any) {
	progressFromContext(ctx).Write([]byte("lupetto: " + fmt.Sprintf(format, args...) + "\n"))
}

func progressTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	return ok && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(file.Fd()))
}

type buildProgress struct {
	mu        sync.Mutex
	ctx       context.Context
	output    io.Writer
	terminal  bool
	stage     string
	started   time.Time
	frame     int
	visible   bool
	lineOpen  bool
	closed    bool
	failed    bool
	sanitizer progressSanitizer
	stop      chan struct{}
	done      chan struct{}
	stopOnce  sync.Once
}

func newBuildProgress(ctx context.Context, output io.Writer, terminal bool) *buildProgress {
	if output == nil {
		output = io.Discard
	}
	progress := &buildProgress{
		ctx: ctx, output: output, terminal: terminal, started: time.Now(),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go progress.run(ctx)
	return progress
}

func (p *buildProgress) run(ctx context.Context) {
	defer close(p.done)
	var ticks <-chan time.Time
	if p.terminal {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		ticks = ticker.C
	}
	defer p.finish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stop:
			return
		case now := <-ticks:
			p.mu.Lock()
			p.drawLocked(now)
			p.mu.Unlock()
		}
	}
}

// Close joins the worker before the CLI prints its final success or error.
func (p *buildProgress) Close() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

func (p *buildProgress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
	p.finishLineLocked()
	p.closed = true
}

func (p *buildProgress) Stage(stage string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.failed || p.ctx.Err() != nil {
		return
	}
	p.sanitizer = progressSanitizer{}
	p.clearLocked()
	p.finishLineLocked()
	p.stage = plainProgressText(stage)
	p.writeLocked([]byte("lupetto: " + p.stage + "\n"))
	p.drawLocked(time.Now())
}

// A broken stderr must not fail a successful tool or alter its captured output.
func (p *buildProgress) Write(data []byte) (int, error) {
	if p == nil {
		return len(data), nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.failed || p.ctx.Err() != nil {
		return len(data), nil
	}
	clean := p.sanitizer.clean(data)
	if len(clean) != 0 {
		p.clearLocked()
		p.writeLocked(clean)
		p.lineOpen = clean[len(clean)-1] != '\n'
		p.drawLocked(time.Now())
	}
	return len(data), nil
}

func (p *buildProgress) writeLocked(data []byte) {
	if p.closed || p.failed {
		return
	}
	n, err := p.output.Write(data)
	if err != nil || n != len(data) {
		p.failed = true
	}
}

func (p *buildProgress) clearLocked() {
	if p.visible {
		p.writeLocked([]byte("\r\x1b[2K"))
		p.visible = false
	}
}

func (p *buildProgress) finishLineLocked() {
	if p.lineOpen {
		p.writeLocked([]byte("\n"))
		p.lineOpen = false
	}
}

func (p *buildProgress) drawLocked(now time.Time) {
	if !p.terminal || p.closed || p.failed || p.ctx.Err() != nil || p.stage == "" || p.lineOpen {
		return
	}
	elapsed := now.Sub(p.started).Truncate(time.Second)
	frame := progressFrame(p.stage, p.frame, elapsed, progressColumns(p.output))
	if frame == "" {
		p.clearLocked()
		return
	}
	p.writeLocked([]byte("\r\x1b[2K" + frame))
	p.frame++
	p.visible = !p.failed
}

func progressColumns(output io.Writer) int {
	if file, ok := output.(*os.File); ok {
		if columns, _, err := term.GetSize(int(file.Fd())); err == nil && columns > 0 {
			return columns
		}
	}
	return 80
}

// Leave the terminal's last cell unused so a spinner never enables autowrap.
// Pipeline stage labels and the elapsed duration are ASCII.
func progressFrame(stage string, frame int, elapsed time.Duration, columns int) string {
	cells := columns - 1
	if cells <= 0 {
		return ""
	}
	frames := "|/-\\"
	prefix := fmt.Sprintf("%c ", frames[frame%len(frames)])
	suffix := fmt.Sprintf(" [%s]", elapsed)
	stageCells := cells - len(prefix) - len(suffix)
	if stageCells <= 0 {
		text := prefix + stage
		return text[:min(len(text), cells)]
	}
	return prefix + stage[:min(len(stage), stageCells)] + suffix
}

// Keep upstream ANSI/OSC sequences and carriage-return animation out of logs.
// State survives tool writes, including escape sequences split across chunks.
// Captured command bytes are deliberately not passed through this sanitizer.
type progressSanitizer struct {
	state byte
}

func (s *progressSanitizer) clean(data []byte) []byte {
	clean := make([]byte, 0, len(data))
	for _, b := range data {
		switch s.state {
		case 1: // ESC sequence, possibly with intermediate bytes.
			switch b {
			case '[':
				s.state = 2
			case ']', 'P', 'X', '^', '_':
				s.state = 3
			default:
				if b < 0x20 || b > 0x2f {
					s.state = 0
				}
			}
		case 2: // CSI ends at its final byte.
			if b >= 0x40 && b <= 0x7e {
				s.state = 0
			}
		case 3: // OSC/control string ends at BEL or ESC-backslash.
			if b == '\a' {
				s.state = 0
			} else if b == 0x1b {
				s.state = 4
			}
		case 4:
			if b == '\\' {
				s.state = 0
			} else if b != 0x1b {
				s.state = 3
			}
		default:
			if b == 0x1b {
				s.state = 1
			} else if b == '\n' || b == '\t' || (b >= 0x20 && b != 0x7f) {
				clean = append(clean, b)
			}
		}
	}
	return clean
}

func plainProgressText(text string) string {
	var sanitizer progressSanitizer
	return string(sanitizer.clean([]byte(text)))
}
