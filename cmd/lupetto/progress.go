package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
	"lupetto/internal/build"
)

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
	sanitizer build.TextSanitizer
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
	p.sanitizer = build.TextSanitizer{}
	p.clearLocked()
	p.finishLineLocked()
	p.stage = build.PlainText(stage)
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
	clean := p.sanitizer.Clean(data)
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
