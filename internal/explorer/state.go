package explorer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type statusCache struct {
	mu   sync.Mutex
	view StatusView
}

func (c *statusCache) snapshot() StatusView { c.mu.Lock(); defer c.mu.Unlock(); return c.view }
func (c *statusCache) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.view.Refreshing {
		return false
	}
	c.view.Refreshing = true
	return true
}
func (c *statusCache) finish(document *StatusDocument, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.view.Refreshing = false
	if err != nil {
		c.view.LastError = err.Error()
		return
	}
	c.view.Document, c.view.LastError = document, ""
}

type discoveryCache struct {
	mu         sync.Mutex
	document   *DiscoverDocument
	err        string
	refreshing bool
}

func (c *discoveryCache) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing {
		return false
	}
	c.refreshing = true
	return true
}
func (c *discoveryCache) finish(document *DiscoverDocument, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshing = false
	if err != nil {
		c.err = err.Error()
		return
	}
	c.document, c.err = document, ""
}
func (c *discoveryCache) snapshot() (*DiscoverDocument, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.document, c.err, c.refreshing
}

var (
	ErrBuildsDisabled = errors.New("builds are disabled; start Explorer with --enable-builds to enable them")
	ErrJobRunning     = errors.New("a build is already running; wait for completion or cancel it first")
	ErrShuttingDown   = errors.New("Explorer is shutting down")
)

type job struct {
	view   JobView
	log    *logBuffer
	cancel context.CancelFunc
}
type jobRunner struct {
	mu          sync.Mutex
	cli         *CLI
	ctx         context.Context
	enabled     bool
	closed      bool
	active      string
	sequence    uint64
	jobs        []*job
	limit       int
	logBytes    int
	wg          sync.WaitGroup
	afterFinish func()
}

func (r *jobRunner) start(request BuildRequest) (JobView, error) {
	if !r.enabled {
		return JobView{}, ErrBuildsDisabled
	}
	if err := ValidateBuild(request); err != nil {
		return JobView{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return JobView{}, ErrShuttingDown
	}
	if r.active != "" {
		return JobView{}, ErrJobRunning
	}
	r.sequence++
	ctx, cancel := context.WithCancel(r.ctx)
	j := &job{view: JobView{ID: fmt.Sprint(r.sequence), Request: request, State: "running", StartedAt: time.Now().UTC()}, log: newLogBuffer(r.logBytes), cancel: cancel}
	r.jobs = append(r.jobs, j)
	if len(r.jobs) > r.limit {
		r.jobs = r.jobs[len(r.jobs)-r.limit:]
	}
	r.active = j.view.ID
	r.wg.Add(1)
	go r.run(ctx, j)
	return j.view, nil
}
func (r *jobRunner) run(ctx context.Context, j *job) {
	defer r.wg.Done()
	defer j.cancel()
	data, exit, err := r.cli.execute(ctx, buildArgs(j.view.Request), j.log)
	var record *BuildRecord
	var parseErr error
	if len(strings.TrimSpace(string(data))) != 0 {
		record, parseErr = parseRecord(data)
	} else if err == nil {
		parseErr = errors.New("incompatible lupetto CLI: successful build printed no version-6 record")
	}
	// exec can return context.Canceled if SIGTERM raced a clean exit. Preserve
	// an exit-0, compatible success record rather than inventing cancellation.
	if exit == 0 && record != nil && record.Outcome == "succeeded" && errors.Is(err, context.Canceled) {
		err = nil
	}
	ended := time.Now().UTC()
	r.mu.Lock()
	j.view.EndedAt, j.view.ExitCode, j.view.Record = &ended, &exit, record
	j.view.State = "succeeded"
	if err != nil || parseErr != nil || (record != nil && record.Outcome != "succeeded") {
		j.view.State = "failed"
	}
	if err != nil {
		j.view.Error = fmt.Sprintf("lupetto build failed (exit %d); inspect stderr and any partial record", exit)
	}
	if errors.Is(err, errOutputLimit) {
		j.view.Error = err.Error()
	}
	if parseErr != nil {
		j.view.Error = parseErr.Error()
	}
	// A cancel that arrives while parsing an already-successful record cannot
	// undo the CLI's completed outcome.
	if err != nil && ctx.Err() != nil {
		j.view.State = "canceled"
		j.view.Error = "build canceled; external side effects may remain"
	}
	r.active = ""
	r.mu.Unlock()
	if r.afterFinish != nil {
		r.afterFinish()
	}
}
func (r *jobRunner) list() ([]JobView, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	views := make([]JobView, 0, len(r.jobs))
	for i := len(r.jobs) - 1; i >= 0; i-- {
		views = append(views, r.jobs[i].view)
	}
	return views, r.active != ""
}
func (r *jobRunner) find(id string) *job {
	for _, j := range r.jobs {
		if j.view.ID == id {
			return j
		}
	}
	return nil
}
func (r *jobRunner) detail(id string, offset int64) (JobView, LogChunk, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.find(id)
	if j == nil {
		return JobView{}, LogChunk{}, false
	}
	chunk := j.log.chunk(offset)
	chunk.Done = j.view.State != "running"
	return j.view, chunk, true
}
func (r *jobRunner) cancelJob(id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.find(id)
	if j == nil {
		return false, nil
	}
	if j.view.State != "running" {
		return true, errors.New("job is no longer running")
	}
	j.view.CancelRequested = true
	j.cancel()
	return true, nil
}
func (r *jobRunner) close() {
	r.mu.Lock()
	r.closed = true
	for _, j := range r.jobs {
		if j.view.State == "running" {
			j.view.CancelRequested = true
			j.cancel()
		}
	}
	r.mu.Unlock()
}
