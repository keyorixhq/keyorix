package admin

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
)

// restoreProgressInterval is how often a heartbeat line is printed while one
// large table loads. Table boundaries always print.
const restoreProgressInterval = 10 * time.Second

var restoreVerbose bool

// restoreProgress turns loader notifications into stderr heartbeat lines so a
// restore of millions of rows does not look hung. A line carries the table
// name, row counts and elapsed time only -- never row content, keys or
// passphrases. now is injectable so tests control the clock.
type restoreProgress struct {
	w        io.Writer
	now      func() time.Time
	interval time.Duration
	start    time.Time
	last     time.Time
}

// newRestoreProgress returns a reporter writing to w, or nil (no output) when
// enabled is false.
func newRestoreProgress(w io.Writer, enabled bool, now func() time.Time, interval time.Duration) *restoreProgress {
	if !enabled || w == nil {
		return nil
	}
	t := now()
	return &restoreProgress{w: w, now: now, interval: interval, start: t, last: t}
}

// restoreProgressEnabled reports whether progress lines are printed: on a
// terminal, or anywhere when --verbose is given.
func restoreProgressEnabled(verbose bool) bool {
	return verbose || term.IsTerminal(int(os.Stderr.Fd())) // #nosec G115 -- a file descriptor fits an int
}

// callback returns the loader hook; a nil reporter yields a nil hook.
func (p *restoreProgress) callback() backupfmt.LoadProgressFunc {
	if p == nil {
		return nil
	}
	return p.event
}

func (p *restoreProgress) event(ev backupfmt.LoadProgress) {
	now := p.now()
	boundary := ev.Start || ev.Finished
	if !boundary && now.Sub(p.last) < p.interval {
		return
	}
	p.last = now
	state := "loading"
	switch {
	case ev.Finished:
		state = "done"
	case ev.Start:
		state = "start"
	}
	_, _ = fmt.Fprintf(p.w, "restore progress: table=%s (%d/%d) %s rows=%d/%d elapsed=%s\n",
		ev.Table, ev.TablesDone+1, ev.TablesTotal, state, ev.TableRows, ev.TableTotal,
		now.Sub(p.start).Round(time.Second))
}

// newStderrRestoreProgress is the reporter restore uses: stderr, wall clock.
func newStderrRestoreProgress() *restoreProgress {
	return newRestoreProgress(os.Stderr, restoreProgressEnabled(restoreVerbose), time.Now, restoreProgressInterval)
}
