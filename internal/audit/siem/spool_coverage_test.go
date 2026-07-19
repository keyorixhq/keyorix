package siem

// spool_coverage_test.go — targeted tests for branches not yet reached:
//
//   replay:   non-NotExist first-read error (spool.go:147–149)
//             empty-line skip in primary scan (spool.go:158–159)
//             non-NotExist re-read error in reconcile (spool.go:195–197)
//             empty-line skip in tail scan (spool.go:208–209)
//   loop:     stop-channel branch (spool.go:122–123) — exercised via close()
//             with a long ticker so only the stop path fires

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// replay() — non-NotExist first-read error (spool.go:147–149)
// ---------------------------------------------------------------------------

// TestReplay_FirstReadPermError exercises the `!os.IsNotExist(err)` branch on
// the initial os.ReadFile inside replay(). We replace s.path with a directory
// whose permissions prevent reading (0o000), which produces a permission error
// rather than ENOENT.
func TestReplay_FirstReadPermError(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close()

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Replace s.path with an unreadable directory: os.ReadFile on a directory
	// returns a permission/is-a-dir error, not ENOENT.
	unreadable := filepath.Join(dir, "unreadable-dir")
	require.NoError(t, os.MkdirAll(unreadable, 0o700))
	require.NoError(t, os.Chmod(unreadable, 0o000))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	s.path = unreadable

	// replay() must log the read error and return without panic.
	s.replay()

	assert.Contains(t, logBuf.String(), "read spool failed",
		"a non-NotExist read error must be logged in replay()")
}

// ---------------------------------------------------------------------------
// replay() — empty-line skip in primary scan (spool.go:158–159)
// ---------------------------------------------------------------------------

// TestReplay_EmptyLinesInSpool verifies that blank lines in the spool file are
// silently skipped, and the valid events on either side are still delivered.
func TestReplay_EmptyLinesInSpool(t *testing.T) {
	dir := t.TempDir()
	var mu bytes.Buffer // unused — just to avoid import clash

	delivered := make([]uint, 0, 2)
	hook := func(_ context.Context, e *models.AuditEvent) error {
		delivered = append(delivered, e.ID)
		return nil
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close()

	tr := true
	ev1, err1 := json.Marshal(&models.AuditEvent{ID: 11, EventType: "secret.read", Success: &tr})
	require.NoError(t, err1)
	ev2, err2 := json.Marshal(&models.AuditEvent{ID: 12, EventType: "secret.read", Success: &tr})
	require.NoError(t, err2)

	// Spool file: event, blank line, blank line, event.
	content := append(ev1, '\n')
	content = append(content, '\n') // blank
	content = append(content, '\n') // blank
	content = append(content, ev2...)
	content = append(content, '\n')

	_ = mu // suppress unused warning
	require.NoError(t, os.WriteFile(s.path, content, 0o600))

	s.replay()

	assert.ElementsMatch(t, []uint{11, 12}, delivered,
		"blank lines must be skipped; both valid events must be delivered")
	_, statErr := os.Stat(s.path)
	assert.True(t, os.IsNotExist(statErr), "a fully-delivered spool must remove its file")
}

// ---------------------------------------------------------------------------
// replay() — non-NotExist reconcile re-read error (spool.go:195–197)
// ---------------------------------------------------------------------------

// TestReplay_ReconcileReadPermError exercises the branch where the second
// os.ReadFile (inside the lock at the end of replay()) returns a non-ENOENT
// error. The deliver hook replaces s.path with an unreadable subdirectory
// while delivery is running, so the reconcile read fails with a permission
// error.
func TestReplay_ReconcileReadPermError(t *testing.T) {
	dir := t.TempDir()
	tr := true

	var hookCount int
	var spoolPath string

	hook := func(_ context.Context, _ *models.AuditEvent) error {
		hookCount++
		if hookCount == 1 && spoolPath != "" {
			// Replace the spool file with an unreadable directory.
			_ = os.Remove(spoolPath)
			_ = os.MkdirAll(spoolPath, 0o700)
			_ = os.Chmod(spoolPath, 0o000)
		}
		return nil // delivery succeeds
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close()
	spoolPath = s.path

	// Add an event so the spool file exists when replay() runs.
	s.add(&models.AuditEvent{ID: 33, EventType: "secret.read", Success: &tr})

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		_ = os.Chmod(spoolPath, 0o700)
		log.SetOutput(prev)
	})

	// replay() delivers event 33 (hook runs, replaces file with unreadable dir),
	// then the reconcile re-read fails → must log "re-read spool failed".
	s.replay()

	assert.Contains(t, logBuf.String(), "re-read spool failed",
		"a non-NotExist reconcile re-read error must be logged")
}

// ---------------------------------------------------------------------------
// replay() — empty-line skip in tail scan (spool.go:208–209)
// ---------------------------------------------------------------------------

// TestReplay_EmptyLinesInTail exercises the empty-line skip in the tail scanner
// (the second scanner over cur[snapshotLen:]). The deliver hook appends a blank
// line followed by a valid event during delivery, so both land in the tail.
func TestReplay_EmptyLinesInTail(t *testing.T) {
	dir := t.TempDir()
	tr := true

	var hookCount int
	var sp *spool

	hook := func(_ context.Context, _ *models.AuditEvent) error {
		hookCount++
		if hookCount == 1 && sp != nil {
			// Append a blank line + a valid event to the file while delivery is
			// running; these bytes land beyond snapshotLen in the tail.
			ev, merr := json.Marshal(&models.AuditEvent{ID: 200, EventType: "sec.read", Success: &tr})
			if merr == nil {
				f, ferr := os.OpenFile(sp.path, os.O_APPEND|os.O_WRONLY, 0o600)
				if ferr == nil {
					_, _ = f.Write([]byte("\n")) // blank line
					_, _ = f.Write(append(ev, '\n'))
					_ = f.Close()
				}
			}
		}
		return nil // delivery succeeds for the snapshot event
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close()
	sp = s

	s.add(&models.AuditEvent{ID: 100, EventType: "sec.read", Success: &tr})

	// Must not panic; the blank line in the tail is silently skipped.
	s.replay()
	// After this replay, event 200 (from the tail) is kept for the next replay.
	// Run it again so it gets delivered and the file is cleaned up.
	s.replay()
}

// ---------------------------------------------------------------------------
// loop() — stop-channel branch (spool.go:122–123)
// ---------------------------------------------------------------------------

// TestLoop_StopBranchExitsCleanly verifies that closing the stop channel
// causes loop() to exit promptly via the `case <-s.stop: return` branch. We
// use a very long ticker interval so only the stop branch can fire during the
// test, avoiding any chance of the ticker branch interfering.
func TestLoop_StopBranchExitsCleanly(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	// 24-hour interval: the ticker will never fire in a test context.
	s, err := newSpool(dir, 24*time.Hour, d.deliver)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		s.close() // signals the stop channel and waits for loop() to exit
		close(done)
	}()

	select {
	case <-done:
		// loop() exited via the stop-channel branch — success.
	case <-time.After(3 * time.Second):
		t.Fatal("close() did not return within 3s; loop() stop-channel branch may be blocked")
	}
}

// ---------------------------------------------------------------------------
// loop() — ticker branch (spool.go:124–125)
// ---------------------------------------------------------------------------

// TestLoop_TickerBranchDrivesReplay verifies that the `case <-t.C: s.replay()`
// branch in loop() fires, delivering an event spooled before the ticker fires.
// We use a very short (1 ms) interval so the ticker fires almost immediately
// after the initial replay(), and wait up to 3 s for delivery to happen.
func TestLoop_TickerBranchDrivesReplay(t *testing.T) {
	dir := t.TempDir()
	tr := true

	// Start with delivery failing so the initial replay (fired inside loop() on
	// start) leaves the event in the spool.
	d := &fakeDelivery{failing: true}

	// Very short interval so the ticker fires quickly.
	s, err := newSpool(dir, time.Millisecond, d.deliver)
	require.NoError(t, err)
	defer s.close()

	// Add an event while failing — it gets written to the spool file.
	s.add(&models.AuditEvent{ID: 555, EventType: "secret.read", Success: &tr})

	// Let the initial loop replay run, then allow delivery to succeed.
	time.Sleep(10 * time.Millisecond)
	d.setFailing(false)

	// Wait for a ticker-driven replay to deliver the event.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d.count() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Greater(t, d.count(), 0,
		"the loop ticker must drive replay() and deliver the spooled event")
}
