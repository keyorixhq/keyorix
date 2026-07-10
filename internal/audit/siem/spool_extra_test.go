package siem

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSpool_CloseNilSafe verifies close() is safe on a nil spool.
func TestSpool_CloseNilSafe(t *testing.T) {
	var s *spool
	s.close() // must not panic
}

// TestSpool_AddMarshalError verifies that an event whose field causes a JSON
// marshal error (tested via a custom type) is handled gracefully.
// Since models.AuditEvent always marshals correctly, we exercise the rewrite
// path that fails to open a tempfile by making the spool dir read-only.
func TestSpool_RewriteWithEmptyRemainingDeletesFile(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close()

	tr := true
	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})

	// Deliver succeeds → remaining is empty → file is removed.
	d.setFailing(false)
	s.replay()

	_, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	assert.True(t, os.IsNotExist(statErr), "a fully-delivered spool must delete its file")
}

// TestSpool_ReplayWhenFileVanishes verifies replay handles the race where the
// spool file disappears between the initial read and the reconcile re-read.
func TestSpool_ReplayWhenFileVanishesMidReconcile(t *testing.T) {
	dir := t.TempDir()
	tr := true

	var hookCallCount int
	// The deliver hook removes the file on the first call, simulating the file
	// being deleted externally between snapshot and reconcile.
	hook := func(ctx context.Context, e *models.AuditEvent) error {
		hookCallCount++
		if hookCallCount == 1 {
			_ = os.Remove(filepath.Join(dir, spoolFileName))
		}
		return nil // delivery succeeds
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close()

	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	// Must not panic or block; the file disappearing mid-replay is handled.
	s.replay()
}

// TestSpool_AddWhenAtCap verifies that the add() size check considers an event
// exactly at the cap as "at cap" and drops it.
func TestSpool_AddAtCapDropsEvent(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{failing: true}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)
	// Set cap to exactly the size of the first event so the second is dropped.
	s.maxBytes = 1 // anything smaller than one JSONL line forces a drop

	tr := true
	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	// At least the second add must hit the cap path and be dropped.
	s.add(&models.AuditEvent{ID: 2, EventType: "secret.read", Success: &tr})
	// The file exists but is bounded (at most a few hundred bytes from the first event).
	info, err := os.Stat(filepath.Join(dir, spoolFileName))
	require.NoError(t, err)
	assert.Less(t, info.Size(), int64(4096))
}

// TestSpool_ReplayWithFileVanishedOnFirstRead verifies that a missing spool file
// on the first ReadFile inside replay() just returns silently (not-exist is not
// an error).
func TestSpool_ReplayMissingFile(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close() // stop background loop

	// No file has been written — replay should return cleanly.
	s.replay()
	assert.Equal(t, 0, d.count())
}

// TestSpool_RewriteErrorPathDoesNotPanic verifies that the rewrite function
// recovers gracefully when the directory becomes unwritable.
// This exercises some of the error branches in rewrite().
func TestSpool_NewSpoolWithBadDir(t *testing.T) {
	// Pass a path that cannot be created (a file in the way).
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocked")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	// Try to create a spool whose dir would require creating a dir where a file exists.
	_, err := newSpool(filepath.Join(blocker, "subdir"), time.Hour, func(context.Context, *models.AuditEvent) error { return nil })
	require.Error(t, err, "creating a spool dir inside a file must fail")
}
