package siem

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// forwarder.go — uncovered branches
// ---------------------------------------------------------------------------

// TestSend_TransportErrorIsRetryable verifies that a transport-level failure
// (unreachable host) returns retryable=true. This exercises the
// `return true, err` branch in send() that is distinct from the HTTP-status
// retryable paths already covered.
func TestSend_TransportErrorIsRetryable(t *testing.T) {
	// Use a server that is closed immediately so any dial attempt fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	endpoint := srv.URL
	srv.Close() // close before the request is made

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: endpoint}, time.Millisecond)
	require.NoError(t, err)
	defer f.Close()

	retryable, sendErr := f.send(context.Background(), sampleEvent())
	require.Error(t, sendErr, "a dial failure must produce an error")
	assert.True(t, retryable, "a transport/dial error must be retryable")
}

// TestSend_WebhookNoToken verifies that a webhook forwarder with an empty token
// sends no Authorization header — exercises the `if f.cfg.Token != ""` branch
// in buildRequest that is skipped when the token is empty.
func TestSend_WebhookNoToken(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK)

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL, Token: ""}, time.Millisecond)
	require.NoError(t, err)
	defer f.Close()

	_, sendErr := f.send(context.Background(), sampleEvent())
	require.NoError(t, sendErr)
	cap.mu.Lock()
	authHeader := cap.headers.Get("Authorization")
	cap.mu.Unlock()
	assert.Empty(t, authHeader, "an empty token must not produce an Authorization header")
}

// TestToPayload_EmptyDiff verifies that toPayload leaves Diff nil when the
// source event has an empty Diff string — exercises the `if e.Diff != ""`
// false branch.
func TestToPayload_EmptyDiff(t *testing.T) {
	e := &models.AuditEvent{ID: 5, EventType: "secret.read", Diff: ""}
	p := toPayload(e)
	assert.Nil(t, p.Diff, "an empty Diff string must produce a nil RawMessage, not a JSON null")
}

// ---------------------------------------------------------------------------
// spool.go — uncovered branches
// ---------------------------------------------------------------------------

// TestSpool_ZeroIntervalUsesDefault verifies that newSpool replaces a zero
// interval with defaultReplayInterval — exercises the `if interval <= 0`
// branch in newSpool.
func TestSpool_ZeroIntervalUsesDefault(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, 0, d.deliver)
	require.NoError(t, err)
	defer s.close()
	assert.Equal(t, defaultReplayInterval, s.interval,
		"a zero interval must be replaced with defaultReplayInterval")
}

// TestSpool_NegativeIntervalUsesDefault verifies that newSpool replaces a
// negative interval with defaultReplayInterval.
func TestSpool_NegativeIntervalUsesDefault(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, -1*time.Second, d.deliver)
	require.NoError(t, err)
	defer s.close()
	assert.Equal(t, defaultReplayInterval, s.interval,
		"a negative interval must be replaced with defaultReplayInterval")
}

// TestSpool_AddWithMaxBytesZeroSkipsCap verifies that when maxBytes is 0 the
// size check is skipped entirely and events are always appended — exercises
// the `if s.maxBytes > 0` false branch in add().
func TestSpool_AddWithMaxBytesZeroSkipsCap(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{failing: true}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close() // stop background loop; we drive add() directly
	s.maxBytes = 0 // disable cap

	tr := true
	for i := 1; i <= 5; i++ {
		s.add(&models.AuditEvent{ID: uint(i), EventType: "secret.read", Success: &tr})
	}
	info, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	require.NoError(t, statErr, "events must be written when maxBytes is 0")
	assert.Greater(t, info.Size(), int64(0), "spool file must be non-empty")
}

// TestSpool_ReplayFileVanishesMidReconcileWithRemaining verifies the branch
// in replay() where the spool file disappears between the snapshot read and
// the reconcile re-read, AND there are still undelivered lines — the
// re-persist branch (s.rewrite(remaining) after IsNotExist) must not panic
// and must attempt to rewrite the failed lines.
func TestSpool_ReplayFileVanishesMidReconcileWithRemaining(t *testing.T) {
	dir := t.TempDir()
	tr := true

	var hookCallCount int
	// Delivery always fails AND removes the spool file on the first call,
	// simulating a concurrent deletion while delivery is failing.
	hook := func(_ context.Context, _ *models.AuditEvent) error {
		hookCallCount++
		if hookCallCount == 1 {
			_ = os.Remove(filepath.Join(dir, spoolFileName))
		}
		return assertErr // fail so the event stays in "remaining"
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close() // stop background loop

	s.add(&models.AuditEvent{ID: 10, EventType: "secret.read", Success: &tr})

	// Must not panic; the IsNotExist branch with remaining != nil re-persists them.
	s.replay()
	// After the re-persist rewrite, the file should exist again.
	_, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	assert.NoError(t, statErr, "replay must re-persist failed lines even if the file vanished mid-reconcile")
}

// TestSpool_TailScanErrorIsLogged verifies that a bufio.ErrTooLong error
// encountered while scanning the concurrent-append tail (the second scanner
// inside replay()) triggers the "tail-scan stopped early" log message.
// This exercises the `ts.Err()` error branch at line ~216 of spool.go.
func TestSpool_TailScanErrorIsLogged(t *testing.T) {
	dir := t.TempDir()
	tr := true

	// The deliver hook appends an oversized line to the spool on first call,
	// making it land in the "tail" (bytes beyond snapshotLen) that the second
	// scanner reads during reconcile. The delivery itself succeeds so the
	// snapshot lines are removed; only the oversized tail causes the scan error.
	var hookCount int
	hook := func(_ context.Context, e *models.AuditEvent) error {
		hookCount++
		if hookCount == 1 {
			// Append an oversized line into the spool while holding no lock
			// (simulating a concurrent add with an enormous payload). This makes
			// the tail-scan hit bufio.ErrTooLong.
			f, ferr := os.OpenFile(filepath.Join(dir, spoolFileName), os.O_APPEND|os.O_WRONLY, 0o600)
			if ferr == nil {
				oversized := bytes.Repeat([]byte("x"), 5<<20) // 5 MiB > 4 MiB cap
				_, _ = f.Write(append(oversized, '\n'))
				_ = f.Close()
			}
		}
		return nil // delivery succeeds
	}

	s, err := newSpool(dir, time.Hour, hook)
	require.NoError(t, err)
	s.close()

	s.add(&models.AuditEvent{ID: 20, EventType: "secret.read", Success: &tr})

	var logBuf bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	s.replay()

	assert.Contains(t, logBuf.String(), "tail-scan stopped early",
		"an oversized tail line must trigger the tail-scan error log")
}

// TestData2Reader verifies the data2reader helper returns a working reader
// over the supplied bytes. Although it is exercised implicitly by replay(),
// a direct unit test ensures the helper itself is counted as covered.
func TestData2Reader(t *testing.T) {
	input := []byte("hello world")
	r := data2reader(input)
	require.NotNil(t, r)
	buf := make([]byte, len(input))
	n, readErr := r.Read(buf)
	require.NoError(t, readErr)
	assert.Equal(t, len(input), n)
	assert.Equal(t, input, buf[:n])
}

// TestSpool_LoopTickerDrivesReplay verifies that the background loop's ticker
// path (not just the initial replay on start) triggers replay and delivers
// spooled events. This exercises the `case <-t.C: s.replay()` branch in
// loop() by using a very short interval and waiting for delivery to occur.
func TestSpool_LoopTickerDrivesReplay(t *testing.T) {
	dir := t.TempDir()
	tr := true

	// Start with delivery failing; we will write an event, then flip delivery
	// to succeed and let the ticker fire the replay.
	d := &fakeDelivery{failing: true}

	// Use a very short interval so the ticker fires quickly.
	s, err := newSpool(dir, 20*time.Millisecond, d.deliver)
	require.NoError(t, err)
	defer s.close()

	// Add event while the SIEM is "down" — spool it.
	s.add(&models.AuditEvent{ID: 77, EventType: "secret.read", Success: &tr})

	// Let the initial loop replay run (it fires immediately in loop()).
	// Then flip delivery to succeeding so the NEXT ticker-driven replay delivers.
	d.setFailing(false)

	// Wait up to 2 s for the ticker to fire replay and deliver.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.count() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Greater(t, d.count(), 0,
		"the loop ticker must drive replay() and deliver spooled events")
}
