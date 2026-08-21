package siem

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// buildRequest() — payload marshal error path
// ---------------------------------------------------------------------------

// TestBuildRequest_MarshalErrorOnInvalidDiff verifies that buildRequest surfaces
// a wrapped error (rather than panicking or silently producing a malformed
// request) when the event's Diff is not valid JSON. eventPayload.Diff is typed
// json.RawMessage, and encoding/json validates a RawMessage field's bytes when
// marshaling the containing struct — a malformed Diff (which should never occur
// given callers write it via json.Marshal, but a corrupted/hand-edited DB row is
// possible) must fail loudly here rather than shipping truncated/invalid JSON to
// the SIEM.
func TestBuildRequest_MarshalErrorOnInvalidDiff(t *testing.T) {
	f, err := New(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: "http://example.invalid"})
	require.NoError(t, err)
	t.Cleanup(f.Close)

	e := sampleEvent()
	e.Diff = `{not valid json` // malformed — not parseable as JSON

	_, err = f.buildRequest(context.Background(), e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal payload")
}

// TestBuildRequest_MarshalErrorOnInvalidDiff_AllProviders verifies the same
// marshal-error path is reached regardless of which provider's envelope wraps
// the payload (Splunk/Datadog nest it under a field; webhook marshals it
// directly) — all three code paths funnel into the same shared error check.
func TestBuildRequest_MarshalErrorOnInvalidDiff_AllProviders(t *testing.T) {
	for _, p := range []Provider{ProviderSplunk, ProviderDatadog, ProviderWebhook} {
		t.Run(string(p), func(t *testing.T) {
			f, err := New(Config{Enabled: true, Provider: p, Endpoint: "http://example.invalid", Token: "tok"})
			require.NoError(t, err)
			t.Cleanup(f.Close)

			e := sampleEvent()
			e.Diff = `[[[`

			_, err = f.buildRequest(context.Background(), e)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "marshal payload")
		})
	}
}

// ---------------------------------------------------------------------------
// scanSpoolLines() — final line with no trailing newline
// ---------------------------------------------------------------------------

// TestScanSpoolLines_FinalLineWithoutTrailingNewline verifies that a spool
// file's last line is still parsed even when it has no trailing '\n'. Every
// line spool.add() writes ends in '\n' (it appends one unconditionally), but a
// process killed mid-write, or a file hand-edited/truncated during recovery,
// can leave a final line with no newline — that record must not be silently
// dropped.
func TestScanSpoolLines_FinalLineWithoutTrailingNewline(t *testing.T) {
	data := []byte("{\"id\":1}\n{\"id\":2}") // second (last) line has NO trailing newline
	lines := scanSpoolLines(data)
	require.Len(t, lines, 2, "the final line without a trailing newline must still be captured")
	assert.Equal(t, `{"id":1}`, string(lines[0]))
	assert.Equal(t, `{"id":2}`, string(lines[1]))
}

// TestSpool_ReplayDeliversFinalLineWithoutTrailingNewline is the end-to-end
// counterpart: a spool file on disk whose last line lacks a trailing newline
// (as a crash mid-append could leave it) must still have that event replayed,
// not silently lost.
func TestSpool_ReplayDeliversFinalLineWithoutTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	s.close() // drive replay() manually

	tr := true
	e1, err := json.Marshal(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	require.NoError(t, err)
	e2, err := json.Marshal(&models.AuditEvent{ID: 2, EventType: "secret.updated", Success: &tr})
	require.NoError(t, err)

	// Write both lines directly, WITHOUT a trailing newline after the second —
	// simulating a process killed mid-append.
	content := append(append(e1, '\n'), e2...)
	require.NoError(t, os.WriteFile(filepath.Join(dir, spoolFileName), content, 0o600))

	s.replay()
	assert.ElementsMatch(t, []uint{1, 2}, d.delivered, "the event on the newline-less final line must still be delivered")
}
