package siem

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDelivery records delivered event IDs and can be toggled to fail.
type fakeDelivery struct {
	mu        sync.Mutex
	failing   bool
	delivered []uint
}

func (d *fakeDelivery) deliver(_ context.Context, e *models.AuditEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return assertErr
	}
	d.delivered = append(d.delivered, e.ID)
	return nil
}

func (d *fakeDelivery) setFailing(v bool) { d.mu.Lock(); d.failing = v; d.mu.Unlock() }
func (d *fakeDelivery) count() int        { d.mu.Lock(); defer d.mu.Unlock(); return len(d.delivered) }

var assertErr = &deliveryError{}

type deliveryError struct{}

func (*deliveryError) Error() string { return "siem down" }

func TestSpool_PersistsAndReplaysOnRecovery(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{failing: true}
	// Long interval so we drive replay() manually and avoid timing flakiness.
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)

	// Spool two events while the SIEM is "down".
	tr := true
	s.add(&models.AuditEvent{ID: 1, EventType: "secret.read", Success: &tr})
	s.add(&models.AuditEvent{ID: 2, EventType: "secret.updated", Success: &tr})

	spoolPath := filepath.Join(dir, spoolFileName)
	_, statErr := os.Stat(spoolPath)
	require.NoError(t, statErr, "events must be persisted to the spool file")

	// A replay while still failing must keep both events (nothing delivered).
	s.replay()
	assert.Equal(t, 0, d.count())
	_, statErr = os.Stat(spoolPath)
	require.NoError(t, statErr, "a failed replay must retain the backlog")

	// SIEM recovers — the next replay drains the backlog and removes the file.
	d.setFailing(false)
	s.replay()
	assert.ElementsMatch(t, []uint{1, 2}, d.delivered)
	_, statErr = os.Stat(spoolPath)
	assert.True(t, os.IsNotExist(statErr), "a fully-drained spool must delete its file")
}

func TestSpool_DiscardsUnparseableLine(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDelivery{}
	s, err := newSpool(dir, time.Hour, d.deliver)
	require.NoError(t, err)
	t.Cleanup(s.close)

	// A corrupt line must not wedge the spool forever.
	require.NoError(t, os.WriteFile(filepath.Join(dir, spoolFileName), []byte("not json\n"), 0o600))
	s.replay()
	_, statErr := os.Stat(filepath.Join(dir, spoolFileName))
	assert.True(t, os.IsNotExist(statErr), "an unparseable backlog must be cleared, not retried forever")
}
