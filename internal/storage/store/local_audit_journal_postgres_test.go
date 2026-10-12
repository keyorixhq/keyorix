package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestLocalAuditJournal_Postgres_ReplayAndRestart runs the journal's DB side
// on real Postgres (the advisory lock, the ON CONFLICT cursor upsert, the
// origin-table key): writes go through LogAuditEvent -> journal ->
// replicator, a retried batch adds nothing, the chain verifies, and a
// restart against the same journal replays nothing twice.
func TestLocalAuditJournal_Postgres_ReplayAndRestart(t *testing.T) {
	ls := multiRowPGStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	const replica = "pg-r1"
	const n = 20

	require.NoError(t, ls.EnableLocalAuditJournal(ctx, dir, replica))
	for i := 0; i < n; i++ {
		tr := true
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "pg_journal.write", Success: &tr, EventTime: time.Now(), ActorType: "system"}))
	}
	require.NoError(t, ls.CloseLocalAuditJournal()) // waits for the replicator to drain
	require.EqualValues(t, n, countReplicaRows(t, ls, replica))

	require.NoError(t, ls.replayJournalRecords(ctx, replica, journalTestRecords(t, 0, 1, 2)),
		"replaying records the cursor already covers must be a no-op, not a key violation")
	require.EqualValues(t, n, countReplicaRows(t, ls, replica))

	restarted := NewLocalStorage(ls.db)
	require.NoError(t, restarted.EnableLocalAuditJournal(ctx, dir, replica))
	require.NoError(t, restarted.CloseLocalAuditJournal())
	require.EqualValues(t, n, countReplicaRows(t, ls, replica))

	var events int64
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Count(&events).Error)
	require.EqualValues(t, n, events)
	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, v.Valid, "chain must verify: %s", v.Reason)
}
