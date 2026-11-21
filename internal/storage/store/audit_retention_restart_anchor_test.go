package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #4351: a purge that removes every chained row still returns an anchor, so the
// caller can sign the count; without it the checkpoint that certified those rows
// read as a truncation. It is a restart anchor: genesis prev_hash, no
// entry_hash, RowID the first id the purge did not remove.
func TestDeleteAuditLogsBefore_EmptiedTableReturnsRestartAnchor(t *testing.T) {
	t.Parallel()
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.AddDate(0, 0, -40)

	require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: old}).Error) // legacy
	prev := auditGenesisHash
	var last uint
	for _, h := range []string{"a", "b", "c"} {
		e := &models.AuditEvent{EventType: "secret.read", EventTime: old, PrevHash: prev, EntryHash: "entry-" + h}
		require.NoError(t, ls.db.Create(e).Error)
		prev, last = e.EntryHash, e.ID
	}

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Equal(t, int64(4), n)
	require.NotNil(t, anchor, "the chained rows' count must not be lost with the last row")
	require.Equal(t, last+1, anchor.RowID)
	require.Equal(t, auditGenesisHash, anchor.PrevHash)
	require.Empty(t, anchor.EntryHash)
	require.Equal(t, int64(3), anchor.PurgedEvents, "chained rows only")
}

// Survivors that already start at genesis (the chain restarted after an
// earlier emptying purge) get a restart anchor at the first survivor.
func TestDeleteAuditLogsBefore_GenesisSurvivorReturnsRestartAnchor(t *testing.T) {
	t.Parallel()
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.AddDate(0, 0, -40)

	require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: old, PrevHash: "x", EntryHash: "entry-a"}).Error)
	g := &models.AuditEvent{EventType: "secret.read", EventTime: now, PrevHash: auditGenesisHash, EntryHash: "entry-g"}
	require.NoError(t, ls.db.Create(g).Error)

	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.NotNil(t, anchor)
	require.Equal(t, g.ID, anchor.RowID)
	require.Equal(t, auditGenesisHash, anchor.PrevHash)
	require.Empty(t, anchor.EntryHash)
	require.Equal(t, int64(1), anchor.PurgedEvents)
}

// Emptying a table that only held legacy (unchained) rows records nothing:
// no checkpoint ever counted them.
func TestDeleteAuditLogsBefore_EmptiedLegacyOnlyTableNoAnchor(t *testing.T) {
	t.Parallel()
	ls := newAuditRetentionTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for range 2 {
		require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: now.AddDate(0, 0, -40)}).Error)
	}
	n, anchor, err := ls.DeleteAuditLogsBefore(ctx, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	require.Nil(t, anchor)
}
