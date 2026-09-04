// local_audit_cascade_sweep_test.go — partial-coverage sweep for
// local_audit.go: GetAuditLogs' two Find-error branches, GetSecretReadCounts'
// Scan error, and DeleteAuditLogsBefore's head-lookup error / genuine
// re-anchor branches. NOTE: line 114 (PrincipalSecretFirstSeen's `if
// r.FirstSeen.t == nil { continue }`) is intentionally NOT covered here --
// investigation found it very likely unreachable: the query's own WHERE
// clause ("access_time >= ?") excludes NULL access_time rows before they can
// ever reach GROUP BY/MIN(), so a matched group's MIN(access_time) can never
// itself be SQL NULL. Same defensive-dead-code shape as
// local_purge.go:PurgeDeletedSecretsBefore's analogous `continue` (see
// local_purge_cascade_sweep_test.go's package doc).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestGetAuditLogs_AscendingFindFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	dropTableAfterQueries(t, ls.db, 1, "audit_events")

	_, _, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{Ascending: true, PageSize: 10})
	require.Error(t, err)
}

func TestGetAuditLogs_FindFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	dropTableAfterQueries(t, ls.db, 1, "audit_events")

	_, _, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{PageSize: 10})
	require.Error(t, err)
}

func TestGetSecretReadCounts_ScanFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetSecretReadCounts(context.Background(), 1, time.Now().Add(-time.Hour), time.Now(), 10)
	require.Error(t, err)
}

func TestDeleteAuditLogsBefore_HeadLookupFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: old}).Error)

	// The Delete (RowsAffected > 0) is a different callback family and runs
	// fine; drop the table before the very first Row-family (Scan) call, the
	// head lookup right after.
	dropTableAfterRows(t, ls.db, 0, "audit_events")

	_, _, err := ls.DeleteAuditLogsBefore(ctx, time.Now())
	require.Error(t, err)
}

func TestDeleteAuditLogsBefore_ReanchorsSurvivingChainedRow(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	surviving := time.Now().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: old}).Error)
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", EventTime: surviving,
		PrevHash: "mid-chain-prev-hash", EntryHash: "mid-chain-entry-hash",
	}).Error)

	cutoff := time.Now().Add(-24 * time.Hour)
	deleted, anchor, err := ls.DeleteAuditLogsBefore(ctx, cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)
	require.NotNil(t, anchor)
	require.Equal(t, "mid-chain-prev-hash", anchor.PrevHash)
	require.Equal(t, "mid-chain-entry-hash", anchor.EntryHash)
}
