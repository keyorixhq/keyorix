// local_audit_chain_cascade_sweep_test.go — partial-coverage sweep for
// local_audit_chain.go: VerifyAuditChain/MigrateAuditChainEncoding DB-error
// and anchor-mismatch branches. NOTE: LogAuditEvent's and
// MigrateAuditChainEncoding's `tx.Dialector.Name() == "postgres"` advisory-
// lock branches (lines 174-175, 279-281) are genuinely unreachable via
// SQLite and are intentionally NOT covered here -- out of scope per this
// sweep's instructions (reserved for the dedicated lock-function tests).
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestVerifyAuditChain_FindFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.VerifyAuditChain(context.Background(), nil)
	require.Error(t, err)
}

func TestVerifyAuditChain_AnchorMismatch(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", EntryHash: "abc123", PrevHash: "not-genesis-and-not-anchor",
	}).Error)

	result, err := ls.VerifyAuditChain(context.Background(), &storage.AuditChainAnchor{
		RowID: 999, PrevHash: "some-other-prev", EntryHash: "some-other-entry",
	})
	require.NoError(t, err)
	require.False(t, result.Valid)
	require.NotNil(t, result.FirstBrokenID)
}

func TestMigrateAuditChainEncoding_FindFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.Error(t, err)
}

func TestMigrateAuditChainEncoding_UpdatesFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})
	// A chained row (non-empty EntryHash) whose stored hash/prev_hash won't
	// match the freshly recomputed value, forcing the corrective Updates call.
	require.NoError(t, ls.db.Create(&models.AuditEvent{
		EventType: "secret.read", EntryHash: "stale-hash", PrevHash: "stale-prev",
	}).Error)

	dropTableAfterQueries(t, ls.db, 1, "audit_events")

	_, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.Error(t, err)
}
