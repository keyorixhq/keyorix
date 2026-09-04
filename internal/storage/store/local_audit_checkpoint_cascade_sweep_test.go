// local_audit_checkpoint_cascade_sweep_test.go — partial-coverage sweep for
// local_audit_checkpoint.go's AuditEntryHashByID: the second (existence
// Count) query's own DB-error branch, isolated from the first (Scan) query
// which store_coverage_gaps_test.go's TestAuditEntryHashByID_BrokenDB already
// covers via a fully-broken DB.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestAuditEntryHashByID_CountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.AuditEvent{})

	require.NoError(t, ls.db.Callback().Query().Before("gorm:query").Register("drop-audit_events-before-count", func(tx *gorm.DB) {
		tx.Exec("DROP TABLE IF EXISTS audit_events")
	}))

	_, _, err := ls.AuditEntryHashByID(context.Background(), 1)
	require.Error(t, err)
}
