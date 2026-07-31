package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A duplicate (request_id, approver_id) approval must collapse to a single row: the
// composite unique index plus OnConflict-DoNothing keep the M-of-K dual-control count
// honest, so a racing same-approver double-submit can't be counted as two sign-offs.
func TestCreateAccessRequestApproval_DedupsSameApprover(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AccessRequestApproval{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: 1, ApproverID: 11}))
	// Same request + approver again — a benign no-op, not a second sign-off.
	require.NoError(t, ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: 1, ApproverID: 11}))

	rows, err := ls.ListAccessRequestApprovals(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 1, "the same approver must yield exactly one approval row")

	// A distinct approver is a separate sign-off.
	require.NoError(t, ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: 1, ApproverID: 12}))
	rows, err = ls.ListAccessRequestApprovals(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
}
