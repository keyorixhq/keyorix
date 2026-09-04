package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newRiskTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RiskException{}))
	return NewLocalStorage(db)
}

func TestRiskExceptions_CreateListRevoke(t *testing.T) {
	ls := newRiskTestStore(t)
	ctx := context.Background()
	exp := time.Now().AddDate(0, 0, 30)

	a, err := ls.CreateRiskException(ctx, &models.RiskException{Title: "a", Category: "sod", ExpiresAt: exp})
	require.NoError(t, err)
	_, err = ls.CreateRiskException(ctx, &models.RiskException{Title: "b", Category: "mfa", ExpiresAt: exp, Revoked: true})
	require.NoError(t, err)

	// activeOnly excludes the revoked row.
	active, err := ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, "a", active[0].Title)

	// Without activeOnly, both are returned.
	all, err := ls.ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// Revoke; it then drops out of the active list.
	got, err := ls.GetRiskException(ctx, a.ID)
	require.NoError(t, err)
	got.Revoked = true
	revoked, err := ls.RevokeRiskExceptionIfNotRevoked(ctx, got)
	require.NoError(t, err)
	require.True(t, revoked)
	active, err = ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	assert.Empty(t, active)
}

// TestRevokeRiskExceptionIfNotRevoked_ConditionalOnNotRevoked_Sequential proves
// the storage guard itself (StateTransitionMissingCAS.ql): a second racing
// revoke against a row a first racing revoke already moved to revoked=true
// reports RowsAffected==0 via the bool, rather than silently re-applying (and
// re-attributing) the revoke the way the old unconditional Save did. Mirrors
// invitations_test.go's TestUpdateProjectInvitation_ConditionalOnPending_Sequential
// (#412) exactly, one level down for RiskException.
func TestRevokeRiskExceptionIfNotRevoked_ConditionalOnNotRevoked_Sequential(t *testing.T) {
	ctx := context.Background()
	ls := newRiskTestStore(t)
	exp := time.Now().AddDate(0, 0, 30)

	created, err := ls.CreateRiskException(ctx, &models.RiskException{
		Title: "shared exception", Category: "sod", ExpiresAt: exp,
	})
	require.NoError(t, err)

	// Two admins race to revoke the SAME still-unrevoked row, both reading it
	// before either write lands (the TOCTOU window this fix closes).
	firstAdminCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	revokedAt1 := time.Now()
	firstAdminCopy.Revoked = true
	firstAdminCopy.RevokedBy = 1
	firstAdminCopy.RevokedAt = &revokedAt1

	secondAdminCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	revokedAt2 := time.Now()
	secondAdminCopy.Revoked = true
	secondAdminCopy.RevokedBy = 2
	secondAdminCopy.RevokedAt = &revokedAt2

	// The first admin's write lands and wins.
	ok, err := ls.RevokeRiskExceptionIfNotRevoked(ctx, firstAdminCopy)
	require.NoError(t, err)
	require.True(t, ok, "the first writer must win")

	// The second admin's write, against a row that is no longer unrevoked, must
	// be rejected — not silently re-applied over (and re-attributed away from)
	// the first admin's revoke.
	ok, err = ls.RevokeRiskExceptionIfNotRevoked(ctx, secondAdminCopy)
	require.NoError(t, err)
	require.False(t, ok, "the second writer must lose, not clobber the first revoke")

	final, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, uint(1), final.RevokedBy, "the winning first admin's attribution must be the persisted state")
}

// TestApproveRiskExceptionIfPending_ConditionalOnPending_Sequential is the
// approve analogue: a second racing approve against a row a first racing
// revoke already moved to revoked=true must be rejected, not silently applied
// over a now-revoked exception (dual control's whole point — an
// approved-after-revoked exception would still suppress its matched violation).
func TestApproveRiskExceptionIfPending_ConditionalOnPending_Sequential(t *testing.T) {
	ctx := context.Background()
	ls := newRiskTestStore(t)
	exp := time.Now().AddDate(0, 0, 30)

	created, err := ls.CreateRiskException(ctx, &models.RiskException{
		Title: "shared exception", Category: "mfa", CreatedBy: 9, ExpiresAt: exp,
	})
	require.NoError(t, err)

	// Admin reads the still-pending row to revoke it.
	revokeCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	revokedAt := time.Now()
	revokeCopy.Revoked = true
	revokeCopy.RevokedBy = 1
	revokeCopy.RevokedAt = &revokedAt

	// A different approver reads the SAME still-pending row before the revoke
	// lands, to approve it.
	approveCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	approvedAt := time.Now()
	approveCopy.Approved = true
	approveCopy.ApprovedBy = 2
	approveCopy.ApprovedAt = &approvedAt

	// The revoke lands first.
	ok, err := ls.RevokeRiskExceptionIfNotRevoked(ctx, revokeCopy)
	require.NoError(t, err)
	require.True(t, ok)

	// The approve, against a row that is no longer unrevoked, must be rejected —
	// a revoked exception must never end up marked approved.
	ok, err = ls.ApproveRiskExceptionIfPending(ctx, approveCopy)
	require.NoError(t, err)
	require.False(t, ok, "an approve racing a revoke must lose, not mark a revoked exception approved")

	final, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked)
	assert.False(t, final.Approved, "the revoked exception must not end up approved")
}

// TestRevokeRiskExceptionIfNotRevoked_DoesNotClobberConcurrentApproval is #G42:
// unlike the two tests above (where the SECOND write is the one that must
// lose), here a legitimate revoke's WHERE clause only guards on `revoked`, so
// it still matches after a concurrent approve — the risk is the revoke's
// blind full-row overwrite silently reverting that just-committed approval
// even though the revoke itself succeeds correctly.
func TestRevokeRiskExceptionIfNotRevoked_DoesNotClobberConcurrentApproval(t *testing.T) {
	ctx := context.Background()
	ls := newRiskTestStore(t)
	exp := time.Now().AddDate(0, 0, 30)

	created, err := ls.CreateRiskException(ctx, &models.RiskException{
		Title: "shared exception", Category: "mfa", CreatedBy: 9, ExpiresAt: exp,
	})
	require.NoError(t, err)

	// An admin reads the still-pending, unrevoked row to revoke it — this copy
	// has NO knowledge of the approval about to land.
	revokeCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	revokedAt := time.Now()
	revokeCopy.Revoked = true
	revokeCopy.RevokedBy = 1
	revokeCopy.RevokedAt = &revokedAt

	// A different approver's approval commits FIRST, before the revoke's write.
	approveCopy, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	approvedAt := time.Now()
	approveCopy.Approved = true
	approveCopy.ApprovedBy = 2
	approveCopy.ApprovedAt = &approvedAt
	ok, err := ls.ApproveRiskExceptionIfPending(ctx, approveCopy)
	require.NoError(t, err)
	require.True(t, ok)

	// The revoke still legitimately matches (revoked was still false when this
	// call's WHERE clause evaluated) — it must succeed, but must NOT revert the
	// just-committed approval using its own stale (pre-approval) copy.
	ok, err = ls.RevokeRiskExceptionIfNotRevoked(ctx, revokeCopy)
	require.NoError(t, err)
	require.True(t, ok, "revoking an approved-but-not-yet-revoked exception is legitimate")

	final, err := ls.GetRiskException(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, final.Revoked, "the revoke itself must have taken effect")
	assert.True(t, final.Approved, "the concurrent approval must survive the revoke")
	assert.Equal(t, uint(2), final.ApprovedBy, "approval attribution must not be reverted")
}
