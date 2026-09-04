package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FIX-5 (Part 2 regression audit): a non-admin, non-creator caller must get the
// IDENTICAL denial (same error classification, same message) whether the target
// risk exception id doesn't exist at all, or exists but belongs to someone else --
// otherwise a caller who can reach this route at all (system.write) but holds no
// creator/admin standing could enumerate valid risk exception IDs by watching
// which response they get. RevokeRiskException had this exact #1645 oracle gap
// even after PR #1695 closed the identical shape for DeleteSoDPolicy -- the fix
// was never swept to this sibling site.
func TestRevokeRiskException_NonAdmin_NonExistentAndNonOwned_IdenticalDenial(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.RiskException{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.AssignUserRole(t, 1, 1, nil) // actor 1: admin-tier, creates the exception
	exc, err := h.CoreService.CreateRiskException(ctx, 1, false, "accept dormant access", "mfa", "", "temporary", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)

	h.CreateTestUser(t, "grace", 22)
	h.AssignUserRole(t, 22, 4, nil) // viewer -- neither creator nor admin-tier

	errOwned := h.CoreService.RevokeRiskException(ctx, 22, exc.ID)
	require.Error(t, errOwned)
	require.True(t, errors.Is(errOwned, core.ErrRiskExceptionPermissionDenied),
		"existing-but-foreign exception must classify as ErrRiskExceptionPermissionDenied")

	const nonExistentID = 999999
	errMissing := h.CoreService.RevokeRiskException(ctx, 22, nonExistentID)
	require.Error(t, errMissing)
	require.True(t, errors.Is(errMissing, core.ErrRiskExceptionPermissionDenied),
		"nonexistent exception id, for a non-admin caller, must ALSO classify as ErrRiskExceptionPermissionDenied")
	require.False(t, errors.Is(errMissing, core.ErrRiskExceptionNotFoundPublic),
		"a non-admin caller must never observe the not-found classification -- that's the oracle")

	assert.Equal(t, errOwned.Error(), errMissing.Error(),
		"the two denials must be byte-identical, not just the same HTTP status -- #1645 403-for-both requires identical bodies")
}

// FIX-5: the real-404 exception is narrow -- an admin-tier caller, who could
// revoke ANY exception regardless of which one this is, gets a genuine
// ErrRiskExceptionNotFoundPublic for a nonexistent id rather than the generic
// denial a non-admin caller gets. Mirrors TestDeleteSoDPolicy_AdminTier_NonExistentGetsRealNotFound.
func TestRevokeRiskException_AdminTier_NonExistentGetsRealNotFound(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.RiskException{}, &models.AuditEvent{}))
	ctx := context.Background()

	h.AssignUserRole(t, 1, 1, nil) // actor 1: admin-tier

	const nonExistentID = 999999
	err := h.CoreService.RevokeRiskException(ctx, 1, nonExistentID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, core.ErrRiskExceptionNotFoundPublic),
		"an admin-tier caller must get the real not-found classification, not the generic denial")
}
