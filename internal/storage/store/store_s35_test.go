// store_s35_test.go — error-path sweep for local_users, local_sharing,
// local_sso, local_webauthn, local_mfa, and local_purge functions whose
// storage-error branches were not yet covered. All tests use newBrokenDB(t)
// (no-table SQLite DB) to force "no such table" errors on every DB operation.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── local_users.go ────────────────────────────────────────────────────────────

func TestGetUser_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUser(context.Background(), 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestLockUserForUpdate_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.LockUserForUpdate(context.Background(), 1)
	require.Error(t, err)
}

func TestGetUserByEmail_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserByEmail(context.Background(), "test@example.com")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestGetUserByUsername_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserByUsername(context.Background(), "testuser")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestGetUserByExternalID_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserByExternalID(context.Background(), "ext123")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestSetAccountState_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.SetAccountState(context.Background(), 1, "active", time.Now())
	require.Error(t, err)
}

func TestSetPasswordHash_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.SetPasswordHash(context.Background(), 1, "hash", time.Now())
	require.Error(t, err)
}

func TestUpdateLoginLockoutState_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.UpdateLoginLockoutState(context.Background(), 1, 0, nil, nil, 0)
	require.Error(t, err)
}

func TestListUsersInStateBefore_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListUsersInStateBefore(context.Background(), "active", time.Now())
	require.Error(t, err)
}

func TestDeleteUser_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteUser(context.Background(), 1)
	require.Error(t, err)
}

func TestRestoreUser_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.RestoreUser(context.Background(), 1)
	require.Error(t, err)
}

func TestListUsers_IncludeDeleted_DBError_S35(t *testing.T) {
	// Exercises the IncludeDeleted branch before Count fails.
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.ListUsers(context.Background(), &storage.UserFilter{IncludeDeleted: true})
	require.Error(t, err)
}

func TestListUsers_WithSearch_DBError_S35(t *testing.T) {
	// Exercises the Search != nil branch before Count fails.
	t.Parallel()
	ls := newBrokenDB(t)
	q := "bob"
	_, _, err := ls.ListUsers(context.Background(), &storage.UserFilter{Search: &q})
	require.Error(t, err)
}

func TestGetUserGroups_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetUserGroups(context.Background(), 1)
	require.Error(t, err)
}

func TestGetGroup_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetGroup(context.Background(), 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestUpdateGroup_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.UpdateGroup(context.Background(), &models.Group{})
	require.Error(t, err)
}

func TestListGroups_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListGroups(context.Background())
	require.Error(t, err)
}

func TestListGroupsPage_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.ListGroupsPage(context.Background(), 0, 10)
	require.Error(t, err)
}

func TestRemoveUserFromGroup_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.RemoveUserFromGroup(context.Background(), 1, 1)
	require.Error(t, err)
}

func TestListGroupMembersByGroupIDs_DBError_S35(t *testing.T) {
	// Non-empty IDs slice: exercises the raw DB query path.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListGroupMembersByGroupIDs(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

func TestAddPasswordHistory_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.AddPasswordHistory(context.Background(), 1, "$2a$10$abc", time.Now())
	require.Error(t, err)
}

func TestRecentPasswordHashes_DBError_S35(t *testing.T) {
	// Limit > 0: exercises the Find path.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.RecentPasswordHashes(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestPrunePasswordHistory_NegativeKeep_DBError_S35(t *testing.T) {
	// keep = -1 → keep becomes 0, then Pluck fails on broken DB.
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.PrunePasswordHistory(context.Background(), 1, -1)
	require.Error(t, err)
}

// ── local_sharing.go ──────────────────────────────────────────────────────────

func TestListSharesBySecret_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharesBySecret(context.Background(), 1)
	require.Error(t, err)
}

func TestListSharesBySecretIDs_DBError_S35(t *testing.T) {
	// Non-empty slice: exercises the Find path (empty returns nil,nil early).
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharesBySecretIDs(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

func TestListSharesByUser_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharesByUser(context.Background(), 1)
	require.Error(t, err)
}

func TestListSharesByOwner_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharesByOwner(context.Background(), 1)
	require.Error(t, err)
}

func TestListSharesByGroup_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListSharesByGroup(context.Background(), 1)
	require.Error(t, err)
}

func TestDeleteExpiredShareRecords_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.DeleteExpiredShareRecords(context.Background(), time.Now())
	require.Error(t, err)
}

// ── local_sso.go ─────────────────────────────────────────────────────────────

func TestConsumeSSOLoginState_DBError_S35(t *testing.T) {
	// Broken DB → First() returns "no such table" (NOT gorm.ErrRecordNotFound)
	// → hits the generic retrieval error branch.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ConsumeSSOLoginState(context.Background(), "state-xyz")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

// ── local_webauthn.go ─────────────────────────────────────────────────────────

func TestListWebAuthnCredentials_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ListWebAuthnCredentials(context.Background(), 1)
	require.Error(t, err)
}

func TestDeleteWebAuthnCredential_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.DeleteWebAuthnCredential(context.Background(), 1, 1)
	require.Error(t, err)
}

func TestCountWebAuthnCredentials_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.CountWebAuthnCredentials(context.Background(), 1)
	require.Error(t, err)
}

func TestConsumeWebAuthnSession_DBError_S35(t *testing.T) {
	// Broken DB → Update inside transaction fails → 1 stmt covered.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ConsumeWebAuthnSession(context.Background(), "token-hash", time.Now())
	require.Error(t, err)
}

// ── local_mfa.go ──────────────────────────────────────────────────────────────

func TestConsumeMFAChallenge_DBError_S35(t *testing.T) {
	// Broken DB → Update inside transaction fails.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.ConsumeMFAChallenge(context.Background(), "token-hash", time.Now())
	require.Error(t, err)
}

// ── local_purge.go ────────────────────────────────────────────────────────────

func TestPurgeDeletedEnvironmentsBefore_DBError_S35(t *testing.T) {
	// Exercises purgeDeletedBefore's result.Error branch.
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.PurgeDeletedEnvironmentsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestDeleteAnomalyAlertsBefore_DBError_S35(t *testing.T) {
	// Both non-zero → Delete fails → result.Error branch.
	t.Parallel()
	ls := newBrokenDB(t)
	ack := time.Now().Add(-24 * time.Hour)
	unack := time.Now().Add(-365 * 24 * time.Hour)
	_, err := ls.DeleteAnomalyAlertsBefore(context.Background(), ack, unack)
	require.Error(t, err)
}

func TestDeleteExpiredBreakGlassBefore_DBError_S35(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.DeleteExpiredBreakGlassBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestDeleteClosedAccessReviewsBefore_DBError_S35(t *testing.T) {
	// Broken DB → Pluck inside transaction fails → outer error path covered.
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.DeleteClosedAccessReviewsBefore(context.Background(), time.Now())
	require.Error(t, err)
}

func TestDeleteResolvedAccessRequestsBefore_DBError_S35(t *testing.T) {
	// Broken DB → Pluck inside transaction fails → outer error path covered.
	t.Parallel()
	ls := newBrokenDB(t)
	_, _, err := ls.DeleteResolvedAccessRequestsBefore(context.Background(), time.Now())
	require.Error(t, err)
}
