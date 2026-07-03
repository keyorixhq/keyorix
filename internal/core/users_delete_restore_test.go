package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #106 — DeleteUser must fully deprovision (deactivate, terminate sessions, revoke
// PATs) instead of only soft-deleting the row, and must refuse to deprovision the
// install's last global administrator. RestoreUser must force re-credentialing
// rather than silently reactivating every pre-deletion PAT/session.

// TestDeleteUser_DeprovisionsAndRevokesCredentials pins the core fix: before it,
// DeleteUser left IsActive/AccountState untouched and never revoked the target's
// session or PAT, leaving both usable indefinitely.
func TestDeleteUser_DeprovisionsAndRevokesCredentials(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	target := seedUserWithRole(t, st, "offboarded", "project_viewer", storage.Scope{ProjectID: 1})
	_, err = c.storage.CreateSession(ctx, &models.Session{UserID: target, SessionToken: "sess-hash-1"})
	require.NoError(t, err)
	_, err = c.storage.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: target, Name: "ci-token", TokenHash: "pat-hash-1",
	})
	require.NoError(t, err)

	require.NoError(t, c.DeleteUser(ctx, admin.ID, target))

	hashes, err := c.storage.ListSessionTokenHashesForUser(ctx, target)
	require.NoError(t, err)
	assert.Empty(t, hashes, "the target's session must be terminated")

	pats, err := c.ListOwnPATs(ctx, target)
	require.NoError(t, err)
	for _, p := range pats {
		assert.True(t, p.Revoked, "every PAT must be revoked, not just left in place")
	}

	// GetUser excludes soft-deleted rows; list with IncludeDeleted to inspect it.
	users, _, err := st.ListUsers(ctx, &storage.UserFilter{IncludeDeleted: true, Page: 1, PageSize: 100})
	require.NoError(t, err)
	var u *models.User
	for _, candidate := range users {
		if candidate.ID == target {
			u = candidate
		}
	}
	require.NotNil(t, u, "the soft-deleted user must still be listable with IncludeDeleted")
	assert.False(t, u.IsActive, "IsActive must be cleared")
	assert.Equal(t, AccountDeprovisioned, u.AccountState)
}

// TestDeleteUser_RefusesLastGlobalAdmin mirrors guardLastAdminDeactivation's SCIM
// coverage for the plain admin DeleteUser path.
func TestDeleteUser_RefusesLastGlobalAdmin(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	err = c.DeleteUser(ctx, admin.ID, admin.ID)
	require.Error(t, err, "deleting the sole global administrator must be refused")
	assert.Contains(t, err.Error(), "last install administrator")
}

// TestDeleteUser_AllowsWhenAnotherAdminExists is the positive control: the guard
// only blocks the LAST admin, not every admin deletion.
func TestDeleteUser_AllowsWhenAnotherAdminExists(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	secondAdmin := seedUserWithRole(t, st, "second-admin", "admin", storage.Scope{})

	require.NoError(t, c.DeleteUser(ctx, admin.ID, secondAdmin),
		"a second global admin survives, so deleting one of them must succeed")
}

// TestRestoreUser_ForcesPasswordReset pins the restore-side fix: before it,
// RestoreUser only cleared deleted_at, silently reactivating the account exactly
// as it was pre-deletion (IsActive/AccountState untouched). Now the account comes
// back requiring a fresh credential.
func TestRestoreUser_ForcesPasswordReset(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	target := seedUserWithRole(t, st, "restored-user", "project_viewer", storage.Scope{ProjectID: 1})

	require.NoError(t, c.DeleteUser(ctx, admin.ID, target))
	require.NoError(t, c.RestoreUser(ctx, admin.ID, target))

	u, err := st.GetUser(ctx, target)
	require.NoError(t, err)
	assert.True(t, u.IsActive, "restore must reactivate the account")
	assert.Equal(t, AccountPasswordResetRequired, u.AccountState,
		"restore must force a fresh credential, not silently reactivate as fully active")
}

// TestRestoreUser_DoesNotResurrectRevokedCredentials pins the "delete→restore
// re-enables every pre-deletion PAT/session" half of #106: DeleteUser's
// revocations are permanent (hard-deleted sessions, revoked=true PATs) and are not
// undone by a later restore.
func TestRestoreUser_DoesNotResurrectRevokedCredentials(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	target := seedUserWithRole(t, st, "resurrection-check", "project_viewer", storage.Scope{ProjectID: 1})
	_, err = c.storage.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: target, Name: "pre-delete-token", TokenHash: "pat-hash-2",
	})
	require.NoError(t, err)

	require.NoError(t, c.DeleteUser(ctx, admin.ID, target))
	require.NoError(t, c.RestoreUser(ctx, admin.ID, target))

	pats, err := c.ListOwnPATs(ctx, target)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	assert.True(t, pats[0].Revoked, "a PAT revoked at delete time must stay revoked after restore")
}
