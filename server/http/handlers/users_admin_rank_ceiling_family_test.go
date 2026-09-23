// users_admin_rank_ceiling_family_test.go — S1 sweep (CLI-split inventory
// #2012): per-route coverage for the rest of the users.write/users.delete
// family that mutates ANOTHER user's account (DeleteUser, RestoreUser,
// SuspendUser, ReactivateUser, RequirePasswordReset, RevokeSessions).
// UpdateUser and ResendSetupLink are covered in
// users_admin_rank_ceiling_test.go. Each route gets: outranked target
// refused (403), ordinary target still allowed (200/204).
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func actorCtx(actorID uint, username string) *middleware.UserContext {
	return &middleware.UserContext{UserID: actorID, Username: username, ActorType: core.ActorTypeUser}
}

// seedGlobalAdminBypassUser creates a user holding a FRESH "admin" role
// (independent of freshCoreS12WithAdmin's own seeded "system_admin" role row,
// but functionally identical) — used where a test needs a second, distinct
// admin-bypass holder (e.g. to delete/suspend the seeded admin without
// tripping guardLastAdminDeactivation's last-admin lockout, which counts
// admins by NAME membership in adminRoleNames, not by the bypass flag alone
// — see targetHasGlobalAdminRole/isAdminRoleName, internal/core/authz.go).
func seedGlobalAdminBypassUser(t *testing.T, db *gorm.DB, username string) uint {
	t.Helper()
	role := &models.Role{Name: "admin", NameFolded: "admin", BypassesPermissionChecks: true}
	if err := db.Where("name = ?", "admin").First(&models.Role{}).Error; err != nil {
		require.NoError(t, db.Create(role).Error)
	} else {
		require.NoError(t, db.Where("name = ?", "admin").First(role).Error)
	}
	u := &models.User{
		Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		AccountState: "active", IsActive: true,
	}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID}).Error)
	return u.ID
}

// ── DELETE /api/v1/users/{id} ───────────────────────────────────────────────

func TestDeleteUser_UsersDeleteHolderCannotDeleteHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_delete", "users.write", "users.delete")

	req := withChiParams(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_delete")))
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)

	assert.Equal(t, 403, w.Code, "a users.delete-only holder must be refused deleting a higher-privileged target: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.DeletedAt.Valid, "the admin must NOT have been soft-deleted")
}

func TestDeleteUser_UsersDeleteHolderCanDeleteOrdinaryTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_delete_target")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_delete_ordinary", "users.write", "users.delete")

	req := withChiParams(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_actor_delete_ordinary")))
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)

	assert.Equal(t, 204, w.Code, "deleting an ordinary target must still succeed: %s", w.Body.String())
}

// ── POST /api/v1/users/{id}/restore ─────────────────────────────────────────

func TestRestoreUser_UsersWriteHolderCannotRestoreHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	// Seed a SECOND, independent admin-bypass holder so
	// guardLastAdminDeactivation doesn't block the delete step below -- this
	// test is about the restore ceiling, not the last-admin guard.
	backupAdminID := seedGlobalAdminBypassUser(t, db, "s1_backup_admin_for_restore")

	deleteReq := withChiParams(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	deleteReq = deleteReq.WithContext(context.WithValue(deleteReq.Context(), middleware.GetUserContextKey(), actorCtx(backupAdminID, "s1_backup_admin_for_restore")))
	wDel := httptest.NewRecorder()
	h.DeleteUser(wDel, deleteReq)
	require.Equal(t, 204, wDel.Code, "setup: deleting the target admin (as ANOTHER admin) must succeed: %s", wDel.Body.String())

	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_restore", "users.write")

	restoreReq := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	restoreReq = restoreReq.WithContext(context.WithValue(restoreReq.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_restore")))
	w := httptest.NewRecorder()
	h.RestoreUser(w, restoreReq)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused restoring a higher-privileged (deleted) target: %s", w.Body.String())
}

func TestRestoreUser_UsersWriteHolderCanRestoreOrdinaryTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_restore_target")

	deleteReq := withChiParams(httptest.NewRequest("DELETE", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	deleteReq = deleteReq.WithContext(context.WithValue(deleteReq.Context(), middleware.GetUserContextKey(), actorCtx(admin.ID, "testuser_s12")))
	wDel := httptest.NewRecorder()
	h.DeleteUser(wDel, deleteReq)
	require.Equal(t, 204, wDel.Code, "setup: deleting the ordinary target must succeed: %s", wDel.Body.String())

	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_restore_ordinary", "users.write")
	restoreReq := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	restoreReq = restoreReq.WithContext(context.WithValue(restoreReq.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_actor_restore_ordinary")))
	w := httptest.NewRecorder()
	h.RestoreUser(w, restoreReq)

	assert.Equal(t, 200, w.Code, "restoring an ordinary target must still succeed: %s", w.Body.String())
}

// ── POST /api/v1/users/{id}/suspend, /reactivate, /require-password-reset ──

func TestSuspendUser_UsersWriteHolderCannotSuspendHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	// A backup admin so guardLastAdminDeactivation (which fires BEFORE the
	// ceiling check inside SuspendUser) doesn't preempt this test's own
	// refusal with its own, unrelated "last install administrator" error.
	_ = seedGlobalAdminBypassUser(t, db, "s1_backup_admin_for_suspend")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_suspend", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_suspend")))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused suspending a higher-privileged target: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", reloaded.AccountState, "the admin's account state must be UNCHANGED")
}

func TestSuspendUser_UsersWriteHolderCanSuspendOrdinaryTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_suspend_target")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_suspend_ordinary", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_actor_suspend_ordinary")))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)

	require.Equal(t, 200, w.Code, "suspending an ordinary target must still succeed: %s", w.Body.String())
	reloaded, err := cs.Storage().GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", reloaded.AccountState)
}

func TestReactivateUser_UsersWriteHolderCannotReactivateHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_reactivate", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_reactivate")))
	w := httptest.NewRecorder()
	h.ReactivateUser(w, req)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused reactivating a higher-privileged target: %s", w.Body.String())
}

func TestRequirePasswordReset_UsersWriteHolderCannotForceResetHigherPrivilegedTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_pwreset", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_pwreset")))
	w := httptest.NewRecorder()
	h.RequirePasswordReset(w, req)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused forcing a password reset on a higher-privileged target: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", reloaded.AccountState, "the admin's account state must be UNCHANGED")
}

func TestRequirePasswordReset_UsersWriteHolderCanForceResetOrdinaryTarget_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_pwreset_target")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_pwreset_ordinary", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_actor_pwreset_ordinary")))
	w := httptest.NewRecorder()
	h.RequirePasswordReset(w, req)

	require.Equal(t, 200, w.Code, "forcing a password reset on an ordinary target must still succeed: %s", w.Body.String())
	reloaded, err := cs.Storage().GetUser(ctx, targetID)
	require.NoError(t, err)
	assert.Equal(t, "password_reset_required", reloaded.AccountState)
}

// ── POST /api/v1/users/{id}/revoke-sessions ─────────────────────────────────

func TestRevokeSessions_UsersWriteHolderCannotRevokeHigherPrivilegedTargetSessions_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_revoke", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_revoke")))
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)

	assert.Equal(t, 403, w.Code, "a users.write-only holder must be refused force-logging-out a higher-privileged target: %s", w.Body.String())
}

func TestRevokeSessions_UsersWriteHolderCanRevokeOrdinaryTargetSessions_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	targetID := seedOrdinaryUser(t, db, "s1_ordinary_revoke_target")
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_actor_revoke_ordinary", "users.write")

	req := withChiParams(httptest.NewRequest("POST", "/", nil), map[string]string{"id": machineUintToStr(targetID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_actor_revoke_ordinary")))
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)

	assert.Equal(t, 200, w.Code, "revoking an ordinary target's sessions must still succeed: %s", w.Body.String())
}

// ── /system sibling regression check ────────────────────────────────────────

// TestUpdateUserIfActiveStateMatchesProxy_StillRefusesUsersWriteOnlyHolder_RealServer
// re-confirms the ALREADY-shipped F5 fix still refuses a users.write-only
// actor after this PR's authz.go change (the bypass-role fix in
// requireEqualOrGreaterAdminAuthority applies to every caller of that
// function, not just the new ones added here).
func TestUpdateUserIfActiveStateMatchesProxy_StillRefusesUsersWriteOnlyHolder_RealServer(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	attackerID := seedUsersWriteOnlyActor(t, db, "s1_attacker_f5_regression", "users.write")

	body, err := json.Marshal(map[string]interface{}{
		"username": admin.Username, "email": "f5-regression@evil.example",
	})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(admin.ID)})
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), actorCtx(attackerID, "s1_attacker_f5_regression")))
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)

	assert.Equal(t, 403, w.Code, "F5's own fix must still refuse a users.write-only holder targeting the admin: %s", w.Body.String())
}
