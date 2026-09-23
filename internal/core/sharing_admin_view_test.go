// sharing_admin_view_test.go — CLI-split inventory §6 secondary gap:
// ListSharedSecretsForUser is the core-layer authorization for the new
// GET /api/v1/users/{id}/shared-secrets route (server/http/handlers/
// shares_query.go). These tests cover the matrix the route needs: self-view,
// an admin viewing a lower-ranked target (allowed + audited), a
// lower-privileged actor refused against a higher-ranked target, and an
// unknown target refused through the IDENTICAL path as a real ceiling
// refusal (no existence oracle).
package core_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var sharedSecretsAdminViewDBCounter atomic.Int64

// freshSharedSecretsAdminViewCore returns a KeyorixCore backed by a fresh,
// uniquely-named in-memory SQLite DB with just the models this test file's
// scenarios touch.
func freshSharedSecretsAdminViewCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	n := sharedSecretsAdminViewDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxsharedsecretsadminview_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.ShareRecord{}, &models.AuditEvent{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedRoleWithPermission creates a role holding a single named permission
// (global scope, non-bypass) and returns its ID.
func seedRoleWithPermission(t *testing.T, db *gorm.DB, roleName, permName string) uint {
	t.Helper()
	perm := &models.Permission{Name: permName}
	require.NoError(t, db.Create(perm).Error)
	role := &models.Role{Name: roleName, NameFolded: roleName}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	return role.ID
}

// seedBypassRole creates an admin-bypass role (BypassesPermissionChecks) —
// the "real system_admin" shape a genuinely higher-ranked target holds.
func seedBypassRole(t *testing.T, db *gorm.DB, roleName string) uint {
	t.Helper()
	role := &models.Role{Name: roleName, NameFolded: roleName, BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	return role.ID
}

// seedSharedSecretsUser creates a user, optionally with a role grant
// (roleID == 0 means no role at all), and returns its ID.
func seedSharedSecretsUser(t *testing.T, db *gorm.DB, username string, roleID uint) uint {
	t.Helper()
	u := &models.User{
		Username: username, UsernameFolded: username,
		Email: username + "@example.com", EmailFolded: username + "@example.com",
		AccountState: "active", IsActive: true,
	}
	require.NoError(t, db.Create(u).Error)
	if roleID != 0 {
		require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: roleID}).Error)
	}
	return u.ID
}

// seedShareForRecipient creates a secret owned by a throwaway owner and
// shares it directly with recipientID, returning the secret's ID.
func seedShareForRecipient(t *testing.T, db *gorm.DB, recipientID uint) uint {
	t.Helper()
	secret := &models.SecretNode{Name: "db-pass", ProjectID: 1, EnvironmentID: 1, OwnerID: 999, Status: "active", Type: "password"}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: secret.ID, OwnerID: 999, RecipientID: recipientID, IsGroup: false, Permission: "read",
	}).Error)
	return secret.ID
}

func countAuditEvents(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// TestListSharedSecretsForUser_SelfView_NoAdminEventEmitted: a caller viewing
// their OWN shared secrets needs no ceiling check and is not treated as an
// "admin viewed another user" disclosure — matches GET /api/v1/shared-secrets
// (the caller's own list), which has never been audited.
func TestListSharedSecretsForUser_SelfView_NoAdminEventEmitted(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	userID := seedSharedSecretsUser(t, db, "self_viewer", 0)
	secretID := seedShareForRecipient(t, db, userID)

	secrets, err := cs.ListSharedSecretsForUser(ctx, userID, userID)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, secretID, secrets[0].ID)

	assert.Zero(t, countAuditEvents(t, db, string(core.ShareAuditEventSharedSecretsAdminViewed)),
		"a self-view must not be audited as an admin disclosure")
}

// TestListSharedSecretsForUser_AdminViewsLowerRankedUser_AllowedAndAudited:
// an actor holding SOME elevated permission (but not global admin) viewing an
// ordinary, unprivileged target's shares must succeed and be audited as a
// disclosure — the ceiling only blocks a target holding MORE than the actor.
func TestListSharedSecretsForUser_AdminViewsLowerRankedUser_AllowedAndAudited(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	actorRoleID := seedRoleWithPermission(t, db, "s6_actor_role", "users.write")
	actorID := seedSharedSecretsUser(t, db, "s6_admin_actor", actorRoleID)
	targetID := seedSharedSecretsUser(t, db, "s6_ordinary_target", 0)
	secretID := seedShareForRecipient(t, db, targetID)

	secrets, err := cs.ListSharedSecretsForUser(ctx, actorID, targetID)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, secretID, secrets[0].ID)

	assert.Equal(t, int64(1), countAuditEvents(t, db, string(core.ShareAuditEventSharedSecretsAdminViewed)),
		"a cross-user view must be audited as a disclosure exactly once")

	var event models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", string(core.ShareAuditEventSharedSecretsAdminViewed)).First(&event).Error)
	require.NotNil(t, event.UserID)
	assert.Equal(t, actorID, *event.UserID, "the audited actor must be the ADMIN making the request, not the target")
	assert.True(t, *event.Success)
}

// TestListSharedSecretsForUser_LowerRankActorRefusedAgainstHigherRankedTarget:
// an actor holding only users.write (not global admin) must be refused when
// targeting a real admin-bypass user — the S1 ceiling extended to this route.
func TestListSharedSecretsForUser_LowerRankActorRefusedAgainstHigherRankedTarget(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	actorRoleID := seedRoleWithPermission(t, db, "s6_weak_actor_role", "users.write")
	actorID := seedSharedSecretsUser(t, db, "s6_weak_actor", actorRoleID)
	adminRoleID := seedBypassRole(t, db, "system_admin")
	targetID := seedSharedSecretsUser(t, db, "s6_admin_target", adminRoleID)
	seedShareForRecipient(t, db, targetID)

	secrets, err := cs.ListSharedSecretsForUser(ctx, actorID, targetID)
	require.Error(t, err)
	assert.Nil(t, secrets)
	assert.True(t, errors.Is(err, core.ErrInsufficientAdminAuthority))

	assert.Equal(t, int64(1), countAuditEvents(t, db, core.EventAdminRankCeilingRefused),
		"the refusal must be audited (ADR-102's detection posture depends on refusals being recorded)")
	assert.Zero(t, countAuditEvents(t, db, string(core.ShareAuditEventSharedSecretsAdminViewed)),
		"a refused attempt must never also emit the disclosure event")
}

// TestListSharedSecretsForUser_UnknownTarget_RefusedIdenticallyToRealCeilingRefusal:
// a target ID that does not exist must resolve through the SAME error type
// and the SAME audit event as a genuine ceiling refusal -- otherwise a caller
// holding the base permission could use this route to probe which numeric
// user IDs exist, especially among higher-privileged accounts.
func TestListSharedSecretsForUser_UnknownTarget_RefusedIdenticallyToRealCeilingRefusal(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	actorRoleID := seedRoleWithPermission(t, db, "s6_probe_actor_role", "users.write")
	actorID := seedSharedSecretsUser(t, db, "s6_probe_actor", actorRoleID)
	const nonexistentTargetID = uint(999999)

	secrets, err := cs.ListSharedSecretsForUser(ctx, actorID, nonexistentTargetID)
	require.Error(t, err)
	assert.Nil(t, secrets)
	assert.True(t, errors.Is(err, core.ErrInsufficientAdminAuthority),
		"an unknown target must wrap the SAME sentinel as a real ceiling refusal")

	assert.Equal(t, int64(1), countAuditEvents(t, db, core.EventAdminRankCeilingRefused),
		"an attempt against an unknown target is itself worth alerting on, same as a real refusal")
}

// TestListSharedSecretsForUser_EqualRankActorAllowed: the ceiling is "equal or
// greater," not "strictly greater" -- an actor holding the SAME permission as
// the target must be allowed, matching UpdateUser's own equal-rank case.
func TestListSharedSecretsForUser_EqualRankActorAllowed(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	roleID := seedRoleWithPermission(t, db, "s6_equal_role", "users.write")
	actorID := seedSharedSecretsUser(t, db, "s6_equal_actor", roleID)
	targetID := seedSharedSecretsUser(t, db, "s6_equal_target", roleID)
	secretID := seedShareForRecipient(t, db, targetID)

	secrets, err := cs.ListSharedSecretsForUser(ctx, actorID, targetID)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, secretID, secrets[0].ID)
}

// TestListSharedSecretsForUser_TargetWithNoSharesReturnsEmptyNotNil: a valid,
// authorized target with zero shares gets an empty slice, matching
// ListSharedSecrets' own nil-to-empty normalization -- important here
// specifically because it must be visually indistinguishable from the
// unknown-target case at the HTTP layer (both empty), even though this one is
// a 200 while the unknown-target case is a 403 (see the router/handler tests
// for the client-visible shape).
func TestListSharedSecretsForUser_TargetWithNoSharesReturnsEmptyNotNil(t *testing.T) {
	cs, db := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	actorRoleID := seedRoleWithPermission(t, db, "s6_empty_actor_role", "users.write")
	actorID := seedSharedSecretsUser(t, db, "s6_empty_actor", actorRoleID)
	targetID := seedSharedSecretsUser(t, db, "s6_empty_target", 0)

	secrets, err := cs.ListSharedSecretsForUser(ctx, actorID, targetID)
	require.NoError(t, err)
	assert.NotNil(t, secrets)
	assert.Empty(t, secrets)
}

// TestListSharedSecretsForUser_ZeroTargetID_ValidationError: userID 0 (no
// target specified) is a validation error, matching ListSharedSecrets.
func TestListSharedSecretsForUser_ZeroTargetID_ValidationError(t *testing.T) {
	cs, _ := freshSharedSecretsAdminViewCore(t)
	ctx := context.Background()

	_, err := cs.ListSharedSecretsForUser(ctx, 1, 0)
	require.Error(t, err)
	assert.False(t, errors.Is(err, core.ErrInsufficientAdminAuthority))
}
