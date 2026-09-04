// local_rbac_cascade_sweep_test.go — partial-coverage sweep for
// local_rbac.go: DB-error paths in the multi-step RBAC read/assign/expiry
// functions, reached via newBrokenDB, partial migration, or
// dropTableAfterQueries/dropTableAfterDeletes (shared helpers,
// local_secrets_cascade_sweep_test.go).
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSetRoleBypassesPermissionChecks_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.SetRoleBypassesPermissionChecks(context.Background(), 1, true)
	require.Error(t, err)
}

func TestAssignUserRole_StaleRowDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 2, ExpiresAt: &expired}).Error)

	dropTableAfterQueries(t, ls.db, 1, "user_roles")

	err := ls.AssignRole(ctx, 1, 2, storage.Scope{})
	require.Error(t, err)
}

func TestAssignUserRole_CreateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	ctx := context.Background()

	// dropTableAfterQueries' After-Query hook doesn't reliably take effect
	// here: it fires on the SAME tx reference as the not-found First() that
	// just ran, whose stale statement state silently no-ops a later Exec on
	// it, and a separate outer-db connection can't see this transaction's
	// uncommitted state either. A Before-Create hook gets a FRESH tx for the
	// new statement, which reliably drops the table right before Create runs.
	require.NoError(t, ls.db.Callback().Create().Before("gorm:create").Register("drop-user_roles-before-create", func(tx *gorm.DB) {
		tx.Exec("DROP TABLE IF EXISTS user_roles")
	}))

	err := ls.AssignRole(ctx, 1, 2, storage.Scope{})
	require.Error(t, err)
}

func TestGetUserRoleScopes_ViaGroupsScanFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	_, err := ls.GetUserRoleScopes(context.Background(), 1)
	require.Error(t, err)
}

func TestListProjectRoleAssignments_GroupRowsFindFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	_, err := ls.ListProjectRoleAssignments(context.Background(), 1)
	require.Error(t, err)
}

func TestListGlobalAdminAssignmentsForUpdate_GroupRowsFindFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	_, err := ls.ListGlobalAdminAssignmentsForUpdate(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

func TestRemoveGlobalAdminRoleGuarded_ListError(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	err := ls.RemoveGlobalAdminRoleGuarded(context.Background(), 1, 2, []uint{3})
	require.Error(t, err)
}

func TestIsProjectMember_ViaGroupCountFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	_, err := ls.IsProjectMember(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestIsGroupProjectScoped_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.IsGroupProjectScoped(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestRoleSetBypassesPermissionChecks_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.RoleSetBypassesPermissionChecks(context.Background(), []uint{1})
	require.Error(t, err)
}

func TestAssignGroupRole_StaleRowDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.GroupRole{})
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 1, RoleID: 2, ExpiresAt: &expired}).Error)

	dropTableAfterQueries(t, ls.db, 1, "group_roles")

	err := ls.AssignRoleToGroup(ctx, 1, 2, storage.Scope{})
	require.Error(t, err)
}

func TestAssignGroupRole_CreateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.GroupRole{})
	ctx := context.Background()

	// See TestAssignUserRole_CreateFails for why a Before-Create hook is used
	// instead of dropTableAfterQueries here.
	require.NoError(t, ls.db.Callback().Create().Before("gorm:create").Register("drop-group_roles-before-create", func(tx *gorm.DB) {
		tx.Exec("DROP TABLE IF EXISTS group_roles")
	}))

	err := ls.AssignRoleToGroup(ctx, 1, 2, storage.Scope{})
	require.Error(t, err)
}

func TestDeleteExpiredRoleGrants_GroupRowsFindFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{})
	_, err := ls.DeleteExpiredRoleGrants(context.Background(), time.Now())
	require.Error(t, err)
}

func TestDeleteExpiredRoleGrants_UserRoleDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{}, &models.GroupRole{})
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 2, ExpiresAt: &expired}).Error)

	// Both Finds (userRows non-empty, groupRows empty) succeed first.
	dropTableAfterQueries(t, ls.db, 2, "user_roles")

	_, err := ls.DeleteExpiredRoleGrants(ctx, time.Now())
	require.Error(t, err)
}

func TestDeleteExpiredRoleGrants_GroupRoleDeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.UserRole{}, &models.GroupRole{})
	ctx := context.Background()
	expired := time.Now().Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 1, RoleID: 2, ExpiresAt: &expired}).Error)

	// Both Finds (userRows empty, groupRows non-empty) succeed first, so the
	// skipped-when-empty UserRole delete never runs; only GroupRole delete does.
	dropTableAfterQueries(t, ls.db, 2, "group_roles")

	_, err := ls.DeleteExpiredRoleGrants(ctx, time.Now())
	require.Error(t, err)
}
