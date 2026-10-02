// concurrency_restoregroup_admin_grant_toctou_test.go — deterministic
// regression for #2455: RestoreGroup read GetGroupRoles and ran
// requireGlobalAdminToReinstateAdminRoles, then separately, UNLOCKED, called
// storage.RestoreGroup. A role grant to the same (soft-deleted) group landing
// in that window is invisible to the check: the check sees the pre-grant role
// set, passes for a non-global-admin actor, and the restore then commits —
// resurrecting a group that, by the time it's live again, already carries an
// admin-conferring role the check never saw.
//
// This uses the same deterministic forced-interleaving technique as
// concurrency_remove_user_role_toctou_test.go: a thin storage.Storage
// decorator pauses ONLY the real storage.RestoreGroup write for the target
// group, right after the real, unmodified GetGroupRoles read and
// requireGlobalAdminToReinstateAdminRoles check have already run and passed.
// A second goroutine then calls the real AssignGroupRoleWithExpiry to grant
// the group an admin-tier role, exactly the call that storage-level write
// (assignGroupRole, local_rbac.go) never checks the target group's
// existence/soft-delete state for.
//
//  1. Goroutine A calls RestoreGroup for a non-global-admin actor: reads
//     GetGroupRoles (empty), the ceiling check passes trivially (no admin
//     role yet), then blocks via the decorator right before its own write.
//  2. Once A is confirmed blocked there, goroutine B grants the group an
//     admin-tier role via AssignGroupRoleWithExpiry. Pre-fix, RestoreGroup
//     holds no lock at all, so B's call (which does take
//     sodGrantLockKey("group", id)) acquires it uncontested and completes
//     immediately. Post-fix, A's entire read+check+write section runs under
//     that SAME lock, so B's call blocks until A's write (released by the
//     test) actually lands.
//  3. The test gives B a generous bounded window to complete BEFORE
//     releasing A. Pre-fix this window is always enough (nothing blocks B);
//     post-fix B is genuinely blocked on the lock and the window always
//     elapses.
package core_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// delayedRestoreGroupStorage wraps a real storage.Storage, pausing exactly
// one targeted RestoreGroup(id) call until released, signaling blocked once
// it starts waiting.
type delayedRestoreGroupStorage struct {
	storage.Storage
	targetGroupID    uint
	blocked, release chan struct{}
}

func (d *delayedRestoreGroupStorage) RestoreGroup(ctx context.Context, id uint) error {
	if id == d.targetGroupID {
		close(d.blocked)
		<-d.release
	}
	return d.Storage.RestoreGroup(ctx, id)
}

// WithTransaction hands fn a tx handle wrapped the same way, so the delay
// still fires now that core.RestoreGroup performs its restore write through
// the transaction handle (#2428) rather than the outer storage.
func (d *delayedRestoreGroupStorage) WithTransaction(ctx context.Context, fn func(tx storage.Storage) error) error {
	return d.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&delayedRestoreGroupStorage{Storage: tx, targetGroupID: d.targetGroupID, blocked: d.blocked, release: d.release})
	})
}

func TestConcurrency_RestoreGroup_AdminGrantRace_TOCTOU_Deterministic(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "restoregroup_toctou.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SoDPolicy{},
	))
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign"}).Error)
	// adminRole has the structural bypass flag -- roleSetContainsAdmin's one
	// real signal (ADR-084), independent of its name or bundled permissions.
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "sneaky_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "nonadmin", UsernameFolded: "nonadmin", AccountState: core.AccountActive}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "g1", NameFolded: "g1", DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true}}).Error)

	realStorage := store.NewLocalStorage(db)
	wrapped := &delayedRestoreGroupStorage{
		Storage:       realStorage,
		targetGroupID: 1,
		blocked:       make(chan struct{}), release: make(chan struct{}),
	}
	c := core.NewKeyorixCore(wrapped)
	ctx := context.Background()

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		_, errA = c.RestoreGroup(ctx, 2, 1) // actor 2: an ordinary, non-global-admin user
	}()

	<-wrapped.blocked // A's check has already passed against the (still empty) role set

	// actorID 0 is the trusted system pseudo-actor (requireGranterHoldsRolePermissions
	// short-circuits it) -- stands in for any sufficiently-privileged granter here;
	// the property under test is RestoreGroup's own serialization, not this call's gate.
	go func() {
		defer close(doneB)
		errB = c.AssignGroupRoleWithExpiry(ctx, 0, 1, 10, core.Scope{}, time.Now().Add(time.Hour), false)
	}()

	var bCompletedBeforeARelease bool
	select {
	case <-doneB:
		bCompletedBeforeARelease = true
	case <-time.After(2 * time.Second):
		bCompletedBeforeARelease = false
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("restore (actor=nonadmin) result: %v", errA)
	t.Logf("grant admin-tier role result: %v", errB)

	assert.False(t, bCompletedBeforeARelease,
		"ADMIN-GRANT TOCTOU (#2455): a role grant to the group completed while RestoreGroup's "+
			"read+check+write section was still in flight for the SAME group -- the ceiling check "+
			"could not have seen this grant, so a non-global-admin actor's restore may have been "+
			"approved against a role set that is already stale by the time the restore commits")

	require.NoError(t, errB, "the admin-tier grant must still succeed once it is unblocked")
	require.NoError(t, errA, "the restore itself is legitimate (checked against an honestly-empty role set) and must succeed")

	roles, err := realStorage.GetGroupRoles(ctx, 1)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, uint(10), roles[0].ID, "the admin-tier grant must land only AFTER the restore's atomic section released, not during it")
}
