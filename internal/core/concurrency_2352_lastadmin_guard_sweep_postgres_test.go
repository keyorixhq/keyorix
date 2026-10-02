package core

// concurrency_2352_lastadmin_guard_sweep_postgres_test.go — cross-replica
// Postgres counterparts to concurrency_2352_lastadmin_guard_sweep_test.go
// (package core_test). package core here (not core_test) for the same
// reason concurrency_remove_user_role_project_postgres_test.go is: these
// need the unexported pgTestDSN/pgIsolatedSchemaDSN/pgOpen helpers in
// postgres_contention_helpers_test.go. Each "replica" gets its OWN *gorm.DB
// connection into the SAME schema (own LocalStorage, own KeyorixCore), so
// storage.WithNamedLock's pg_advisory_lock -- not an in-process mutex -- is
// the only thing that can still serialize them.
//
// Fewer trials than the SQLite versions: a real network round-trip per
// advisory-lock acquisition makes high trial counts slow; still enough to
// reproduce a real gap reliably if the lock stopped working across
// connections specifically (as opposed to within one process).

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const lastAdminSweepPGTrials = 15

var lastAdminSweepPGModels = []interface{}{
	&models.User{}, &models.Session{}, &models.AuditEvent{}, &models.PersonalAccessToken{},
	&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
	&models.Project{}, &models.Environment{},
	&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.SecretNode{}, &models.ShareRecord{}, &models.SecretACL{}, &models.SystemMetadata{},
}

// newPGLastAdminSchemaDSN creates a fresh isolated schema, migrates it, seeds
// the one shared roles.assign permission every fixture below needs, and
// returns the DSN -- callers open their own independent connections against
// it via pgOpen for each simulated replica.
func newPGLastAdminSchemaDSN(t *testing.T) (dsn string, setupDB *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn = pgIsolatedSchemaDSN(t, base)
	setupDB = pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(lastAdminSweepPGModels...))
	require.NoError(t, setupDB.Create(&models.Permission{Name: "roles.assign"}).Error)
	return dsn, setupDB
}

// --- RemoveUserFromGroup, global scope, cross-replica ------------------------

func TestConcurrency_RemoveUserFromGroup_GlobalScope_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	var bothGone, neitherGone int
	for trial := 0; trial < lastAdminSweepPGTrials; trial++ {
		dsn, setupDB := newPGLastAdminSchemaDSN(t)
		require.NoError(t, setupDB.Create(&models.Role{Name: "admin", BypassesPermissionChecks: true}).Error)
		var role models.Role
		require.NoError(t, setupDB.Where("name = ?", "admin").First(&role).Error)
		userA := models.User{Username: "gu-a", IsActive: true, AccountState: AccountActive, ExternalID: "okta|gu-a"}
		userB := models.User{Username: "gu-b", IsActive: true, AccountState: AccountActive, ExternalID: "okta|gu-b"}
		require.NoError(t, setupDB.Create(&userA).Error)
		require.NoError(t, setupDB.Create(&userB).Error)
		groupA := models.Group{Name: "group-a"}
		groupB := models.Group{Name: "group-b"}
		require.NoError(t, setupDB.Create(&groupA).Error)
		require.NoError(t, setupDB.Create(&groupB).Error)
		require.NoError(t, setupDB.Create(&models.GroupRole{GroupID: groupA.ID, RoleID: role.ID}).Error)
		require.NoError(t, setupDB.Create(&models.GroupRole{GroupID: groupB.ID, RoleID: role.ID}).Error)
		require.NoError(t, setupDB.Create(&models.UserGroup{UserID: userA.ID, GroupID: groupA.ID}).Error)
		require.NoError(t, setupDB.Create(&models.UserGroup{UserID: userB.ID, GroupID: groupB.ID}).Error)

		coreA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
		coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
		ctx := context.Background()

		var errA, errB error
		doneA, doneB := make(chan struct{}), make(chan struct{})
		go func() { defer close(doneA); errA = coreA.RemoveUserFromGroup(ctx, 99, userA.ID, groupA.ID, 0) }()
		go func() { defer close(doneB); errB = coreB.RemoveUserFromGroup(ctx, 99, userB.ID, groupB.ID, 0) }()
		<-doneA
		<-doneB
		_, _ = errA, errB

		verifier := pgOpen(t, dsn)
		var nA, nB int64
		_ = verifier.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", userA.ID, groupA.ID).Count(&nA)
		_ = verifier.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", userB.ID, groupB.ID).Count(&nB)
		aGone, bGone := nA == 0, nB == 0
		switch {
		case aGone && bGone:
			bothGone++
		case !aGone && !bGone:
			neitherGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d cross-replica Postgres trials removed BOTH admin-route memberships, stranding the install with zero admins", bothGone, lastAdminSweepPGTrials)
	assert.Zero(t, neitherGone, "%d/%d cross-replica Postgres trials refused BOTH removals", neitherGone, lastAdminSweepPGTrials)
}

// --- Cross-path: DeleteGroup vs RemoveProjectMember, cross-replica -----------
//
// This is the highest-value Postgres coverage in this file: it proves the
// lock-domain-mismatch fix (withGroupProjectAdminGuardLocks) actually closes
// the gap ACROSS independent connections, not just within one process's
// in-process lock bookkeeping.

func TestConcurrency_DeleteGroup_RemoveProjectMember_CrossPath_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	var bothGone int
	for trial := 0; trial < lastAdminSweepPGTrials; trial++ {
		dsn, setupDB := newPGLastAdminSchemaDSN(t)
		proj := models.Project{Name: "proj"}
		require.NoError(t, setupDB.Create(&proj).Error)
		var perm models.Permission
		require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&perm).Error)
		role := models.Role{Name: "proj_admin"}
		require.NoError(t, setupDB.Create(&role).Error)
		require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
		userA := models.User{Username: "pm-a", IsActive: true, AccountState: AccountActive, ExternalID: "okta|pm-a"}
		userB := models.User{Username: "pm-b", IsActive: true, AccountState: AccountActive, ExternalID: "okta|pm-b"}
		require.NoError(t, setupDB.Create(&userA).Error)
		require.NoError(t, setupDB.Create(&userB).Error)
		group := models.Group{Name: "group-a"}
		require.NoError(t, setupDB.Create(&group).Error)
		require.NoError(t, setupDB.Create(&models.GroupRole{GroupID: group.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
		require.NoError(t, setupDB.Create(&models.UserGroup{UserID: userA.ID, GroupID: group.ID}).Error)
		require.NoError(t, setupDB.Create(&models.UserRole{UserID: userB.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)

		coreA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
		coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
		ctx := context.Background()

		var errA, errB error
		doneA, doneB := make(chan struct{}), make(chan struct{})
		go func() { defer close(doneA); errA = coreA.DeleteGroup(ctx, 99, group.ID) }()
		go func() { defer close(doneB); errB = coreB.RemoveProjectMember(ctx, 99, proj.ID, userB.ID) }()
		<-doneA
		<-doneB
		t.Logf("trial %d: DeleteGroup=%v RemoveProjectMember=%v", trial, errA, errB)

		verifier := pgOpen(t, dsn)
		var groupGrants, userGrants int64
		_ = verifier.Model(&models.GroupRole{}).Where("group_id = ? AND project_id = ?", group.ID, proj.ID).Count(&groupGrants)
		_ = verifier.Model(&models.UserRole{}).Where("user_id = ? AND project_id = ?", userB.ID, proj.ID).Count(&userGrants)
		if groupGrants == 0 && userGrants == 0 {
			bothGone++
		}
	}
	assert.Zero(t, bothGone, "%d/%d cross-replica Postgres trials: DeleteGroup and RemoveProjectMember together stripped the project's ONLY two roles.assign routes across independent connections", bothGone, lastAdminSweepPGTrials)
}

// --- RemoveRoleFromGroup, project scope: deterministic cross-replica TOCTOU --

// pgDelayedRemoveRoleFromGroupStorage is this file's own copy of
// concurrency_2352_lastadmin_guard_sweep_test.go's
// delayedRemoveRoleFromGroupStorage -- that one lives in package core_test,
// this file lives in package core (needed for the PG helpers), so the two
// can't share the type directly. Same mechanism as
// concurrency_remove_user_role_project_postgres_test.go's
// pgDelayedRemoveRoleStorage, applied to the group-role storage call.
type pgDelayedRemoveRoleFromGroupStorage struct {
	storage.Storage
	targetGroupID, targetRoleID uint
	blocked, release            chan struct{}
}

func (d *pgDelayedRemoveRoleFromGroupStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	if groupID == d.targetGroupID && roleID == d.targetRoleID {
		close(d.blocked)
		<-d.release
	}
	return d.Storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope)
}

func TestConcurrency_RemoveRoleFromGroup_ProjectScope_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	proj := models.Project{Name: "proj"}
	require.NoError(t, setupDB.Create(&proj).Error)
	var perm models.Permission
	require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&perm).Error)
	role := models.Role{Name: "proj_admin"}
	require.NoError(t, setupDB.Create(&role).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	groupA := models.Group{Name: "group-a"}
	groupB := models.Group{Name: "group-b"}
	require.NoError(t, setupDB.Create(&groupA).Error)
	require.NoError(t, setupDB.Create(&groupB).Error)
	require.NoError(t, setupDB.Create(&models.GroupRole{GroupID: groupA.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
	require.NoError(t, setupDB.Create(&models.GroupRole{GroupID: groupB.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
	// resolveProjectAdminHolders expands a group's grant to its LIVE members --
	// an admin-holding group with zero members resolves to zero holders, so
	// each group needs one or guardLastProjectAdminGroupRole refuses BOTH
	// removals outright and the race never reaches either write (see the
	// identical fixture note in the SQLite variant of this test).
	userA := models.User{Username: "pg-rfg-a", IsActive: true, AccountState: AccountActive, ExternalID: "okta|pg-rfg-a"}
	userB := models.User{Username: "pg-rfg-b", IsActive: true, AccountState: AccountActive, ExternalID: "okta|pg-rfg-b"}
	require.NoError(t, setupDB.Create(&userA).Error)
	require.NoError(t, setupDB.Create(&userB).Error)
	require.NoError(t, setupDB.Create(&models.UserGroup{UserID: userA.ID, GroupID: groupA.ID}).Error)
	require.NoError(t, setupDB.Create(&models.UserGroup{UserID: userB.ID, GroupID: groupB.ID}).Error)

	wrapped := &pgDelayedRemoveRoleFromGroupStorage{
		Storage:       localstore.NewLocalStorage(pgOpen(t, dsn)),
		targetGroupID: groupA.ID, targetRoleID: role.ID,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	coreA := NewKeyorixCore(wrapped)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	ctx := context.Background()
	scope := Scope{ProjectID: proj.ID}

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = coreA.RemoveRoleFromGroup(ctx, 99, groupA.ID, role.ID, scope)
	}()

	<-wrapped.blocked // replica A's removal passed the guard, paused right before its write

	go func() {
		defer close(doneB)
		errB = coreB.RemoveRoleFromGroup(ctx, 99, groupB.ID, role.ID, scope)
	}()

	select {
	case <-doneB:
	case <-time.After(3 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("remove group-a's role result: %v", errA)
	t.Logf("remove group-b's role result: %v", errB)

	verifier := pgOpen(t, dsn)
	var gA, gB int64
	_ = verifier.Model(&models.GroupRole{}).Where("group_id = ? AND role_id = ? AND project_id = ?", groupA.ID, role.ID, proj.ID).Count(&gA)
	_ = verifier.Model(&models.GroupRole{}).Where("group_id = ? AND role_id = ? AND project_id = ?", groupB.ID, role.ID, proj.ID).Count(&gB)
	aGone, bGone := gA == 0, gB == 0

	if aGone && bGone {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED ACROSS REPLICAS (project-scope TOCTOU): both groups' "+
			"project-admin grant removed via two independent Postgres connections (errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, aGone && bGone, "both groups' project-admin grant must not be removable concurrently across replicas")
}
