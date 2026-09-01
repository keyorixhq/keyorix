// store_s3_local3_test.go — coverage sweep for local_secrets, local_users,
// local_rbac (advanced), local_webauthn, local_system_metadata, local_sod,
// local_stats, local_sharing, local_memberships (ListProjectMemberships),
// and local_notifications (UpdateNotification).
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// local_secrets — Projects, Environments, Secrets, Versions, Tags
// ---------------------------------------------------------------------------

func newSecretsFullStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "secrets_full_"+t.Name(),
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.ShareRecord{}, &models.Tag{}, &models.SecretTag{})
}

func TestProject_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newSecretsFullStore(t)

	// CreateProject.
	p, err := ls.CreateProject(ctx, &models.Project{Name: "proj-alpha"})
	require.NoError(t, err)
	assert.NotZero(t, p.ID)

	// ListProjects.
	list, err := ls.ListProjects(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// GetProject.
	got, err := ls.GetProject(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "proj-alpha", got.Name)

	// GetProject — not found.
	_, err = ls.GetProject(ctx, 99999)
	require.Error(t, err)

	// UpdateProject.
	p.Description = "updated"
	updated, err := ls.UpdateProject(ctx, p)
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.Description)
}

func TestProject_isDuplicateProjectNameViolation(t *testing.T) {
	// Test the predicate directly.
	assert.False(t, isDuplicateProjectNameViolation(nil))

	// Simulated constraint error text from Postgres.
	fakeErr := fmt.Errorf("ERROR: duplicate key value violates unique constraint \"uniq_projects_name_active\"")
	assert.True(t, isDuplicateProjectNameViolation(fakeErr))

	// Unrelated error.
	assert.False(t, isDuplicateProjectNameViolation(fmt.Errorf("some other error")))
}

func TestEnvironment_ListGet(t *testing.T) {
	ctx := context.Background()
	ls := newSecretsFullStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "env-proj"})
	require.NoError(t, err)

	// CreateEnvironment.
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "prod"})
	require.NoError(t, err)
	assert.NotZero(t, e.ID)

	// GetEnvironment.
	got, err := ls.GetEnvironment(ctx, e.ID)
	require.NoError(t, err)
	assert.Equal(t, "prod", got.Name)

	// GetEnvironment — not found.
	_, err = ls.GetEnvironment(ctx, 99999)
	require.Error(t, err)

	// ListEnvironments (via ListEnvironmentsByProject).
	envs, err := ls.ListEnvironmentsByProject(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
}

func TestSecret_GetByNameUpdateCertNotAfter(t *testing.T) {
	ctx := context.Background()
	ls := newSecretsFullStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "sec-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)

	// CreateSecret (via db directly to keep test self-contained).
	sn := &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "api-key", IsSecret: true,
	}
	require.NoError(t, ls.db.Create(sn).Error)

	// GetSecretByName.
	got, err := ls.GetSecretByName(ctx, "api-key", p.ID, e.ID)
	require.NoError(t, err)
	assert.Equal(t, sn.ID, got.ID)

	// GetSecretByName — not found.
	_, err = ls.GetSecretByName(ctx, "nope", p.ID, e.ID)
	require.Error(t, err)

	// UpdateSecret.
	sn.Description = "updated"
	updated, err := ls.UpdateSecret(ctx, sn)
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.Description)

	// SetSecretCertNotAfter.
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	require.NoError(t, ls.SetSecretCertNotAfter(ctx, sn.ID, &notAfter))
	// Verify via direct db read.
	var reloaded models.SecretNode
	require.NoError(t, ls.db.First(&reloaded, sn.ID).Error)
	require.NotNil(t, reloaded.CertNotAfter)
}

func TestSecretVersion_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newSecretsFullStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "ver-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)
	sn := &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "mysecret", IsSecret: true}
	require.NoError(t, ls.db.Create(sn).Error)

	// CreateSecretVersion.
	v1, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: sn.ID, VersionNumber: 1, EncryptedValue: []byte("enc1"),
	})
	require.NoError(t, err)
	assert.NotZero(t, v1.ID)

	v2, err := ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: sn.ID, VersionNumber: 2, EncryptedValue: []byte("enc2"),
	})
	require.NoError(t, err)

	// GetSecretVersions — newest first.
	versions, err := ls.GetSecretVersions(ctx, sn.ID)
	require.NoError(t, err)
	assert.Len(t, versions, 2)
	assert.Equal(t, 2, versions[0].VersionNumber, "newest first")

	// GetLatestSecretVersion.
	latest, err := ls.GetLatestSecretVersion(ctx, sn.ID)
	require.NoError(t, err)
	assert.Equal(t, v2.ID, latest.ID)

	// GetLatestSecretVersion — no versions.
	sn2 := &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "empty", IsSecret: true}
	require.NoError(t, ls.db.Create(sn2).Error)
	_, err = ls.GetLatestSecretVersion(ctx, sn2.ID)
	require.Error(t, err)

	// IncrementSecretReadCount.
	require.NoError(t, ls.IncrementSecretReadCount(ctx, v1.ID))
	var rv models.SecretVersion
	require.NoError(t, ls.db.First(&rv, v1.ID).Error)
	assert.Equal(t, 1, rv.ReadCount)
}

func TestSecretTags_GetSet(t *testing.T) {
	ctx := context.Background()
	ls := newSecretsFullStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "tag-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)
	sn := &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "tagged", IsSecret: true}
	require.NoError(t, ls.db.Create(sn).Error)

	// GetSecretTags — empty.
	tags, err := ls.GetSecretTags(ctx, sn.ID)
	require.NoError(t, err)
	assert.Empty(t, tags)

	// SetSecretTags.
	require.NoError(t, ls.SetSecretTags(ctx, sn.ID, []string{"infra", "prod", "cert"}))

	tags2, err := ls.GetSecretTags(ctx, sn.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"cert", "infra", "prod"}, tags2)

	// SetSecretTags — replace.
	require.NoError(t, ls.SetSecretTags(ctx, sn.ID, []string{"db"}))
	tags3, err := ls.GetSecretTags(ctx, sn.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"db"}, tags3)

	// SetSecretTags — clear.
	require.NoError(t, ls.SetSecretTags(ctx, sn.ID, nil))
	tags4, err := ls.GetSecretTags(ctx, sn.ID)
	require.NoError(t, err)
	assert.Empty(t, tags4)
}

func TestSecret_ListOrphanedAndCounts(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "orphaned_"+t.Name(),
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.User{}, &models.SecretVersion{})

	p, err := ls.CreateProject(ctx, &models.Project{Name: "orphan-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)

	// Active user.
	u := &models.User{Username: "active-u", UsernameFolded: "active-u", Email: "active@example.com", EmailFolded: "active@example.com"}
	require.NoError(t, ls.db.Create(u).Error)

	// Secret owned by live user → not orphaned.
	snLive := &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "live-secret", IsSecret: true, OwnerID: u.ID,
	}
	require.NoError(t, ls.db.Create(snLive).Error)

	// Secret owned by non-existent user (id=9999) → orphaned.
	snOrph := &models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "orphan-secret", IsSecret: true, OwnerID: 9999,
	}
	require.NoError(t, ls.db.Create(snOrph).Error)

	orphans, err := ls.ListOrphanedSecrets(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, orphans, 1)
	assert.Equal(t, snOrph.ID, orphans[0].ID)

	// CountOrphanedSecretsByProject.
	counts, err := ls.CountOrphanedSecretsByProject(ctx, []uint{p.ID})
	require.NoError(t, err)
	assert.Equal(t, 1, counts[p.ID])

	// Empty input → empty map.
	empty, err := ls.CountOrphanedSecretsByProject(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestSecret_CountExpiringAndLiveName(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "expiring_"+t.Name(),
		&models.Project{}, &models.Environment{}, &models.SecretNode{})

	p, err := ls.CreateProject(ctx, &models.Project{Name: "exp-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)

	soon := time.Now().Add(time.Hour)
	later := time.Now().Add(30 * 24 * time.Hour)

	// Two expiring-soon secrets.
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "expiring1", IsSecret: true, Expiration: &soon,
	}).Error)
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "expiring2", IsSecret: true, Expiration: &soon,
	}).Error)
	// One far-future expiry.
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "stable", IsSecret: true, Expiration: &later,
	}).Error)

	// Count expiring before 2h from now → 2.
	cutoff := time.Now().Add(2 * time.Hour)
	counts, err := ls.CountExpiringSecretsByProject(ctx, []uint{p.ID}, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 2, counts[p.ID])

	// Empty projectIDs → empty.
	empty, err := ls.CountExpiringSecretsByProject(ctx, nil, cutoff)
	require.NoError(t, err)
	assert.Empty(t, empty)

	// ListLiveSecretNamesByProject.
	rows, truncated, err := ls.ListLiveSecretNamesByProject(ctx, []uint{p.ID}, 100)
	require.NoError(t, err)
	assert.False(t, truncated)
	assert.Len(t, rows, 3)
}

// ---------------------------------------------------------------------------
// local_users — User CRUD, GetByEmail/ExternalID, SetAccountState, etc.
// ---------------------------------------------------------------------------

func newUsersFullStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "users_full_"+t.Name(), &models.User{}, &models.Group{}, &models.UserGroup{})
}

func TestUser_GetByEmail(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{
		Username: "alice", UsernameFolded: "alice", Email: "alice@example.com", EmailFolded: "alice@example.com",
	})
	require.NoError(t, err)

	// GetUserByEmail.
	got, err := ls.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// Case-insensitive.
	got2, err := ls.GetUserByEmail(ctx, "ALICE@EXAMPLE.COM")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got2.ID)

	// Not found.
	_, err = ls.GetUserByEmail(ctx, "nobody@example.com")
	require.Error(t, err)
}

func TestUser_GetByExternalID(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{
		Username: "ext-user", UsernameFolded: "ext-user", Email: "ext@example.com", EmailFolded: "ext@example.com", ExternalID: "ext-123",
	})
	require.NoError(t, err)

	got, err := ls.GetUserByExternalID(ctx, "ext-123")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	_, err = ls.GetUserByExternalID(ctx, "nope")
	require.Error(t, err)
}

func TestUser_LockForUpdate(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "lock-u", UsernameFolded: "lock-u", Email: "lock@example.com", EmailFolded: "lock@example.com"})
	require.NoError(t, err)

	got, err := ls.LockUserForUpdate(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	_, err = ls.LockUserForUpdate(ctx, 99999)
	require.Error(t, err)
}

func TestUser_UpdateAndSetAccountState(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "state-u", UsernameFolded: "state-u", Email: "state@example.com", EmailFolded: "state@example.com"})
	require.NoError(t, err)

	// UpdateUser.
	u.DisplayName = "State User"
	updated, err := ls.UpdateUser(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, "State User", updated.DisplayName)

	// SetAccountState.
	require.NoError(t, ls.SetAccountState(ctx, u.ID, "suspended", time.Now()))
	var r models.User
	require.NoError(t, ls.db.First(&r, u.ID).Error)
	assert.Equal(t, "suspended", r.AccountState)

	// SetAccountState — not found.
	err = ls.SetAccountState(ctx, 99999, "suspended", time.Now())
	require.Error(t, err)
}

func TestUser_SetPasswordHash(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "pw-u", UsernameFolded: "pw-u", Email: "pw@example.com", EmailFolded: "pw@example.com"})
	require.NoError(t, err)

	require.NoError(t, ls.SetPasswordHash(ctx, u.ID, "$2a$bcrypt", time.Now()))
	var r models.User
	require.NoError(t, ls.db.First(&r, u.ID).Error)
	assert.Equal(t, "$2a$bcrypt", r.PasswordHash)

	// Not found.
	err = ls.SetPasswordHash(ctx, 99999, "hash", time.Now())
	require.Error(t, err)
}

func TestUser_UpdateLoginLockoutState(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "lock-state-u", UsernameFolded: "lock-state-u", Email: "lockstate@example.com", EmailFolded: "lockstate@example.com"})
	require.NoError(t, err)

	now := time.Now()
	until := now.Add(time.Hour)
	require.NoError(t, ls.UpdateLoginLockoutState(ctx, u.ID, 3, &now, &until, 1))
	var r models.User
	require.NoError(t, ls.db.First(&r, u.ID).Error)
	assert.Equal(t, 3, r.FailedLoginAttempts)
}

func TestUser_DeleteAndRestore(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "del-u", UsernameFolded: "del-u", Email: "del@example.com", EmailFolded: "del@example.com"})
	require.NoError(t, err)

	// DeleteUser (soft-delete).
	require.NoError(t, ls.DeleteUser(ctx, u.ID))

	// GetUser returns ErrUserNotFound after soft-delete.
	_, err = ls.GetUser(ctx, u.ID)
	require.Error(t, err)

	// RestoreUser.
	require.NoError(t, ls.RestoreUser(ctx, u.ID))

	// User is back.
	got, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
}

func TestUser_escapeLike(t *testing.T) {
	// escapeLike is a package-level function; verify it's exercised.
	result := escapeLike("100% complete_test")
	assert.Equal(t, `100\% complete\_test`, result)

	// Backslash.
	assert.Equal(t, `a\\b`, escapeLike(`a\b`))
}

func TestGroup_UpdateAndList(t *testing.T) {
	ctx := context.Background()
	ls := newUsersFullStore(t)

	// CreateGroup (via RBAC in store_s3_local2_test.go already tests create).
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "list-group", NameFolded: "list-group"})
	require.NoError(t, err)

	// UpdateGroup.
	g.Description = "updated"
	_, err = ls.UpdateGroup(ctx, g)
	require.NoError(t, err)
	got, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Description)

	// ListGroups.
	list, err := ls.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// ListGroupsPage.
	page, total, err := ls.ListGroupsPage(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, page, 1)
}

// ---------------------------------------------------------------------------
// local_rbac — advanced: RemoveAllProjectRoleGrants, GetUserRoleScopes,
// ListProjectRoleAssignments, ListProjectMachineRoleAssignments,
// IsProjectMember, RoleSetHasPermission, GetPermission, GetGroupRoleGrants,
// ListGroupRoleAssignments, DeleteExpiredRoleGrants.
// ---------------------------------------------------------------------------

func newRBACAdvancedStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "rbac_adv_"+t.Name(),
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.User{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{})
}

func TestRBAC_RemoveAllProjectRoleGrants(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	projRoleName, err := identity.NewFoldedName("proj-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, projRoleName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "proj-user", UsernameFolded: "proj-user", Email: "pu@example.com", EmailFolded: "pu@example.com"})
	require.NoError(t, err)

	scope1 := coreStorage.Scope{ProjectID: 1, EnvironmentID: 0}
	scope2 := coreStorage.Scope{ProjectID: 1, EnvironmentID: 2}

	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, scope1))
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, scope2))

	// RemoveAllProjectRoleGrants removes both.
	require.NoError(t, ls.RemoveAllProjectRoleGrants(ctx, u.ID, 1))

	ids, err := ls.GetUserRoleIDsAt(ctx, u.ID, scope1)
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestRBAC_GetUserRoleScopes(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	scopeRoleName, err := identity.NewFoldedName("scope-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, scopeRoleName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "scope-user", UsernameFolded: "scope-user", Email: "su@example.com", EmailFolded: "su@example.com"})
	require.NoError(t, err)

	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, coreStorage.Scope{ProjectID: 5, EnvironmentID: 0}))
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, coreStorage.Scope{ProjectID: 5, EnvironmentID: 3}))

	scopes, err := ls.GetUserRoleScopes(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, scopes, 2)
}

func TestRBAC_ListProjectRoleAssignments(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	listRoleName, err := identity.NewFoldedName("list-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, listRoleName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "list-user", UsernameFolded: "list-user", Email: "lu@example.com", EmailFolded: "lu@example.com"})
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: 10, EnvironmentID: 0}
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, scope))

	// Add a group grant too.
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "list-group2", NameFolded: "list-group2"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignRoleToGroup(ctx, g.ID, role.ID, scope))

	assignments, err := ls.ListProjectRoleAssignments(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, assignments, 2, "one user + one group")

	// Empty project → empty.
	none, err := ls.ListProjectRoleAssignments(ctx, 9999)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestRBAC_ListProjectMachineRoleAssignments(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	machRoleName, err := identity.NewFoldedName("mach-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, machRoleName, "")
	require.NoError(t, err)

	m, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 20, Name: "ci-bot", IdentityType: "ci", State: "active",
	})
	require.NoError(t, err)

	machScope := coreStorage.Scope{ProjectID: 20, EnvironmentID: 0}
	require.NoError(t, ls.AssignMachineRole(ctx, m.ID, role.ID, machScope))

	assigns, err := ls.ListProjectMachineRoleAssignments(ctx, 20)
	require.NoError(t, err)
	assert.Len(t, assigns, 1)
	assert.Equal(t, "machine", assigns[0].PrincipalType)

	// Empty → empty.
	none, err := ls.ListProjectMachineRoleAssignments(ctx, 9999)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestRBAC_IsProjectMember(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	memberRoleName, err := identity.NewFoldedName("member-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, memberRoleName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "member-u", UsernameFolded: "member-u", Email: "member@example.com", EmailFolded: "member@example.com"})
	require.NoError(t, err)

	// Zero projectID → always false.
	ok, err := ls.IsProjectMember(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.False(t, ok)

	// Not a member yet.
	ok, err = ls.IsProjectMember(ctx, u.ID, 30)
	require.NoError(t, err)
	assert.False(t, ok)

	// Assign.
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, coreStorage.Scope{ProjectID: 30}))

	ok, err = ls.IsProjectMember(ctx, u.ID, 30)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRBAC_RoleSetHasPermission(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	permRoleName, err := identity.NewFoldedName("perm-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, permRoleName, "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"})
	require.NoError(t, err)

	// No assignment yet → false.
	ok, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok)

	// Empty roleIDs → false.
	ok, err = ls.RoleSetHasPermission(ctx, nil, "secrets.read")
	require.NoError(t, err)
	assert.False(t, ok)

	// Assign.
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	ok, err = ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	assert.True(t, ok)

	// Different permission → false.
	ok, err = ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.write")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRBAC_GetPermission(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "roles.view", Resource: "roles", Action: "view"})
	require.NoError(t, err)

	got, err := ls.GetPermission(ctx, perm.ID)
	require.NoError(t, err)
	assert.Equal(t, "roles.view", got.Name)

	// Not found.
	_, err = ls.GetPermission(ctx, 99999)
	require.Error(t, err)
}

func TestRBAC_GetGroupRoleGrants(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	grpGrantsRoleName, err := identity.NewFoldedName("grp-grants-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, grpGrantsRoleName, "")
	require.NoError(t, err)
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "grants-group", NameFolded: "grants-group"})
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: 40, EnvironmentID: 0}
	require.NoError(t, ls.AssignRoleToGroup(ctx, g.ID, role.ID, scope))

	grants, err := ls.GetGroupRoleGrants(ctx, g.ID)
	require.NoError(t, err)
	assert.Len(t, grants, 1)
	assert.Equal(t, role.ID, grants[0].ID)

	// ListGroupRoleAssignments.
	assignments, err := ls.ListGroupRoleAssignments(ctx, g.ID)
	require.NoError(t, err)
	assert.Len(t, assignments, 1)
}

func TestRBAC_DeleteExpiredRoleGrants(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	expRoleName, err := identity.NewFoldedName("exp-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, expRoleName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "exp-u", UsernameFolded: "exp-u", Email: "expu@example.com", EmailFolded: "expu@example.com"})
	require.NoError(t, err)

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Expired grant.
	require.NoError(t, ls.db.Create(&models.UserRole{
		UserID: u.ID, RoleID: role.ID, ProjectID: 50, ExpiresAt: &past,
	}).Error)

	// Live grant.
	require.NoError(t, ls.db.Create(&models.UserRole{
		UserID: u.ID, RoleID: role.ID, ProjectID: 50, EnvironmentID: 1, ExpiresAt: &future,
	}).Error)

	// DeleteExpiredRoleGrants.
	deleted, err := ls.DeleteExpiredRoleGrants(ctx, now)
	require.NoError(t, err)
	assert.Len(t, deleted, 1)
	assert.Equal(t, "user", deleted[0].PrincipalType)

	// Live grant remains.
	var count int64
	ls.db.Model(&models.UserRole{}).Where("user_id = ?", u.ID).Count(&count)
	assert.Equal(t, int64(1), count)
}

// ---------------------------------------------------------------------------
// local_rbac — ListGlobalAdminAssignmentsForUpdate, RemoveGlobalAdminRoleGuarded
// ---------------------------------------------------------------------------

func TestRBAC_GlobalAdmin(t *testing.T) {
	ctx := context.Background()
	ls := newRBACAdvancedStore(t)

	globalAdminName, err := identity.NewFoldedName("global-admin")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, globalAdminName, "")
	require.NoError(t, err)

	u, err := ls.CreateUser(ctx, &models.User{Username: "gadmin", UsernameFolded: "gadmin", Email: "gadmin@example.com", EmailFolded: "gadmin@example.com"})
	require.NoError(t, err)

	// Assign global role (scope 0/0).
	globalScope := coreStorage.Scope{ProjectID: 0, EnvironmentID: 0}
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, globalScope))

	adminRoleIDs := []uint{role.ID}

	// ListGlobalAdminAssignmentsForUpdate.
	rows, err := ls.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	// Add a second admin so we can remove one safely.
	u2, err := ls.CreateUser(ctx, &models.User{Username: "gadmin2", UsernameFolded: "gadmin2", Email: "gadmin2@example.com", EmailFolded: "gadmin2@example.com"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignRole(ctx, u2.ID, role.ID, globalScope))

	// RemoveGlobalAdminRoleGuarded — must succeed when > 1 admin remains.
	require.NoError(t, ls.RemoveGlobalAdminRoleGuarded(ctx, u.ID, role.ID, adminRoleIDs))

	rows2, err := ls.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
	require.NoError(t, err)
	assert.Len(t, rows2, 1)

	// RemoveGlobalAdminRoleGuarded — removing last admin must fail.
	err = ls.RemoveGlobalAdminRoleGuarded(ctx, u2.ID, role.ID, adminRoleIDs)
	require.Error(t, err, "cannot remove the last global admin")
}

// ---------------------------------------------------------------------------
// local_webauthn — List, Update, AdvanceCounter, Delete, Count, SetEnabled,
// CreateSession, ConsumeSession
// ---------------------------------------------------------------------------

func newWebAuthnStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "webauthn_"+t.Name(),
		&models.User{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{})
}

func TestWebAuthn_Credential_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newWebAuthnStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "wa-user", UsernameFolded: "wa-user", Email: "wa@example.com", EmailFolded: "wa@example.com"})
	require.NoError(t, err)

	blob := []byte(`{"authenticator":{"signCount":10}}`)
	cred := &models.WebAuthnCredential{
		UserID: u.ID, CredentialID: []byte("cred-id-1"), Name: "TouchID", CredentialBlob: blob,
	}
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, cred))

	// ListWebAuthnCredentials.
	list, err := ls.ListWebAuthnCredentials(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// CountWebAuthnCredentials.
	n, err := ls.CountWebAuthnCredentials(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// UpdateWebAuthnCredential.
	cred.Name = "YubiKey"
	require.NoError(t, ls.UpdateWebAuthnCredential(ctx, cred))
	list2, err := ls.ListWebAuthnCredentials(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "YubiKey", list2[0].Name)

	// SetUserWebAuthnEnabled.
	require.NoError(t, ls.SetUserWebAuthnEnabled(ctx, u.ID, true))
	var ru models.User
	require.NoError(t, ls.db.First(&ru, u.ID).Error)
	assert.True(t, ru.WebAuthnEnabled)

	// DeleteWebAuthnCredential.
	require.NoError(t, ls.DeleteWebAuthnCredential(ctx, u.ID, cred.ID))
	list3, err := ls.ListWebAuthnCredentials(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, list3)

	// Delete non-existent → error.
	err = ls.DeleteWebAuthnCredential(ctx, u.ID, 99999)
	require.Error(t, err)
}

func TestWebAuthn_AdvanceCredentialCounter(t *testing.T) {
	ctx := context.Background()
	ls := newWebAuthnStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "wa-adv", UsernameFolded: "wa-adv", Email: "wa-adv@example.com", EmailFolded: "wa-adv@example.com"})
	require.NoError(t, err)

	type blobT struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	b := blobT{}
	b.Authenticator.SignCount = 5
	blobBytes, _ := json.Marshal(b)

	cred := &models.WebAuthnCredential{
		UserID: u.ID, CredentialID: []byte("adv-cred"), Name: "Adv", CredentialBlob: blobBytes,
	}
	require.NoError(t, ls.CreateWebAuthnCredential(ctx, cred))

	// Advance from 5 → 6.
	b.Authenticator.SignCount = 6
	newBlob, _ := json.Marshal(b)
	advanced, err := ls.AdvanceWebAuthnCredentialCounter(ctx, []byte("adv-cred"), u.ID, newBlob, 6, time.Now())
	require.NoError(t, err)
	assert.True(t, advanced)

	// Stale counter (6 → 5) must be rejected.
	b.Authenticator.SignCount = 5
	staleBlob, _ := json.Marshal(b)
	advanced2, err := ls.AdvanceWebAuthnCredentialCounter(ctx, []byte("adv-cred"), u.ID, staleBlob, 5, time.Now())
	require.NoError(t, err)
	assert.False(t, advanced2)
}

func TestWebAuthn_Session_CreateConsume(t *testing.T) {
	ctx := context.Background()
	ls := newWebAuthnStore(t)

	now := time.Now()
	sess := &models.WebAuthnSession{
		UserID:    1,
		TokenHash: "wh-session-hash",
		Purpose:   "login",
		Data:      []byte(`{}`),
		ExpiresAt: now.Add(5 * time.Minute),
	}
	require.NoError(t, ls.CreateWebAuthnSession(ctx, sess))

	// ConsumeWebAuthnSession.
	consumed, err := ls.ConsumeWebAuthnSession(ctx, "wh-session-hash", now)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, consumed.ID)

	// Consuming again → error (already used).
	_, err = ls.ConsumeWebAuthnSession(ctx, "wh-session-hash", now)
	require.Error(t, err)

	// Expired session → error.
	expired := &models.WebAuthnSession{
		UserID:    1,
		TokenHash: "expired-hash",
		Purpose:   "register",
		Data:      []byte(`{}`),
		ExpiresAt: now.Add(-time.Minute), // already expired
	}
	require.NoError(t, ls.CreateWebAuthnSession(ctx, expired))
	_, err = ls.ConsumeWebAuthnSession(ctx, "expired-hash", now)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_system_metadata
// ---------------------------------------------------------------------------

func TestSystemMetadata_GetSet(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "sysmd_"+t.Name(), &models.SystemMetadata{})

	// Get — not found → (empty, false, nil).
	val, found, err := ls.GetSystemMetadata(ctx, "checkpoint.high_water")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, val)

	// Set.
	require.NoError(t, ls.SetSystemMetadata(ctx, "checkpoint.high_water", "42"))
	val2, found2, err := ls.GetSystemMetadata(ctx, "checkpoint.high_water")
	require.NoError(t, err)
	assert.True(t, found2)
	assert.Equal(t, "42", val2)

	// Upsert (update).
	require.NoError(t, ls.SetSystemMetadata(ctx, "checkpoint.high_water", "100"))
	val3, _, err := ls.GetSystemMetadata(ctx, "checkpoint.high_water")
	require.NoError(t, err)
	assert.Equal(t, "100", val3)
}

// ---------------------------------------------------------------------------
// local_sod
// ---------------------------------------------------------------------------

func TestSoDPolicy_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "sod_"+t.Name(), &models.SoDPolicy{})

	// CreateSoDPolicy.
	p, err := ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "no-self-assign",
		PermissionA: "roles.assign",
		PermissionB: "secrets.delete",
		CreatedBy:   1,
	})
	require.NoError(t, err)
	assert.NotZero(t, p.ID)

	// GetSoDPolicy.
	got, err := ls.GetSoDPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "no-self-assign", got.Name)

	// GetSoDPolicy — not found.
	_, err = ls.GetSoDPolicy(ctx, 99999)
	require.Error(t, err)

	// ListSoDPolicies.
	list, err := ls.ListSoDPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// DeleteSoDPolicy.
	require.NoError(t, ls.DeleteSoDPolicy(ctx, p.ID))
	_, err = ls.GetSoDPolicy(ctx, p.ID)
	require.Error(t, err)

	// DeleteSoDPolicy — not found.
	err = ls.DeleteSoDPolicy(ctx, 99999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_stats
// ---------------------------------------------------------------------------

func TestStats_GetStatsAndHealthCheck(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "stats_"+t.Name(),
		&models.SecretNode{}, &models.User{}, &models.Role{}, &models.Session{})

	// GetStats on empty tables.
	stats, err := ls.GetStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Zero(t, stats.TotalSecrets)
	assert.Zero(t, stats.TotalUsers)

	// HealthCheck.
	require.NoError(t, ls.HealthCheck(ctx))
}

// TestStats_GetStats_PropagatesCountError is #G54: a failed Count query for
// any one of the four entity types must fail the whole call, not leave that
// field at its Go zero value while GetStats still reports success — which
// would fabricate a "0 secrets" result indistinguishable from a genuinely
// empty deployment.
func TestStats_GetStats_PropagatesCountError(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "stats_err_"+t.Name(),
		&models.SecretNode{}, &models.User{}, &models.Role{}, &models.Session{})

	require.NoError(t, ls.db.Migrator().DropTable(&models.SecretNode{}))

	_, err := ls.GetStats(ctx)
	require.Error(t, err, "a Count failure on any one entity type must fail the whole call")
}

func TestStats_SaveAndGetPreviousSnapshot(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "stats_snap_"+t.Name(), &models.StatsSnapshot{})

	userID := uint(1)

	// GetPreviousStatsSnapshot — none yet → error (record not found).
	_, err := ls.GetPreviousStatsSnapshot(ctx, userID)
	require.Error(t, err)

	// Save a snapshot 25 hours ago.
	oldSnap := &models.StatsSnapshot{
		UserID:       userID,
		TotalSecrets: 50,
		CreatedAt:    time.Now().Add(-25 * time.Hour),
		SnapshotDate: time.Now().Add(-25 * time.Hour),
	}
	require.NoError(t, ls.SaveStatsSnapshot(ctx, oldSnap))

	// Save a recent snapshot (< 20 hours ago) — should NOT be returned.
	recentSnap := &models.StatsSnapshot{
		UserID:       userID,
		TotalSecrets: 55,
		CreatedAt:    time.Now().Add(-5 * time.Hour),
		SnapshotDate: time.Now().Add(-5 * time.Hour),
	}
	require.NoError(t, ls.SaveStatsSnapshot(ctx, recentSnap))

	// GetPreviousStatsSnapshot returns the old one.
	got, err := ls.GetPreviousStatsSnapshot(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, int64(50), got.TotalSecrets)
}

// ---------------------------------------------------------------------------
// local_sharing — UpdateShareRecord, DeleteExpiredShareRecords
// ---------------------------------------------------------------------------

func newSharingStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "sharing_"+t.Name(), &models.ShareRecord{})
}

func TestSharing_UpdateAndDeleteExpired(t *testing.T) {
	ctx := context.Background()
	ls := newSharingStore(t)

	now := time.Now()

	// Create a share record via db.
	share := &models.ShareRecord{
		SecretID:    1,
		OwnerID:     2,
		RecipientID: 3,
		IsGroup:     false,
		Permission:  "read",
	}
	require.NoError(t, ls.db.Create(share).Error)

	// UpdateShareRecord.
	share.Permission = "write"
	updated, err := ls.UpdateShareRecord(ctx, share)
	require.NoError(t, err)
	assert.Equal(t, "write", updated.Permission)

	// UpdateShareRecord — invalid permission → error.
	share.Permission = "admin"
	_, err = ls.UpdateShareRecord(ctx, share)
	require.Error(t, err)

	// Create an expired share record.
	past := now.Add(-time.Hour)
	expiredShare := &models.ShareRecord{
		SecretID:    4,
		OwnerID:     5,
		RecipientID: 6,
		IsGroup:     false,
		Permission:  "read",
		ExpiresAt:   &past,
	}
	require.NoError(t, ls.db.Create(expiredShare).Error)

	// DeleteExpiredShareRecords.
	removed, err := ls.DeleteExpiredShareRecords(ctx, now)
	require.NoError(t, err)
	assert.Len(t, removed, 1)
	assert.Equal(t, expiredShare.ID, removed[0].ID)
}

// ---------------------------------------------------------------------------
// local_memberships — ListProjectMemberships
// ---------------------------------------------------------------------------

func TestListProjectMemberships(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "proj_memb_"+t.Name(),
		&models.Project{}, &models.User{}, &models.ProjectMembership{})

	p, err := ls.CreateProject(ctx, &models.Project{Name: "memb-proj"})
	require.NoError(t, err)
	u, err := ls.CreateUser(ctx, &models.User{Username: "memb-user", UsernameFolded: "memb-user", Email: "memb@example.com", EmailFolded: "memb@example.com"})
	require.NoError(t, err)

	// Add membership.
	memb := &models.ProjectMembership{ProjectID: p.ID, UserID: u.ID, State: "active"}
	require.NoError(t, ls.db.Create(memb).Error)

	// ListProjectMemberships.
	list, err := ls.ListProjectMemberships(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, u.ID, list[0].UserID)

	// Empty project → empty.
	empty, err := ls.ListProjectMemberships(ctx, 9999)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// ---------------------------------------------------------------------------
// local_notifications — UpdateNotification
// ---------------------------------------------------------------------------

func TestNotification_Update(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "notif_update_"+t.Name(), &models.Notification{})

	// Create a notification.
	notif := &models.Notification{
		UserID:  1,
		Type:    "info",
		Title:   "Original Title",
		Message: "Hello",
	}
	require.NoError(t, ls.db.Create(notif).Error)

	// UpdateNotification — update title and message.
	notif.Title = "Updated Title"
	notif.Message = "Updated Message"
	require.NoError(t, ls.UpdateNotification(ctx, notif))

	var r models.Notification
	require.NoError(t, ls.db.First(&r, notif.ID).Error)
	assert.Equal(t, "Updated Title", r.Title)
	assert.Equal(t, "Updated Message", r.Message)

	// UpdateNotification — wrong user_id → not found.
	notif.UserID = 99999
	err := ls.UpdateNotification(ctx, notif)
	require.Error(t, err)
}
