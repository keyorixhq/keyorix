package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newMachineCredTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.MachineIdentityCredential{}, &models.MachineIdentityRole{}, &models.Role{},
		&models.Project{}, &models.Environment{},
	))
	return NewLocalStorage(db)
}

func TestMachineCredentialLifecycle(t *testing.T) {
	ls := newMachineCredTestStore(t)
	ctx := context.Background()

	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: 1, Name: "ci", TokenHash: "hash-abc", TokenPrefix: "kx_machine_ab12cd", CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NotZero(t, cred.ID)

	got, err := ls.GetMachineIdentityCredentialByHash(ctx, "hash-abc")
	require.NoError(t, err)
	assert.Equal(t, cred.ID, got.ID)
	assert.False(t, got.Revoked)

	list, err := ls.ListMachineIdentityCredentials(ctx, 1)
	require.NoError(t, err)
	require.Len(t, list, 1)

	require.NoError(t, ls.RevokeMachineIdentityCredential(ctx, cred.ID))
	got, err = ls.GetMachineIdentityCredentialByHash(ctx, "hash-abc")
	require.NoError(t, err)
	assert.True(t, got.Revoked, "revoke flips the flag, row preserved for audit")
}

func TestOIDCBindingResolution(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityOIDCBinding{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.db.Create(&models.MachineIdentity{ID: 5, Name: "ci", State: "active"}).Error)
	_, err = ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: 5, Issuer: "https://k8s.local", Subject: "system:serviceaccount:ci:deployer",
	})
	require.NoError(t, err)

	// Resolve by (issuer, subject) → the machine.
	m, err := ls.GetMachineByOIDCSubject(ctx, "https://k8s.local", "system:serviceaccount:ci:deployer")
	require.NoError(t, err)
	assert.Equal(t, uint(5), m.ID)

	// A different subject does not resolve.
	_, err = ls.GetMachineByOIDCSubject(ctx, "https://k8s.local", "other")
	require.Error(t, err)

	// (issuer, subject) is unique — a duplicate binding is rejected.
	_, err = ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: 5, Issuer: "https://k8s.local", Subject: "system:serviceaccount:ci:deployer",
	})
	require.Error(t, err, "duplicate (issuer,subject) binding rejected by unique index")

	bindings, err := ls.ListOIDCBindings(ctx, 5)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	require.NoError(t, ls.DeleteOIDCBinding(ctx, bindings[0].ID))
	_, err = ls.GetMachineByOIDCSubject(ctx, "https://k8s.local", "system:serviceaccount:ci:deployer")
	require.Error(t, err, "binding gone after delete")
}

func TestMachineRoleGrantScopeResolution(t *testing.T) {
	ls := newMachineCredTestStore(t)
	ctx := context.Background()
	const machineID = uint(1)

	// A global grant (project 0) and a project-2 grant.
	require.NoError(t, ls.AssignMachineRole(ctx, machineID, 100, storage.Scope{}))
	require.NoError(t, ls.AssignMachineRole(ctx, machineID, 200, storage.Scope{ProjectID: 2}))

	// Duplicate grant is rejected.
	require.Error(t, ls.AssignMachineRole(ctx, machineID, 100, storage.Scope{}))

	// At project 2: both the global and the project-2 grant apply.
	ids, err := ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{100, 200}, ids)

	// At project 3: only the global grant applies (project-2 grant excluded).
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{100}, ids)

	// Remove the project-2 grant.
	require.NoError(t, ls.RemoveMachineRole(ctx, machineID, 200, storage.Scope{ProjectID: 2}))
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{100}, ids)
}

// Environment-axis isolation: GetMachineRoleIDsAt uses the same
// "(env = 0 OR env = ?)" structure as the user query, so an env-scoped grant must
// not leak across projects at the same environment. This is the parenthesisation
// guard for machines (cf. the user-RBAC scope-boundary tests).
func TestMachineRoleGrantScopeResolution_EnvCrossLeak(t *testing.T) {
	ls := newMachineCredTestStore(t)
	ctx := context.Background()
	const machineID = uint(1)

	// role 300 granted at exactly project 2 / env 9.
	require.NoError(t, ls.AssignMachineRole(ctx, machineID, 300, storage.Scope{ProjectID: 2, EnvironmentID: 9}))

	ids, err := ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 2, EnvironmentID: 9})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{300}, ids, "applies at its exact project/env")

	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 3, EnvironmentID: 9})
	require.NoError(t, err)
	assert.Empty(t, ids, "env-9 grant in project 2 must NOT leak to project 3 at env 9")

	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 2, EnvironmentID: 8})
	require.NoError(t, err)
	assert.Empty(t, ids, "does not apply at a different environment")

	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.Empty(t, ids, "an env-scoped grant does not apply at project-level env 0")
}

// #312: a machine role bound directly to a project must stop authorizing the
// moment the project is soft-deleted, and resume once the project is restored —
// mirroring GetUserRoleIDsAt's #161 fix (PR #568), for the machine-principal
// path. Before this fix, GetMachineRoleIDsAt had no join against the projects
// table at all, so a project-scoped machine role kept authorizing regardless of
// the project's own soft-delete state.
func TestGetMachineRoleIDsAt_DeletedProjectStopsAuthorizing(t *testing.T) {
	ls := newMachineCredTestStore(t)
	ctx := context.Background()
	const machineID = uint(1)
	require.NoError(t, ls.db.Create(&models.Project{ID: 5, Name: "proj-5"}).Error)
	require.NoError(t, ls.AssignMachineRole(ctx, machineID, 20, storage.Scope{ProjectID: 5}))

	ids, err := ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{20}, ids, "live project: the project-scoped grant authorizes")

	require.NoError(t, ls.db.Delete(&models.Project{}, 5).Error)
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5})
	require.NoError(t, err)
	assert.Empty(t, ids, "soft-deleted project: the grant must stop authorizing")

	require.NoError(t, ls.db.Model(&models.Project{}).Unscoped().Where("id = ?", 5).Update("deleted_at", nil).Error)
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{20}, ids, "restored project: the grant authorizes again")
}

// #312: the same deleted_at gate applies to an ENVIRONMENT-scoped machine grant.
func TestGetMachineRoleIDsAt_DeletedEnvironmentStopsAuthorizing(t *testing.T) {
	ls := newMachineCredTestStore(t)
	ctx := context.Background()
	const machineID = uint(1)
	require.NoError(t, ls.db.Create(&models.Project{ID: 5, Name: "proj-5"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 9, ProjectID: 5, Name: "prod"}).Error)
	require.NoError(t, ls.AssignMachineRole(ctx, machineID, 30, storage.Scope{ProjectID: 5, EnvironmentID: 9}))

	ids, err := ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5, EnvironmentID: 9})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{30}, ids, "live environment: the env-scoped grant authorizes")

	require.NoError(t, ls.db.Delete(&models.Environment{}, 9).Error)
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5, EnvironmentID: 9})
	require.NoError(t, err)
	assert.Empty(t, ids, "soft-deleted environment: the grant must stop authorizing")

	require.NoError(t, ls.db.Model(&models.Environment{}).Unscoped().Where("id = ?", 9).Update("deleted_at", nil).Error)
	ids, err = ls.GetMachineRoleIDsAt(ctx, machineID, storage.Scope{ProjectID: 5, EnvironmentID: 9})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{30}, ids, "restored environment: the grant authorizes again")
}
