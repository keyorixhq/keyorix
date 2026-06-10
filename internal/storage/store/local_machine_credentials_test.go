package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newMachineCredTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.MachineIdentityCredential{}, &models.MachineIdentityRole{}, &models.Role{},
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
