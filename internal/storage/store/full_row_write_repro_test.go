// full_row_write_repro_test.go — deterministic repros for the stale full-row write
// class, ported from the closed duplicate #2725 onto the #2727 guard (#2926).
// Each plays the cross-replica interleaving sequentially on one SQLite store: the
// operation's read, the concurrent writer's committed change, then the operation's
// write.
//
//   - #2696 (ClassifyMachineToken un-revoking a concurrently revoked token) is FIXED
//     (column-scoped, conditional SetMachineIdentityCredentialClassification), so its
//     repro runs as a regression test.
//   - #2695 (the former UpdateSecret's Save resurrecting a concurrently deleted
//     secret): every caller persists through a column-scoped write, and the full-row
//     primitive itself has since been deleted, so the repro runs as a regression test
//     against UpdateSecretFields.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func newFullRowReproStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewLocalStorage(db)
}

// A machine-token credential revoked between ClassifyMachineToken's read and its
// write must stay revoked: token auth reads `revoked` from the row (#2696).
func TestFullRowRepro_ClassifyMachineTokenKeepsConcurrentlyRevokedToken(t *testing.T) {
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	mi, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{Name: "ci", ProjectID: 1, State: "active"})
	require.NoError(t, err)
	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: mi.ID, Name: "t", TokenHash: "h"})
	require.NoError(t, err)

	stale, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID) // replica A: ClassifyMachineToken's read
	require.NoError(t, err)
	require.NoError(t, ls.RevokeMachineIdentityCredential(ctx, 1, cred.ID)) // replica B: RevokeMachineToken commits

	// replica A: its write, built from the stale read.
	matched, err := ls.SetMachineIdentityCredentialClassification(ctx, cred.ID, stale.Classification, "internal")
	require.NoError(t, err)
	require.True(t, matched, "the classification column was untouched by the revoke, so the conditional write must apply")

	got, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	require.True(t, got.Revoked, "a machine token revoked by another replica was un-revoked by a stale classification write (#2696)")
	require.Equal(t, "internal", got.Classification)
}

// The callers #2695 listed (ClassifySecret, SetSecretDescription, MoveSecret, ...)
// now write through UpdateSecretFields: a secret deleted, or suspended, between the
// caller's read and its write must not be resurrected or un-suspended.
func TestFullRowRepro_UpdateSecretFieldsKeepsConcurrentDeleteAndSuspend(t *testing.T) {
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	mk := func(name string) *models.SecretNode {
		s, err := ls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: 1, EnvironmentID: 1, Type: "password", Status: "active"})
		require.NoError(t, err)
		return s
	}
	desc := "edited on replica A"

	// Concurrent delete: must stay deleted, and the caller must be told.
	gone := mk("gone")
	_, err := ls.GetSecret(ctx, gone.ID) // replica A: the operation's read
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, gone.ID)) // replica B: DeleteSecret commits
	matched, err := ls.UpdateSecretFields(ctx, gone.ID, storage.SecretFieldUpdate{Description: &desc})
	require.NoError(t, err)
	require.False(t, matched, "a write onto a concurrently deleted secret must report matched=false")
	_, err = ls.GetSecret(ctx, gone.ID)
	require.Error(t, err, "a secret deleted by another replica was resurrected by a stale field update (#2695)")

	// Concurrent suspend: an incident freeze must survive the caller's write.
	frozen := mk("frozen")
	_, err = ls.GetSecret(ctx, frozen.ID) // replica A: the operation's read (status=active)
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", frozen.ID).Update("status", "suspended").Error) // replica B
	matched, err = ls.UpdateSecretFields(ctx, frozen.ID, storage.SecretFieldUpdate{Description: &desc})
	require.NoError(t, err)
	require.True(t, matched)
	got, err := ls.GetSecret(ctx, frozen.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "a suspension by another replica was reverted by a stale field update (#2695)")
	require.Equal(t, desc, got.Description)
}
