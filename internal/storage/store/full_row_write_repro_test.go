// full_row_write_repro_test.go — deterministic repros for two open stale
// full-row writes the C-GUARD-3 guard 1 review classified UNSAFE-OPEN (see
// docs/full-row-write-exempt.tsv). Each plays the cross-replica interleaving
// sequentially on one SQLite store: the operation's read, the concurrent
// writer's committed change, then the operation's stale whole-row Save.
// Skipped until the issue in the skip message is fixed; un-skip with the fix.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
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

// A secret deleted between an UpdateSecret caller's read and its write
// (ClassifySecret, SetSecretDescription, MoveSecret, RotateSecret, ...) must
// stay deleted. GORM Save's UPDATE ... WHERE deleted_at IS NULL matches 0
// rows and falls back to INSERT ... ON CONFLICT DO UPDATE SET deleted_at=NULL.
func TestFullRowRepro_UpdateSecretResurrectsConcurrentlyDeletedSecret(t *testing.T) {
	t.Skip(fullRowReproSkipSecret)
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	sec, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "db-password", ProjectID: 1, EnvironmentID: 1, Type: "password", Status: "active"})
	require.NoError(t, err)

	stale, err := ls.GetSecret(ctx, sec.ID) // replica A: the operation's read
	require.NoError(t, err)
	require.NoError(t, ls.DeleteSecret(ctx, sec.ID)) // replica B: DeleteSecret commits

	stale.Description = "edited on replica A" // replica A: its stale whole-row write
	_, err = ls.UpdateSecret(ctx, stale)
	require.NoError(t, err)

	_, err = ls.GetSecret(ctx, sec.ID)
	require.Error(t, err, "a secret deleted by another replica was resurrected by a stale UpdateSecret")
}

// A machine-token credential revoked between ClassifyMachineToken's read and
// its write must stay revoked: token auth reads `revoked` from the row.
func TestFullRowRepro_ClassifyMachineTokenUnrevokesConcurrentlyRevokedToken(t *testing.T) {
	t.Skip(fullRowReproSkipMachineToken)
	ctx := context.Background()
	ls := newFullRowReproStore(t)
	mi, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{Name: "ci", ProjectID: 1, State: "active"})
	require.NoError(t, err)
	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{MachineIdentityID: mi.ID, Name: "t", TokenHash: "h"})
	require.NoError(t, err)

	stale, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID) // replica A: ClassifyMachineToken's read
	require.NoError(t, err)
	require.NoError(t, ls.RevokeMachineIdentityCredential(ctx, 1, cred.ID)) // replica B: RevokeMachineToken commits

	stale.Classification = "internal" // replica A: its stale whole-row write
	require.NoError(t, ls.UpdateMachineIdentityCredential(ctx, stale))

	got, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	require.True(t, got.Revoked, "a machine token revoked by another replica was un-revoked by a stale classification write")
}

const (
	fullRowReproSkipSecret       = "#2695: open stale full-row write — UpdateSecret resurrects a concurrently deleted secret; un-skip with the fix"
	fullRowReproSkipMachineToken = "#2696: open stale full-row write — ClassifyMachineToken un-revokes a concurrently revoked token; un-skip with the fix"
)
