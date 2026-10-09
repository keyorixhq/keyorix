// full_row_write_repro_test.go — deterministic repro for an open stale
// full-row write the C-GUARD-3 guard 1 review classified UNSAFE-OPEN (see
// docs/full-row-write-exempt.tsv). Plays the cross-replica interleaving
// sequentially on one SQLite store: the operation's read, the concurrent
// writer's committed change, then the operation's stale whole-row Save.
// Skipped until the issue in the skip message is fixed; un-skip with the fix.
//
// #2696's repro (ClassifyMachineToken un-revoking a concurrently revoked
// token) lived here too until #2696 landed: UpdateMachineIdentityCredential's
// full-row Save was replaced by the column-scoped
// SetMachineIdentityCredentialClassification, which cannot write the Revoked
// column at all, so the repro's premise no longer exists. Removed rather than
// updated — there is no write path left to reproduce against.
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

const fullRowReproSkipSecret = "#2695: open stale full-row write — UpdateSecret resurrects a concurrently deleted secret; un-skip with the fix"
