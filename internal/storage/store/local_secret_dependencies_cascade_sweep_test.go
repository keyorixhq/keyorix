// local_secret_dependencies_cascade_sweep_test.go — partial-coverage sweep
// for local_secret_dependencies.go: GetSecretDependency's error path and
// CreateSecretDependencyExclusive's Create-failure branches (generic error
// and the genuine concurrent-insert race, #260's belt-and-suspenders catch).
// NOTE: the two `tx.Dialector.Name() == "postgres"` row-lock branches
// (ListSecretDependenciesForProjectForUpdate line 50,
// CreateSecretDependencyExclusive line 83) are intentionally NOT covered --
// genuinely unreachable via SQLite, out of scope per this sweep's
// instructions.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestGetSecretDependency_BrokenDB(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetSecretDependency(context.Background(), 1)
	require.Error(t, err)
}

func TestCreateSecretDependencyExclusive_CreateFailsGenericError(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretDependency{})
	dropTableAfterQueries(t, ls.db, 1, "secret_dependencies")

	_, err := ls.CreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.Error(t, err)
	assert.NotErrorIs(t, err, storage.ErrDuplicateSecretDependency)
}

func TestCreateSecretDependencyExclusive_ConcurrentInsertRaceCaught(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.SecretDependency{})
	ctx := context.Background()

	// Fire right before the function's own real INSERT, using a raw SQL Exec
	// (not a nested GORM Create) via the callback's own tx handle -- a
	// concurrent winner inserting the exact same edge between this
	// transaction's own read and its write.
	require.NoError(t, ls.db.Callback().Create().Before("gorm:create").Register("dep-race-insert", func(tx *gorm.DB) {
		tx.Exec("INSERT INTO secret_dependencies (project_id, dependent_secret_id, depends_on_secret_id, created_at) VALUES (1, 10, 20, datetime('now'))")
	}))

	_, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 10, DependsOnSecretID: 20,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateSecretDependency)
}
