// concurrency_deleteenvironment_orphan_test.go — SESSION-AT: DeleteEnvironment
// counted active secrets and deleted the environment as two separate,
// non-transactional, unlocked statements, AND CreateSecret's own
// environment-existence check (GetEnvironment) ran with no lock spanning it
// and the actual insert. A secret created in the window between
// DeleteEnvironment's count and its delete -- or created after
// DeleteEnvironment had already committed, racing CreateSecret's own
// GetEnvironment-then-Create gap -- was silently orphaned: the environment
// row is gone, but a secret_nodes row with that environment_id remains,
// pointing at nothing.
//
// Uses a real, file-backed SQLite DB (WAL + busy_timeout) with the FULL
// production schema (kxstorage.MigrateExisting, not a hand-picked AutoMigrate
// subset -- see CLAUDE.md's own note on why that distinction matters), so
// two genuinely concurrent connections/goroutines can interleave through the
// real core.CreateSecret / core.DeleteEnvironment call chain, not a
// synthetic storage-layer-only bypass.
package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const deleteEnvironmentOrphanTrials = 50

// newProjectEnvFixture creates a fresh file-backed DB (full production
// schema) with exactly one project and one environment, no auth/RBAC setup
// -- neither core.CreateSecret nor core.DeleteEnvironment requires an
// authenticated actor at the core layer (authorization is enforced at the
// transport layer, above core), so this fixture stays minimal.
func newProjectEnvFixture(t *testing.T, dbFile string) (c *core.KeyorixCore, db *gorm.DB, projectID, envID uint) {
	t.Helper()
	dsn := "file:" + dbFile + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(db))

	proj := &models.Project{Name: "proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), db, proj.ID, env.ID
}

// TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedSecret
// races core.DeleteEnvironment(envID) against core.CreateSecret(environment_id=envID)
// many times and asserts the bad outcome (the environment is gone AND an
// active secret pointing at it exists) never happens.
func TestConcurrency_DeleteEnvironment_NeverOrphansAConcurrentlyCreatedSecret(t *testing.T) {
	var orphaned int
	for trial := 0; trial < deleteEnvironmentOrphanTrials; trial++ {
		c, db, projectID, envID := newProjectEnvFixture(t, filepath.Join(t.TempDir(), "delete_env.db"))
		ctx := context.Background()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = c.DeleteEnvironment(ctx, envID)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.CreateSecret(ctx, &core.CreateSecretRequest{
				Name: "concurrent-secret", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID,
				Type: "generic", CreatedBy: "test",
			})
		}()
		close(start)
		wg.Wait()

		var envExists bool
		require.NoError(t, db.Model(&models.Environment{}).
			Select("count(*) > 0").Where("id = ?", envID).Find(&envExists).Error)
		var secretCount int64
		require.NoError(t, db.Model(&models.SecretNode{}).
			Where("environment_id = ? AND status = 'active'", envID).Count(&secretCount).Error)

		if !envExists && secretCount > 0 {
			orphaned++
		}
	}
	assert.Zero(t, orphaned, "%d/%d trials orphaned a secret: environment deleted while a concurrently-created active secret still points at it", orphaned, deleteEnvironmentOrphanTrials)
}
