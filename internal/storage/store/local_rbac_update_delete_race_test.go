package store

// STORE-STALE-WRITE-1 item 1: UpdateRole used to persist the role with a
// full-row Save. Save is an upsert, so an update whose UPDATE matched nothing
// because a concurrent DeleteRole had committed re-inserted the deleted custom
// role under the same id with the stale name and description.
//
// Each test asserts the roles table, never only the return value. On Postgres
// replica B is a separate connection (its own *gorm.DB pool, the same schema)
// that commits on its own, as another replica would; replica A's transaction
// has only read the role at that point (core UpdateRole's GetRole, no row
// lock), so B never blocks. SQLite serializes writers, so there B's delete runs
// on A's transaction handle at the same point: the UPDATE sees the identical
// database state (the row gone).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

type roleRaceWorld struct {
	backend string
	lsA     *LocalStorage // replica A
	lsB     *LocalStorage // replica B: its own connection on Postgres, a second pool on SQLite
	dbA     *gorm.DB
}

func roleRaceBackends() []string {
	if os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
		return []string{"sqlite"}
	}
	return []string{"sqlite", "postgres"}
}

func newRoleRaceWorld(t *testing.T, backend string) *roleRaceWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	w := &roleRaceWorld{backend: backend}
	var dbB *gorm.DB
	if backend == "sqlite" {
		dsn := "file:" + filepath.Join(t.TempDir(), "role-race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
		var err error
		w.dbA, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		dbB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			for _, db := range []*gorm.DB{w.dbA, dbB} {
				if sqlDB, err := db.DB(); err == nil {
					_ = sqlDB.Close()
				}
			}
		})
	} else {
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		w.dbA = pgOpen(t, dsn)
		dbB = pgOpen(t, dsn)
	}
	require.NoError(t, w.dbA.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.GroupRole{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{}, &models.SystemMetadata{},
	))
	w.lsA = NewLocalStorage(w.dbA)
	w.lsB = NewLocalStorage(dbB)
	return w
}

func (w *roleRaceWorld) seedRole(t *testing.T, name string) *models.Role {
	t.Helper()
	r := &models.Role{Name: name, NameFolded: name, Description: "before", AssignableScope: models.RoleAssignableProject}
	require.NoError(t, w.dbA.Create(r).Error)
	return r
}

func (w *roleRaceWorld) roleRows(t *testing.T, id uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.dbA.Model(&models.Role{}).Where("id = ?", id).Count(&n).Error)
	return n
}

// Delete lands between the update's read and its write (the stale Save's
// window): the update must fail as not found and the role must stay deleted.
func TestUpdateRole_DeleteBetweenReadAndWrite_RoleStaysDeleted(t *testing.T) {
	for _, backend := range roleRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newRoleRaceWorld(t, backend)
			ctx := context.Background()
			seeded := w.seedRole(t, "deploy-operators")

			tx := w.dbA.Begin()
			require.NoError(t, tx.Error)
			defer tx.Rollback()
			lsTx := &LocalStorage{db: tx}

			// Replica A: core UpdateRole's in-transaction read, then the edit.
			stale, err := lsTx.GetRole(ctx, seeded.ID)
			require.NoError(t, err)
			stale.Description = "after"

			// Replica B deletes the role and commits.
			deleter := w.lsB
			if backend == "sqlite" {
				deleter = lsTx
			}
			_, err = deleter.DeleteRole(ctx, seeded.ID)
			require.NoError(t, err)

			_, err = lsTx.UpdateRole(ctx, stale)
			require.Error(t, err, "an update of a role deleted after it was read must fail, not re-create it")
			require.True(t, errors.Is(err, storage.ErrRoleNotFound), "want ErrRoleNotFound, got %v", err)

			var inTx int64
			require.NoError(t, tx.Session(&gorm.Session{NewDB: true}).Model(&models.Role{}).Where("id = ?", seeded.ID).Count(&inTx).Error)
			require.Zero(t, inTx, "the stale update re-inserted the deleted role")
			require.NoError(t, tx.Rollback().Error)
			if backend != "sqlite" { // on SQLite the rollback also undid B's in-transaction delete
				require.Zero(t, w.roleRows(t, seeded.ID), "the deleted role came back")
			}
		})
	}
}

// The other order: the update commits first, then the delete. The role is gone.
func TestUpdateRole_ThenDelete_RoleStaysDeleted(t *testing.T) {
	for _, backend := range roleRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newRoleRaceWorld(t, backend)
			ctx := context.Background()
			seeded := w.seedRole(t, "deploy-operators")

			stale, err := w.lsA.GetRole(ctx, seeded.ID)
			require.NoError(t, err)
			stale.Description = "after"
			stale.AssignableScope = models.RoleAssignableGlobal
			got, err := w.lsA.UpdateRole(ctx, stale)
			require.NoError(t, err)
			require.Equal(t, "after", got.Description)
			require.Equal(t, models.RoleAssignableGlobal, got.AssignableScope)
			require.Equal(t, "deploy-operators", got.Name, "UpdateRole returns the stored row")

			_, err = w.lsB.DeleteRole(ctx, seeded.ID)
			require.NoError(t, err)
			require.Zero(t, w.roleRows(t, seeded.ID))

			// A second update by a client that still holds the old struct.
			_, err = w.lsA.UpdateRole(ctx, stale)
			require.True(t, errors.Is(err, storage.ErrRoleNotFound), "want ErrRoleNotFound, got %v", err)
			require.Zero(t, w.roleRows(t, seeded.ID), "the deleted role came back")
		})
	}
}

// UpdateRole writes only description and assignable_scope: it never moves
// the name or the bypass flag from a stale struct.
func TestUpdateRole_IsColumnScoped(t *testing.T) {
	w := newRoleRaceWorld(t, "sqlite")
	ctx := context.Background()
	seeded := w.seedRole(t, "deploy-operators")
	stale := *seeded
	stale.Name, stale.NameFolded, stale.BypassesPermissionChecks = "renamed", "renamed", true
	stale.Description = "after"
	got, err := w.lsA.UpdateRole(ctx, &stale)
	require.NoError(t, err)
	require.Equal(t, "deploy-operators", got.Name)
	require.Equal(t, "deploy-operators", got.NameFolded)
	require.False(t, got.BypassesPermissionChecks)
	require.Equal(t, "after", got.Description)
}

// Free-running race: replica A updates from a stale read while replica B
// deletes, many times, in both start orders. Every role must end deleted.
func TestUpdateRole_ConcurrentDelete_NeverResurrects(t *testing.T) {
	for _, backend := range roleRaceBackends() {
		t.Run(backend, func(t *testing.T) {
			w := newRoleRaceWorld(t, backend)
			ctx := context.Background()
			const rounds = 40
			for i := range rounds {
				seeded := w.seedRole(t, fmt.Sprintf("race-%d", i))
				stale, err := w.lsA.GetRole(ctx, seeded.ID)
				require.NoError(t, err)
				stale.Description = "after"

				var wg sync.WaitGroup
				start := make(chan struct{})
				var delErr, updErr error
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					if i%2 == 0 {
						_, delErr = w.lsB.DeleteRole(ctx, seeded.ID)
					} else {
						_, updErr = w.lsA.UpdateRole(ctx, stale)
					}
				}()
				go func() {
					defer wg.Done()
					<-start
					if i%2 == 0 {
						_, updErr = w.lsA.UpdateRole(ctx, stale)
					} else {
						_, delErr = w.lsB.DeleteRole(ctx, seeded.ID)
					}
				}()
				close(start)
				wg.Wait()

				require.NoError(t, delErr, "round %d", i)
				if updErr != nil {
					require.True(t, errors.Is(updErr, storage.ErrRoleNotFound), "round %d: %v", i, updErr)
				}
				require.Zero(t, w.roleRows(t, seeded.ID), "round %d: the deleted role came back", i)
			}
		})
	}
}
