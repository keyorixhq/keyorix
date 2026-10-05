// read_path_cache_race_test.go — ONE table-driven harness that races a write
// through every cached read's generation/data window, plus a completeness
// check that fails if a method using the read-path helper has no row here.
//
// # What the window is, and why the harness opens it where it does
//
// read_path_cache.go's contract is "stamp first, data second". On a MISS that
// produces two statements with a real gap between them:
//
//	gen(ctx)            <- the stamp
//	   ** window **     <- a write committing HERE is the whole bug class
//	load(ctx)           <- the data
//	cache.store(stamp, data)
//
// If the implementation ever reverts to reading the stamp AFTER the data, a
// write landing in that gap is recorded under the post-write stamp and served
// from then on — not for a TTL (there is none) but until some unrelated write
// moves that generation again. The harness registers a one-shot GORM
// After("gorm:query") callback keyed on the window table and commits the
// mutation from inside it, so the write lands in that exact gap.
//
// Deliberately NOT warmed first: a cache HIT issues only the generation query,
// so there is no data query to hang the window on and nothing to race. The
// first read in each case is a cold miss — which is the only read that writes
// an entry, and therefore the only one that can write a wrong one.
//
// # What each row asserts, and what it does not
//
// The in-flight read may legitimately still answer with the pre-write value:
// it read before the write committed, and every database read has that
// property. What must never happen is that answer being CACHED under the
// post-write stamp. So the assertion is always on the NEXT read, and
// `require.False(t, armed, ...)` fails a row whose window never opened — a
// vacuous pass is a failure here, not a pass.
//
// # Red proof
//
// Run against #2764's and #2767's pre-fix commits (see this session's report):
// the GetLatestSecretVersion and RoleSetHasPermission rows go red there with
// the stale value served. GetSecret's and GetSecretAccessSchedule's rows are
// expected GREEN even pre-fix, because both are same-row cases
// (cachedReadSameRow) where the stamp comes from the load itself and the
// window cannot produce a mismatched pair — recorded here as the known-good
// calibration direction rather than omitted.
package store

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// raceHandle carries whatever fixture ids a row's mutate/read need. One struct
// rather than `any` so a row cannot quietly mean something different by the
// value it returns.
type raceHandle struct {
	secretID  uint
	versionID uint
	roleID    uint
	permID    uint
}

// cacheRaceCase is one row: a cached read, the table whose query opens its
// generation/data window, the write committed inside that window, and the
// assertion the NEXT read must satisfy.
type cacheRaceCase struct {
	// name identifies the row; include the writer type it exercises so item 4's
	// coverage is readable straight off the table.
	name string
	// site is the package function under test. The completeness check requires
	// every function that calls cachedRead/cachedReadSameRow to appear here.
	site string
	// window is the GORM table name whose query the mutation is committed after.
	window string
	setup  func(t *testing.T, ls *LocalStorage) raceHandle
	mutate func(t *testing.T, ls *LocalStorage, h raceHandle)
	// read performs the cached read. It returns (value, error) untyped so one
	// harness can drive all four methods; wantFresh does the typed assertion.
	read      func(t *testing.T, ls *LocalStorage, h raceHandle) (any, error)
	wantFresh func(t *testing.T, got any, err error)
	// rollbackMutate, when set, gives this row a second leg
	// (TestReadPathCacheRace_RolledBackTransactionDoesNotPoisonTheCache): the
	// write and the cached read both happen INSIDE a transaction that is then
	// rolled back, and commitMutate then performs a COMMITTED write that
	// reproduces the same generation value. The coordinator's 2026-10-05
	// blocker: a tx-scoped LocalStorage shares the parent's cache pointer and
	// reads through the transaction handle, so everything it resolves is
	// uncommitted; if it cached, the rollback would leave that entry to be
	// validated and served by the next committed write.
	rollbackMutate func(t *testing.T, tx storage.Storage, h raceHandle)
	commitMutate   func(t *testing.T, ls *LocalStorage, h raceHandle)
	wantCommitted  func(t *testing.T, got any, err error)
}

func newRaceTestStorage(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{},
		&models.ShareRecord{}, &models.SecretACL{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{},
		&models.UserRole{}, &models.GroupRole{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{},
	))
	// The node cache's stamp is secret_nodes.cache_epoch, maintained by a
	// trigger that AutoMigrate cannot create. Without this call the store
	// correctly refuses to use the node cache at all (nodeCache() returns nil),
	// so every GetSecret row below would pass against an UNCACHED read — the
	// textbook vacuous pass. The cache_epoch row in the table is what caught
	// that; the assertion in runCacheRaceCase is what keeps it caught.
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	return NewLocalStorage(db)
}

func seedRaceSecret(t *testing.T, ls *LocalStorage) raceHandle {
	t.Helper()
	created, err := ls.CreateSecret(context.Background(), &models.SecretNode{
		Name: "raced", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return raceHandle{secretID: created.ID}
}

func seedRaceSecretWithVersion(t *testing.T, ls *LocalStorage) raceHandle {
	t.Helper()
	h := seedRaceSecret(t, ls)
	v, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{
		SecretNodeID: h.secretID, VersionNumber: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	h.versionID = v.ID
	return h
}

func seedRaceSecretWithSchedule(t *testing.T, ls *LocalStorage) raceHandle {
	t.Helper()
	h := seedRaceSecret(t, ls)
	require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: h.secretID, AllowedDays: "1,2,3", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}))
	return h
}

func seedRaceRoleWithPermission(t *testing.T, ls *LocalStorage) raceHandle {
	t.Helper()
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "raced-role"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))
	return raceHandle{roleID: role.ID, permID: perm.ID}
}

func seedRaceRoleWithoutPermission(t *testing.T, ls *LocalStorage) raceHandle {
	t.Helper()
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "raced-role"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	return raceHandle{roleID: role.ID, permID: perm.ID}
}

func readSecret(t *testing.T, ls *LocalStorage, h raceHandle) (any, error) {
	return ls.GetSecret(context.Background(), h.secretID)
}

func readLatestVersion(t *testing.T, ls *LocalStorage, h raceHandle) (any, error) {
	return ls.GetLatestSecretVersion(context.Background(), h.secretID)
}

func readSchedule(t *testing.T, ls *LocalStorage, h raceHandle) (any, error) {
	return ls.GetSecretAccessSchedule(context.Background(), h.secretID)
}

func readRolePermission(t *testing.T, ls *LocalStorage, h raceHandle) (any, error) {
	return ls.RoleSetHasPermission(context.Background(), []uint{h.roleID}, "secrets.read")
}

// cacheRaceCases — one row per cached read (enforced complete by
// TestReadPathCacheRace_EveryHelperSiteHasARow) and one row per writer TYPE of
// a cached row (item 4's coverage, readable off the row names).
//
// Writer types covered: node update (Save), node status transition
// (Select("*").Updates), node single-column update, node soft-delete, node
// read-count increment (UpdateColumn), version create, version read-count
// increment (UpdateColumn), schedule set (upsert), schedule delete, role
// permission grant, role permission revoke, role delete (cascade).
//
// Deliberately NOT covered, named rather than silently absent:
// internal/encryption/sweep.go's DEK rewrap of secret_versions.encrypted_value
// — it runs only under the exclusive key lock (ADR-010, RotateDEKWithSweep),
// the stopped-server class, and it is outside this package. See
// secret_metadata_cache.go's header.
func cacheRaceCases() []cacheRaceCase {
	return []cacheRaceCase{
		{
			name:   "GetSecret / node update (Save)",
			site:   "GetSecret",
			window: "secret_nodes",
			setup:  seedRaceSecret,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				row, err := ls.GetSecretIncludingDeleted(context.Background(), h.secretID)
				require.NoError(t, err)
				row.Description = "raced-in"
				row.UpdatedAt = time.Now()
				_, err = ls.UpdateSecret(context.Background(), row)
				require.NoError(t, err)
			},
			read: readSecret,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, "raced-in", got.(*models.SecretNode).Description)
			},
		},
		{
			name:   "GetSecret / node status transition (Select(\"*\").Updates)",
			site:   "GetSecret",
			window: "secret_nodes",
			setup:  seedRaceSecret,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				row, err := ls.GetSecretIncludingDeleted(context.Background(), h.secretID)
				require.NoError(t, err)
				row.Status = "suspended"
				row.UpdatedAt = time.Now()
				ok, err := ls.TransitionSecretStatus(context.Background(), row, "active")
				require.NoError(t, err)
				require.True(t, ok)
			},
			read: readSecret,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, "suspended", got.(*models.SecretNode).Status)
			},
		},
		{
			name:   "GetSecret / node read-count increment (UpdateColumn, #133 max-reads)",
			site:   "GetSecret",
			window: "secret_nodes",
			setup:  seedRaceSecret,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				ok, err := ls.TryIncrementSecretNodeReadCount(context.Background(), h.secretID, 10)
				require.NoError(t, err)
				require.True(t, ok)
			},
			read: readSecret,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, got.(*models.SecretNode).ReadCount,
					"a stale read_count is written back by RotateSecret's read-modify-write and resets the max-reads budget")
			},
		},
		{
			// The epoch row the coordinator asked for: a write whose ONLY visible
			// effect is the trigger's own cache_epoch bump. It uses a column no
			// other row in this table touches and asserts on that column, so the
			// row fails if the trigger stops firing even while every other row
			// still passes on its own content.
			name:   "GetSecret / cache_epoch trigger (raw SQL, no GORM callback at all)",
			site:   "GetSecret",
			window: "secret_nodes",
			setup:  seedRaceSecret,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				before := nodeCacheEpochForRace(t, ls, h.secretID)
				// Raw SQL: no GORM model, no auto-timestamp callback, no hook —
				// the shape no Go-side bump could ever cover, and the reason the
				// stamp is maintained by the database instead.
				require.NoError(t, ls.db.Exec(
					"UPDATE secret_nodes SET rotation_ref = ? WHERE id = ?", "raced-ref", h.secretID).Error)
				require.Greater(t, nodeCacheEpochForRace(t, ls, h.secretID), before,
					"the trigger must bump cache_epoch for a raw-SQL update, or this row cannot detect anything")
			},
			read: readSecret,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, "raced-ref", got.(*models.SecretNode).RotationRef,
					"a raw-SQL write inside the window was not reflected: the cache_epoch stamp did not move")
			},
		},
		{
			name:   "GetSecret / node soft-delete",
			site:   "GetSecret",
			window: "secret_nodes",
			setup:  seedRaceSecret,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.DeleteSecret(context.Background(), h.secretID))
			},
			read: readSecret,
			wantFresh: func(t *testing.T, got any, err error) {
				require.Error(t, err, "a soft-deleted secret must not be served from cache")
			},
		},
		{
			name:   "GetLatestSecretVersion / version create (rotation)",
			site:   "GetLatestSecretVersion",
			window: "secret_versions",
			setup:  seedRaceSecretWithVersion,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				_, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{
					SecretNodeID: h.secretID, VersionNumber: 2, CreatedAt: time.Now(),
				})
				require.NoError(t, err)
			},
			read: readLatestVersion,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, 2, got.(*models.SecretVersion).VersionNumber,
					"the pre-rotation version was cached under the post-rotation generation")
			},
		},
		{
			name:   "GetLatestSecretVersion / version read-count increment (UpdateColumn)",
			site:   "GetLatestSecretVersion",
			window: "secret_versions",
			setup:  seedRaceSecretWithVersion,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				ok, err := ls.TryIncrementSecretReadCount(context.Background(), h.versionID, 10)
				require.NoError(t, err)
				require.True(t, ok)
			},
			read: readLatestVersion,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, got.(*models.SecretVersion).ReadCount)
			},
		},
		{
			name:   "GetSecretAccessSchedule / schedule set (upsert)",
			site:   "GetSecretAccessSchedule",
			window: "secret_access_schedules",
			setup:  seedRaceSecretWithSchedule,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
					SecretNodeID: h.secretID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC",
				}))
			},
			read: readSchedule,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, "*", got.(*models.SecretAccessSchedule).AllowedDays,
					"a stale schedule keeps a closed read window open")
			},
		},
		{
			name:   "GetSecretAccessSchedule / schedule delete",
			site:   "GetSecretAccessSchedule",
			window: "secret_access_schedules",
			setup:  seedRaceSecretWithSchedule,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.DeleteSecretAccessSchedule(context.Background(), h.secretID))
			},
			read: readSchedule,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Nil(t, got, "a deleted schedule must not be served from cache")
			},
		},
		{
			name:   "GetLatestSecretVersion / ROLLED-BACK version create",
			site:   "GetLatestSecretVersion",
			window: "secret_versions",
			setup:  seedRaceSecretWithVersion,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				_, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{
					SecretNodeID: h.secretID, VersionNumber: 2, EncryptedValue: []byte("WINDOW"), CreatedAt: time.Now(),
				})
				require.NoError(t, err)
			},
			read: readLatestVersion,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, 2, got.(*models.SecretVersion).VersionNumber)
			},
			rollbackMutate: func(t *testing.T, tx storage.Storage, h raceHandle) {
				_, err := tx.CreateSecretVersion(context.Background(), &models.SecretVersion{
					SecretNodeID: h.secretID, VersionNumber: 2, EncryptedValue: []byte("ROLLED-BACK"), CreatedAt: time.Now(),
				})
				require.NoError(t, err)
				// Resolving the latest version inside the transaction is what
				// would publish the uncommitted row.
				latest, err := tx.GetLatestSecretVersion(context.Background(), h.secretID)
				require.NoError(t, err)
				require.Equal(t, []byte("ROLLED-BACK"), latest.EncryptedValue,
					"the transaction must see its own uncommitted version")
			},
			commitMutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				_, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{
					SecretNodeID: h.secretID, VersionNumber: 2, EncryptedValue: []byte("COMMITTED"), CreatedAt: time.Now(),
				})
				require.NoError(t, err)
			},
			wantCommitted: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.Equal(t, []byte("COMMITTED"), got.(*models.SecretVersion).EncryptedValue,
					"a version row from a rolled-back transaction was served: the committed version reproduced its aggregate exactly")
			},
		},
		{
			name:   "RoleSetHasPermission / ROLLED-BACK permission grant",
			site:   "RoleSetHasPermission",
			window: "permissions",
			setup:  seedRaceRoleWithoutPermission,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.AssignPermissionToRole(context.Background(), h.roleID, h.permID))
			},
			read: readRolePermission,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.True(t, got.(bool))
			},
			rollbackMutate: func(t *testing.T, tx storage.Storage, h raceHandle) {
				require.NoError(t, tx.AssignPermissionToRole(context.Background(), h.roleID, h.permID))
				allowed, err := tx.RoleSetHasPermission(context.Background(), []uint{h.roleID}, "secrets.read")
				require.NoError(t, err)
				require.True(t, allowed, "the transaction must see its own uncommitted grant")
			},
			commitMutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				// An UNRELATED committed grant, which advances the global
				// generation by exactly one — reproducing the value the
				// rolled-back transaction stamped its entry with.
				otherRole, err := ls.CreateRole(context.Background(), mustFoldedName(t, "other-role"), "")
				require.NoError(t, err)
				otherPerm, err := ls.CreatePermission(context.Background(), &models.Permission{Name: "secrets.write"})
				require.NoError(t, err)
				require.NoError(t, ls.AssignPermissionToRole(context.Background(), otherRole.ID, otherPerm.ID))
			},
			wantCommitted: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.False(t, got.(bool),
					"a permission from a rolled-back transaction is authorizing: its uncommitted answer was cached under the uncommitted generation")
			},
		},
		{
			name:   "RoleSetHasPermission / permission revoke",
			site:   "RoleSetHasPermission",
			window: "permissions",
			setup:  seedRaceRoleWithPermission,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.RemovePermissionFromRole(context.Background(), h.roleID, h.permID))
			},
			read: readRolePermission,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.False(t, got.(bool),
					"a revoked permission is still authorizing: the pre-revoke decision was cached under the post-revoke generation")
			},
		},
		{
			name:   "RoleSetHasPermission / permission grant",
			site:   "RoleSetHasPermission",
			window: "permissions",
			setup:  seedRaceRoleWithoutPermission,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				require.NoError(t, ls.AssignPermissionToRole(context.Background(), h.roleID, h.permID))
			},
			read: readRolePermission,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.True(t, got.(bool), "a granted permission must take effect on the next read")
			},
		},
		{
			name:   "RoleSetHasPermission / role delete (cascade)",
			site:   "RoleSetHasPermission",
			window: "permissions",
			setup:  seedRaceRoleWithPermission,
			mutate: func(t *testing.T, ls *LocalStorage, h raceHandle) {
				_, err := ls.DeleteRole(context.Background(), h.roleID)
				require.NoError(t, err)
			},
			read: readRolePermission,
			wantFresh: func(t *testing.T, got any, err error) {
				require.NoError(t, err)
				require.False(t, got.(bool), "a deleted role's grants must not keep authorizing")
			},
		},
	}
}

func TestReadPathCacheRace_WriteInsideTheWindowIsNotCachedStale(t *testing.T) {
	for _, tc := range cacheRaceCases() {
		t.Run(tc.name, func(t *testing.T) {
			ls := newRaceTestStorage(t)
			// Anti-vacuity: every row below is about what a CACHE does, so a
			// store that is not caching makes the row prove nothing. Both halves
			// matter — cacheEnabled covers the store itself, nodeCache() covers
			// the node stamp being trustworthy on this schema.
			require.True(t, ls.cacheEnabled, "the store must be caching or this row tests an uncached path")
			require.NotNil(t, ls.nodeCache(), "the node cache must be usable (cache_epoch trigger present) or the GetSecret rows test an uncached path")
			h := tc.setup(t, ls)

			armed := true
			const cbName = "guard6:race-window"
			require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register(cbName, func(tx *gorm.DB) {
				if armed && tx.Statement.Table == tc.window {
					armed = false
					tc.mutate(t, ls, h)
				}
			}))
			t.Cleanup(func() {
				_ = ls.db.Callback().Query().After("gorm:query").Remove(cbName)
			})

			// The cold read: generation, then window (the mutation commits here),
			// then data, then the entry is written. Its own answer may be the
			// pre-write one — legitimately so, it read first.
			_, _ = tc.read(t, ls, h)
			require.False(t, armed,
				"the window never opened: no query ran against %q, so this row proves nothing", tc.window)

			// The next read is the one that must never be served a stale entry.
			got, err := tc.read(t, ls, h)
			tc.wantFresh(t, got, err)
		})
	}
}

// TestReadPathCacheRace_RolledBackTransactionDoesNotPoisonTheCache drives the
// coordinator's 2026-10-05 blocker from the same table: a transaction writes,
// resolves the cached read inside itself, and rolls back; a COMMITTED write
// then reproduces the same generation value; the next read must see the
// committed state.
//
// Rows without a rollbackMutate are skipped — not every writer type has a
// transaction-reachable form — and the count of rows that DID run is asserted,
// so a row quietly losing its rollback leg fails here instead of silently
// dropping out.
func TestReadPathCacheRace_RolledBackTransactionDoesNotPoisonTheCache(t *testing.T) {
	ran := 0
	for _, tc := range cacheRaceCases() {
		if tc.rollbackMutate == nil {
			continue
		}
		ran++
		t.Run(tc.name, func(t *testing.T) {
			ls := newRaceTestStorage(t)
			require.True(t, ls.cacheEnabled)
			require.NotNil(t, ls.nodeCache())
			h := tc.setup(t, ls)

			sentinel := errors.New("roll back on purpose")
			txErr := ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
				tc.rollbackMutate(t, tx, h)
				return sentinel
			})
			require.ErrorIs(t, txErr, sentinel)

			tc.commitMutate(t, ls, h)
			got, err := tc.read(t, ls, h)
			tc.wantCommitted(t, got, err)
		})
	}
	require.Equal(t, 2, ran,
		"expected the two transaction-reachable rollback rows; a row that lost its rollbackMutate would otherwise be skipped silently")
}

// TestReadPathCacheRace_EveryHelperSiteHasARow is the completeness registry:
// a method that goes through read_path_cache.go but has no row above fails
// here, so a new cache cannot be added without its race row. Same pattern as
// the GUARD-3 registry guards and remote_reachability_registry_test.go.
//
// Recognised: a call to cachedRead or cachedReadSameRow inside a top-level
// func or method declared in a non-test file of this package. NOT recognised,
// and stated rather than assumed: a call made through a function value or from
// outside this package, and a site reached only via a wrapper that itself does
// not name the helper (there is none today — the four sites call it directly).
func TestReadPathCacheRace_EveryHelperSiteHasARow(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, tc := range cacheRaceCases() {
		covered[tc.site] = true
	}

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	sites := map[string]string{} // site -> file

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, perr)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := ""
				switch f := call.Fun.(type) {
				case *ast.Ident:
					callee = f.Name
				case *ast.IndexExpr: // explicit type arguments
					if id, ok := f.X.(*ast.Ident); ok {
						callee = id.Name
					}
				case *ast.IndexListExpr:
					if id, ok := f.X.(*ast.Ident); ok {
						callee = id.Name
					}
				}
				if callee == "cachedRead" || callee == "cachedReadSameRow" {
					sites[fn.Name.Name] = name
				}
				return true
			})
		}
	}

	require.NotEmpty(t, sites,
		"found no call to cachedRead/cachedReadSameRow in this package: the registry has stopped recognising the helper's call shape, so it would pass vacuously")

	var missing []string
	for site, file := range sites {
		if !covered[site] {
			missing = append(missing, site+" ("+file+")")
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing,
		"these functions use read_path_cache.go but have no row in cacheRaceCases(), so nothing races a write through their generation/data window:\n  %s",
		strings.Join(missing, "\n  "))

	// And the converse: a row naming a site that no longer exists is dead
	// weight that would quietly stop testing anything.
	var stale []string
	for site := range covered {
		if _, ok := sites[site]; !ok {
			stale = append(stale, site)
		}
	}
	sort.Strings(stale)
	require.Empty(t, stale,
		"cacheRaceCases() names sites that no longer call the read-path helper: %s", strings.Join(stale, ", "))

	// Guard against a silently-mistyped site name defeating both checks above
	// by matching nothing on either side.
	require.Len(t, sites, 4, "expected exactly the four cached reads; got %v", sites)
	_ = identity.FoldedName{} // keep the identity import used by mustFoldedName visible here
}

// nodeCacheEpochForRace reads the stamp directly, so the epoch row can assert
// the trigger fired rather than inferring it from the cache's behaviour.
func nodeCacheEpochForRace(t *testing.T, ls *LocalStorage, id uint) int64 {
	t.Helper()
	var row struct{ CacheEpoch int64 }
	require.NoError(t, ls.db.Model(&models.SecretNode{}).
		Select("cache_epoch").Where(sqlWhereID, id).Take(&row).Error)
	return row.CacheEpoch
}
