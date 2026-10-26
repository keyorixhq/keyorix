// trigger_function_hardening_postgres_test.go — review follow-ups on
// TRIGGER-ROWDIGEST-1 (#3631, docs/design/trigger-rowdigest.md):
//
//   - a failed repair must not let the next integrity tick adopt whatever the
//     catalog then shows as a fresh baseline (fail closed): a body replaced,
//     a repair that cannot commit, and the body restored before the next tick
//     must still flush the warm caches;
//   - the generation function and the secret_nodes cache-epoch function pin
//     search_path, so a writer whose search_path puts its own schema before
//     pg_catalog cannot shadow the operator the bodies use and make its write
//     move neither the generation nor the stamp.
package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRolePermGenerationIntegrity_FailedRepairIsRetriedNotAdopted_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, db, w)

	// Another session holds system_metadata, so the repair's generation bump
	// cannot commit and the whole repair transaction rolls back.
	lock := db.Begin()
	require.NoError(t, lock.Error)
	require.NoError(t, lock.Exec("LOCK TABLE system_metadata IN EXCLUSIVE MODE").Error)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	flushed, err := c.check(ctx)
	cancel()
	require.NoError(t, lock.Rollback().Error)
	require.Error(t, err, "premise: the repair transaction failed")
	require.False(t, flushed)

	// The body is restored before the next tick, without a bump: the tamperer
	// covering their tracks, or simply another replica booting (its installer
	// rewrites a differing function and bumps nothing).
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the definition reads as this release's again")

	requireStaleThenFlushed(t, w, c)
}

// TestRolePermGenerationIntegrity_BlockedRepairStillFlushes_Postgres: the
// invalidation must not wait on the repair. A trigger re-created on fewer
// events, a direct revoke, and then another session holds role_permissions
// (an idle transaction, a long pg_dump), so the repair's DROP TRIGGER cannot
// get its lock. Every tick must still flush the warm caches, fail its repair
// within the lock timeout instead of queueing behind the holder, and stay
// pending; once the holder is gone the next tick repairs. Red before the bump
// had its own transaction: the bump rolled back with the blocked repair and
// the warm cache kept authorizing the revoked permission.
func TestRolePermGenerationIntegrity_BlockedRepairStillFlushes_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		for _, q := range []string{
			"DROP TRIGGER " + RolePermissionsGenerationTrigger + " ON role_permissions",
			"CREATE TRIGGER " + RolePermissionsGenerationTrigger + " AFTER INSERT ON role_permissions FOR EACH STATEMENT EXECUTE PROCEDURE " + rolePermGenerationFunc + "()",
			"ALTER TABLE role_permissions ENABLE ALWAYS TRIGGER " + RolePermissionsGenerationTrigger,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}))
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen and the warm cache still authorizes")

	lock := db.Begin()
	require.NoError(t, lock.Error)
	t.Cleanup(func() { _ = lock.Rollback().Error })
	require.NoError(t, lock.Exec("LOCK TABLE role_permissions IN ACCESS SHARE MODE").Error)
	for tick := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		flushed, err := c.check(ctx)
		cancel()
		took := time.Since(start)
		require.Error(t, err, "tick %d: premise: the repair cannot take its lock", tick)
		require.True(t, flushed, "tick %d: the bump committed although the repair failed", tick)
		require.False(t, w.decide(t, w.perm.Name), "tick %d: the reader answers from the live join", tick)
		require.Less(t, took, 8*time.Second, "tick %d: the repair gives up at its lock timeout, not the caller's deadline", tick)
		// A further direct write while the trigger is still wrong: the next
		// tick, still pending, must flush it too.
		require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", w.role.ID, w.perm.ID).Error)
		require.True(t, w.decide(t, w.perm.Name))
		revokeDirect(t, db, w)
		require.True(t, w.decide(t, w.perm.Name), "tick %d: premise: the trigger still misses a DELETE", tick)
	}
	require.NoError(t, lock.Rollback().Error)

	flushed, err := c.check(context.Background())
	require.NoError(t, err, "the holder is gone: the repair commits")
	require.True(t, flushed)
	require.False(t, w.decide(t, w.perm.Name))
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the definition is this release's again")
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a repaired state is the new baseline, not a second alarm")
}

// pgFuncConfig returns pg_proc.proconfig of a zero-argument function in the
// connection's schema, as text ("" when NULL).
func pgFuncConfig(t *testing.T, db *gorm.DB, fn string) string {
	t.Helper()
	var cfg []struct{ Proconfig *string }
	require.NoError(t, db.Raw("SELECT proconfig::text AS proconfig FROM pg_catalog.pg_proc WHERE oid = ?::regprocedure", fn+"()").Scan(&cfg).Error)
	require.Len(t, cfg, 1, "%s() is installed", fn)
	if cfg[0].Proconfig == nil {
		return ""
	}
	return *cfg[0].Proconfig
}

// requireFuncPinned asserts fn() pins search_path, and that the installer
// re-pins an older release's unpinned function.
func requireFuncPinned(t *testing.T, db *gorm.DB, fn string, ensure func(*gorm.DB) error) {
	t.Helper()
	require.Equal(t, `{"search_path=pg_catalog, pg_temp"}`, pgFuncConfig(t, db, fn), "%s() pins search_path", fn)
	require.NoError(t, db.Exec("ALTER FUNCTION "+fn+"() RESET ALL").Error)
	require.Empty(t, pgFuncConfig(t, db, fn), "premise: an older release's unpinned function")
	require.NoError(t, ensure(db))
	require.Equal(t, `{"search_path=pg_catalog, pg_temp"}`, pgFuncConfig(t, db, fn), "%s() re-pinned on upgrade", fn)
}

func TestRolePermGeneration_FunctionPinsSearchPath_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	requireFuncPinned(t, w.writer.db, rolePermGenerationFunc, EnsureRolePermissionsGenerationTriggers)
}

func TestSecretNodeCacheEpoch_FunctionPinsSearchPath_Postgres(t *testing.T) {
	db, _, _ := cacheEpochReplicaWorld(t)
	requireFuncPinned(t, db, secretNodeCacheEpochFunc, EnsureSecretNodeCacheEpoch)
}

// shadowPlusSchema creates a schema with a bigint + integer operator that
// returns its left operand unchanged, and returns a search_path that puts it
// before pg_catalog and then the connection's own schema.
func shadowPlusSchema(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var current string
	require.NoError(t, db.Raw("SELECT pg_catalog.current_schema()").Scan(&current).Error)
	evil := fmt.Sprintf("kx_shadow_%d", time.Now().UnixNano())
	for _, q := range []string{
		"CREATE SCHEMA " + evil,
		"CREATE FUNCTION " + evil + ".keep(bigint, integer) RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT $1'",
		"CREATE OPERATOR " + evil + ".+ (LEFTARG = bigint, RIGHTARG = integer, FUNCTION = " + evil + ".keep)",
	} {
		require.NoError(t, db.Exec(q).Error)
	}
	t.Cleanup(func() { _ = db.Exec("DROP SCHEMA " + evil + " CASCADE").Error })
	return evil + ", pg_catalog, " + `"` + current + `"`
}

func TestRolePermGeneration_WriterSearchPathCannotShadowTheBump_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	require.True(t, w.decide(t, w.perm.Name), "warm")
	path := shadowPlusSchema(t, w.writer.db)
	require.NoError(t, w.writer.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL search_path = " + path).Error; err != nil {
			return err
		}
		revokeDirect(t, tx, w)
		return nil
	}))
	require.False(t, w.decide(t, w.perm.Name), "a direct revocation from a session whose search_path shadows + must still move the generation")
}

func TestSecretNodeCacheEpoch_WriterSearchPathCannotShadowTheBump_Postgres(t *testing.T) {
	db, ls, created := cacheEpochReplicaWorld(t)
	ctx := context.Background()
	path := shadowPlusSchema(t, db)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL search_path = " + path).Error; err != nil {
			return err
		}
		return tx.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", created.ID).Error
	}))
	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "a write from a session whose search_path shadows + must still move cache_epoch")
}
