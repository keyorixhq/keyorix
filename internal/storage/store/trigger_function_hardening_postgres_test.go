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
