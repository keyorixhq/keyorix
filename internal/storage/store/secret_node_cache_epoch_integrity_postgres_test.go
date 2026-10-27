// secret_node_cache_epoch_integrity_postgres_test.go — TRIGGER-HARDEN-1: the
// owner of the cache-epoch function (the server's own database role, not a
// superuser) can change what the trigger does while the per-read proof still
// passes. Each test makes one such change, shows a direct UPDATE then leaves
// the stamp where it was and the warm cache serves the old row (the gap), runs
// one integrity tick and expects the next read to come from the database.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const noopEpochBody = "CREATE OR REPLACE FUNCTION " + secretNodeCacheEpochFunc + "() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NEW; END;$x$"

// restoreEpochFunc is CREATE OR REPLACE with exactly this release's function.
const restoreEpochFunc = "CREATE OR REPLACE FUNCTION " + secretNodeCacheEpochFunc + "() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $keyorix$" + postgresSecretNodeCacheEpochFuncBody + "$keyorix$"

type epochIntegrityWorld struct {
	db      *gorm.DB
	ls      *LocalStorage
	id      uint
	checker *secretNodeCacheEpochIntegrityChecker
}

// newEpochIntegrityWorld is a warm Postgres cache-epoch world with a checker
// whose first tick has recorded the baseline.
func newEpochIntegrityWorld(t *testing.T) epochIntegrityWorld {
	t.Helper()
	db, ls, created := cacheEpochReplicaWorld(t)
	var super bool
	require.NoError(t, db.Raw("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super).Error)
	t.Logf("tampering as a role with rolsuper=%v", super)
	c := &secretNodeCacheEpochIntegrityChecker{ls: ls, logf: t.Logf}
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a fresh install is clean: the first tick only records the baseline")
	return epochIntegrityWorld{db: db, ls: ls, id: created.ID, checker: c}
}

func (w epochIntegrityWorld) suspendDirect(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", w.id).Error)
}

func (w epochIntegrityWorld) status(t *testing.T) string {
	t.Helper()
	got, err := w.ls.GetSecret(context.Background(), w.id)
	require.NoError(t, err)
	return got.Status
}

// requireStaleThenFlushed asserts the gap (the per-read proof passes and the
// warm cache still serves the pre-update row), then that one tick flushes it,
// restores the definition and is quiet afterwards.
func requireEpochStaleThenFlushed(t *testing.T, w epochIntegrityWorld) {
	t.Helper()
	require.True(t, SecretNodeCacheEpochTriggerPresent(w.db), "premise: the per-read proof still passes")
	require.Equal(t, "active", w.status(t), "premise: the direct update went unseen and the warm cache still serves the old row")
	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	flushed, err := w.checker.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the tick must see the change")
	require.Greater(t, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), before, "and count it")
	require.Equal(t, "suspended", w.status(t), "after the tick the reader answers from the database")
	st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the definition is this release's again")
	flushed, err = w.checker.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a repaired state is the new baseline, not a second alarm")
}

func TestSecretNodeCacheEpochIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec(noopEpochBody).Error)
	w.suspendDirect(t, w.db)
	requireEpochStaleThenFlushed(t, w)

	// The restored body stamps again: a direct update is seen without a tick.
	require.NoError(t, w.db.Exec("UPDATE secret_nodes SET status = 'active' WHERE id = ?", w.id).Error)
	require.Equal(t, "active", w.status(t))
}

func TestSecretNodeCacheEpochIntegrity_AlteredSearchPathIsRestored_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("ALTER FUNCTION "+secretNodeCacheEpochFunc+"() SET search_path = public").Error)
	require.Equal(t, `{search_path=public}`, pgFuncConfig(t, w.db, secretNodeCacheEpochFunc))
	st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
	require.NoError(t, err)
	require.NotEmpty(t, st.problem, "the check reports the changed setting")
	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	flushed, err := w.checker.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.Greater(t, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), before)
	require.Equal(t, `{"search_path=pg_catalog, pg_temp"}`, pgFuncConfig(t, w.db, secretNodeCacheEpochFunc))
	flushed, err = w.checker.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed)
}

func TestSecretNodeCacheEpochIntegrity_SecurityDefinerIsRestored_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("ALTER FUNCTION "+secretNodeCacheEpochFunc+"() SECURITY DEFINER").Error)
	flushed, err := w.checker.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	var def bool
	require.NoError(t, w.db.Raw("SELECT prosecdef FROM pg_proc WHERE oid = ?::regprocedure", secretNodeCacheEpochFunc+"()").Scan(&def).Error)
	require.False(t, def)
}

func TestSecretNodeCacheEpochIntegrity_DisableWriteEnableInOneTransactionIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("ALTER TABLE secret_nodes DISABLE TRIGGER " + SecretNodeCacheEpochTrigger).Error; err != nil {
			return err
		}
		w.suspendDirect(t, tx)
		return tx.Exec("ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER " + SecretNodeCacheEpochTrigger).Error
	}))
	st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the definition reads exactly as before")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_ReplaceThenRestoreIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec(noopEpochBody).Error)
	w.suspendDirect(t, w.db)
	require.NoError(t, w.db.Exec(restoreEpochFunc).Error)
	st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the original definition is back")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_TriggerRecreatedAfterOrWithWhenIsRestored_Postgres(t *testing.T) {
	for name, create := range map[string]string{
		"after":    "CREATE TRIGGER " + SecretNodeCacheEpochTrigger + " AFTER UPDATE ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()",
		"when":     "CREATE TRIGGER " + SecretNodeCacheEpochTrigger + " BEFORE UPDATE ON secret_nodes FOR EACH ROW WHEN (OLD.status = NEW.status) EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()",
		"of-names": "CREATE TRIGGER " + SecretNodeCacheEpochTrigger + " BEFORE UPDATE OF name ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()",
	} {
		t.Run(name, func(t *testing.T) {
			w := newEpochIntegrityWorld(t)
			require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
				for _, q := range []string{
					"DROP TRIGGER " + SecretNodeCacheEpochTrigger + " ON secret_nodes",
					create,
					"ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER " + SecretNodeCacheEpochTrigger,
				} {
					if err := tx.Exec(q).Error; err != nil {
						return err
					}
				}
				return nil
			}))
			st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
			require.NoError(t, err)
			require.NotEmpty(t, st.problem, "the check reports the re-created trigger")
			w.suspendDirect(t, w.db)
			requireEpochStaleThenFlushed(t, w)
		})
	}
}

// TestSecretNodeCacheEpochIntegrity_CleanTicksAndReplicaBootsDoNotFlush is the
// other direction: in-app writes, another replica's boot (the installer on an
// already correct schema) and repeated ticks are not tampering.
func TestSecretNodeCacheEpochIntegrity_CleanTicksAndReplicaBootsDoNotFlush_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db))
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db))
	w.suspendDirect(t, w.db)
	require.Equal(t, "suspended", w.status(t), "an ordinary direct write is seen through the trigger, no tick needed")
	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	for range 3 {
		flushed, err := w.checker.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushed)
	}
	require.Equal(t, before, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
}

// TestSecretNodeCacheEpochIntegrity_FailedRepairIsRetriedNotAdopted: a repair
// that cannot run (secret_nodes locked) stays pending, and a body restored
// before the next tick, without a bump, still flushes.
func TestSecretNodeCacheEpochIntegrity_FailedRepairIsRetriedNotAdopted_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec(noopEpochBody).Error)
	w.suspendDirect(t, w.db)

	lock := w.db.Begin()
	require.NoError(t, lock.Error)
	require.NoError(t, lock.Exec("LOCK TABLE secret_nodes IN EXCLUSIVE MODE").Error)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	flushed, err := w.checker.check(ctx)
	cancel()
	require.NoError(t, lock.Rollback().Error)
	require.Error(t, err, "premise: the invalidation could not commit")
	require.False(t, flushed)

	require.NoError(t, w.db.Exec(restoreEpochFunc).Error)
	st, err := readSecretNodeCacheEpochIntegrity(context.Background(), w.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the definition reads as this release's again")
	requireEpochStaleThenFlushed(t, w)
}

// TestSecretNodeCacheEpochIntegrity_BackgroundJobFlushesAndStopsOnClose drives
// the job the factory starts, not one tick by hand.
func TestSecretNodeCacheEpochIntegrity_BackgroundJobFlushesAndStopsOnClose_Postgres(t *testing.T) {
	old := rolePermGenerationIntegrityInterval
	rolePermGenerationIntegrityInterval = 50 * time.Millisecond
	t.Cleanup(func() { rolePermGenerationIntegrityInterval = old })
	db, ls, created := cacheEpochReplicaWorld(t)
	ls.StartRolePermissionsGenerationIntegrityCheck(t.Logf)
	time.Sleep(3 * rolePermGenerationIntegrityInterval) // the first tick records the baseline
	require.NoError(t, db.Exec(noopEpochBody).Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", created.ID).Error)
	require.Eventually(t, func() bool {
		got, err := ls.GetSecret(context.Background(), created.ID)
		return err == nil && got.Status == "suspended"
	}, 10*time.Second, 20*time.Millisecond, "the background job must flush the stale row")
	done := make(chan error, 1)
	go func() { done <- ls.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not stop the integrity job")
	}
}
