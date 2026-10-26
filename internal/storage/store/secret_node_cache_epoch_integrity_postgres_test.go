// secret_node_cache_epoch_integrity_postgres_test.go — STARTUP-GUARD-TAILS-1
// item 2: the periodic trigger integrity check covers the secret_nodes
// cache-epoch trigger and function, which have the same owner-level exposure
// as the role-permission generation triggers (docs/design/trigger-rowdigest.md,
// "Findings"). Each test makes one change as the server's own role, shows a
// warm reader keeps serving the pre-change row (the gap), then runs one tick
// on another store (another replica) and expects the reader's next read to be
// live.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type epochIntegrityWorld struct {
	db      *gorm.DB
	reader  *LocalStorage // warm
	created *models.SecretNode
	c       *triggerIntegrityChecker // on another store
}

func newEpochIntegrityWorld(t *testing.T) epochIntegrityWorld {
	t.Helper()
	db, reader, created := cacheEpochReplicaWorld(t)
	c := &triggerIntegrityChecker{ls: NewLocalStorage(db), logf: t.Logf, target: secretNodeCacheEpochIntegrityTarget}
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a fresh install is clean: the first tick only records the baseline")
	return epochIntegrityWorld{db: db, reader: reader, created: created, c: c}
}

func (w epochIntegrityWorld) status(t *testing.T) string {
	t.Helper()
	got, err := w.reader.GetSecret(context.Background(), w.created.ID)
	require.NoError(t, err)
	return got.Status
}

func (w epochIntegrityWorld) setStatusDirect(t *testing.T, db *gorm.DB, status string) {
	t.Helper()
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = ? WHERE id = ?", status, w.created.ID).Error)
}

// requireEpochStaleThenFlushed asserts the gap (the proof passes and the warm
// entry still reads "active" after a direct suspend), then that one tick
// flushes it, repairs the definition and records the repaired state as the
// new baseline.
func requireEpochStaleThenFlushed(t *testing.T, w epochIntegrityWorld) {
	t.Helper()
	require.True(t, SecretNodeCacheEpochTriggerPresent(w.db), "premise: the per-statement proof passes")
	require.Equal(t, "active", w.status(t), "premise: the suspend went unstamped and the warm entry is served")
	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	flushed, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the tick must see the change")
	require.Greater(t, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), before, "and count it")
	require.Equal(t, "suspended", w.status(t), "after the tick the reader reads the live row")
	st, err := readTriggerIntegrity(context.Background(), w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the definition is this release's again")
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a repaired state is the new baseline, not a second alarm")
	w.setStatusDirect(t, w.db, "active")
	require.Equal(t, "active", w.status(t), "the restored trigger stamps a direct write without a tick")
}

func TestSecretNodeCacheEpochIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("CREATE OR REPLACE FUNCTION "+secretNodeCacheEpochFunc+"() RETURNS trigger LANGUAGE plpgsql "+pgTriggerFuncSetClause+" AS $x$BEGIN NEW.cache_epoch := OLD.cache_epoch; RETURN NEW; END;$x$").Error)
	w.setStatusDirect(t, w.db, "suspended")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_ReplaceThenRestoreIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("CREATE OR REPLACE FUNCTION "+secretNodeCacheEpochFunc+"() RETURNS trigger LANGUAGE plpgsql "+pgTriggerFuncSetClause+" AS $x$BEGIN NEW.cache_epoch := OLD.cache_epoch; RETURN NEW; END;$x$").Error)
	w.setStatusDirect(t, w.db, "suspended")
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "the original body is back (another replica boots)")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_DisabledTriggerReenabledByBootIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("ALTER TABLE secret_nodes DISABLE TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	require.False(t, SecretNodeCacheEpochTriggerPresent(w.db), "premise: the proof fails closed while the trigger is disabled")
	w.setStatusDirect(t, w.db, "suspended")
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "another replica boots")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_ReplicaTriggerConvergedByBootIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("ALTER TABLE secret_nodes ENABLE REPLICA TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	st, err := readTriggerIntegrity(context.Background(), w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Contains(t, st.problem, "is not ENABLE ALWAYS")
	w.setStatusDirect(t, w.db, "suspended")
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "another replica boots")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_DroppedFunctionReinstalledByBootIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("DROP FUNCTION "+secretNodeCacheEpochFunc+"() CASCADE").Error)
	w.setStatusDirect(t, w.db, "suspended")
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "another replica boots")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_DroppedFunctionIsRestoredByTheTick_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("DROP FUNCTION "+secretNodeCacheEpochFunc+"() CASCADE").Error)
	st, err := readTriggerIntegrity(context.Background(), w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Contains(t, st.problem, "0 of 1 triggers present")
	flushed, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.True(t, SecretNodeCacheEpochTriggerPresent(w.db), "the tick re-installs function and trigger")
	w.setStatusDirect(t, w.db, "suspended")
	require.Equal(t, "suspended", w.status(t))
}

func TestSecretNodeCacheEpochIntegrity_DisableWriteEnableInOneTransactionIsFlushed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("ALTER TABLE secret_nodes DISABLE TRIGGER " + SecretNodeCacheEpochTrigger).Error; err != nil {
			return err
		}
		w.setStatusDirect(t, tx, "suspended")
		return tx.Exec("ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER " + SecretNodeCacheEpochTrigger).Error
	}))
	st, err := readTriggerIntegrity(context.Background(), w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the definition reads exactly as before")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_TriggerRecreatedAsAfterIsRestored_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Transaction(func(tx *gorm.DB) error {
		for _, q := range []string{
			"DROP TRIGGER " + SecretNodeCacheEpochTrigger + " ON secret_nodes",
			"CREATE TRIGGER " + SecretNodeCacheEpochTrigger + " AFTER UPDATE ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()",
			"ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER " + SecretNodeCacheEpochTrigger,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}))
	w.setStatusDirect(t, w.db, "suspended")
	requireEpochStaleThenFlushed(t, w)
}

// TestSecretNodeCacheEpochIntegrity_FailedRepairIsRetriedNotAdopted_Postgres:
// with a bad definition the invalidation runs only after the repair (it goes
// through the trigger). A repair that cannot get its lock must leave the
// checker pending, and the next tick must still flush once it can, even if
// the body was restored in between.
func TestSecretNodeCacheEpochIntegrity_FailedRepairIsRetriedNotAdopted_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, w.db.Exec("CREATE OR REPLACE FUNCTION "+secretNodeCacheEpochFunc+"() RETURNS trigger LANGUAGE plpgsql "+pgTriggerFuncSetClause+" AS $x$BEGIN NEW.cache_epoch := OLD.cache_epoch; RETURN NEW; END;$x$").Error)
	w.setStatusDirect(t, w.db, "suspended")

	lock := w.db.Begin()
	require.NoError(t, lock.Error)
	require.NoError(t, lock.Exec("SELECT id FROM secret_nodes WHERE id = ? FOR UPDATE", w.created.ID).Error)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	flushed, err := w.c.check(ctx)
	cancel()
	require.NoError(t, lock.Rollback().Error)
	require.Error(t, err, "premise: the repair's invalidation cannot lock the row")
	require.False(t, flushed)

	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "the body is restored without a bump")
	requireEpochStaleThenFlushed(t, w)
}

func TestSecretNodeCacheEpochIntegrity_CleanTicksAndReplicaBootsDoNotFlush_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db))
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.c.ls.db))
	w.setStatusDirect(t, w.db, "suspended")
	require.Equal(t, "suspended", w.status(t), "an ordinary direct write is stamped by the trigger, no tick needed")
	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	for range 3 {
		flushed, err := w.c.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushed)
	}
	require.Equal(t, before, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
}

// TestSecretNodeCacheEpochIntegrity_BackgroundJobFlushes_Postgres drives the
// job the factory starts, not one tick by hand.
func TestSecretNodeCacheEpochIntegrity_BackgroundJobFlushes_Postgres(t *testing.T) {
	old := rolePermGenerationIntegrityInterval
	rolePermGenerationIntegrityInterval = 50 * time.Millisecond
	t.Cleanup(func() { rolePermGenerationIntegrityInterval = old })
	db, reader, created := cacheEpochReplicaWorld(t)
	job := NewLocalStorage(db)
	job.StartTriggerIntegrityCheck(t.Logf)
	time.Sleep(3 * rolePermGenerationIntegrityInterval) // the first tick records the baseline
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+secretNodeCacheEpochFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NEW; END;$x$").Error)
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", created.ID).Error)
	require.Eventually(t, func() bool {
		got, err := reader.GetSecret(context.Background(), created.ID)
		return err == nil && got.Status == "suspended"
	}, 10*time.Second, 20*time.Millisecond, "the background job must flush the stale row")
	done := make(chan error, 1)
	go func() { done <- job.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not stop the integrity job")
	}
}
