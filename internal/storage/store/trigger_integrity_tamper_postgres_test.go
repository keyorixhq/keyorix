// trigger_integrity_tamper_postgres_test.go — STARTUP-GUARD-TAILS-1 item 2:
// the tampers the periodic trigger integrity check
// (role_permission_generation_integrity.go) must answer, named one by one for
// the role-permission generation triggers (disabled, ENABLE REPLICA, dropped
// function, a session not in 'origin'), and the cache-epoch installer's half
// (it must not rewrite a correct function, and must re-create a same-named
// trigger of another shape), which the check depends on.
//
// A disabled or ENABLE REPLICA trigger and a dropped function already fail the
// per-statement proof closed while they last. The gap is what follows: the
// next boot of any replica converges the trigger back to ENABLE ALWAYS, the
// proof passes again, and a revocation made while it was off was never
// counted. Only the check's catalog row versions see it.
package store

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRolePermGenerationIntegrity_DisabledTriggerReenabledByBootIsFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("ALTER TABLE role_permissions DISABLE TRIGGER "+RolePermissionsGenerationTrigger).Error)
	revokeDirect(t, db, w)
	require.False(t, w.decide(t, w.perm.Name), "premise: the proof fails closed while the trigger is disabled")
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "another replica boots")
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_ReplicaTriggerConvergedByBootIsFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("ALTER TABLE role_permissions ENABLE REPLICA TRIGGER "+RolePermissionsGenerationTrigger).Error)
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Contains(t, st.problem, "is not ENABLE ALWAYS", "an ENABLE REPLICA trigger never fires for an origin session's write")
	revokeDirect(t, db, w)
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "another replica boots")
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_ReplicaTriggerIsRestoredByTheTick_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("ALTER TABLE role_permissions ENABLE REPLICA TRIGGER "+RolePermissionsGenerationTrigger).Error)
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.Equal(t, "A", rpgTgenabled(t, db), "the tick restores ENABLE ALWAYS")
	require.True(t, RolePermissionsGenerationTriggersPresent(w.ls.db))
}

func TestRolePermGenerationIntegrity_DroppedFunctionReinstalledByBootIsFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("DROP FUNCTION "+rolePermGenerationFunc+"() CASCADE").Error)
	revokeDirect(t, db, w)
	require.False(t, w.decide(t, w.perm.Name), "premise: the proof fails closed while the triggers are gone")
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "another replica boots")
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_DroppedFunctionIsRestoredByTheTick_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("DROP FUNCTION "+rolePermGenerationFunc+"() CASCADE").Error)
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Contains(t, st.problem, "0 of 2 triggers present")
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.True(t, RolePermissionsGenerationTriggersPresent(w.ls.db), "the tick re-installs function and triggers")
	revokeDirect(t, db, w)
	require.False(t, w.decide(t, w.perm.Name), "the restored triggers bump again")
}

// TestRolePermGenerationIntegrity_NonOriginSessionIsRejected_Postgres: the
// per-statement proof trusts nothing on a connection whose
// session_replication_role is not 'origin' (pgTriggerFiresForEveryWriter);
// the periodic check must not report such a session as clean either.
func TestRolePermGenerationIntegrity_NonOriginSessionIsRejected_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	sqlDB, err := w.writer.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // the check's reads and writes all run on the one session set below
	if err := w.writer.db.Exec("SET session_replication_role = replica").Error; err != nil {
		t.Skipf("pg-gated: this role may not SET session_replication_role (needs a superuser or GRANT SET): %v", err)
	}
	reset := func() { require.NoError(t, w.writer.db.Exec("RESET session_replication_role").Error) }
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	flushed, err := c.check(context.Background())
	require.ErrorContains(t, err, "session_replication_role", "a non-origin session cannot be repaired from here and must stay pending")
	require.True(t, flushed, "the generation is bumped anyway")
	require.Greater(t, testutil.ToFloat64(rolePermGenerationTamperTotal), before)
	reset()
	flushed, err = c.check(context.Background())
	require.NoError(t, err, "back in origin: the pending tick completes")
	require.True(t, flushed)
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed)
}

// cacheEpochFuncXmin is the pg_proc row version of the cache-epoch function.
func cacheEpochFuncXmin(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var s string
	require.NoError(t, db.Raw("SELECT xmin::text FROM pg_proc WHERE oid = ?::regprocedure", secretNodeCacheEpochFunc+"()").Scan(&s).Error)
	return s
}

// TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres: a
// boot on a correct schema must not rewrite the function's pg_proc row, or
// every replica boot would read as tampering to every other replica.
func TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres(t *testing.T) {
	db, _, _ := cacheEpochReplicaWorld(t)
	before := cacheEpochFuncXmin(t, db)
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	require.Equal(t, before, cacheEpochFuncXmin(t, db), "a correct function is left as it is")
}

// TestSecretNodeCacheEpoch_EnsureRestoresRecreatedTrigger_Postgres: a trigger
// of the right name as AFTER UPDATE passes the presence proof, but an AFTER
// trigger's NEW.cache_epoch assignment is discarded, so the stamp never
// moves; the next boot must re-create it.
func TestSecretNodeCacheEpoch_EnsureRestoresRecreatedTrigger_Postgres(t *testing.T) {
	db, ls, created := cacheEpochReplicaWorld(t)
	require.NoError(t, db.Exec("DROP TRIGGER "+SecretNodeCacheEpochTrigger+" ON secret_nodes").Error)
	require.NoError(t, db.Exec("CREATE TRIGGER "+SecretNodeCacheEpochTrigger+" AFTER UPDATE ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE "+secretNodeCacheEpochFunc+"()").Error)
	require.NoError(t, db.Exec("ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER "+SecretNodeCacheEpochTrigger).Error)
	require.True(t, SecretNodeCacheEpochTriggerPresent(db), "premise: the presence proof passes")
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	var tgtype int
	require.NoError(t, db.Raw("SELECT tgtype FROM pg_trigger WHERE tgrelid = 'secret_nodes'::regclass AND tgname = ?", SecretNodeCacheEpochTrigger).Scan(&tgtype).Error)
	require.Equal(t, 19, tgtype, "BEFORE UPDATE ... FOR EACH ROW")
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", created.ID).Error)
	got, err := ls.GetSecret(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "the re-created trigger stamps a direct write again")
}
