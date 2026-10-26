// role_permission_generation_integrity_postgres_test.go — TRIGGER-ROWDIGEST-1
// (docs/design/trigger-rowdigest.md): the owner of the generation function
// (the server's own database role, not a superuser) can change what the
// triggers do while the per-statement proof still passes. Each test makes one
// such change on the writer's connection, shows the warm reader keeps
// answering from its cache (the gap), then runs one integrity tick on the
// writer (another replica) and expects the reader's next decision to come
// from the live join.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// rpgIntegrityWorld is a Postgres rpgWorld, warm, with a checker on the
// writer whose first tick has recorded the baseline.
func rpgIntegrityWorld(t *testing.T) (rpgWorld, *triggerIntegrityChecker) {
	t.Helper()
	w := rpgPostgresWorld(t)
	var super bool
	require.NoError(t, w.writer.db.Raw("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super).Error)
	t.Logf("tampering as a role with rolsuper=%v", super)
	c := &triggerIntegrityChecker{ls: w.writer, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a fresh install is clean: the first tick only records the baseline")
	require.True(t, w.decide(t, w.perm.Name), "warm")
	return w, c
}

// requireStaleThenFlushed asserts the gap (the proof still passes and the
// warm cache still authorizes the revoked permission), then that one tick
// flushes it.
func requireStaleThenFlushed(t *testing.T, w rpgWorld, c *triggerIntegrityChecker) {
	t.Helper()
	require.True(t, RolePermissionsGenerationTriggersPresent(w.ls.db), "premise: the per-statement proof still passes")
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen and the warm cache still authorizes")
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the tick must see the change")
	require.Greater(t, testutil.ToFloat64(rolePermGenerationTamperTotal), before, "and count it")
	require.False(t, w.decide(t, w.perm.Name), "after the tick the reader answers from the live join")
	st, err := readRolePermGenerationIntegrity(context.Background(), w.writer.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the definition is this release's again")
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a repaired state is the new baseline, not a second alarm")
}

func TestRolePermGenerationIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)

	// The restored body bumps again: a direct re-grant is seen without a tick.
	require.NoError(t, db.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", w.role.ID, w.perm.ID).Error)
	require.True(t, w.decide(t, w.perm.Name))
}

func TestRolePermGenerationIntegrity_DisableWriteEnableInOneTransactionIsFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	require.NoError(t, w.writer.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("ALTER TABLE role_permissions DISABLE TRIGGER " + RolePermissionsGenerationTrigger).Error; err != nil {
			return err
		}
		revokeDirect(t, tx, w)
		return tx.Exec("ALTER TABLE role_permissions ENABLE ALWAYS TRIGGER " + RolePermissionsGenerationTrigger).Error
	}))
	st, err := readRolePermGenerationIntegrity(context.Background(), w.writer.db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the definition reads exactly as before")
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_ReplaceThenRestoreIsFlushed_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, db, w)
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql "+pgTriggerFuncSetClause+" AS $keyorix$"+postgresRolePermGenerationFuncBody+"$keyorix$").Error)
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Empty(t, st.problem, "premise: the original body is back")
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_TriggerRecreatedOnFewerEventsIsRestored_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	require.NoError(t, w.writer.db.Transaction(func(tx *gorm.DB) error {
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
	revokeDirect(t, w.writer.db, w)
	requireStaleThenFlushed(t, w, c)
}

func TestRolePermGenerationIntegrity_FunctionSettingsAreRestored_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("ALTER FUNCTION "+rolePermGenerationFunc+"() SET search_path = public").Error)
	require.NoError(t, db.Exec("ALTER FUNCTION "+rolePermGenerationFunc+"() SECURITY DEFINER").Error)
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.NotEmpty(t, st.problem)
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	var cfg []struct {
		Proconfig *string
		Prosecdef bool
	}
	require.NoError(t, db.Raw("SELECT proconfig::text AS proconfig, prosecdef FROM pg_proc WHERE oid = ?::regprocedure", rolePermGenerationFunc+"()").Scan(&cfg).Error)
	require.Len(t, cfg, 1)
	require.NotNil(t, cfg[0].Proconfig)
	require.Equal(t, `{"search_path=pg_catalog, pg_temp"}`, *cfg[0].Proconfig, "CREATE OR REPLACE resets the per-function settings to the pinned search_path alone")
	require.False(t, cfg[0].Prosecdef)
}

// TestRolePermGenerationIntegrity_CleanTicksAndReplicaBootsDoNotFlush is the
// other direction: in-app writes, another replica's boot (the installer on an
// already correct schema) and repeated ticks are not tampering, and must not
// flush every cache.
func TestRolePermGenerationIntegrity_CleanTicksAndReplicaBootsDoNotFlush_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	ctx := context.Background()
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(w.writer.db))
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(w.ls.db))
	require.NoError(t, w.writer.RemovePermissionFromRole(ctx, w.role.ID, w.perm.ID))
	require.NoError(t, w.writer.AssignPermissionToRole(ctx, w.role.ID, w.perm.ID))
	require.NoError(t, w.writer.db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", w.role.ID, w.perm.ID).Error)
	require.False(t, w.decide(t, w.perm.Name), "an ordinary direct write is seen through the trigger, no tick needed")
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	for range 3 {
		flushed, err := c.check(ctx)
		require.NoError(t, err)
		require.False(t, flushed)
	}
	require.Equal(t, before, testutil.ToFloat64(rolePermGenerationTamperTotal))
}

// TestRolePermGenerationIntegrity_BackgroundJobFlushesAndStopsOnClose drives
// the job the factory starts, not one tick by hand.
func TestRolePermGenerationIntegrity_BackgroundJobFlushesAndStopsOnClose_Postgres(t *testing.T) {
	old := rolePermGenerationIntegrityInterval
	rolePermGenerationIntegrityInterval = 50 * time.Millisecond
	t.Cleanup(func() { rolePermGenerationIntegrityInterval = old })
	w := rpgPostgresWorld(t)
	require.True(t, w.decide(t, w.perm.Name), "warm")
	w.writer.StartTriggerIntegrityCheck(t.Logf)
	time.Sleep(3 * rolePermGenerationIntegrityInterval) // the first tick records the baseline
	require.NoError(t, w.writer.db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, w.writer.db, w)
	require.Eventually(t, func() bool {
		ok, err := w.ls.RoleSetHasPermission(context.Background(), []uint{w.role.ID}, w.perm.Name)
		return err == nil && !ok
	}, 10*time.Second, 20*time.Millisecond, "the background job must flush the stale decision")
	done := make(chan error, 1)
	go func() { done <- w.writer.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not stop the integrity job")
	}
}
