// system_metadata_write_target_postgres_test.go — TRIGGER-INTEGRITY-1 item 2
// (#3713): the generation triggers and every invalidation, the integrity
// check's own included, UPDATE system_metadata. The owner of that table (the
// server's own database role) can make the UPDATE a no-op there while every
// trigger and function the check compares still reads as correct: a BEFORE
// UPDATE trigger that keeps OLD.value, a rule, or forced row level security
// that hides the row. Each test makes one such change, shows a direct revoke
// then goes unseen by the warm cache, and expects one tick on another replica
// to remove it and flush.
package store

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// smWriteTargetWorld is rpgIntegrityWorld with the audit retention-anchor
// trigger installed on system_metadata, as every PostgreSQL migration does:
// the one trigger that table may carry.
func smWriteTargetWorld(t *testing.T) (rpgWorld, *triggerIntegrityChecker) {
	t.Helper()
	w := rpgPostgresWorld(t)
	require.NoError(t, EnsureAuditRetentionAnchorTrigger(w.writer.db))
	c := &triggerIntegrityChecker{ls: w.writer, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "a fresh install with the anchor trigger is clean")
	require.True(t, w.decide(t, w.perm.Name), "warm")
	return w, c
}

// systemMetadataObjects names the non-internal triggers and the rules on
// system_metadata, and its row level security flags.
func systemMetadataObjects(t *testing.T, db *gorm.DB) (triggers, rules []string, rls, force bool) {
	t.Helper()
	require.NoError(t, db.Raw("SELECT tgname::text FROM pg_trigger WHERE tgrelid = 'system_metadata'::regclass AND NOT tgisinternal ORDER BY 1").Scan(&triggers).Error)
	require.NoError(t, db.Raw("SELECT rulename::text FROM pg_rewrite WHERE ev_class = 'system_metadata'::regclass ORDER BY 1").Scan(&rules).Error)
	var flags []struct{ Rls, Force bool }
	require.NoError(t, db.Raw("SELECT relrowsecurity AS rls, relforcerowsecurity AS force FROM pg_class WHERE oid = 'system_metadata'::regclass").Scan(&flags).Error)
	require.Len(t, flags, 1)
	return triggers, rules, flags[0].Rls, flags[0].Force
}

func requireSystemMetadataClean(t *testing.T, db *gorm.DB) {
	t.Helper()
	triggers, rules, rls, force := systemMetadataObjects(t, db)
	require.Equal(t, []string{AuditRetentionAnchorTrigger}, triggers, "only the retention-anchor trigger is left")
	require.Empty(t, rules)
	require.False(t, rls)
	require.False(t, force)
}

func TestRolePermGenerationIntegrity_SystemMetadataBeforeUpdateTriggerIsRemovedAndFlushed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec(`CREATE FUNCTION keep_generation() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key = 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`).Error)
	require.NoError(t, db.Exec("CREATE TRIGGER keep_generation BEFORE UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE keep_generation()").Error)
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, db)
}

// A rule is the loud variant: PostgreSQL refuses INSERT ... ON CONFLICT, the
// first statement of every bump (the triggers' and the check's own), on a
// table with an INSERT or UPDATE rule. Every role-permission write then fails
// instead of going unseen, and so does the check's invalidation; the tick must
// still remove the rule rather than stop at that error.
func TestRolePermGenerationIntegrity_SystemMetadataRuleIsRemovedAndFlushed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("CREATE RULE keep_generation AS ON UPDATE TO system_metadata WHERE OLD.key = 'role_permissions_generation' DO INSTEAD NOTHING").Error)
	require.Error(t, db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", w.role.ID, w.perm.ID).Error,
		"premise: with the rule in place the generation trigger's bump fails, and the revoke with it")
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.Greater(t, testutil.ToFloat64(rolePermGenerationTamperTotal), before)
	requireSystemMetadataClean(t, db)
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "the repaired state is the new baseline")
	revokeDirect(t, db, w)
	require.False(t, w.decide(t, w.perm.Name), "with the rule gone a direct revoke bumps again")
}

// The policies keep every statement but the generation row's UPDATE working,
// so the revoke itself succeeds and nothing fails loudly.
func TestRolePermGenerationIntegrity_SystemMetadataForcedRowSecurityIsTurnedOffAndFlushed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	for _, q := range []string{
		"CREATE POLICY sm_read ON system_metadata FOR SELECT USING (true)",
		"CREATE POLICY sm_insert ON system_metadata FOR INSERT WITH CHECK (true)",
		"CREATE POLICY sm_update ON system_metadata FOR UPDATE USING (key <> 'role_permissions_generation')",
		"ALTER TABLE system_metadata ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE system_metadata FORCE ROW LEVEL SECURITY",
	} {
		require.NoError(t, db.Exec(q).Error, q)
	}
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, db)
}

// The retention-anchor trigger is allowed only as its installer creates it:
// re-created without its WHEN clause, over a function that keeps the
// generation, it is the BEFORE UPDATE route under the allowed name.
func TestRolePermGenerationIntegrity_SystemMetadataAnchorTriggerWithoutItsWhenIsRestored_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		for _, q := range []string{
			`CREATE OR REPLACE FUNCTION ` + auditRetentionAnchorFunc + `() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key = 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`,
			"DROP TRIGGER " + AuditRetentionAnchorTrigger + " ON system_metadata",
			"CREATE TRIGGER " + AuditRetentionAnchorTrigger + " BEFORE UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE " + auditRetentionAnchorFunc + "()",
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}))
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, db)
	var when []string
	require.NoError(t, db.Raw("SELECT pg_get_expr(tgqual, tgrelid) FROM pg_trigger WHERE tgrelid = 'system_metadata'::regclass AND tgname = ?", AuditRetentionAnchorTrigger).Scan(&when).Error)
	require.Equal(t, []string{"(key = 'audit_retention_anchor'::text)"}, when, "the anchor trigger is re-created as its installer creates it")
}

// TestRolePermGenerationIntegrity_SystemMetadataUpkeepDoesNotFlush_Postgres is
// the other direction: the retention-anchor installer re-run by other
// replicas' boots (it rewrites its function every time), ANALYZE, VACUUM and
// in-app bumps change nothing the write-target check reads.
func TestRolePermGenerationIntegrity_SystemMetadataUpkeepDoesNotFlush_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, EnsureAuditRetentionAnchorTrigger(db))
	require.NoError(t, EnsureAuditRetentionAnchorTrigger(w.ls.db))
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	require.NoError(t, db.Exec("ANALYZE system_metadata").Error)
	require.NoError(t, db.Exec("VACUUM system_metadata").Error)
	ctx := context.Background()
	require.NoError(t, w.writer.RemovePermissionFromRole(ctx, w.role.ID, w.perm.ID))
	require.NoError(t, w.writer.AssignPermissionToRole(ctx, w.role.ID, w.perm.ID))
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	for range 3 {
		flushed, err := c.check(ctx)
		require.NoError(t, err)
		require.False(t, flushed)
	}
	require.Equal(t, before, testutil.ToFloat64(rolePermGenerationTamperTotal))
}
