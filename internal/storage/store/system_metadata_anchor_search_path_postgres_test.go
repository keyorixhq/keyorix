// system_metadata_anchor_search_path_postgres_test.go — TRIGGER-INTEGRITY-1
// review fix (REVIEW-3841-DEEP-3 B2): the write-target check compares the
// retention-anchor trigger's WHEN clause as pg_get_triggerdef deparses it,
// and that text depends on the reading session's search_path. The server's
// role can create an `=` on (text, text) in its own schema, re-create the
// anchor trigger with the installer's text under a search_path that lists
// that schema before pg_catalog, and give its own role that search_path
// (ALTER ROLE <self> SET search_path). The clause then deparses exactly as
// installed on every connection of the server while it calls the role's
// operator, which also lets the generation row through to an anchor function
// that keeps OLD.value: every generation bump is a no-op, the check's own
// invalidation included. The reading and the repair must resolve operators
// in pg_catalog first, whatever the session's search_path.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// plantShadowedAnchorOperator creates in w's schema an `=` on (text, text)
// that is texteq except that 'role_permissions_generation' also equals
// 'audit_retention_anchor', makes the anchor function keep OLD.value for the
// generation row, and re-creates the anchor trigger with the installer's
// WHEN text under a search_path listing the schema before pg_catalog. It
// returns a pool whose connections have that search_path, as an
// ALTER ROLE <self> SET search_path would give every connection of the
// server's role.
func plantShadowedAnchorOperator(t *testing.T, w rpgWorld) *gorm.DB {
	t.Helper()
	db := w.writer.db
	var schema string
	require.NoError(t, db.Raw("SELECT current_schema()").Scan(&schema).Error)
	require.NoError(t, db.Exec(`CREATE OR REPLACE FUNCTION `+auditRetentionAnchorFunc+`() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF OLD.key OPERATOR(pg_catalog.=) 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`).Error)
	require.NoError(t, db.Exec(`CREATE FUNCTION `+schema+`.keq(a text, b text) RETURNS boolean LANGUAGE sql IMMUTABLE AS
$x$ SELECT pg_catalog.texteq(a, b) OR (pg_catalog.texteq(a, 'role_permissions_generation') AND pg_catalog.texteq(b, 'audit_retention_anchor')) $x$`).Error)
	require.NoError(t, db.Exec(`CREATE OPERATOR `+schema+`.= (LEFTARG = text, RIGHTARG = text, FUNCTION = `+schema+`.keq)`).Error)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL search_path = " + schema + ", pg_catalog").Error; err != nil {
			return err
		}
		if err := tx.Exec("DROP TRIGGER " + AuditRetentionAnchorTrigger + " ON system_metadata").Error; err != nil {
			return err
		}
		if err := tx.Exec("CREATE TRIGGER " + AuditRetentionAnchorTrigger + " BEFORE UPDATE ON system_metadata FOR EACH ROW WHEN (OLD.key = 'audit_retention_anchor') EXECUTE PROCEDURE " + auditRetentionAnchorFunc + "()").Error; err != nil {
			return err
		}
		return tx.Exec("ALTER TABLE system_metadata ENABLE ALWAYS TRIGGER " + AuditRetentionAnchorTrigger).Error
	}))
	shadow := pgOpen(t, pgdsn.PGSearchPathDSN(pgTestDSN(t), schema+",pg_catalog"))
	var def string
	require.NoError(t, shadow.Raw("SELECT pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = 'system_metadata'::regclass AND t.tgname OPERATOR(pg_catalog.=) ?", AuditRetentionAnchorTrigger).Scan(&def).Error)
	require.Contains(t, def, "WHEN ((old.key = 'audit_retention_anchor'::text))", "premise: on the shadowed search_path the clause deparses as installed")
	return shadow
}

// requireAnchorWhenCallsCatalogOperator: on the shadowed search_path,
// pg_catalog's `=` is the one that deparses qualified.
func requireAnchorWhenCallsCatalogOperator(t *testing.T, shadow *gorm.DB) {
	t.Helper()
	var def string
	require.NoError(t, shadow.Raw("SELECT pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t WHERE t.tgrelid = 'system_metadata'::regclass AND t.tgname OPERATOR(pg_catalog.=) ?", AuditRetentionAnchorTrigger).Scan(&def).Error)
	require.Contains(t, def, "OPERATOR(pg_catalog.=)", "the re-created anchor trigger calls pg_catalog's operator, not the role's")
}

// A checker that boots on the shadowed search_path must not adopt the state.
func TestRolePermGenerationIntegrity_SystemMetadataAnchorShadowedOperatorSeenAtBoot_Postgres(t *testing.T) {
	w, _ := smWriteTargetWorld(t)
	shadow := plantShadowedAnchorOperator(t, w)
	c := &triggerIntegrityChecker{ls: &LocalStorage{db: shadow}, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	revokeDirect(t, w.writer.db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, w.writer.db)
	requireAnchorTriggerAsInstalled(t, w)
	requireAnchorWhenCallsCatalogOperator(t, shadow)
}

// A running checker on the shadowed search_path sees the trigger's new row
// version; its flush must not be a bump the planted trigger swallows.
func TestRolePermGenerationIntegrity_SystemMetadataAnchorShadowedOperatorIsRemovedAndFlushed_Postgres(t *testing.T) {
	w, _ := smWriteTargetWorld(t)
	var schema string
	require.NoError(t, w.writer.db.Raw("SELECT current_schema()").Scan(&schema).Error)
	shadowBefore := pgOpen(t, pgdsn.PGSearchPathDSN(pgTestDSN(t), schema+",pg_catalog"))
	c := &triggerIntegrityChecker{ls: &LocalStorage{db: shadowBefore}, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "premise: a clean install reads clean on the shadowed search_path too")
	plantShadowedAnchorOperator(t, w)
	revokeDirect(t, w.writer.db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, w.writer.db)
	requireAnchorTriggerAsInstalled(t, w)
	requireAnchorWhenCallsCatalogOperator(t, shadowBefore)
}

// The installers' reading sees it too, and leaves the transaction's
// search_path as it found it.
func TestRolePermGenerationIntegrity_InstallerReadingIgnoresShadowedSearchPath_Postgres(t *testing.T) {
	w, _ := smWriteTargetWorld(t)
	db := w.writer.db
	plantShadowedAnchorOperator(t, w)
	var schema string
	require.NoError(t, db.Raw("SELECT current_schema()").Scan(&schema).Error)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		require.NoError(t, tx.Exec("SET LOCAL search_path = "+schema+", pg_catalog").Error)
		var before, after string
		require.NoError(t, tx.Raw("SELECT pg_catalog.current_setting('search_path')").Scan(&before).Error)
		st, err := readInstalledTriggerDef(tx, rolePermGenerationDef)
		require.NoError(t, err)
		require.Contains(t, st.problem, "system_metadata has triggers other than the retention-anchor one")
		require.NoError(t, tx.Raw("SELECT pg_catalog.current_setting('search_path')").Scan(&after).Error)
		require.Equal(t, before, after, "the installer's transaction keeps its search_path")
		return nil
	}))
}
