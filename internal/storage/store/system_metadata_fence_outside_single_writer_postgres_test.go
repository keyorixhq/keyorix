// system_metadata_fence_outside_single_writer_postgres_test.go — PR #3841
// review F1: the write-target check allowed a trigger on system_metadata named
// like the single_writer fence's, AFTER, executing the fence's guard function
// with its exact body, without checking what that body calls
// (<schema>.keyorix_sole_writer_check(text)). Outside single_writer mode no
// fence exists and nothing else checks that callee, so the server's own role
// could plant a callee that pins the generation row back and every bump, the
// check's own included, became a no-op (#3713). Outside single_writer mode a
// fence-named trigger is foreign like any other.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// plantFenceShapedGenerationPin installs, as the server's own role can, a
// fence-shaped AFTER UPDATE trigger on system_metadata over the fence's exact
// guard body, whose callee puts the generation row back to its current value.
// It returns the trigger's name.
func plantFenceShapedGenerationPin(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var gen string
	require.NoError(t, db.Raw("SELECT value FROM system_metadata WHERE key = ?", rolePermissionsGenerationKey).Scan(&gen).Error)
	name := SoleWriterFenceTriggerPrefix + "pin"
	for _, q := range []string{
		"CREATE TABLE keyorix_write_epoch (id int PRIMARY KEY, n bigint)",
		"INSERT INTO keyorix_write_epoch VALUES (1, 0)",
		`CREATE FUNCTION keyorix_sole_writer_check(sch text) RETURNS void LANGUAGE plpgsql AS $x$
BEGIN
  EXECUTE pg_catalog.format('UPDATE %I.system_metadata SET value = ''` + gen + `'' WHERE key = ''` + rolePermissionsGenerationKey + `'' AND value <> ''` + gen + `''', sch);
END;$x$`,
		"CREATE FUNCTION " + SoleWriterGuardFunc + "() RETURNS trigger LANGUAGE plpgsql AS $keyorix$" + SoleWriterGuardFuncBody + "$keyorix$",
		"CREATE TRIGGER " + name + " AFTER UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE " + SoleWriterGuardFunc + "()",
	} {
		require.NoError(t, db.Exec(q).Error, q)
	}
	return name
}

func TestRolePermGenerationIntegrity_SystemMetadataFenceShapedTriggerOutsideSingleWriterIsRemovedAndFlushed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	name := plantFenceShapedGenerationPin(t, db)
	st, err := readRolePermGenerationIntegrity(context.Background(), db)
	require.NoError(t, err)
	require.Contains(t, st.problem, name, "outside single_writer mode a fence-named trigger is foreign")
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, db)
}

// A replica that boots after the trigger was planted has no baseline to
// compare with: the reading itself must name it.
func TestRolePermGenerationIntegrity_SystemMetadataFenceShapedTriggerOutsideSingleWriterSeenAtBoot_Postgres(t *testing.T) {
	w, _ := smWriteTargetWorld(t)
	db := w.writer.db
	plantFenceShapedGenerationPin(t, db)
	revokeDirect(t, db, w)
	booted := &triggerIntegrityChecker{ls: w.writer, logf: t.Logf, target: rolePermGenerationIntegrityTarget}
	requireStaleThenFlushed(t, w, booted)
	requireSystemMetadataClean(t, db)
}
