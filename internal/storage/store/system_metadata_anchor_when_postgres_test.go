// system_metadata_anchor_when_postgres_test.go — TRIGGER-INTEGRITY-1 review
// fix (REVIEW-3841-DEEP-2 N1): the write-target check must read the
// retention-anchor trigger's WHEN clause without an error for any clause the
// server's role can write. pg_get_expr(tgqual, tgrelid) cannot deparse a
// clause that references NEW ("expression contains variables of more than one
// relation"), and an error there failed the whole reading on every tick: no
// SECURITY line, no flush, no repair (#3713 open again, and #3631's restore of
// a replaced generation body blinded). And a reading that keeps failing for
// any reason fails closed.
package store

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// plantAnchorTriggerWhen re-creates the retention-anchor trigger, name and
// shape unchanged, with WHEN (when).
func plantAnchorTriggerWhen(t *testing.T, w rpgWorld, when string) {
	t.Helper()
	db := w.writer.db
	require.NoError(t, db.Exec("DROP TRIGGER "+AuditRetentionAnchorTrigger+" ON system_metadata").Error)
	require.NoError(t, db.Exec("CREATE TRIGGER "+AuditRetentionAnchorTrigger+" BEFORE UPDATE ON system_metadata FOR EACH ROW WHEN ("+when+") EXECUTE PROCEDURE "+auditRetentionAnchorFunc+"()").Error)
	require.NoError(t, db.Exec("ALTER TABLE system_metadata ENABLE ALWAYS TRIGGER "+AuditRetentionAnchorTrigger).Error)
}

func requireAnchorTriggerAsInstalled(t *testing.T, w rpgWorld) {
	t.Helper()
	var when []string
	require.NoError(t, w.writer.db.Raw("SELECT pg_get_expr(tgqual, tgrelid) FROM pg_trigger WHERE tgrelid = 'system_metadata'::regclass AND tgname = ?", AuditRetentionAnchorTrigger).Scan(&when).Error)
	require.Equal(t, []string{"(key = 'audit_retention_anchor'::text)"}, when, "the anchor trigger is re-created as its installer creates it")
}

// An anchor-named trigger whose WHEN clause also lets the generation row
// through, over an anchor function that keeps OLD.value for it: every bump is
// a no-op. One tick must restore the trigger and flush, and the boot
// installers must not fail on it.
func TestRolePermGenerationIntegrity_SystemMetadataAnchorTriggerWhenOnNewIsRestored_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec(`CREATE OR REPLACE FUNCTION `+auditRetentionAnchorFunc+`() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key = 'role_permissions_generation' THEN NEW.value := OLD.value; END IF;
  RETURN NEW;
END;$x$`).Error)
	plantAnchorTriggerWhen(t, w, "OLD.key = 'audit_retention_anchor' OR NEW.key = 'role_permissions_generation'")
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "the boot installer reads the same write target")
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	requireSystemMetadataClean(t, db)
	requireAnchorTriggerAsInstalled(t, w)
}

// The same planted trigger, harmless in itself (its clause matches only the
// anchor row), must not hide a replaced generation function: main restores
// that within one tick (#3631, _ReplacedBodyIsRestoredAndFlushed).
func TestRolePermGenerationIntegrity_ReplacedBodyBesideAnchorWhenOnNewIsRestored_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	plantAnchorTriggerWhen(t, w, "OLD.key = 'audit_retention_anchor' AND NEW.key = 'audit_retention_anchor'")
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, db, w)
	requireStaleThenFlushed(t, w, c)
	var body string
	require.NoError(t, db.Raw("SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure", rolePermGenerationFunc+"()").Scan(&body).Error)
	require.Equal(t, postgresRolePermGenerationFuncBody, body, "the generation function is restored")
	requireSystemMetadataClean(t, db)
	requireAnchorTriggerAsInstalled(t, w)
}

// Any reading that fails fails closed: the first failed tick invalidates, a
// second one in a row is also reported (SECURITY, counted as tamper), and
// once the reading works again the next tick restores what it hid. The
// failing reading here is a statement that always errors, standing in for
// whatever catalog state makes the real one fail.
func TestRolePermGenerationIntegrity_FailingReadingFailsClosed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	good := c.target
	failingDef := *good.def
	failingDef.sql = "SELECT pg_catalog.length($1::text || $2::text) / 0" // both binds: the body and the schema
	failing := *good
	failing.def = &failingDef
	var logs []string
	c.logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
		t.Logf(format, args...)
	}
	security := func() int {
		n := 0
		for _, l := range logs {
			if strings.HasPrefix(l, "SECURITY:") {
				n++
			}
		}
		return n
	}
	c.target = &failing
	ctx := context.Background()
	// What the failing reading hides: a generation function that no longer
	// bumps, so a direct revoke goes unseen.
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)

	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen")
	flushed, err := c.check(ctx)
	require.ErrorContains(t, err, "division by zero")
	require.True(t, flushed, "a failed reading invalidates")
	require.False(t, w.decide(t, w.perm.Name))
	require.Equal(t, before, testutil.ToFloat64(rolePermGenerationTamperTotal), "one failed reading is not yet reported as tamper")
	require.Zero(t, security())

	require.NoError(t, w.writer.AssignPermissionToRole(ctx, w.role.ID, w.perm.ID))
	require.True(t, w.decide(t, w.perm.Name), "warm again")
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen")
	flushed, err = c.check(ctx)
	require.Error(t, err)
	require.True(t, flushed)
	require.False(t, w.decide(t, w.perm.Name))
	require.Equal(t, before+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "a reading that keeps failing is reported")
	require.Equal(t, 1, security())

	flushed, err = c.check(ctx)
	require.Error(t, err)
	require.True(t, flushed, "every failed reading invalidates")
	require.Equal(t, before+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "counted once per run of failures")
	require.Equal(t, 2, security(), "reported on every tick")

	c.target = good
	flushed, err = c.check(ctx)
	require.NoError(t, err)
	require.True(t, flushed, "the first good reading restores the function and invalidates")
	flushed, err = c.check(ctx)
	require.NoError(t, err)
	require.False(t, flushed, "then it is the baseline")
}

// The same for the secret_nodes cache-epoch target (checkRepairFirst): a
// reading that keeps failing is reported, and an invalidation is owed that
// runs from the first row once the reading works, with nothing in the catalog
// changed meanwhile.
func TestSecretNodeCacheEpochIntegrity_FailingReadingFailsClosed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	good := w.c.target
	failingDef := *good.def
	failingDef.sql = "SELECT pg_catalog.length($1::text || $2::text) / 0" // both binds: the body and the schema
	failing := *good
	failing.def = &failingDef
	w.c.target = &failing
	ctx := context.Background()

	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	flushed, err := w.c.check(ctx)
	require.ErrorContains(t, err, "division by zero")
	require.False(t, flushed, "no batch runs behind an unverified trigger")
	require.Equal(t, before, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
	flushed, err = w.c.check(ctx)
	require.Error(t, err)
	require.False(t, flushed)
	require.Equal(t, before+1, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), "a reading that keeps failing is reported")

	w.c.target = good
	flushed, err = w.c.check(ctx)
	require.NoError(t, err)
	require.True(t, flushed, "the owed invalidation runs once the reading works")
	flushed, err = w.c.check(ctx)
	require.NoError(t, err)
	require.False(t, flushed, "then it is the baseline")
}
