// trigger_integrity_newer_bound_postgres_test.go — REVFIX-3841-7 (ask
// 3841-forged-marker-acceptance-bound, option a): a self-consistent marker one
// version ahead is accepted as a newer release's definition only for
// triggerDefNewerAcceptBound. After it the checker reports SECURITY, counts
// tamper, restores this release's definition (the installer's
// leaveNewerTriggerDef no longer protects it) and flushes; a newer definition
// read after that restore gets the whole bound again, so a rolling upgrade
// that outlasts it costs one restore, not a ping-pong every tick.
package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// forgeNewerDef replaces fn's body with a no-op and writes a self-consistent
// marker one version ahead of def, as the server's role can.
func forgeNewerDef(t *testing.T, db *gorm.DB, def *pgTriggerDef, body string) string {
	t.Helper()
	d := *def
	d.version, d.body = def.version+1, body
	marker := d.marker()
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+def.funcName+"() RETURNS trigger LANGUAGE plpgsql "+pgTriggerFuncSetClause+" AS $x$"+body+"$x$").Error)
	require.NoError(t, db.Exec("COMMENT ON FUNCTION "+def.funcName+"() IS '"+marker+"'").Error)
	return marker
}

// ageNewerAcceptance moves c's first reading of the newer definition back past
// the bound, as 24 hours of ticks would.
func ageNewerAcceptance(t *testing.T, c *triggerIntegrityChecker) {
	t.Helper()
	require.False(t, c.newerSince.IsZero(), "premise: the checker has read the newer definition")
	c.newerSince = time.Now().Add(-triggerDefNewerAcceptBound - time.Minute)
}

// recordLogs makes c's log lines readable by the test.
func recordLogs(t *testing.T, c *triggerIntegrityChecker) func() string {
	var mu sync.Mutex
	var lines []string
	c.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(f, a...))
		t.Logf(f, a...)
	}
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		s := strings.Join(lines, "\n")
		lines = nil
		return s
	}
}

func TestTriggerIntegrityNewerBound_ForgedMarkerRestoredAfterBound_Postgres(t *testing.T) {
	const noop = "\nBEGIN\n  RETURN NULL;\nEND;\n"
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	logs := recordLogs(t, c)
	tamper := testutil.ToFloat64(rolePermGenerationTamperTotal)
	newer := testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal)

	forged := forgeNewerDef(t, db, rolePermGenerationDef, noop)
	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the newer definition is flushed once")
	require.Equal(t, newer+1, testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal))
	require.True(t, w.decide(t, w.perm.Name), "re-warmed")
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: under the forged no-op body the revoke went unseen")

	// Within the bound: the residual, left in place.
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed)
	body, m := installedDef(t, db, rolePermGenerationFunc)
	require.Equal(t, noop, body)
	require.Equal(t, forged, m)
	logs()

	// Past the bound: SECURITY, tamper, restored, flushed.
	ageNewerAcceptance(t, c)
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the forged definition is flushed once the bound has passed")
	out := logs()
	require.Contains(t, out, "SECURITY:")
	require.Contains(t, out, "a forged version marker")
	require.Equal(t, tamper+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "counted as tamper")
	require.Equal(t, newer+1, testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal), "not as another newer definition")
	body, m = installedDef(t, db, rolePermGenerationFunc)
	require.Equal(t, postgresRolePermGenerationFuncBody, body, "restored to this release's definition")
	require.Equal(t, rolePermGenerationDef.marker(), m)
	require.False(t, w.decide(t, w.perm.Name), "the revoke made under the forged body is seen")
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "the restored state is the new baseline")

	// A newer definition read after the restore gets the whole bound again:
	// left in place, not restored at once.
	forgeNewerDef(t, db, rolePermGenerationDef, noop)
	flushed, err = c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.Equal(t, tamper+1, testutil.ToFloat64(rolePermGenerationTamperTotal))
	body, _ = installedDef(t, db, rolePermGenerationFunc)
	require.Equal(t, noop, body)
}

// TestTriggerIntegrityNewerBound_RebootDoesNotProtectExpiredMarker_Postgres:
// a replica's boot (the installer) between the ticks leaves the newer
// definition alone, and the checker's restore once the bound has passed is
// not undone by it: leaveNewerTriggerDef reads the restored definition.
func TestTriggerIntegrityNewerBound_RebootDoesNotProtectExpiredMarker_Postgres(t *testing.T) {
	const noop = "\nBEGIN\n  RETURN NULL;\nEND;\n"
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	forged := forgeNewerDef(t, db, rolePermGenerationDef, noop)
	_, err := c.check(context.Background())
	require.NoError(t, err)
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "a replica boots")
	_, m := installedDef(t, db, rolePermGenerationFunc)
	require.Equal(t, forged, m, "the installer leaves a newer definition alone")
	ageNewerAcceptance(t, c)
	_, err = c.check(context.Background())
	require.NoError(t, err)
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "a replica boots")
	body, m := installedDef(t, db, rolePermGenerationFunc)
	require.Equal(t, postgresRolePermGenerationFuncBody, body)
	require.Equal(t, rolePermGenerationDef.marker(), m)
}

// TestTriggerIntegrityNewerBound_CacheEpochForgedMarkerRestoredAfterBound_Postgres:
// the same bound on the secret_nodes cache-epoch target (checkRepairFirst).
func TestTriggerIntegrityNewerBound_CacheEpochForgedMarkerRestoredAfterBound_Postgres(t *testing.T) {
	const keepEpoch = "BEGIN NEW.cache_epoch := OLD.cache_epoch; RETURN NEW; END;"
	w := newEpochIntegrityWorld(t)
	logs := recordLogs(t, w.c)
	tamper := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)

	forged := forgeNewerDef(t, w.db, secretNodeCacheEpochDef, keepEpoch)
	_, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.Equal(t, "active", w.status(t), "re-warmed")
	w.setStatusDirect(t, w.db, "suspended")
	require.Equal(t, "active", w.status(t), "premise: under the forged body the suspend went unstamped")
	flushed, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "within the bound: left in place")
	_, m := installedDef(t, w.db, secretNodeCacheEpochFunc)
	require.Equal(t, forged, m)
	logs()

	ageNewerAcceptance(t, w.c)
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	out := logs()
	require.Contains(t, out, "SECURITY:")
	require.Contains(t, out, "a forged version marker")
	require.Equal(t, tamper+1, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
	body, m := installedDef(t, w.db, secretNodeCacheEpochFunc)
	require.Equal(t, postgresCacheEpochFuncBody, body)
	require.Equal(t, secretNodeCacheEpochDef.marker(), m)
	require.Equal(t, "suspended", w.status(t), "the suspend made under the forged body is seen")
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "the restored state is the new baseline")
}
