// trigger_integrity_versions_postgres_test.go — TRIGGER-INTEGRITY-1 item 1
// (#3717): two simulated releases, N (this one) and N+1 (the same definition
// with another body, version 2), each with its own checker, against ONE
// database, ticking alternately as their replicas do during a rolling
// upgrade. The definition must not flip, N reports a newer definition (not
// tampering), N+1 still restores a genuine tamper to its own definition, and
// a forged or inconsistent version marker is still tampering
// (pgTriggerDef.newerThan states the rule).
package store

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// testReleaseTarget is target as release v2 with body ships it: its own
// definition, everything else (invalidation, repair, counters) the same.
func testReleaseTarget(target *triggerIntegrityTarget, body string) *triggerIntegrityTarget {
	def := *target.def
	def.version, def.body = target.def.version+1, body
	next := *target
	next.def = &def
	return &next
}

// releaseBoots runs target's installer, as a replica of that release does at
// boot.
func releaseBoots(t *testing.T, db *gorm.DB, target *triggerIntegrityTarget) {
	t.Helper()
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error { return target.repair(tx, target.def) }))
}

// installedDef is the function's body and version marker.
func installedDef(t *testing.T, db *gorm.DB, fn string) (string, string) {
	t.Helper()
	var row []struct{ Body, Marker string }
	require.NoError(t, db.Raw("SELECT prosrc AS body, COALESCE(obj_description(oid, 'pg_proc'), '') AS marker FROM pg_proc WHERE oid = ?::regprocedure", fn+"()").Scan(&row).Error)
	require.Len(t, row, 1)
	return row[0].Body, row[0].Marker
}

func TestTriggerIntegrityVersions_TwoReleasesTickAlternately_Postgres(t *testing.T) {
	w, cN := rpgIntegrityWorld(t)
	db := w.writer.db
	n1 := testReleaseTarget(rolePermGenerationIntegrityTarget, rpgV2Body)
	require.Equal(t, rpgV2Marker, n1.def.marker())
	cN1 := &triggerIntegrityChecker{ls: NewLocalStorage(db), logf: t.Logf, target: n1}
	tamper := testutil.ToFloat64(rolePermGenerationTamperTotal)
	newer := testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal)

	releaseBoots(t, db, n1) // the first N+1 replica: its migration upgrades the definition
	requireDef := func(body, marker string) {
		t.Helper()
		b, m := installedDef(t, db, rolePermGenerationFunc)
		require.Equal(t, body, b)
		require.Equal(t, marker, m)
	}
	requireDef(rpgV2Body, rpgV2Marker)
	for i := range 3 {
		flushedN, err := cN.check(context.Background())
		require.NoError(t, err)
		require.Equal(t, i == 0, flushedN, "N flushes once, when it first reads the newer definition")
		flushedN1, err := cN1.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushedN1, "N+1 reads its own definition")
		releaseBoots(t, db, rolePermGenerationIntegrityTarget) // an N replica restarts
		requireDef(rpgV2Body, rpgV2Marker)
	}
	st, err := readTriggerIntegrity(context.Background(), db, rolePermGenerationIntegrityTarget)
	require.NoError(t, err)
	require.Empty(t, st.problem)
	require.Equal(t, rpgV2Marker, st.newer, "N reads a newer release's definition")
	require.Equal(t, tamper, testutil.ToFloat64(rolePermGenerationTamperTotal), "no tamper alarm on either release")
	require.Equal(t, newer+1, testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal), "N counts the newer definition once, under its own label")

	// A genuine tamper of the newer definition: CREATE OR REPLACE keeps the
	// comment, so the v2 marker no longer matches the body.
	require.True(t, w.decide(t, w.perm.Name), "warm")
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $x$BEGIN RETURN NULL; END;$x$").Error)
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revoke went unseen")
	flushed, err := cN1.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.False(t, w.decide(t, w.perm.Name), "N+1's tick flushes")
	requireDef(rpgV2Body, rpgV2Marker) // restored to N+1's own, not N's
	require.Equal(t, tamper+1, testutil.ToFloat64(rolePermGenerationTamperTotal))
	flushed, err = cN.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "N sees the rewrite and flushes too")
	requireDef(rpgV2Body, rpgV2Marker)
	require.Equal(t, tamper+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "and counts it as a newer definition, which it is again")
	require.Equal(t, newer+2, testutil.ToFloat64(rolePermGenerationNewerDefinitionTotal))
}

// TestTriggerIntegrityVersions_ForgedMarkersAreTampering_Postgres: what N
// reports for each marker the owner can write. Only a marker one version
// ahead whose digest matches the installed definition reads as newer; a
// self-consistent forgery of exactly that shape is the stated residual (N
// leaves it, N+1 restores it).
func TestTriggerIntegrityVersions_ForgedMarkersAreTampering_Postgres(t *testing.T) {
	const noop = "\nBEGIN\n  RETURN NULL;\nEND;\n"
	fn := rolePermGenerationFunc
	marker := func(version int, body string) string {
		d := *rolePermGenerationDef
		d.version, d.body = version, body
		return d.marker()
	}
	cases := []struct {
		name, body, marker, extra, problem string
	}{
		{name: "own body, marker removed", body: postgresRolePermGenerationFuncBody, problem: "carries no version marker"},
		{name: "own body, malformed marker", body: postgresRolePermGenerationFuncBody, marker: "keyorix-trigger-def " + fn + " v2", problem: "malformed version marker"},
		{name: "no-op body under this release's marker", body: noop, marker: marker(1, postgresRolePermGenerationFuncBody), problem: "is marked v1 but is not this release's v1"},
		{name: "no-op body under a genuine v2 marker", body: noop, marker: rpgV2Marker, problem: "do not match the marker's digest"},
		{name: "genuine v2 with its search_path changed", body: rpgV2Body, marker: rpgV2Marker, extra: "ALTER FUNCTION " + fn + "() SET search_path = public", problem: "do not match the marker's digest"},
		{name: "genuine v2 made SECURITY DEFINER", body: rpgV2Body, marker: rpgV2Marker, extra: "ALTER FUNCTION " + fn + "() SECURITY DEFINER", problem: "do not match the marker's digest"},
		{name: "genuine v2 with a trigger on fewer events", body: rpgV2Body, marker: rpgV2Marker,
			extra:   "DROP TRIGGER " + RolePermissionsGenerationTrigger + " ON role_permissions; CREATE TRIGGER " + RolePermissionsGenerationTrigger + " AFTER INSERT ON role_permissions FOR EACH STATEMENT EXECUTE PROCEDURE " + fn + "(); ALTER TABLE role_permissions ENABLE ALWAYS TRIGGER " + RolePermissionsGenerationTrigger,
			problem: "do not match the marker's digest"},
		{name: "self-consistent no-op two versions ahead", body: noop, marker: marker(3, noop), problem: "more than 1 ahead"},
		{name: "self-consistent no-op one version ahead (residual)", body: noop, marker: marker(2, noop)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, c := rpgIntegrityWorld(t)
			db := w.writer.db
			require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+fn+"() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $x$"+tc.body+"$x$").Error)
			comment := "NULL"
			if tc.marker != "" {
				comment = "'" + tc.marker + "'"
			}
			require.NoError(t, db.Exec("COMMENT ON FUNCTION "+fn+"() IS "+comment).Error)
			if tc.extra != "" {
				require.NoError(t, db.Exec(tc.extra).Error)
			}
			st, err := readRolePermGenerationIntegrity(context.Background(), db)
			require.NoError(t, err)
			tamper := testutil.ToFloat64(rolePermGenerationTamperTotal)
			flushed, err := c.check(context.Background())
			require.NoError(t, err)
			require.True(t, flushed)
			if tc.problem == "" {
				require.Empty(t, st.problem)
				require.Equal(t, tc.marker, st.newer, "N cannot tell this forgery from release N+1")
				require.Equal(t, tamper, testutil.ToFloat64(rolePermGenerationTamperTotal))
				n1 := testReleaseTarget(rolePermGenerationIntegrityTarget, rpgV2Body)
				st1, err := readTriggerIntegrity(context.Background(), db, n1)
				require.NoError(t, err)
				require.Contains(t, st1.problem, "is marked v2 but is not this release's v2", "release N+1 compares exactly")
				cN1 := &triggerIntegrityChecker{ls: NewLocalStorage(db), logf: t.Logf, target: n1}
				_, err = cN1.check(context.Background())
				require.NoError(t, err)
				body, m := installedDef(t, db, fn)
				require.Equal(t, rpgV2Body, body)
				require.Equal(t, rpgV2Marker, m)
				return
			}
			require.Contains(t, st.problem, tc.problem)
			require.Empty(t, st.newer)
			require.Equal(t, tamper+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "reported as tampering")
			body, m := installedDef(t, db, fn)
			require.Equal(t, postgresRolePermGenerationFuncBody, body, "and restored to this release's definition")
			require.Equal(t, rolePermGenerationDef.marker(), m)
		})
	}
}

// TestTriggerIntegrityVersions_CacheEpochTwoReleasesTickAlternately_Postgres:
// the version marker covers the secret_nodes cache-epoch registration too.
func TestTriggerIntegrityVersions_CacheEpochTwoReleasesTickAlternately_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	n1 := testReleaseTarget(secretNodeCacheEpochIntegrityTarget, cacheEpochV2Body)
	require.Equal(t, cacheEpochV2Marker, n1.def.marker())
	cN1 := &triggerIntegrityChecker{ls: NewLocalStorage(w.db), logf: t.Logf, target: n1}
	tamper := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	newer := testutil.ToFloat64(secretNodeCacheEpochNewerDefinitionTotal)

	releaseBoots(t, w.db, n1)
	for i := range 3 {
		flushedN, err := w.c.check(context.Background())
		require.NoError(t, err)
		require.Equal(t, i == 0, flushedN, "N flushes once, when it first reads the newer definition")
		flushedN1, err := cN1.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushedN1)
		require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "an N replica restarts")
		body, m := installedDef(t, w.db, secretNodeCacheEpochFunc)
		require.Equal(t, cacheEpochV2Body, body)
		require.Equal(t, cacheEpochV2Marker, m)
	}
	require.Equal(t, tamper, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
	require.Equal(t, newer+1, testutil.ToFloat64(secretNodeCacheEpochNewerDefinitionTotal))

	// A genuine tamper under the v2 marker: N+1 restores its own and flushes.
	require.Equal(t, "active", w.status(t), "warm")
	replaceCacheEpochBodyKeepingOldEpoch(t, w.db)
	w.setStatusDirect(t, w.db, "suspended")
	require.Equal(t, "active", w.status(t), "premise: the suspend went unstamped")
	flushed, err := cN1.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	require.Equal(t, "suspended", w.status(t))
	body, m := installedDef(t, w.db, secretNodeCacheEpochFunc)
	require.Equal(t, cacheEpochV2Body, body)
	require.Equal(t, cacheEpochV2Marker, m)
	require.Equal(t, tamper+1, testutil.ToFloat64(secretNodeCacheEpochTamperTotal))
}

// TestTriggerIntegrityVersions_CatalogDigestMatchesTheInstaller_Postgres: the
// digest a checker computes from the catalog (pgTriggerDef.newerThan) and the
// one the installer writes (pgTriggerDef.marker) are the same text for both
// targets; read by a checker one version behind, this release's installed
// definition is accepted as newer.
func TestTriggerIntegrityVersions_CatalogDigestMatchesTheInstaller_Postgres(t *testing.T) {
	w, _ := rpgIntegrityWorld(t)
	ew := newEpochIntegrityWorld(t)
	for _, tc := range []struct {
		db     *gorm.DB
		target *triggerIntegrityTarget
	}{{w.writer.db, rolePermGenerationIntegrityTarget}, {ew.db, secretNodeCacheEpochIntegrityTarget}} {
		older := *tc.target
		def := *tc.target.def
		def.version = 0
		older.def = &def
		st, err := readTriggerIntegrity(context.Background(), tc.db, &older)
		require.NoError(t, err)
		require.Equal(t, tc.target.def.marker(), st.newer, tc.target.what)
	}
}
