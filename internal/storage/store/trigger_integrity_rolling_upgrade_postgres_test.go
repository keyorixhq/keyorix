// trigger_integrity_rolling_upgrade_postgres_test.go — TRIGGER-INTEGRITY-1
// item 1 (#3717): a rolling upgrade to a release that changes a trigger
// function's definition. The newer release installs its body and its version
// marker; a replica still on this release must leave that definition in place
// on its ticks and its boots, warn under its own counter label, and keep the
// caches correct (the newer body still bumps). Before the version markers the
// older replica read every newer definition as tampering and re-installed its
// own every tick, and the newer replicas reverted it back.
//
// This file uses only what the release before markers already had, so it runs
// red there by behaviour; the two-checker version of the same scenario is in
// trigger_integrity_versions_postgres_test.go.
package store

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// rpgV2Body is a test release's v2 of the generation function: the same bump,
// a different body.
const rpgV2Body = `
BEGIN
  -- v2 of the definition (a test release): the same bump.
  EXECUTE format('INSERT INTO %I.system_metadata (key, value, updated_at) VALUES ($1, ''0'', now()) ON CONFLICT (key) DO NOTHING', TG_TABLE_SCHEMA)
    USING 'role_permissions_generation';
  EXECUTE format('UPDATE %I.system_metadata SET value = CAST(CAST(value AS BIGINT) + 1 AS TEXT) WHERE key = $1', TG_TABLE_SCHEMA)
    USING 'role_permissions_generation';
  RETURN NULL;
END;
`

// rpgV2Marker is the version marker that release writes for rpgV2Body with
// this release's trigger shape and pinned search_path
// (TestTriggerDefMarker_TestReleaseLiterals checks it).
const rpgV2Marker = "keyorix-trigger-def keyorix_bump_role_permissions_generation v2 sha256:6b38e10527ef881c42269de2f30c750bcfb561077f10a0286fd1946c8bb74a5d"

// cacheEpochV2Body is the same for the cache-epoch function.
const cacheEpochV2Body = `
BEGIN
  -- v2 of the definition (a test release): the same stamp.
  NEW.cache_epoch := OLD.cache_epoch + 1;
  RETURN NEW;
END;
`

const cacheEpochV2Marker = "keyorix-trigger-def keyorix_secret_nodes_bump_cache_epoch v2 sha256:9cd3c2cf72e6a763206666e5d8dd4611e947c8b7c1683965c9e9888392e43d21"

// installTestReleaseDef does what that release's installer does to the
// function: its body, the pinned search_path, its marker.
func installTestReleaseDef(t *testing.T, db *gorm.DB, fn, body, marker string) {
	t.Helper()
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("CREATE OR REPLACE FUNCTION " + fn + "() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $keyorix$" + body + "$keyorix$").Error; err != nil {
			return err
		}
		return tx.Exec("COMMENT ON FUNCTION " + fn + "() IS '" + marker + "'").Error
	}))
}

// installedFuncBody reads fn's prosrc.
func installedFuncBody(t *testing.T, db *gorm.DB, fn string) string {
	t.Helper()
	var src []string
	require.NoError(t, db.Raw("SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure", fn+"()").Scan(&src).Error)
	require.Len(t, src, 1)
	return src[0]
}

func TestRolePermGenerationIntegrity_NewerReleaseDefinitionIsLeftInPlace_Postgres(t *testing.T) {
	w, c := rpgIntegrityWorld(t)
	db := w.writer.db
	tamper := testutil.ToFloat64(rolePermGenerationTamperTotal)
	installTestReleaseDef(t, db, rolePermGenerationFunc, rpgV2Body, rpgV2Marker)

	flushed, err := c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "a newly installed definition this replica cannot verify is flushed once")
	require.Equal(t, rpgV2Body, installedFuncBody(t, db, rolePermGenerationFunc), "an older replica's tick must not take the newer definition back")
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db), "an older replica boots")
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(w.ls.db), "and another")
	require.Equal(t, rpgV2Body, installedFuncBody(t, db, rolePermGenerationFunc), "nor its boot")
	for range 3 {
		flushed, err := c.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushed, "the newer definition, once seen, is the baseline: no flush every tick")
	}
	require.Equal(t, rpgV2Body, installedFuncBody(t, db, rolePermGenerationFunc))
	require.Equal(t, tamper, testutil.ToFloat64(rolePermGenerationTamperTotal), "a newer release's definition is not the tamper alarm")

	require.True(t, w.decide(t, w.perm.Name), "warm")
	require.NoError(t, db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", w.role.ID, w.perm.ID).Error)
	require.False(t, w.decide(t, w.perm.Name), "the newer body bumps the generation: a direct revoke is seen without a tick")
}

func TestSecretNodeCacheEpochIntegrity_NewerReleaseDefinitionIsLeftInPlace_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	tamper := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	installTestReleaseDef(t, w.db, secretNodeCacheEpochFunc, cacheEpochV2Body, cacheEpochV2Marker)

	flushed, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "a newly installed definition this replica cannot verify is flushed once")
	require.Equal(t, cacheEpochV2Body, installedFuncBody(t, w.db, secretNodeCacheEpochFunc), "an older replica's tick must not take the newer definition back")
	require.NoError(t, EnsureSecretNodeCacheEpoch(w.db), "an older replica boots")
	require.Equal(t, cacheEpochV2Body, installedFuncBody(t, w.db, secretNodeCacheEpochFunc), "nor its boot")
	for range 3 {
		flushed, err := w.c.check(context.Background())
		require.NoError(t, err)
		require.False(t, flushed, "the newer definition, once seen, is the baseline: no flush every tick")
	}
	require.Equal(t, cacheEpochV2Body, installedFuncBody(t, w.db, secretNodeCacheEpochFunc))
	require.Equal(t, tamper, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), "a newer release's definition is not the tamper alarm")

	require.Equal(t, "active", w.status(t), "warm")
	w.setStatusDirect(t, w.db, "suspended")
	require.Equal(t, "suspended", w.status(t), "the newer body stamps a direct write without a tick")
}
