// secret_node_cache_epoch_ensure_postgres_test.go — TRIGGER-HARDEN-1: the
// cache-epoch installer converges like the role-permission one. It compiles on
// the base, so these two are red there by behaviour.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres: a boot
// on an already correct schema must not give the pg_proc or pg_trigger row a
// new xmin (CREATE OR REPLACE ran on every boot, so every replica boot would
// read as tampering to the integrity check on the others).
func TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres(t *testing.T) {
	db, _, _ := cacheEpochReplicaWorld(t)
	read := func() string {
		var v string
		require.NoError(t, db.Raw("SELECT p.xmin::text || ':' || t.xmin::text FROM pg_catalog.pg_proc p, pg_catalog.pg_trigger t WHERE p.oid = ?::regprocedure AND t.tgrelid = 'secret_nodes'::regclass AND t.tgname = ?",
			secretNodeCacheEpochFunc+"()", SecretNodeCacheEpochTrigger).Scan(&v).Error)
		return v
	}
	before := read()
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	require.Equal(t, before, read())
}

// TestSecretNodeCacheEpoch_EnsureRestoresRecreatedTrigger_Postgres: a trigger
// of the same name re-created as AFTER passes the presence proof and stamps
// nothing; the installer used to leave it because it only created an absent
// trigger. The behaviour is checked through a direct update, not a catalog read.
func TestSecretNodeCacheEpoch_EnsureRestoresRecreatedTrigger_Postgres(t *testing.T) {
	db, ls, created := cacheEpochReplicaWorld(t)
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		for _, q := range []string{
			"DROP TRIGGER " + SecretNodeCacheEpochTrigger + " ON secret_nodes",
			"CREATE TRIGGER " + SecretNodeCacheEpochTrigger + " BEFORE UPDATE OF name ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()",
			"ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER " + SecretNodeCacheEpochTrigger,
		} {
			if err := tx.Exec(q).Error; err != nil {
				return err
			}
		}
		return nil
	}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	require.NoError(t, db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", created.ID).Error)
	got, err := ls.GetSecret(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", got.Status, "the converged trigger stamps an update of any column")
}
