// trigger_integrity_repair_budget_postgres_test.go — TRIGGER-INTEGRITY-1 review
// fix (REVIEW-3841-DEEP-2 N1): the invalidation before a repair runs through
// system_metadata, so it fires the object the repair is about to drop. A
// planted object that makes that write slow must not use up the tick, or the
// repair never runs and the state is reported every tick but never repaired.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestRolePermGenerationIntegrity_SlowPlantedTriggerDoesNotStarveTheRepair_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	// Keeps OLD.value for the generation row, and once armed (a row in
	// slow_generation_arm) sleeps past the tick first. Armed only after the
	// direct revoke, so the revoke itself is quick.
	var schema string
	require.NoError(t, db.Raw("SELECT current_schema()").Scan(&schema).Error)
	require.NoError(t, db.Exec("CREATE TABLE slow_generation_arm (x int)").Error)
	require.NoError(t, db.Exec(`CREATE FUNCTION slow_keep_generation() RETURNS trigger LANGUAGE plpgsql AS $x$
BEGIN
  IF NEW.key = 'role_permissions_generation' THEN
    IF EXISTS (SELECT 1 FROM `+pgx.Identifier{schema, "slow_generation_arm"}.Sanitize()+`) THEN PERFORM pg_catalog.pg_sleep(15); END IF;
    NEW.value := OLD.value;
  END IF;
  RETURN NEW;
END;$x$`).Error)
	require.NoError(t, db.Exec("CREATE TRIGGER slow_keep_generation BEFORE UPDATE ON system_metadata FOR EACH ROW EXECUTE PROCEDURE slow_keep_generation()").Error)
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen")
	require.NoError(t, db.Exec("INSERT INTO slow_generation_arm VALUES (1)").Error)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	flushed, err := c.check(ctx)
	require.NoError(t, err, "the repair runs within the tick")
	require.True(t, flushed)
	require.False(t, c.pending)
	require.False(t, w.decide(t, w.perm.Name), "flushed")
	requireSystemMetadataClean(t, db)
}
