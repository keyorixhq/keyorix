// trigger_integrity_slow_reading_postgres_test.go — TRIGGER-INTEGRITY-1 review
// fix (REVIEW-3841-DEEP-2 B1): a catalog reading that outlasts the tick's
// deadline (the server's role can make it slow) fails closed like a reading
// that errors; only a cancelled tick (shutdown) changes nothing.
package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// slowReadingSQL stands in for a catalog reading the server's role made slow
// (a huge WHEN clause on the anchor-named trigger): it outlasts any tick
// deadline the tests below use. Both binds: the body and the schema.
const slowReadingSQL = "SELECT pg_catalog.length($1::text || $2::text) FROM pg_catalog.pg_sleep(30)"

// slowReadingTickTimeout is the per-tick deadline of these tests, as
// StartTriggerIntegrityCheck gives every tick rolePermGenerationIntegrityTickTimeout.
const slowReadingTickTimeout = 2 * time.Second

func slowReadingTick(t *testing.T, c *triggerIntegrityChecker) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), slowReadingTickTimeout)
	defer cancel()
	return c.check(ctx)
}

// A reading that outlasts the tick deadline is a failed reading, not a
// cancelled tick: it invalidates, and from the second tick in a row on it is
// reported (SECURITY, counted once) with an invalidation owed. Before the fix
// such a tick changed nothing, so a slow reading blinded the check (REVIEW-3841
// DEEP-2 B1).
func TestRolePermGenerationIntegrity_ReadingPastTickDeadlineFailsClosed_Postgres(t *testing.T) {
	w, c := smWriteTargetWorld(t)
	db := w.writer.db
	good := c.target
	slowDef := *good.def
	slowDef.sql = slowReadingSQL
	slow := *good
	slow.def = &slowDef
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
	c.target = &slow
	ctx := context.Background()
	// What the slow reading hides: a generation function that no longer
	// bumps, so a direct revoke goes unseen.
	require.NoError(t, db.Exec("CREATE OR REPLACE FUNCTION "+rolePermGenerationFunc+"() RETURNS trigger LANGUAGE plpgsql AS $x$BEGIN RETURN NULL; END;$x$").Error)

	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen")
	flushed, err := slowReadingTick(t, c)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, flushed, "a reading past the deadline invalidates")
	require.False(t, w.decide(t, w.perm.Name))
	require.Equal(t, 1, c.readFailures, "a reading past the deadline is a failed reading")
	require.Zero(t, security())

	require.NoError(t, w.writer.AssignPermissionToRole(ctx, w.role.ID, w.perm.ID))
	require.True(t, w.decide(t, w.perm.Name), "warm again")
	revokeDirect(t, db, w)
	require.True(t, w.decide(t, w.perm.Name), "premise: the revocation went unseen")
	flushed, err = slowReadingTick(t, c)
	require.Error(t, err)
	require.True(t, flushed)
	require.False(t, w.decide(t, w.perm.Name))
	require.Equal(t, before+1, testutil.ToFloat64(rolePermGenerationTamperTotal), "a reading that keeps timing out is reported")
	require.Equal(t, 1, security())
	require.True(t, c.pending, "an invalidation is owed")

	c.target = good
	flushed, err = slowReadingTick(t, c)
	require.NoError(t, err)
	require.True(t, flushed, "the first good reading restores the function and invalidates")
	flushed, err = slowReadingTick(t, c)
	require.NoError(t, err)
	require.False(t, flushed, "then it is the baseline")
}

// The same for the secret_nodes cache-epoch target (checkRepairFirst).
func TestSecretNodeCacheEpochIntegrity_ReadingPastTickDeadlineFailsClosed_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	good := w.c.target
	slowDef := *good.def
	slowDef.sql = slowReadingSQL
	slow := *good
	slow.def = &slowDef
	w.c.target = &slow

	before := testutil.ToFloat64(secretNodeCacheEpochTamperTotal)
	flushed, err := slowReadingTick(t, w.c)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, flushed, "no batch runs behind an unverified trigger")
	require.Equal(t, 1, w.c.readFailures)
	flushed, err = slowReadingTick(t, w.c)
	require.Error(t, err)
	require.False(t, flushed)
	require.Equal(t, before+1, testutil.ToFloat64(secretNodeCacheEpochTamperTotal), "a reading that keeps timing out is reported")
	require.True(t, w.c.pending)

	w.c.target = good
	flushed, err = slowReadingTick(t, w.c)
	require.NoError(t, err)
	require.True(t, flushed, "the owed invalidation runs once the reading works")
}

// Shutdown still changes nothing: a tick whose parent was cancelled neither
// counts a failed reading nor invalidates.
func TestRolePermGenerationIntegrity_CancelledTickChangesNothing_Postgres(t *testing.T) {
	_, c := smWriteTargetWorld(t)
	slowDef := *c.target.def
	slowDef.sql = slowReadingSQL
	slow := *c.target
	slow.def = &slowDef
	c.target = &slow
	before := testutil.ToFloat64(rolePermGenerationTamperTotal)
	for range triggerIntegrityReadFailureLimit + 1 {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		flushed, err := c.check(ctx)
		cancel()
		require.ErrorIs(t, err, context.Canceled)
		require.False(t, flushed)
	}
	require.Zero(t, c.readFailures)
	require.False(t, c.pending)
	require.Equal(t, before, testutil.ToFloat64(rolePermGenerationTamperTotal))
}
