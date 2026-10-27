package solewriter

// MUTANT-SEC-3: effects a gremlins mutant of the non-Postgres paths of this
// package left unchanged (the Postgres-backed paths need KEYORIX_TEST_PG_DSN
// and are not part of the measured run).

import (
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptionsDefaults(t *testing.T) {
	var o Options
	o.defaults()
	assert.Equal(t, 120*time.Second, o.LockWait)
	assert.Equal(t, 30*time.Second, o.SettleTimeout)
	require.NotNil(t, o.Now)
	require.NotNil(t, o.Wall)

	set := Options{LockWait: 5 * time.Second, SettleTimeout: 7 * time.Second}
	set.defaults()
	assert.Equal(t, 5*time.Second, set.LockWait, "an explicit value is kept")
	assert.Equal(t, 7*time.Second, set.SettleTimeout, "an explicit value is kept")
}

func TestEndKind_DegenerateInputs(t *testing.T) {
	assert.Equal(t, stmtEnd, endKind(""))
	assert.Equal(t, stmtEnd, endKind(" ; \t"))
	assert.Equal(t, stmtEndChain, endKind("and chain"), "two words is enough for the chain suffix")
	assert.Equal(t, stmtEnd, endKind("chain"))
	assert.Equal(t, stmtEnd, endKind("rollback work"))
	assert.Equal(t, stmtRead, endKind("rollback to"))
}

// A fenced table named AFTER an ignorable one in the same statement still makes
// it a fenced write: every name is checked, not just the first.
func TestClassifyStatement_EveryFencedNameIsChecked(t *testing.T) {
	assert.Equal(t, stmtFencedWrite, classifyStatement(
		`UPDATE "machine_identity_credentials" SET "last_used_at"=$1 WHERE id = (SELECT id FROM roles LIMIT 1)`, nil))
	assert.Equal(t, stmtFencedWrite, classifyStatement(
		`INSERT INTO "system_metadata" ("key","value") SELECT name, 'x' FROM projects`, []any{"schema_epoch", "x"}))
	// Control: the ignorable table alone stays a non-fenced write.
	assert.Equal(t, stmtOtherWrite, classifyStatement(
		`UPDATE "machine_identity_credentials" SET "last_used_at"=$1 WHERE id = $2`, nil))
}

type cyclicValuer struct{}

func (cyclicValuer) Value() (driver.Value, error) { return []any{cyclicValuer{}}, nil }

// argIsKey terminates on a self-referencing argument and fails open to "not
// the key" only at the depth bound.
func TestArgIsKey_BoundedOnCycles(t *testing.T) {
	cyc := make([]any, 1)
	cyc[0] = cyc
	assert.False(t, argIsKey(cyc, "k", 0))
	assert.False(t, argIsKey(cyclicValuer{}, "k", 0))

	// The bound is not hit by honest nesting.
	assert.True(t, argIsKey([]any{[]any{"k"}}, "k", 0))
	assert.True(t, argIsKey([]any{[]any{[]any{"k"}}}, "k", 0))
	assert.False(t, argIsKey([]any{[]any{"other"}}, "k", 0))
}

func TestTriggerSpecs_RowTriggersCarryAWhenOnlyWhenTheyHaveACondition(t *testing.T) {
	const schema = "sw_test"
	unconditional := "FOR EACH ROW " + "EXECUTE PROCEDURE " + qualify(schema, guardFunc) + "()"
	var plain, conditional int
	for _, s := range triggerSpecs(schema) {
		switch {
		case s.rest == unconditional:
			plain++
		case strings.HasPrefix(s.rest, "FOR EACH ROW WHEN ("):
			conditional++
			assert.NotContains(t, s.rest, "WHEN ()", s.name+" on "+s.table)
			assert.True(t, strings.HasSuffix(s.rest, ") EXECUTE PROCEDURE "+qualify(schema, guardFunc)+"()"), s.rest)
		case s.rest == "FOR EACH ROW EXECUTE PROCEDURE "+qualify(schema, fenceOnlyFunc)+"()":
			// the own tables' row fence
		default:
			assert.Contains(t, s.rest, "FOR EACH STATEMENT", "every other spec is a statement trigger: %s", s.rest)
		}
	}
	assert.NotZero(t, plain, "tables with no key and no ignored columns get an unconditional row trigger")
	assert.NotZero(t, conditional, "keyed tables get a conditional row trigger")
}

func guardAt(state State, lastGood, now time.Time) *Guard {
	clock := now
	g := &Guard{state: state, lastGoodMono: lastGood, lastGoodWall: lastGood.Round(0)}
	g.opts.Now = func() time.Time { return clock }
	g.opts.Wall = func() time.Time { return clock.Round(0) }
	return g
}

func TestGuardAuthoritative_RequiresStateAndAFreshGoodPoll(t *testing.T) {
	var nilGuard *Guard
	assert.False(t, nilGuard.Authoritative())

	base := time.Now()
	assert.True(t, guardAt(StateAuthoritative, base, base.Add(LeaseDuration/2)).Authoritative())
	assert.False(t, guardAt(StateAuthoritative, base, base.Add(2*LeaseDuration)).Authoritative(), "lease run out")
	assert.False(t, guardAt(StateConfirming, base, base.Add(LeaseDuration/2)).Authoritative(), "not in the authoritative state")
	assert.False(t, guardAt(StateAuthoritative, time.Time{}, base).Authoritative(), "no good poll yet")
}

func TestGuardStatus_LeaseExpiryShowsConfirming(t *testing.T) {
	base := time.Now()
	fresh := guardAt(StateAuthoritative, base, base.Add(LeaseDuration/2)).Status()
	assert.Equal(t, StateAuthoritative, fresh.State)
	assert.True(t, fresh.Authoritative)
	assert.Equal(t, (LeaseDuration / 2).Milliseconds(), fresh.LastPollAgeMS)

	stale := guardAt(StateAuthoritative, base, base.Add(3*LeaseDuration)).Status()
	assert.Equal(t, StateConfirming, stale.State)
	assert.False(t, stale.Authoritative)
	assert.Contains(t, stale.Reason, "lease expired")

	// A guard that was never authoritative keeps its own state and reason.
	g := guardAt(StateSettling, base, base.Add(3*LeaseDuration))
	g.reason = "starting"
	st := g.Status()
	assert.Equal(t, StateSettling, st.State)
	assert.Equal(t, "starting", st.Reason)
}

func TestMetrics_PollAgeIsReportedInSeconds(t *testing.T) {
	base := time.Now()
	restore := SetCurrentForTest(guardAt(StateAuthoritative, base, base.Add(LeaseDuration/2)))
	defer restore()
	got := gatherValues(t, newMetricsCollector())
	assert.InDelta(t, LeaseDuration.Seconds()/2, got["keyorix_single_writer_last_poll_age_seconds"], 1e-9)
	assert.Equal(t, 1.0, got["keyorix_single_writer_state{state=authoritative}"])
	assert.Equal(t, 0.0, got["keyorix_single_writer_state{state=confirming}"])
}

// The lease boundaries are exact on both clocks.
func TestLapsedLocked_ExactBoundaries(t *testing.T) {
	base := time.Now()
	lapsed := func(monoDelta, wallDelta time.Duration) bool {
		g := &Guard{lastGoodMono: base, lastGoodWall: base.Round(0)}
		return g.lapsedLocked(base.Add(monoDelta), base.Round(0).Add(wallDelta))
	}
	for _, tc := range []struct {
		name            string
		mono, wall      time.Duration
		wantLapsedValue bool
	}{
		{"same instant", 0, 0, false},
		{"just inside the lease", LeaseDuration - 1, LeaseDuration - 1, false},
		{"monotonic exactly one lease", LeaseDuration, 0, true},
		{"monotonic went backwards", -1, 0, true},
		{"wall exactly one lease ahead", 0, LeaseDuration, true},
		{"wall exactly one lease behind", 0, -LeaseDuration, true},
		{"wall just inside, behind", 0, -LeaseDuration + 1, false},
		{"wall just inside, ahead", 0, LeaseDuration - 1, false},
	} {
		assert.Equal(t, tc.wantLapsedValue, lapsed(tc.mono, tc.wall), tc.name)
	}
	assert.False(t, (&Guard{}).lapsedLocked(base, base), "no good poll yet is not a lapse")
}

// argIsKey follows nesting up to depth 4 and no further.
func TestArgIsKey_DepthBoundIsExact(t *testing.T) {
	nest := func(levels int) any {
		var v any = "k"
		for range levels {
			v = []any{v}
		}
		return v
	}
	assert.True(t, argIsKey(nest(1), "k", 0))
	assert.True(t, argIsKey(nest(4), "k", 0), "the key at depth 4 is still seen")
	assert.False(t, argIsKey(nest(5), "k", 0), "beyond depth 4 nothing is followed")
}
