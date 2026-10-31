// audit_verify_state_rolling_upgrade_rejecting_test.go — REVIEW-3854-DEEP-1: an
// older replica that REJECTS the row it loads (deleted, put back below a
// generation it read, older than the checkpoint trail, garbled) starts over and
// saves an authentic, unplaced row at the next generation and the current
// trail. Without a check on that rejection the row passes every re-sign
// condition (#3708), so the older replica would launder the deletion or the
// put-back for a DB-write actor and the next full verification would read
// valid. It must latch instead, on the rejecting save itself and on the older
// replica's later saves that still carry the rejection. Every case runs on
// SQLite and, with KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// olderReplicaRejectingSave is the row an older replica's save writes after its
// load rejected the stored row (135f1b37a^:internal/core/audit_verify_state.go,
// loadAuditVerifyStateUnobserved and loadAuditVerifyStateForWrite): it keeps
// only the generation, failure and job of the rejected row (kept, nil when the
// row was deleted or did not decode), saves under gen at the current trail and
// records the rejection under that same generation.
func olderReplicaRejectingSave(t *testing.T, c *KeyorixCore, kept *auditVerifyState, gen uint64, reason string) string {
	t.Helper()
	m := map[string]any{"v": 1}
	if kept != nil {
		if kept.Failure != nil {
			m["failure"] = kept.Failure
		}
		if kept.Job != nil {
			m["job"] = kept.Job
		}
	}
	m["rejected"] = map[string]any{"at": time.Now().UTC(), "gen": gen, "reason": reason}
	// olderReplicaStateValue sets gen and binds the current trail.
	return olderReplicaStateValue(t, c, signedStateValue(t, c, m), gen)
}

func TestAuditVerifyStateRollingUpgrade_OlderReplicaRejectingResaveLatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// row returns what the older replica rejected (nil: nothing it could
		// decode) and the reason its load gave, given the pre-break row and
		// the generation the older replica already read.
		row func(before *auditVerifyState, seen uint64) (*auditVerifyState, string)
		// ticks is how many more saves the older replica makes after the
		// rejecting one (each keeps the rejection, at a higher generation).
		ticks int
	}{
		{name: "deleted", row: func(_ *auditVerifyState, seen uint64) (*auditVerifyState, string) {
			return nil, fmt.Sprintf("the persisted verification state is missing although this server already read generation %d (deleted or rolled back) and was ignored", seen)
		}},
		{name: "deleted_then_more_saves", ticks: 2, row: func(_ *auditVerifyState, seen uint64) (*auditVerifyState, string) {
			return nil, fmt.Sprintf("the persisted verification state is missing although this server already read generation %d (deleted or rolled back) and was ignored", seen)
		}},
		{name: "garbled", row: func(*auditVerifyState, uint64) (*auditVerifyState, string) {
			return nil, "the persisted verification state is malformed and was ignored"
		}},
		{name: "put_back_below_seen", row: func(before *auditVerifyState, seen uint64) (*auditVerifyState, string) {
			return before, fmt.Sprintf("the persisted verification state is generation %d, older than generation %d this server already read (a replayed or rolled-back row) and was ignored", before.Gen, seen)
		}},
		{name: "stale_bind", row: func(before *auditVerifyState, _ uint64) (*auditVerifyState, string) {
			return before, fmt.Sprintf("the persisted verification state was saved at checkpoint #%d and high-water %d, older than the signed checkpoint #%d and high-water %d (a replayed or rolled-back row) and was ignored",
				before.Bind.CheckpointID, before.Bind.HighWater, before.Bind.CheckpointID+1, before.Bind.HighWater+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				fcCertify(t, e)
				before := ffDecode(t, e.c, fcStateValue(t, e.db))
				recordBreakAndRepair(t, e)
				// The older replica has read the row that carries the failure.
				seen := ffDecode(t, e.c, fcStateValue(t, e.db)).Gen
				require.Greater(t, seen, before.Gen)

				kept, reason := tc.row(before, seen)
				gen := max(seen, before.Gen) + 1
				v := olderReplicaRejectingSave(t, e.c, kept, gen, reason)
				for range tc.ticks {
					gen++
					v = olderReplicaStateValue(t, e.c, v, gen)
				}
				require.NotNil(t, ffDecode(t, e.c, v).Rejected, "precondition: the older replica's save keeps the rejection")
				fcSetStateValue(t, e.db, v)

				c := e.restart()
				fcTick(t, e, c)
				assertDiscontinuity(t, e, c, "before a recorded break")
				assertDiscontinuitySticky(t, e, c, "before a recorded break")
			})
		})
	}
}
