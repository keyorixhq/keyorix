package core

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// TestScheduleInterleavings_Postgres replays a fixed set of concurrent schedules
// against a REAL Postgres-backed store (KEYORIX_TEST_PG_DSN), where the
// connection pool is NOT capped to one connection and goroutine-per-op therefore
// gets genuine DB-level write concurrency — the regime SQLite's single-connection
// pool cannot reproduce. It is the teeth behind the serial-equivalence oracle for
// the two-writer cases (two deletes, two grants, delete-vs-update): if an
// in-process named lock or a storage row lock were missing on one of these
// paths, Postgres is where "both writes succeeded" would surface as a
// linearizability violation.
//
// Still SINGLE PROCESS: one KeyorixCore, one *gorm.DB pool. It does NOT exercise
// the cross-REPLICA (multi-process, independent pools) races that
// FuzzCrossReplicaInvariants covers — see that fuzzer.
//
// Skips cleanly (not a failure) when KEYORIX_TEST_PG_DSN is unset. To avoid any
// table-reset fragility, one schema is bootstrapped once and every rep seeds
// FRESH entities (unique names) rather than truncating — so an oracle only ever
// reasons about its own rep's rows.
func TestScheduleInterleavings_Postgres(t *testing.T) {
	if os.Getenv(fuzzworld.PGDSNEnv) == "" {
		t.Skipf("%s not set — Postgres interleaving replay skipped", fuzzworld.PGDSNEnv)
	}
	db := fuzzworld.OpenPostgres(t, "rc_sched")
	require.NotNil(t, db)
	w := mustBootstrap(t, db, "postgres")
	t.Cleanup(func() { _ = w.st.Close() })

	// A curated program set that maximises two-writer linearizability pressure,
	// plus audit-append concurrency. Each is replayed many times; the Go
	// scheduler + Postgres pool vary the interleaving across reps.
	progs := []schedProgram{
		// two concurrent deletes (exactly one must win)
		{domain: dmSecret, split: 1, ops: []schedOp{{kind: opDelete}, {kind: opDelete}}},
		// delete vs update (final must be gone; update ok XOR not-found)
		{domain: dmSecret, split: 1, ops: []schedOp{{kind: opDelete}, {kind: opUpdate, arg: 1}}},
		// two concurrent updates (final value ∈ {u1,u2})
		{domain: dmSecret, split: 1, ops: []schedOp{{kind: opUpdate, arg: 1}, {kind: opUpdate, arg: 2}}},
		// read racing delete+update
		{domain: dmSecret, split: 1, ops: []schedOp{{kind: opRead}, {kind: opDelete}, {kind: opUpdate, arg: 3}}},
		// two concurrent role revokes (exactly one ok, one not-found)
		{domain: dmRole, split: 1, ops: []schedOp{{kind: opRevokeRole}, {kind: opRevokeRole}}},
		// grant racing revoke racing authorize
		{domain: dmRole, split: 1, ops: []schedOp{{kind: opGrantRole}, {kind: opRevokeRole}, {kind: opAuthorize}}},
		// PAT: concurrent revoke + validate
		{domain: dmPAT, split: 1, ops: []schedOp{{kind: opRevoke}, {kind: opValidate}}},
		// PAT happens-before: revoke then validate (must be revoked)
		{domain: dmPAT, hb: true, split: 1, ops: []schedOp{{kind: opRevoke}, {kind: opValidate}}},
		// 4 concurrent audited revokes (chain must stay valid; 4 new events)
		{domain: dmAudit, split: 1, ops: []schedOp{{kind: opAuditMutate}, {kind: opAuditMutate}, {kind: opAuditMutate}, {kind: opAuditMutate}}},
	}

	// repsPerProg defaults to 25 but can be raised for a longer soak via
	// KEYORIX_SCHED_PG_REPS (the fuzzing campaign drives it to a few thousand to
	// widen the set of Postgres interleavings each program is observed under).
	repsPerProg := 25
	if v := os.Getenv("KEYORIX_SCHED_PG_REPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			repsPerProg = n
		}
	}
	rep := 0
	for pi, base := range progs {
		for r := 0; r < repsPerProg; r++ {
			rep++
			w.uniq = fmt.Sprintf("-p%d-r%d", pi, rep)
			// vary delays per rep so interleavings differ
			prog := base
			prog.ops = append([]schedOp(nil), base.ops...)
			for i := range prog.ops {
				prog.ops[i].delay = (r + i) % 6
			}
			runAndCheck(t, w, prog)
		}
	}
	t.Logf("postgres interleaving replay: %d reps across %d programs — all oracles green", rep, len(progs))
}
