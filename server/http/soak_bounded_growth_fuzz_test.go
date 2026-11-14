package http

// soak_bounded_growth_fuzz_test.go -- FuzzSoakOperationSequence feeds the soak
// operation mix at a SMALL scale so Go's coverage-guided fuzzer can explore
// operation ORDERINGS (not just one seeded order) against the same fully-wired
// in-process stack, with the same consistency oracle the long soak uses, scaled
// down: after every fuzzer-chosen sequence the audit hash-chain must still be VALID
// (no gap, no duplicate, no break) and the live goroutine count must not have run
// away. A per-input fuzzer cannot assert long-run bounded growth (it has no time
// axis), so this target's job is to surface a crash, panic, audit-chain break, or
// per-operation goroutine blow-up that a particular op ordering triggers; the
// regression/heap/fd/latency oracles live in TestSoakBoundedGrowth.
//
// The world is built once per backend and REUSED across iterations (a fresh
// bootstrap per input would dominate wall time). State accumulates; to keep the
// per-iteration chain walk affordable, the volatile tables are trimmed back to a
// clean genesis once the audit log passes a ceiling -- which also exercises the
// chain's "restart from genesis" path.

import (
	"context"
	"math/rand"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// fuzzSeqMaxOps bounds how many operations one corpus input drives, so a huge
// input cannot turn a single iteration into a mini-soak and starve coverage.
const fuzzSeqMaxOps = 64

// fuzzTrimCeiling is the audit-event count above which the volatile tables are
// trimmed to genesis between iterations, bounding the chain-walk cost.
const fuzzTrimCeiling = 8000

// fuzzGoroutineCeiling is how far above the post-build baseline the live goroutine
// count may rise within a single bounded sequence before it is treated as a
// per-operation goroutine leak. Generous: the detached audit writers are
// short-lived, so steady state sits a handful above baseline, never ~one-per-op.
const fuzzGoroutineCeiling = 120

func FuzzSoakOperationSequence(f *testing.F) {
	// Seeds: each byte selects an operation kind (byte % len(soakOpKinds)); a few
	// representative orderings get the corpus started.
	f.Add([]byte{0, 1, 2, 3, 0, 1, 2, 4}) // create,read,update,rotate,create,read,update,delete
	f.Add([]byte{0, 0, 0, 4, 4, 4})        // create burst then delete burst
	f.Add([]byte{6, 6, 6})                 // churn (login/logout) only
	f.Add([]byte{0, 5, 0, 5, 7})           // create, audit-read, ..., project churn
	f.Add([]byte{})

	worlds := []*soakWorld{buildSoakWorldSQLite(f)}
	if pg := buildSoakWorldPostgres(f); pg != nil {
		worlds = append(worlds, pg)
	} else {
		f.Logf("KEYORIX_TEST_PG_DSN not set -- fuzz runs SQLite only")
	}

	cfg := soakConfigFromEnv(f)
	cfg.targetLive = 24 // keep the live set small at fuzz scale

	// Baseline goroutine count after both worlds are fully built and warm.
	baseG := runtime.NumGoroutine()

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, w := range worlds {
			runFuzzSeq(t, w, data, cfg, baseG)
		}
	})
}

func runFuzzSeq(t *testing.T, w *soakWorld, data []byte, cfg soakConfig, baseG int) {
	t.Helper()
	ctx := context.Background()
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // per-op jitter only, not security
	stats := &soakStats{byKind: map[string]int{}}
	live := w.fuzzLive

	n := len(data)
	if n > fuzzSeqMaxOps {
		n = fuzzSeqMaxOps
	}
	for i := range n {
		kind := soakOpKinds[int(data[i])%len(soakOpKinds)]
		// Steer so a byte stream of all-creates or all-deletes cannot run the live
		// set away or empty it (which would make most ops no-ops).
		switch {
		case kind == "create" && len(live) >= cfg.targetLive*2:
			kind = "delete"
		case (kind == "read" || kind == "update" || kind == "rotate" || kind == "delete") && len(live) == 0:
			kind = "create"
		}
		w.stepKind(kind, rng, &live, stats, cfg)
	}
	w.fuzzLive = live

	// Oracle 1 (scaled down): the audit hash chain must remain intact after any
	// fuzzer-chosen sequence -- a gap, duplicate, or break makes it invalid.
	v, err := w.c.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("[%s] VerifyAuditChain error after sequence %v: %v", w.backend, stats.byKind, err)
	}
	if !v.Valid || v.FirstBrokenID != nil {
		t.Fatalf("[%s] AUDIT CHAIN BROKEN after sequence %v: valid=%v firstBroken=%v reason=%q",
			w.backend, stats.byKind, v.Valid, v.FirstBrokenID, v.Reason)
	}

	// Oracle 2 (scaled down): no per-operation goroutine blow-up.
	if g := runtime.NumGoroutine(); g > baseG+fuzzGoroutineCeiling {
		// Give transient detached writers a moment, then re-check to avoid a flake.
		w.quiesce()
		if g2 := runtime.NumGoroutine(); g2 > baseG+fuzzGoroutineCeiling {
			t.Fatalf("[%s] GOROUTINE RUNAWAY: %d goroutines (baseline %d, ceiling +%d) after sequence %v",
				w.backend, g2, baseG, fuzzGoroutineCeiling, stats.byKind)
		}
	}

	// Keep the cumulative chain-walk cheap: trim to genesis past the ceiling. This
	// also exercises VerifyAuditChain's fresh-genesis path on the next iteration.
	if w.countRows("audit_events") > fuzzTrimCeiling {
		w.fuzzTrim()
	}
}

// fuzzTrim deletes the volatile tables (audit log, secret versions/nodes, sessions)
// in FK-safe order, resetting the world to a clean genesis without a full rebuild.
// users/projects/environments and the admin session are kept so the world stays
// usable; the probe secret is not used by the fuzzer.
func (w *soakWorld) fuzzTrim() {
	for _, tbl := range []string{"audit_events", "secret_versions", "secret_nodes", "sessions"} {
		w.db.Exec("DELETE FROM " + tbl) // tbl is a hardcoded literal, never external input
	}
	w.fuzzLive = nil
	// Re-login the admin: its session row was just deleted.
	if sess, _, err := w.c.Login(context.Background(), &core.LoginRequest{Username: "soakadmin", Password: "SoakPassword123!"}); err == nil && sess != nil {
		w.adminTok = sess.SessionToken
	}
}
