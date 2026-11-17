// commit_oracle_test.go is the real-PostgreSQL durability oracle for a TCP
// connection fault (class a) during keyorix's audit-commit path. It is the
// direct counterpart to scripts/powercut's SQLite oracle, restated for a wire
// fault instead of a block-device power cut:
//
//   ORACLE 1 (no acknowledged commit lost): every LogAuditEvent that returned
//     nil (the client saw the commit acknowledged) must be present in the
//     database after the connection is cut and re-established. A TCP fault can
//     only ever error the ONE in-flight commit; it can never retroactively
//     unmake a commit the server already acknowledged.
//
//   ORACLE 2 (chain intact / no torn row): VerifyAuditChain must pass after the
//     fault. PostgreSQL's MVCC+WAL make a row all-or-nothing, so a cut can never
//     leave half an audit row or a broken hash link — this oracle is the check
//     that that holds in practice through keyorix's batched group-commit path.
//
//   ORACLE 3 (ambiguous commit is never a false success): the quadrant that is
//     forbidden is acknowledged-but-absent. A row that is PRESENT but was NOT
//     acknowledged (server committed, the ack was lost in the cut) is the
//     legitimate ambiguous-commit window and is allowed — the client correctly
//     saw an error, not a false success. What must never happen is the reverse:
//     the client sees success while the row is gone.
//
// What this does NOT verify: disk-full / read-only-filesystem errors, and
// crash-recovery of the server itself (classes b and c) — both need a cluster
// this host cannot start (see the FSPG report). It also does not cover
// multi-statement application transactions beyond the audit path, nor retry
// idempotency of a non-idempotent op (LogAuditEvent appends unconditionally).
package pgfault

import (
	"context"
	"slices"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	warmupCommits = 3
	perCommit     = 4 * time.Second
)

// faultOutcome is everything the oracles inspect about one fault case.
type faultOutcome struct {
	acked   []int        // indices whose commit returned nil (warmup + burst)
	present map[int]bool // indices actually in the DB after the cut
	tripped bool         // the proxy fault actually fired
	verify  *store.LocalStorage
}

// runFaultCase truncates, warms the connection with warmupCommits unfaulted
// commits, arms spec, runs burstN faulted commits, disarms, and reads back the
// state through the DIRECT handle (which never saw the fault). Uses the default
// perCommit deadline.
func runFaultCase(t *testing.T, w *pgWorld, spec faultSpec, burstN int) faultOutcome {
	return runFaultCaseT(t, w, spec, burstN, perCommit)
}

// runFaultCaseT is runFaultCase with a caller-chosen per-commit deadline (the
// fuzz target uses a shorter one to keep per-input wall time bounded).
func runFaultCaseT(t *testing.T, w *pgWorld, spec faultSpec, burstN int, perCommit time.Duration) faultOutcome {
	t.Helper()
	w.truncate(t)
	ls := openProxiedStorage(t, w)
	defer func() { _ = ls.Close() }()

	ctx := context.Background()
	acked := commitRange(ctx, ls, 0, warmupCommits, perCommit)

	w.proxy.Arm(spec)
	acked = append(acked, commitRange(ctx, ls, warmupCommits, burstN, perCommit)...)
	w.proxy.Disarm()

	present := w.presentIndices(t)
	return faultOutcome{acked: acked, present: present, tripped: w.proxy.Tripped(), verify: w.verifyStorage()}
}

// missingAcked returns acked indices that are NOT present — ORACLE 1 violations.
func missingAcked(o faultOutcome) []int {
	var miss []int
	for _, i := range o.acked {
		if !o.present[i] {
			miss = append(miss, i)
		}
	}
	return miss
}

// assertOracles applies oracles 1–3 to one outcome.
func assertOracles(t *testing.T, label string, o faultOutcome) {
	t.Helper()
	// ORACLE 1 + 3: acknowledged ⇒ present (no lost ack, no false success).
	if miss := missingAcked(o); len(miss) > 0 {
		t.Errorf("%s: ORACLE 1 VIOLATION — acknowledged commits lost after cut: %v", label, miss)
	}
	// ORACLE 2: chain intact.
	res, err := o.verify.VerifyAuditChain(context.Background(), nil)
	if err != nil {
		t.Errorf("%s: ORACLE 2 — VerifyAuditChain errored: %v", label, err)
		return
	}
	if res == nil || !res.Valid {
		t.Errorf("%s: ORACLE 2 VIOLATION — audit chain broken after cut: %+v", label, res)
	}
}

// TestPGFault_ConnectionCut sweeps a cut at many protocol points, in both
// directions, across a commit burst. Whatever commit the cut lands on, the
// oracles must hold. At least one swept case must actually trip the fault, or
// the sweep proved nothing.
func TestPGFault_ConnectionCut(t *testing.T) {
	w := newPGWorld(t)
	anyTripped := false
	// backend direction n: the Nth server->client message after arm — the
	// ReadyForQuery / CommandComplete that acknowledges a COMMIT lives here, so
	// small n lands in or just after the first burst commit's ack window.
	// frontend direction n: the Nth client->server message — Parse/Bind/Execute/
	// Sync of a commit, i.e. the cut arrives before the server ever sees COMMIT.
	for _, dir := range []int{dirBackend, dirFrontend} {
		for _, n := range []int{1, 2, 4, 7, 12, 20} {
			spec := faultSpec{mode: faultCut, dir: dir, n: n}
			o := runFaultCase(t, w, spec, 24)
			assertOracles(t, label(dir, n, "cut"), o)
			if o.tripped {
				anyTripped = true
			}
		}
	}
	if !anyTripped {
		t.Fatal("no swept cut case ever tripped the fault — the sweep verified nothing")
	}
}

// TestPGFault_StallThenCut arms a stall that holds the stream past the client's
// per-commit deadline, then cuts — the ambiguous stall shape. The oracles must
// still hold: a commit that times out on the client is either absent or a
// legitimate present-but-unacked row, never an acknowledged-but-absent one.
func TestPGFault_StallThenCut(t *testing.T) {
	w := newPGWorld(t)
	anyTripped := false
	for _, n := range []int{1, 3, 6} {
		spec := faultSpec{mode: faultStall, dir: dirBackend, n: n, stallFor: perCommit + 2*time.Second}
		o := runFaultCase(t, w, spec, 12)
		assertOracles(t, label(dirBackend, n, "stall"), o)
		if o.tripped {
			anyTripped = true
		}
	}
	if !anyTripped {
		t.Fatal("no swept stall case ever tripped the fault")
	}
}

func label(dir, n int, mode string) string {
	d := "backend"
	if dir == dirFrontend {
		d = "frontend"
	}
	return mode + "/" + d + "/n=" + itoa(n)
}

var _ corestorage.Storage = (*store.LocalStorage)(nil)

// slicesEqualSorted is a small helper for the red-proof tests.
func sortedCopy(in []int) []int {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
