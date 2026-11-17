// redproof_test.go proves the oracles in commit_oracle_test.go have teeth: each
// plants the exact violation its oracle exists to catch and confirms the oracle
// goes red, then the throwaway database is dropped (restore) on cleanup. Per
// FS-PG RULES — a guard nobody has watched fail is not a guard — and the planted
// defect lives in the fault's own effect surface (the audit rows), never in
// production code.
package pgfault

import (
	"context"
	"testing"
)

// TestPGFault_RedProof_FaultIsLoadBearing proves the proxy cut actually
// INTERRUPTS a commit — without this, the oracle sweep could be green simply
// because nothing ever broke. A cut placed in the backend ack stream during a
// burst must leave at least one attempted commit UN-acknowledged (its ack was
// cut), i.e. fewer acks than attempts, and the fault must report tripped.
func TestPGFault_RedProof_FaultIsLoadBearing(t *testing.T) {
	w := newPGWorld(t)
	const attempts = warmupCommits + 16
	sawInterruption := false
	for _, n := range []int{1, 2, 3, 4, 5} {
		o := runFaultCase(t, w, faultSpec{mode: faultCut, dir: dirBackend, n: n}, 16)
		if !o.tripped {
			continue
		}
		if len(o.acked) < attempts {
			sawInterruption = true
			t.Logf("cut backend n=%d: %d/%d commits acked (at least one interrupted)", n, len(o.acked), attempts)
			break
		}
	}
	if !sawInterruption {
		t.Fatal("no cut ever left a commit un-acknowledged — the proxy fault is not interrupting commits, so the oracle sweep would be vacuous")
	}
}

// TestPGFault_RedProof_OracleDetectsLostAck plants ORACLE 1's violation: after a
// clean faulted run (oracles green), delete one ACKNOWLEDGED row from the DB and
// confirm the oracle now reports it as a lost acknowledged commit.
func TestPGFault_RedProof_OracleDetectsLostAck(t *testing.T) {
	w := newPGWorld(t)
	o := runFaultCase(t, w, faultSpec{mode: faultCut, dir: dirBackend, n: 3}, 20)
	if len(o.acked) == 0 {
		t.Fatal("no acked commits to plant with")
	}
	// Green first: the real run must satisfy ORACLE 1.
	if miss := missingAcked(o); len(miss) > 0 {
		t.Fatalf("precondition: real run already lost acked commits %v — cannot cleanly red-proof", miss)
	}

	// Plant: delete one acknowledged commit from the DB (simulating a backend
	// that lost an acknowledged write).
	victim := sortedCopy(o.acked)[len(o.acked)/2]
	if err := w.verify.Exec(
		"DELETE FROM audit_events WHERE event_type = 'pgfault.commit' AND description = ?",
		"pc-"+itoa(victim)).Error; err != nil {
		t.Fatalf("plant delete: %v", err)
	}

	// Red: re-read present and confirm the oracle now fires on exactly the victim.
	planted := faultOutcome{acked: o.acked, present: w.presentIndices(t)}
	miss := missingAcked(planted)
	if len(miss) != 1 || miss[0] != victim {
		t.Fatalf("ORACLE 1 red-proof: expected it to flag lost acked commit %d, got %v", victim, miss)
	}
	t.Logf("ORACLE 1 red-proof ok: flagged planted lost acked commit %d", victim)
}

// TestPGFault_RedProof_OracleDetectsBrokenChain plants ORACLE 2's violation:
// after a clean run, tamper with a committed row so the hash chain no longer
// links, and confirm VerifyAuditChain reports it invalid.
func TestPGFault_RedProof_OracleDetectsBrokenChain(t *testing.T) {
	w := newPGWorld(t)
	o := runFaultCase(t, w, faultSpec{mode: faultCut, dir: dirBackend, n: 4}, 20)

	// Green first.
	ctx := context.Background()
	res, err := o.verify.VerifyAuditChain(ctx, nil)
	if err != nil || res == nil || !res.Valid {
		t.Fatalf("precondition: real run chain not valid (err=%v res=%+v) — cannot cleanly red-proof", err, res)
	}
	if res.ChainedEvents < 2 {
		t.Fatalf("precondition: need >=2 chained events to tamper, got %d", res.ChainedEvents)
	}

	// Plant: mutate the payload of a middle row WITHOUT recomputing its hash, so
	// the stored hash no longer matches the row content and the next row's
	// prev_hash no longer links.
	if err := w.verify.Exec(
		"UPDATE audit_events SET description = 'tampered' " +
			"WHERE id = (SELECT id FROM audit_events ORDER BY id LIMIT 1 OFFSET 1)").Error; err != nil {
		t.Fatalf("plant tamper: %v", err)
	}

	// Red.
	res2, err := w.verifyStorage().VerifyAuditChain(ctx, nil)
	if err != nil {
		t.Fatalf("ORACLE 2 red-proof: VerifyAuditChain errored unexpectedly: %v", err)
	}
	if res2 == nil || res2.Valid {
		t.Fatalf("ORACLE 2 red-proof: expected chain INVALID after tamper, got %+v", res2)
	}
	t.Logf("ORACLE 2 red-proof ok: chain reported invalid after planted tamper (firstBroken=%v)", res2.FirstBrokenID)
}
