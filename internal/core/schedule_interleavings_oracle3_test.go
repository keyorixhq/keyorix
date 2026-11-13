package core

import (
	"context"
	"testing"
)

// TestOracle3_AuditChain_RedGreen proves oracle 3 fires: the integrity half on a
// corrupted hash chain, and the count half when the chain gains the wrong number
// of events for the observed successful ops. GREEN counterparts confirm both pass
// on an intact chain / correct count (the "both directions" discipline).
func TestOracle3_AuditChain_RedGreen(t *testing.T) {
	ctx := context.Background()

	// GREEN integrity + count: one successful audited revoke -> exactly 1 event.
	w := newSQLiteWorld(t)
	defer func() { _ = w.st.Close() }()
	prog := schedProgram{domain: dmAudit, split: 1, ops: []schedOp{{kind: opAuditMutate}}}
	w.seedFixture(ctx, prog)
	baseC, baseU, _ := w.drainAudit(t)
	if _, err := w.c.RevokeOwnPAT(ctx, w.adminID, w.auditPAT[0].id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	observed := []opResult{{class: clOK}}
	if err := checkAuditCountAndChain(t, w, prog, observed, baseC, baseU); err != nil {
		t.Fatalf("GREEN (1 revoke -> 1 event) should pass: %v", err)
	}

	// RED count: claim a successful revoke happened (expect 1 event) but do NOT
	// perform it -- the chain gained 0. This is the shape a revoke that silently
	// skipped its audit append would produce.
	baseC2, baseU2, _ := w.drainAudit(t)
	if err := checkAuditCountAndChain(t, w, prog, observed, baseC2, baseU2); err == nil {
		t.Fatalf("RED (claimed revoke, no audit event) should FAIL oracle 3 count, but passed")
	}

	// RED integrity: corrupt one audit rows entry_hash so the hash chain no longer
	// verifies; checkAuditChain must report the break.
	if err := w.db.Exec("UPDATE audit_events SET entry_hash = ? WHERE id = (SELECT MIN(id) FROM audit_events WHERE entry_hash != ?)", "deadbeef", "").Error; err != nil {
		t.Fatalf("corrupt chain: %v", err)
	}
	if _, err := checkAuditChain(t, w, baseU2); err == nil {
		t.Fatalf("RED (corrupted entry_hash) should FAIL oracle 3 integrity, but passed")
	}
}
