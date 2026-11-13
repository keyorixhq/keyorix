package core

import "testing"

// These self-tests are the "a guard nobody has watched fail is not a guard"
// discipline applied to the serial-equivalence (oracle 1) and post-return
// visibility (oracle 2) checkers: each is exercised against a crafted VALID
// outcome (must pass, green) AND a crafted IMPOSSIBLE outcome (must fail, red),
// so the checkers are proven to fire, not merely to exist. The oracle-3
// (audit chain) and oracle-4 (deadlock/panic/race) teeth are proven by the
// production-code red-proofs documented in out/rc-REPORT.md §7, which cannot be
// expressed as a pure-function self-test.

func TestOracle1_SerialEquivalence_RedGreen(t *testing.T) {
	// GREEN: PAT, two validates both OK, one revoke OK, final NOT revoked is
	// impossible — but validate||revoke with both validates before revoke is a
	// legal serial order, final revoked. Build a consistent observation.
	progPAT := schedProgram{domain: dmPAT, split: 1, ops: []schedOp{
		{kind: opValidate}, {kind: opRevoke},
	}}
	// validate saw OK (ran first), revoke OK, final revoked -> serial [validate,revoke].
	green := []opResult{{class: clOK}, {class: clOK}}
	if err := checkSerialEquivalence(progPAT, green, modelState{revoked: true}); err != nil {
		t.Fatalf("GREEN should pass: %v", err)
	}

	// RED: a revoke returned OK but the final state is NOT revoked. No serial
	// order can produce "revoke ok" and leave the token live. This is exactly
	// the shape a dropped revoke-commit would produce.
	redFinal := modelState{revoked: false}
	if err := checkSerialEquivalence(progPAT, green, redFinal); err == nil {
		t.Fatalf("RED (revoke ok but final not revoked) should FAIL oracle 1, but it passed")
	}

	// RED: secret read returned a value NO update ever wrote. Two updates write
	// "u1"/"u2"; a read observing "u9" is non-serializable.
	progSec := schedProgram{domain: dmSecret, split: 1, ops: []schedOp{
		{kind: opUpdate, arg: 1}, {kind: opRead},
	}}
	redRead := []opResult{{class: clOK}, {class: clOKVal, val: "u9"}}
	if err := checkSerialEquivalence(progSec, redRead, modelState{exists: true, value: "u1"}); err == nil {
		t.Fatalf("RED (read of a never-written value) should FAIL oracle 1, but it passed")
	}

	// GREEN counterpart: read observed "u1" (update ran first) — legal.
	greenRead := []opResult{{class: clOK}, {class: clOKVal, val: "u1"}}
	if err := checkSerialEquivalence(progSec, greenRead, modelState{exists: true, value: "u1"}); err != nil {
		t.Fatalf("GREEN (read of the written value) should pass: %v", err)
	}

	// RED: two concurrent deletes BOTH returned OK. In the model exactly one
	// delete can be ok; the other must be not-found. Both-ok is non-serializable
	// — the precise linearizability break a missing row-lock would cause.
	progDel := schedProgram{domain: dmSecret, split: 1, ops: []schedOp{
		{kind: opDelete}, {kind: opDelete},
	}}
	redBothDel := []opResult{{class: clOK}, {class: clOK}}
	if err := checkSerialEquivalence(progDel, redBothDel, modelState{exists: false}); err == nil {
		t.Fatalf("RED (two deletes both ok) should FAIL oracle 1, but it passed")
	}
	greenOneDel := []opResult{{class: clOK}, {class: clNotFound}}
	if err := checkSerialEquivalence(progDel, greenOneDel, modelState{exists: false}); err != nil {
		t.Fatalf("GREEN (one delete ok, one not-found) should pass: %v", err)
	}

	// RED: two concurrent grants BOTH returned OK. Exactly one grant can be ok;
	// the other must be a conflict.
	progGrant := schedProgram{domain: dmRole, split: 1, ops: []schedOp{
		{kind: opRevokeRole}, {kind: opGrantRole}, {kind: opGrantRole},
	}}
	// after a revoke, two grants: one ok one conflict. both-ok is impossible.
	redBothGrant := []opResult{{class: clOK}, {class: clOK}, {class: clOK}}
	if err := checkSerialEquivalence(progGrant, redBothGrant, modelState{hasRole: true}); err == nil {
		t.Fatalf("RED (two grants both ok) should FAIL oracle 1, but it passed")
	}
}

func TestOracle2_PostReturnVisibility_RedGreen(t *testing.T) {
	// PAT: HB, group1 = revoke (ok), group2 = validate. Oracle 2 requires the
	// group-2 validate to NOT be OK.
	progPAT := schedProgram{domain: dmPAT, hb: true, split: 1, ops: []schedOp{
		{kind: opRevoke}, {kind: opValidate},
	}}
	// RED: validate returned OK after revoke had returned.
	red := []opResult{{class: clOK}, {class: clOK}}
	if err := checkPostReturnVisibility(progPAT, red); err == nil {
		t.Fatalf("RED (validate ok after revoke returned) should FAIL oracle 2, but it passed")
	}
	// GREEN: validate returned revoked.
	green := []opResult{{class: clOK}, {class: clRevoked}}
	if err := checkPostReturnVisibility(progPAT, green); err != nil {
		t.Fatalf("GREEN (validate revoked after revoke) should pass: %v", err)
	}

	// Secret: HB, group1 = delete (ok), group2 = read. Read must be not-found.
	progSec := schedProgram{domain: dmSecret, hb: true, split: 1, ops: []schedOp{
		{kind: opDelete}, {kind: opRead},
	}}
	redSec := []opResult{{class: clOK}, {class: clOKVal, val: "v0"}}
	if err := checkPostReturnVisibility(progSec, redSec); err == nil {
		t.Fatalf("RED (read value after delete returned) should FAIL oracle 2, but it passed")
	}
	greenSec := []opResult{{class: clOK}, {class: clNotFound}}
	if err := checkPostReturnVisibility(progSec, greenSec); err != nil {
		t.Fatalf("GREEN (read not-found after delete) should pass: %v", err)
	}

	// Role: HB, group1 = revoke (ok), group2 = authorize (no re-grant). Must deny.
	progRole := schedProgram{domain: dmRole, hb: true, split: 1, ops: []schedOp{
		{kind: opRevokeRole}, {kind: opAuthorize},
	}}
	redRole := []opResult{{class: clOK}, {class: clAuthzTrue}}
	if err := checkPostReturnVisibility(progRole, redRole); err == nil {
		t.Fatalf("RED (authorize true after role revoke returned) should FAIL oracle 2, but it passed")
	}
	greenRole := []opResult{{class: clOK}, {class: clAuthzFalse}}
	if err := checkPostReturnVisibility(progRole, greenRole); err != nil {
		t.Fatalf("GREEN (authorize false after role revoke) should pass: %v", err)
	}

	// Role, in-group-1 re-grant: HB, group1 = revokeRole(ok) + grantRole(ok)
	// (concurrent, no HB edge between them), group2 = authorize. Because a legal
	// serialization runs the grant last, the role may legitimately be HELD at the
	// boundary, so authorize=true MUST NOT be flagged (oracle 1 judges this case).
	// This is the regression guard for the FuzzScheduleInterleavings/b78054a10a72fe74
	// false positive: without the g1HasGrant skip this outcome was wrongly rejected.
	progRegrant := schedProgram{domain: dmRole, hb: true, split: 2, ops: []schedOp{
		{kind: opRevokeRole}, {kind: opGrantRole}, {kind: opAuthorize},
	}}
	regrantTrue := []opResult{{class: clOK}, {class: clOK}, {class: clAuthzTrue}}
	if err := checkPostReturnVisibility(progRegrant, regrantTrue); err != nil {
		t.Fatalf("GREEN (authorize true after revoke+concurrent regrant in group 1) should pass: %v", err)
	}
	// And authorize=false is equally legal for the same program (revoke runs last).
	regrantFalse := []opResult{{class: clOK}, {class: clOK}, {class: clAuthzFalse}}
	if err := checkPostReturnVisibility(progRegrant, regrantFalse); err != nil {
		t.Fatalf("GREEN (authorize false after revoke+concurrent regrant in group 1) should pass: %v", err)
	}
}
