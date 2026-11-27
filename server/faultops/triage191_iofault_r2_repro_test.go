package faultops

// triage191_iofault_r2_repro_test.go — TRIAGE-191-IOFAULT-R2 (fuzz-corpus#191).
//
// Reproduces the CI finding: op "REST POST /api/v1/secret-templates/{id}/apply",
// fault enospc-before at statement 1, STICKY. The faulted statement 1 is the
// middleware cache-hit session-liveness read (GetSessionAuthLiveness); the op
// reports SUCCESS and writes no audit event although the fault-free run writes 1.
//
// These tests are INVESTIGATIVE (not product changes). They drive the REAL
// httptest server + auth middleware (world.httpServer), so the demonstration
// runs at the layer a live caller drives, not only at the storage layer.
//
// Verdict they establish:
//   Q1 (fail-open?): NO. Under a sticky ENOSPC a full disk still serves READS,
//      so GetSessionAuthLiveness's documented per-statement fallback
//      (ComposeSessionAuthLiveness: two SELECTs) returns a GENUINE "session is
//      live" answer and the request is correctly authenticated. The same op
//      under a sticky EIO (which fails reads too) is REFUSED with 503
//      (INV-MW-cache-hit-recheck-fails-closed). The path is fail-CLOSED when the
//      liveness answer is truly unknown; it is not fail-open.
//   Q2 (missing audit): the apply is a read-only dry-run; its only write is the
//      best-effort LogSecretTemplateApplied audit append AFTER success. Under a
//      sticky disk that write fails too and is swallowed by design. So the
//      missing audit IS explained by the (sticky) fault — R2's premise ("the
//      faulted statement was not an audit write, so the loss is unexplained") is
//      invalid for a sticky fault. The live harness already gates R2 off for a
//      sticky disk fault (fuzz_io_fault_operations_test.go: `if !stickyDisk`).
//
// What these tests do NOT verify: that no OTHER op loses an owed audit under a
// non-sticky fault (that is the owed-audit oracle's job); the error text of the
// 503; PostgreSQL-specific behaviour (SQLite backend here unless KEYORIX_TEST_PG_DSN).

import (
	"context"
	"strings"
	"testing"
)

const triage191ApplyOpKey = "REST POST /api/v1/secret-templates/{id}/apply"

func triage191ApplyOp(tb testing.TB) operation {
	tb.Helper()
	for _, op := range opCatalog {
		if op.Key == triage191ApplyOpKey {
			return op
		}
	}
	tb.Fatalf("op %q not in opCatalog", triage191ApplyOpKey)
	return operation{}
}

func triage191AuditCount(s dbSnapshot) int { return len(s.Tables["AuditEvent"].Rows) }

// Test_Triage191_ApplyUnderStickyENOSPC_AuthenticatesAndDropsAudit reproduces the
// finding end-to-end through the real router+middleware and shows WHY:
//   - fault-free apply writes exactly 1 audit event (the baseline the oracle uses)
//   - the faulted statement 1 is attributed to GetSessionAuthLiveness, a SELECT
//     (not an audit write) — exactly what the R2 message asserts
//   - the request nonetheless succeeds (HTTP 2xx): the liveness read-fallback
//     survives a full disk, so auth is NOT fail-open — it got a real "live" answer
//   - it writes 0 audit events: the best-effort audit append (a WRITE) also hit
//     the sticky ENOSPC and was swallowed — the loss IS explained by the fault
func Test_Triage191_ApplyUnderStickyENOSPC_AuthenticatesAndDropsAudit(t *testing.T) {
	_, w, pool := newIOFaultTestWorlds(t)
	ctx := context.Background()
	op := triage191ApplyOp(t)

	// A reusable world is inert until reset: resetForReuse re-bootstraps, logs in
	// and populates w.adminToken (the same first step runIOFaultIteration runs).
	w.resetForReuse(t, nil)

	// Setup creates the template AND makes the first authenticated HTTP request,
	// which caches the admin session token (slow path).
	state, err := op.Setup(ctx, w)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Warm-up apply (unfaulted) — this is now a cache HIT, so the next faulted
	// request's statement 1 is the cache-hit liveness read, matching the seed.
	if r, err := op.Execute(ctx, w, state); err != nil || !r.Success {
		t.Fatalf("warm-up apply failed: %v %s", err, r.Detail)
	}
	drainAllBackgroundGoroutines()
	s0, err := snapshotDB(w.db)
	if err != nil {
		t.Fatalf("snapshot s0: %v", err)
	}

	// Fault-free reference run: one apply, count the audit delta.
	refRes, err := op.Execute(ctx, w, state)
	if err != nil || !refRes.Success {
		t.Fatalf("fault-free apply failed: %v %s", err, refRes.Detail)
	}
	drainAllBackgroundGoroutines()
	s1, err := snapshotDB(w.db)
	if err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	cleanDelta := triage191AuditCount(s1) - triage191AuditCount(s0)
	t.Logf("fault-free apply: success=%v audit_delta=%d detail=%s", refRes.Success, cleanDelta, refRes.Detail)
	if cleanDelta != 1 {
		t.Fatalf("expected the fault-free apply to write exactly 1 audit event, got %d (fixture drift)", cleanDelta)
	}

	// Faulted run: sticky ENOSPC armed at statement 1.
	pool.Arm(&ioFault{kind: ioDiskFullBefore, at: 1, sticky: true})
	faultRes, err := op.Execute(ctx, w, state)
	fired, attr := pool.Fired()
	pool.Disarm()
	if err != nil {
		t.Fatalf("faulted apply returned a transport error: %v", err)
	}
	drainAllBackgroundGoroutines()
	s2, err := snapshotDB(w.db)
	if err != nil {
		t.Fatalf("snapshot s2: %v", err)
	}
	faultDelta := triage191AuditCount(s2) - triage191AuditCount(s1)

	t.Logf("faulted apply: fired=%v success=%v audit_delta=%d", fired, faultRes.Success, faultDelta)
	t.Logf("attributed faulted statement: method=%q nth=%d sql=%q", attr.method, attr.nth, attr.sql)
	t.Logf("faulted apply detail: %s", faultRes.Detail)

	if !fired {
		t.Fatalf("the fault never fired at statement 1 — the request issued no SQL (cache not warm?)")
	}
	// The faulted statement is the middleware cache-hit liveness read, a SELECT.
	if attr.method != "GetSessionAuthLiveness" {
		t.Fatalf("expected statement 1 to be attributed to GetSessionAuthLiveness (the cache-hit liveness read), got %q — cache was not warm, reproduction not valid", attr.method)
	}
	if strings.Contains(strings.ToLower(attr.sql), "audit") || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(attr.sql)), "SELECT") {
		t.Fatalf("expected the faulted statement to be a non-audit SELECT, got %q", attr.sql)
	}
	// Q1: NOT fail-open — the request succeeded because the liveness read-fallback
	// genuinely confirmed the session is live (a full disk still serves reads).
	if !faultRes.Success {
		t.Fatalf("expected the apply to succeed under a sticky ENOSPC (read-fallback confirms liveness), got failure: %s", faultRes.Detail)
	}
	// Q2: the audit append (a WRITE) also hit the sticky fault and was swallowed.
	if faultDelta != 0 {
		t.Fatalf("expected 0 audit events under the sticky disk, got %d", faultDelta)
	}
	t.Logf("VERDICT Q1: authenticated via liveness read-fallback (NOT fail-open); Q2: best-effort audit append lost to the SAME sticky disk (loss explained by the fault)")
}

// triage191CacheHitRefusal is refuseUnverifiedCacheHit's fixed answer
// (server/middleware/auth.go): the cache-hit re-check could not be completed.
const triage191CacheHitRefusal = "authentication temporarily unavailable, please retry"

// Test_Triage191_ApplyUnderStickyEIO_FailsClosed is the fail-OPEN control: a
// sticky EIO fails reads too, so the liveness read-fallback cannot answer and the
// middleware MUST refuse (503, INV-MW-cache-hit-recheck-fails-closed). This is the
// evidence the ENOSPC success is correct authentication, not a fail-open: when the
// liveness answer is genuinely unknown, the request is refused BY THE MIDDLEWARE.
//
// "Refused" alone would not tell the two apart: a fail-open middleware would pass
// the request on and the handler's own template read would then fail under the same
// sticky EIO. So the at=1 case requires the middleware's own 503 and fixed message,
// and the at=2 case (the liveness read succeeds, a later statement fails) shows that
// a refusal from past the middleware does NOT carry that message, i.e. the at=1
// assertion discriminates.
//
// What it does NOT verify: a cold cache (the slow-path ValidateSessionToken read,
// covered by the middleware's own tests), a PAT or machine token (other cache-hit
// branches), PostgreSQL unless KEYORIX_TEST_PG_DSN is set.
func Test_Triage191_ApplyUnderStickyEIO_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		at           int
		wantMWRefuse bool
	}{
		{"liveness-read-faulted", 1, true},
		{"later-statement-faulted", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w, pool := newIOFaultTestWorlds(t)
			ctx := context.Background()
			op := triage191ApplyOp(t)

			w.resetForReuse(t, nil)
			state, err := op.Setup(ctx, w)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			if r, err := op.Execute(ctx, w, state); err != nil || !r.Success {
				t.Fatalf("warm-up apply failed: %v %s", err, r.Detail)
			}
			drainAllBackgroundGoroutines()

			pool.Arm(&ioFault{kind: ioEIOBefore, at: tc.at, sticky: true})
			res, err := op.Execute(ctx, w, state)
			fired, attr := pool.Fired()
			pool.Disarm()
			drainAllBackgroundGoroutines()
			if err != nil {
				t.Fatalf("faulted apply returned a transport error: %v", err)
			}
			t.Logf("sticky-EIO@%d apply: fired=%v success=%v method=%q detail=%s", tc.at, fired, res.Success, attr.method, res.Detail)
			if !fired {
				t.Fatalf("the EIO fault never fired at statement %d", tc.at)
			}
			if res.Success {
				t.Fatalf("FAIL-OPEN: a sticky EIO at statement %d yielded a SUCCESS (%s)", tc.at, res.Detail)
			}
			mwRefused := strings.HasPrefix(res.Detail, "HTTP 503:") && strings.Contains(res.Detail, triage191CacheHitRefusal)
			if tc.wantMWRefuse {
				if attr.method != "GetSessionAuthLiveness" {
					t.Fatalf("expected statement 1 attributed to GetSessionAuthLiveness (cache-hit liveness read), got %q: cache not warm, reproduction not valid", attr.method)
				}
				if !mwRefused {
					t.Fatalf("FAIL-OPEN: the liveness read failed and the fallback could not answer, but the middleware did not refuse with its 503 %q; the request got past it: %s", triage191CacheHitRefusal, res.Detail)
				}
				return
			}
			if attr.method == "GetSessionAuthLiveness" {
				t.Fatalf("control invalid: statement %d is still the liveness read", tc.at)
			}
			if mwRefused {
				t.Fatalf("control invalid: a fault past the liveness read still produced the middleware's refusal (%s), so the at=1 assertion cannot discriminate", res.Detail)
			}
		})
	}
	t.Logf("VERDICT Q1: sticky EIO on the liveness read => refused by the auth middleware (503) => fail-closed, not fail-open")
}

// Test_Triage191_R2OraclePremiseInvalidUnderSticky is the oracle-artefact proof.
//
// RED: the raw R2 check (ioCheckSuccessHasAudit) DOES flag this shape — a success
// with no audit, attributed to a non-audit SELECT — exactly the false positive CI
// reported, because the raw check only inspects the ATTRIBUTED statement.
//
// GREEN: the live harness (runIOFaultIteration via runIOCase) does NOT surface an
// R2 violation for the real sticky seed, because it gates R2 off for a sticky disk
// fault (`if !stickyDisk`). The gate is therefore load-bearing and already correct
// on main; the finding is a harness/oracle artefact, not a product defect.
func Test_Triage191_R2OraclePremiseInvalidUnderSticky(t *testing.T) {
	// RED: raw oracle on the exact shape (ref=1 audit, after=0), attributed to the
	// non-audit liveness SELECT. It flags — that is the premise that is wrong.
	row := func(n int) dbSnapshot {
		s := dbSnapshot{Tables: map[string]tableSnapshot{}}
		s.Tables["AuditEvent"] = tableSnapshot{Table: "AuditEvent", Rows: make([]string, n)}
		return s
	}
	livenessAttr := ioAttribution{
		method: "GetSessionAuthLiveness",
		sql:    "SELECT u.id AS user_id, u.is_active, s.id AS session_id FROM users u LEFT JOIN sessions s ON s.id = ?",
	}
	raw := ioCheckSuccessHasAudit(triage191ApplyOpKey, true, livenessAttr, row(0), row(0), row(1))
	if len(raw) != 1 || !strings.Contains(raw[0], "R2 VIOLATION") {
		t.Fatalf("RED PROOF FAILED: the raw R2 oracle did not flag the reported shape: %v", raw)
	}
	t.Logf("RED (raw oracle, ungated): %s", raw[0])

	// GREEN: the full harness on the real sticky seed surfaces no R2 violation.
	ref, w, pool := newIOFaultTestWorlds(t)
	seed := ioSeed(triage191ApplyOpKey, ioDiskFullBefore, 1, true)
	if seed == nil {
		t.Fatalf("could not build seed for %q", triage191ApplyOpKey)
	}
	out, findings, notEval := runIOCase(t, ref, w, pool, seed, nil)
	t.Logf("GREEN (full harness on seed %x): fired=%v success=%v attr=%s#%d notEvaluated=%q findings=%v",
		seed, out.fired, out.success, out.attr.method, out.attr.nth, notEval, findings)
	for _, f := range findings {
		if strings.Contains(f, "R2 VIOLATION") {
			t.Fatalf("the live harness surfaced an R2 violation for the sticky seed — the !stickyDisk gate is not suppressing it: %s", f)
		}
	}
	// No R2 finding means nothing unless the case really reached the shape CI saw:
	// evaluated, fired on the cache-hit liveness read, and reported success.
	if notEval != "" || !out.fired || !out.success || out.attr.method != "GetSessionAuthLiveness" {
		t.Fatalf("GREEN is vacuous: the seed did not reproduce the #191 shape (notEvaluated=%q fired=%v success=%v attr=%q)",
			notEval, out.fired, out.success, out.attr.method)
	}
	t.Logf("VERDICT: R2 premise invalid under a sticky fault; the live harness's !stickyDisk gate already suppresses it => harness/oracle ARTEFACT")
}
