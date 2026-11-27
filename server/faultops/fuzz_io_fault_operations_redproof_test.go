package faultops

// fuzz_io_fault_operations_redproof_test.go: the red proofs and reach checks for
// FuzzIOFaultOperations. Every oracle is shown RED against a planted defect and
// GREEN on the real code, in one run, so a harness that stops detecting fails here.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

func newIOFaultTestWorlds(t *testing.T) (ref, w *faultWorld, pool *ioFaultPool) {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	ref = buildReusableFaultWorld(t, nil)
	w = buildReusableFaultWorld(t, nil)
	pool = installIOFaultPool(t, w)
	return ref, w, pool
}

// runIOCase drives one input and returns the oracle findings instead of failing.
func runIOCase(t *testing.T, ref, w *faultWorld, pool *ioFaultPool, data []byte, plant *ioPlant) (ioOutcome, []string, string) {
	t.Helper()
	sink := &driveSink{t: t}
	var out ioOutcome
	func() {
		defer func() { rethrowUnlessDriveAbort(recover()) }()
		out = runIOFaultIteration(t, sink, data, ref, w, pool, plant)
	}()
	return out, sink.findings, sink.notEvaluated
}

// TestIOFaultSeedsReachRealCode: every committed seed must actually fire its fault
// on the real storage path, otherwise the seed is a no-op that looks like coverage.
func TestIOFaultSeedsReachRealCode(t *testing.T) {
	ref, w, pool := newIOFaultTestWorlds(t)
	seeds := ioFaultSeeds()
	if len(seeds) < 8 {
		t.Fatalf("only %d seeds resolved against opCatalog: an op key drifted", len(seeds))
	}
	fired := 0
	for _, s := range seeds {
		out, findings, notEval := runIOCase(t, ref, w, pool, s, nil)
		if notEval != "" {
			t.Errorf("seed %x was not evaluated: %s", s, notEval)
			continue
		}
		if out.fired {
			fired++
		} else {
			t.Errorf("seed %x never fired its fault: it reaches no statement, move its ordinal", s)
		}
		for _, f := range findings {
			t.Errorf("seed %x: %s", s, f)
		}
	}
	t.Logf("%d/%d seeds fired on %s", fired, len(seeds), w.backend)
}

// TestIOFaultRedProof_SuccessAfterFailedDurableWrite plants the defect "a write that
// hit ENOSPC/EIO is reported as a success". The state oracle must flag it for at
// least one ordinal, and the same sweep on the real code must not flag that ordinal.
func TestIOFaultRedProof_SuccessAfterFailedDurableWrite(t *testing.T) {
	ref, w, pool := newIOFaultTestWorlds(t)
	flaggedPlanted, flaggedReal := 0, 0
	for _, k := range []ioFaultKind{ioDiskFullBefore, ioEIOBefore} {
		for at := 1; at <= 16; at++ {
			data := ioSeed("REST POST /api/v1/secrets/", k, at)
			if data == nil {
				t.Fatal("op REST POST /api/v1/secrets/ is not in opCatalog")
			}
			_, planted, ne := runIOCase(t, ref, w, pool, data, &ioPlant{swallowWrites: true})
			if ne != "" {
				continue
			}
			_, real, _ := runIOCase(t, ref, w, pool, data, nil)
			if hasORACLEa(planted) {
				flaggedPlanted++
				if hasORACLEa(real) {
					flaggedReal++
					t.Errorf("REAL FINDING candidate: %s at %d is flagged on the unplanted code too: %v", k, at, real)
				}
			}
		}
	}
	if flaggedPlanted == 0 {
		t.Fatalf("RED PROOF FAILED: the planted success-after-failed-write was never flagged")
	}
	t.Logf("planted defect flagged at %d (kind,ordinal) points; the real code flagged %d of those", flaggedPlanted, flaggedReal)
}

func hasORACLEa(findings []string) bool {
	for _, f := range findings {
		if strings.Contains(f, "ORACLE (a)") || strings.Contains(f, "ORACLE (d)") {
			return true
		}
	}
	return false
}

// TestIOFaultRedProof_RecoveryOracles: R1 on a broken audit chain and a leaked
// connection, R2 on a lost audit event, R3 on a canary in a log line. Each case is
// the oracle function on a planted input, plus the same call on a clean input.
func TestIOFaultRedProof_RecoveryOracles(t *testing.T) {
	ref, w, _ := newIOFaultTestWorlds(t)
	ctx := context.Background()
	w.resetForReuse(t, nil)
	_ = ref

	t.Run("audit chain: green then red", func(t *testing.T) {
		if f := ioCheckRecovery(ctx, w); len(f) != 0 {
			t.Fatalf("clean world flagged: %v", f)
		}
		if err := w.db.Exec("UPDATE audit_events SET description = description || 'tampered' WHERE id = (SELECT MIN(id) FROM (SELECT id FROM audit_events) AS m)").Error; err != nil {
			t.Fatalf("plant: %v", err)
		}
		f := ioCheckRecovery(ctx, w)
		if len(f) == 0 || !strings.Contains(strings.Join(f, "\n"), "audit chain") {
			t.Fatalf("RED PROOF FAILED: a tampered audit row was not reported: %v", f)
		}
	})

	t.Run("connection leak: green then red", func(t *testing.T) {
		w.resetForReuse(t, nil)
		if f := ioCheckPoolQuiescent(w.db); len(f) != 0 {
			t.Fatalf("clean pool flagged: %v", f)
		}
		sqlDB, _ := w.db.DB()
		conn, err := sqlDB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		f := ioCheckPoolQuiescent(w.db)
		_ = conn.Close()
		if len(f) == 0 {
			t.Fatalf("RED PROOF FAILED: a held connection was not reported (waited %v)", time.Since(start))
		}
		if f := ioCheckPoolQuiescent(w.db); len(f) != 0 {
			t.Fatalf("pool still flagged after the connection was released: %v", f)
		}
	})

	t.Run("lost audit event: green then red", func(t *testing.T) {
		row := func(n int) dbSnapshot {
			s := dbSnapshot{Tables: map[string]tableSnapshot{}}
			rows := make([]string, n)
			s.Tables["AuditEvent"] = tableSnapshot{Table: "AuditEvent", Rows: rows}
			return s
		}
		attr := ioAttribution{method: "CreateSecret", sql: "INSERT INTO secret_nodes"}
		if f := ioCheckSuccessHasAudit("REST POST /api/v1/secrets/", true, attr, row(2), row(3), row(3)); len(f) != 0 {
			t.Fatalf("a success with its audit event was flagged: %v", f)
		}
		if f := ioCheckSuccessHasAudit("REST POST /api/v1/secrets/", true, attr, row(2), row(2), row(3)); len(f) != 1 {
			t.Fatalf("RED PROOF FAILED: a success without an audit event was not flagged: %v", f)
		}
		if f := ioCheckSuccessHasAudit("REST POST /api/v1/secrets/", false, attr, row(2), row(2), row(3)); len(f) != 0 {
			t.Fatalf("a reported failure was flagged for a missing audit event: %v", f)
		}
		audit := ioAttribution{method: "LogAuditEvent", sql: "INSERT INTO audit_events"}
		if f := ioCheckSuccessHasAudit("REST POST /api/v1/secrets/", true, audit, row(2), row(2), row(3)); len(f) != 0 {
			t.Fatalf("a faulted audit write (best-effort by design) was flagged: %v", f)
		}
	})

	t.Run("canary in log: green then red", func(t *testing.T) {
		if f := ioCheckCanaryInLog("storage: disk I/O error (10)"); len(f) != 0 {
			t.Fatalf("clean log flagged: %v", f)
		}
		if f := ioCheckCanaryInLog("storage: write failed for value fuzz-value"); len(f) != 1 {
			t.Fatalf("RED PROOF FAILED: a log line carrying the canary was not flagged: %v", f)
		}
	})
}

// TestIOFaultPG_BackendReallyTerminated: on PostgreSQL a connection-drop fault inside
// a transaction must terminate the real backend, not just return an error, so the
// pool, the pgx connection and the server all see a dead connection. Skips on SQLite.
func TestIOFaultPG_BackendReallyTerminated(t *testing.T) {
	ref, w, pool := newIOFaultTestWorlds(t)
	if w.backend != "postgres" {
		t.Skip("needs KEYORIX_TEST_PG_DSN")
	}
	for at := 1; at <= 20; at++ {
		data := ioSeed("REST POST /api/v1/secrets/", ioConnDropBefore, at)
		_, findings, ne := runIOCase(t, ref, w, pool, data, nil)
		if ne != "" {
			continue
		}
		for _, f := range findings {
			t.Errorf("at=%d: %s", at, f)
		}
	}
	pool.mu.Lock()
	n := pool.terminated
	pool.mu.Unlock()
	if n == 0 {
		t.Fatalf("no PostgreSQL backend was terminated in 20 ordinals: the in-transaction drop is not exercised")
	}
	t.Logf("%d backends really terminated with pg_terminate_backend", n)
}
