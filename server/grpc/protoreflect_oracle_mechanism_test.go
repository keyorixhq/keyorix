package grpc_test

// protoreflect_oracle_mechanism_test.go red/green-proofs the oracle MECHANISMS
// FuzzGRPCProtoreflectInvariants relies on, directly and in isolation --
// per CLAUDE.md's "a mechanism must be validated against a failure that
// actually happened, not against the one its author imagined": each test here
// plants a synthetic violation and confirms the check fires (red), then a
// synthetic clean case and confirms it doesn't (green), independent of
// whether any REAL keyorix handler currently has the bug in question.

import (
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
)

// --- oracle 1: classifyStatusLeak ---------------------------------------

func TestClassifyStatusLeak(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantBad bool
	}{
		{"nil error is clean", nil, false},
		{"NotFound with any message is not this oracle's concern", status.Error(codes.NotFound, "secret not found"), false},
		{"PermissionDenied is not this oracle's concern", status.Error(codes.PermissionDenied, "insufficient permissions"), false},
		// RED: codes.Unknown must always be flagged -- this codebase's handlers
		// never intentionally return it (confirmed by grep in the file header),
		// so its presence always means an unmapped error reached the client.
		{"Unknown is always a leak", status.Error(codes.Unknown, "some wrapped internal error"), true},
		// RED: codes.Internal carrying a raw, unmapped error shape.
		{"Internal with a raw SQL driver error is a leak", status.Error(codes.Internal, `pq: duplicate key value violates unique constraint "idx_x"`), true},
		{"Internal with a Go panic value is a leak", status.Error(codes.Internal, "runtime error: invalid memory address or nil pointer dereference"), true},
		{"Internal with a file:line reference is a leak", status.Error(codes.Internal, "secrets.go:142: unexpected nil"), true},
		// GREEN: codes.Internal carrying this codebase's own hand-written,
		// client-safe fallback messages must NOT be flagged.
		{"Internal with the real clientSafe() message is clean", status.Error(codes.Internal, "an internal error occurred; please try again or contact support if the problem persists"), false},
		{"Internal with a real hand-written fallback message is clean", status.Error(codes.Internal, "role operation failed"), false},
		{"Internal with another real hand-written fallback message is clean", status.Error(codes.Internal, "compliance query failed"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad, reason := classifyStatusLeak(tc.err)
			if bad != tc.wantBad {
				t.Fatalf("classifyStatusLeak(%v) = (%v, %q), want bad=%v", tc.err, bad, reason, tc.wantBad)
			}
		})
	}
}

// --- oracle 2/3: unexplainedWrite / the write-count trigger mechanism ---

// oracleTestDBSeq gives each newOracleTestDB call its own shared-cache
// in-memory database name -- without this, every test function in this file
// would collide on one process-wide "kxoracletest" database (SQLite
// shared-cache in-memory DBs are keyed by name within one process) and the
// second test's CREATE TABLE would fail with "table already exists".
var oracleTestDBSeq atomic.Int64

// bestEffortSideEffectTablesForTest points the oracle's real (package-var)
// exemption list at a fake table name for the duration of one test, and
// restores it on cleanup -- every test below that exercises
// unexplainedWrite's EXEMPT path needs this (the red test, which deliberately
// writes a NON-exempt table, does not).
func bestEffortSideEffectTablesForTest(t *testing.T, fake []string) {
	t.Helper()
	orig := bestEffortSideEffectTables
	bestEffortSideEffectTables = fake
	t.Cleanup(func() { bestEffortSideEffectTables = orig })
}

// newOracleTestDB opens an isolated, fresh in-memory SQLite DB (NOT the fuzz
// world) with two real business tables ("widgets", "widgets_audit") and
// installs the write-count triggers on BOTH via discoverAllTables -- exactly
// mirroring buildPRWorld's own installWriteCountTriggers(f, sqlDB,
// discoverAllTables(f, sqlDB)) call, not a hand-picked subset, so these tests
// prove the mechanism as it's actually wired in production, not a
// best-case simplification of it. Proves the detection mechanism itself,
// independent of any real keyorix table or handler.
func newOracleTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:kxoracletest_%d?mode=memory&cache=shared", oracleTestDBSeq.Add(1))
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gdb.Exec("CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT)").Error; err != nil {
		t.Fatalf("create widgets: %v", err)
	}
	if err := gdb.Exec("CREATE TABLE widgets_audit (id INTEGER PRIMARY KEY, note TEXT)").Error; err != nil {
		t.Fatalf("create widgets_audit: %v", err)
	}
	db, err := gdb.DB()
	if err != nil {
		t.Fatalf("underlying *sql.DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	installWriteCountTriggers(t, db, discoverAllTables(t, db))
	return db
}

func TestUnexplainedWrite_RedOnUnexemptedTableWrite(t *testing.T) {
	db := newOracleTestDB(t)
	bestEffortSideEffectTablesForTest(t, []string{"widgets_audit"})

	before := snapshotDB(t, db)
	// A write to a table NOT in the exempt list -- the exact shape of an
	// unauthorized mutation this oracle exists to catch.
	if _, err := db.Exec("INSERT INTO widgets (name) VALUES ('x')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	after := snapshotDB(t, db)

	if !before.unexplainedWrite(after) {
		t.Fatal("expected unexplainedWrite to report true for a write to a non-exempt table, got false")
	}
}

// TestUnexplainedWrites_NamesTheDifferingTable proves the PR #2390 review ask
// directly: a violation must name exactly which table changed and by how
// many write operations, not just assert that SOME table did.
func TestUnexplainedWrites_NamesTheDifferingTable(t *testing.T) {
	db := newOracleTestDB(t)
	bestEffortSideEffectTablesForTest(t, []string{"widgets_audit"})

	before := snapshotDB(t, db)
	if _, err := db.Exec("INSERT INTO widgets (name) VALUES ('x')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec("INSERT INTO widgets (name) VALUES ('y')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	after := snapshotDB(t, db)

	diffs := before.unexplainedWrites(after)
	if len(diffs) != 1 || diffs[0].table != "widgets" || diffs[0].n != 2 {
		t.Fatalf("expected exactly one diff {widgets, 2}, got %v", diffs)
	}
	if got := formatTableDeltas(diffs); got != "widgets:+2" {
		t.Fatalf("formatTableDeltas = %q, want %q", got, "widgets:+2")
	}
}

func TestUnexplainedWrite_GreenOnExemptedTableInsert(t *testing.T) {
	db := newOracleTestDB(t)
	bestEffortSideEffectTablesForTest(t, []string{"widgets_audit"})

	before := snapshotDB(t, db)
	if _, err := db.Exec("INSERT INTO widgets_audit (note) VALUES ('ok')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	after := snapshotDB(t, db)

	if before.unexplainedWrite(after) {
		t.Fatal("expected unexplainedWrite to report false for an INSERT into the documented exempt table, got true")
	}
}

// TestUnexplainedWrite_GreenOnExemptedTableNoOpUpdate is the exact live
// finding this mechanism was built to handle (see bestEffortSideEffectTables's
// compliance_posture_snapshots and sessions entries): an UPDATE that sets a
// row to the SAME value it already had still counts in SQLite's
// total_changes(), even though a content-hash comparison would see no
// difference. A row-hash-based exemption failed this red-proof live (false
// positive); the write-count trigger mechanism must pass it.
func TestUnexplainedWrite_GreenOnExemptedTableNoOpUpdate(t *testing.T) {
	db := newOracleTestDB(t)
	bestEffortSideEffectTablesForTest(t, []string{"widgets_audit"})

	if _, err := db.Exec("INSERT INTO widgets_audit (id, note) VALUES (1, 'same')"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	before := snapshotDB(t, db)
	// An UPDATE that writes the SAME value the row already had -- SQLite's
	// total_changes() still counts this (this is exactly the shape of
	// ValidateSessionToken's throttled session.last_seen_at touch: a real
	// UPDATE statement regardless of whether the stamped value happens to
	// already be fresh).
	if _, err := db.Exec("UPDATE widgets_audit SET note = 'same' WHERE id = 1"); err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	after := snapshotDB(t, db)

	if before.unexplainedWrite(after) {
		t.Fatal("expected unexplainedWrite to report false for a same-value UPDATE to the documented exempt table, got true (this is the exact false positive the trigger-based mechanism replaced a content-hash approach to fix)")
	}
}

func TestUnexplainedWrite_RedOnMixedExemptAndNonExemptWrite(t *testing.T) {
	db := newOracleTestDB(t)
	bestEffortSideEffectTablesForTest(t, []string{"widgets_audit"})

	before := snapshotDB(t, db)
	if _, err := db.Exec("INSERT INTO widgets_audit (note) VALUES ('ok')"); err != nil {
		t.Fatalf("exempt insert: %v", err)
	}
	if _, err := db.Exec("INSERT INTO widgets (name) VALUES ('sneaky')"); err != nil {
		t.Fatalf("non-exempt insert: %v", err)
	}
	after := snapshotDB(t, db)

	diffs := before.unexplainedWrites(after)
	if len(diffs) != 1 || diffs[0].table != "widgets" {
		t.Fatalf("expected a diff naming only 'widgets' (widgets_audit is exempt), got %v -- exempting one table must never mask a write to another", diffs)
	}
}

// --- oracle 4: checkBoundedWork ------------------------------------------

// fatalRecorder satisfies tLogger without ever actually failing the
// enclosing test -- it records whether Fatalf was called instead. A real
// *testing.T's Fatalf aborts the calling goroutine and marks every ancestor
// subtest failed, which would make the RED half of this proof itself report
// as a failing `go test` run; this recorder lets the red case assert "the
// check fires" as a plain, passing assertion.
type fatalRecorder struct {
	failed bool
	msg    string
}

func (f *fatalRecorder) Helper() {}
func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = fmt.Sprintf(format, args...)
}
func (f *fatalRecorder) Logf(format string, args ...any) {}

func TestCheckBoundedWork(t *testing.T) {
	m := grpcMethod{serviceFull: "test.Service", methodName: "Method"}

	t.Run("red: small request, timed out", func(t *testing.T) {
		rec := &fatalRecorder{}
		checkBoundedWork(rec, "admin", m, 100, 5*time.Second, true)
		if !rec.failed {
			t.Fatal("expected checkBoundedWork to report a violation for a small request that timed out, but it did not")
		}
	})

	t.Run("green: small request, did not time out", func(t *testing.T) {
		rec := &fatalRecorder{}
		checkBoundedWork(rec, "admin", m, 100, 5*time.Millisecond, false)
		if rec.failed {
			t.Fatalf("expected checkBoundedWork to pass for a fast small request, but it reported: %s", rec.msg)
		}
	})

	t.Run("green: huge request, timed out (not disproportionate)", func(t *testing.T) {
		rec := &fatalRecorder{}
		checkBoundedWork(rec, "admin", m, disproportionateSizeThreshold+1, 5*time.Second, true)
		if rec.failed {
			t.Fatalf("expected checkBoundedWork to pass (log only) for a huge request that timed out, but it reported: %s", rec.msg)
		}
	})
}

// --- oracle "no leak": a non-status error is itself a leak signal -------

func TestClassifyStatusLeak_NonStatusError(t *testing.T) {
	bad, reason := classifyStatusLeak(errors.New("plain non-gRPC error"))
	if !bad {
		t.Fatal("expected a non-gRPC-status error to be flagged as bad, got false")
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason")
	}
}
