package store

// local_audit_journal_crash_test.go -- ADR-115 / PERF-4's required kill -9
// test: "after restart no acknowledged read lacks its audit entry, the
// chain verifies, the DB copy converges."
//
// This uses the standard Go "helper subprocess" pattern (the same technique
// os/exec's own tests use): TestLocalAuditJournal_KillNineWorker is a real
// Test function that is a no-op under a normal `go test` run (it checks for
// a sentinel env var and returns immediately if absent) but, when the test
// BINARY is re-executed with that env var set and -test.run targeting it
// specifically, becomes a tight loop that keeps writing audit events via
// the real LogAuditEvent -> journal path until the PARENT test process
// sends it SIGKILL. A real kill -9 is the only way to test "what survives
// an actual, uncontrolled process death" -- anything short of that (a
// simulated panic, a deferred-cleanup skip) risks testing the test's own
// idea of a crash rather than a real one.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditjournal"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
)

const (
	crashWorkerEnv  = "KX_AUDIT_JOURNAL_CRASH_WORKER"
	crashJournalEnv = "KX_AUDIT_JOURNAL_CRASH_DIR"
	crashDBEnv      = "KX_AUDIT_JOURNAL_CRASH_DB"
	crashAckLogEnv  = "KX_AUDIT_JOURNAL_CRASH_ACKLOG"
	crashReplicaEnv = "KX_AUDIT_JOURNAL_CRASH_REPLICA"
	crashDescPrefix = "crash-test-event:"
	crashKillCycles = 10
	// crashMinRunTime/crashMaxRunTime must comfortably exceed this helper
	// process's own startup cost (re-exec the test binary, testing.Main's
	// flag/test discovery) -- too short a window kills the worker before
	// it ever reaches EnableLocalAuditJournal, which looks like (but is
	// NOT) a durability bug: zero acknowledged writes with nothing to
	// check is a broken test, not a passing one. Measured empirically:
	// sub-50ms windows reliably starved every cycle on this harness.
	crashMinRunTime = 150 * time.Millisecond
	crashMaxRunTime = 400 * time.Millisecond
)

// openCrashTestDB opens (creating if needed) a file-backed SQLite database
// with exactly the schema the journal path needs -- the same minimal
// AutoMigrate set newAuditChainTestStore already uses for AuditEvent, plus
// AuditJournalReplayState (ADR-115). File-backed (never :memory:) is
// required here specifically because this test's whole point is surviving
// a process restart -- an in-memory DB dies with the process.
func openCrashTestDB(t testing.TB, path string) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db %s: %v", path, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("underlying sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&models.AuditEvent{}, &models.AuditJournalReplayState{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return NewLocalStorage(db)
}

// TestLocalAuditJournal_KillNineWorker is the helper-subprocess entry point
// described above. A no-op unless crashWorkerEnv is set.
func TestLocalAuditJournal_KillNineWorker(t *testing.T) {
	if os.Getenv(crashWorkerEnv) != "1" {
		t.Skip("helper process for TestLocalAuditJournal_KillNineLoop; not invoked directly")
	}

	dir := os.Getenv(crashJournalEnv)
	dbPath := os.Getenv(crashDBEnv)
	ackLogPath := os.Getenv(crashAckLogEnv)
	replicaID := os.Getenv(crashReplicaEnv)

	ls := openCrashTestDB(t, dbPath)
	ctx := context.Background()
	if err := ls.EnableLocalAuditJournal(ctx, dir, replicaID); err != nil {
		// A startup refusal here (e.g. a *auditjournal.CorruptionError left
		// by a PREVIOUS kill) is itself a finding worth surfacing loudly --
		// exit nonzero with the reason on stderr rather than silently
		// swallowing it, so the parent's loop notices a worker that failed
		// to even start (distinct from one that was killed mid-run).
		fmt.Fprintf(os.Stderr, "FATAL: EnableLocalAuditJournal: %v\n", err)
		os.Exit(2)
	}

	ackFile, err := os.OpenFile(ackLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test-only path from an env var this same test suite set
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: open ack log: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = ackFile.Close() }()

	for {
		id := randomHex(16)
		tr := true
		event := &models.AuditEvent{
			EventType:   "crash_test.write",
			Description: crashDescPrefix + id,
			Success:     &tr,
			EventTime:   time.Now(),
			ActorType:   "system",
		}
		err := ls.LogAuditEvent(ctx, event)
		if err != nil {
			// Not acknowledged -- correctly do NOT record it. A failed
			// write (e.g. ctx canceled) must never appear in the ack log.
			continue
		}
		// Record the ack as close to the LogAuditEvent return as possible,
		// fsyncing immediately: see this file's header for the narrow,
		// inherent race this cannot fully close (a kill between
		// LogAuditEvent returning and this write reaching disk undercounts
		// acks -- never overcounts, so it can only make this test's check
		// WEAKER on that one event, never wrongly fail it).
		if _, err := ackFile.WriteString(id + "\n"); err != nil {
			continue
		}
		_ = ackFile.Sync()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TestLocalAuditJournal_KillNineLoop is the actual test: repeatedly starts
// the worker helper process above, lets it run for a short random window,
// and sends it SIGKILL (os/exec's Process.Kill(), which on Unix IS SIGKILL)
// -- a real, uncontrolled process death, not a simulated one. After
// crashKillCycles iterations it verifies, against the journal and database
// left behind, every property ADR-115/PERF-4 require:
//
//   - every acknowledged write (recorded in the ack log by a worker that
//     successfully returned from LogAuditEvent before being killed) has a
//     corresponding row in audit_events after the final EnableLocalAuditJournal
//     call's synchronous crash replay;
//   - the audit hash chain (ADR-029, unmodified) verifies clean;
//   - the DB copy has converged with the journal: the persisted replay
//     cursor equals the journal's own last sequence number, and the DB row
//     count for this replica equals the journal's own record count.
func TestLocalAuditJournal_KillNineLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("kill -9 loop is slow; skipped in -short")
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	dir := t.TempDir()
	journalDir := filepath.Join(dir, "journal")
	dbPath := filepath.Join(dir, "audit.db")
	ackLogPath := filepath.Join(dir, "acked.log")
	const replicaID = "crash-test-replica-1"

	env := append(os.Environ(),
		crashWorkerEnv+"=1",
		crashJournalEnv+"="+journalDir,
		crashDBEnv+"="+dbPath,
		crashAckLogEnv+"="+ackLogPath,
		crashReplicaEnv+"="+replicaID,
	)

	for i := 0; i < crashKillCycles; i++ {
		cmd := exec.Command(self, "-test.run=^TestLocalAuditJournal_KillNineWorker$", "-test.v") //nolint:gosec // self is this same test binary; args/env are fixed constants, not attacker input
		cmd.Env = env
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Start(); err != nil {
			t.Fatalf("cycle %d: start worker: %v", i, err)
		}

		runFor := crashMinRunTime + time.Duration(pseudoJitter(i))*time.Millisecond
		time.Sleep(runFor)

		killErr := cmd.Process.Kill() // SIGKILL on Unix -- a real kill -9.
		waitErr := cmd.Wait()

		if killErr != nil {
			// The process may have already exited on its own (e.g. a
			// startup failure) before the kill reached it -- that's the
			// FATAL exit-2 path in the worker, and it means
			// EnableLocalAuditJournal refused to (re)start against
			// whatever the PREVIOUS cycle left behind. That is a real bug
			// this test exists to catch, not a race to paper over.
			t.Fatalf("cycle %d: worker exited before it could be killed (startup failure?) -- stderr:\n%s", i, stderr.String())
		}
		_ = waitErr // expected: killed, non-nil, not a signal we need to inspect further
	}

	// Final phase: no worker process is running. Open fresh and let
	// EnableLocalAuditJournal's synchronous crash replay catch the DB up to
	// whatever is durable on disk.
	ls := openCrashTestDB(t, dbPath)
	ctx := context.Background()
	if err := ls.EnableLocalAuditJournal(ctx, journalDir, replicaID); err != nil {
		t.Fatalf("final EnableLocalAuditJournal (crash replay): %v", err)
	}
	defer func() { _ = ls.CloseLocalAuditJournal() }()

	acked := readAckLog(t, ackLogPath)
	t.Logf("kill -9 loop: %d acknowledged writes across %d kill cycles", len(acked), crashKillCycles)
	if len(acked) == 0 {
		t.Fatalf("no writes were ever acknowledged -- the test setup itself is broken (worker never got far enough to succeed once)")
	}

	present := dbDescriptions(t, ls)
	var missing []string
	for id := range acked {
		if !present[crashDescPrefix+id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d acknowledged write(s) have NO audit_events row after crash replay (violates audit-before-disclosure durability): %v", len(missing), missing)
	}

	verify, err := ls.VerifyAuditChain(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !verify.Valid {
		t.Fatalf("audit chain does not verify after the kill -9 loop: reason=%q firstBrokenID=%v", verify.Reason, verify.FirstBrokenID)
	}

	journalResult, err := auditjournal.Validate(journalDir)
	if err != nil {
		t.Fatalf("auditjournal.Validate on the final journal state: %v", err)
	}
	dbRowCount := countReplicaRows(t, ls, replicaID)
	if uint64(dbRowCount) != uint64(len(journalResult.Records)) {
		t.Fatalf("DB copy has not converged with the journal: journal has %d records, DB has %d rows for replica %q",
			len(journalResult.Records), dbRowCount, replicaID)
	}

	cursor, _, err := ls.auditJournalReplayCursor(ctx, replicaID)
	if err != nil {
		t.Fatalf("read replay cursor: %v", err)
	}
	if len(journalResult.Records) > 0 {
		wantCursor := journalResult.Records[len(journalResult.Records)-1].Seq
		if cursor != wantCursor {
			t.Fatalf("replay cursor = %d, want %d (the journal's last record's seq)", cursor, wantCursor)
		}
	}
}

// pseudoJitter returns a small, deterministic-per-i spread so successive
// kill cycles land at different points relative to the worker's own
// internal loop/batching timing, without pulling in a full PRNG dependency
// for what is just "vary the kill delay a bit."
func pseudoJitter(i int) int64 {
	spread := int64(crashMaxRunTime/time.Millisecond) - int64(crashMinRunTime/time.Millisecond)
	if spread <= 0 {
		return 0
	}
	return int64(i*7+3) % spread
}

func readAckLog(t testing.TB, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-only path
	if err != nil {
		t.Fatalf("open ack log: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			out[line] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan ack log: %v", err)
	}
	return out
}

func dbDescriptions(t testing.TB, ls *LocalStorage) map[string]bool {
	t.Helper()
	var rows []models.AuditEvent
	if err := ls.DB().Where("description LIKE ?", crashDescPrefix+"%").Find(&rows).Error; err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Description] = true
	}
	return out
}

func countReplicaRows(t testing.TB, ls *LocalStorage, replicaID string) int64 {
	t.Helper()
	var n int64
	if err := ls.DB().Model(&models.AuditEvent{}).Where("journal_replica_id = ?", replicaID).Count(&n).Error; err != nil {
		t.Fatalf("count replica rows: %v", err)
	}
	return n
}
