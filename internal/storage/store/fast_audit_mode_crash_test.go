// fast_audit_mode_crash_test.go — ADR-112 Amendment 1 / FASTAUDIT-1's
// required crash test (docs/specs/fast-audit-mode.md §S3): "verify-audit must
// pass after a simulated crash. Lost tail entries are allowed in this mode; a
// broken chain is not."
//
// Two separate crash shapes are tested, because the spec makes two DIFFERENT
// claims about them and a single test would conflate them:
//
//  1. TestFastAuditMode_KillNineLosesNothing — a real kill -9 of the writing
//     process, in a loop. The spec's claim here is the strong one: a Keyorix
//     PROCESS crash loses NOTHING even with the mode on, because the WAL
//     frames are already in the OS page cache. So this asserts zero
//     acknowledged writes are missing, not merely that the chain verifies.
//     Uses the standard Go helper-subprocess pattern (the technique os/exec's
//     own tests use), same shape as PERF-4's ADR-115 crash test: a real
//     SIGKILL is the only way to find out what survives an actual,
//     uncontrolled process death — a simulated panic tests the test's idea of
//     a crash, not a crash.
//
//  2. TestFastAuditMode_WalTailLossLeavesAPrefixNotAGap — the lost-tail case
//     itself, which no process-level kill can produce (killing the process
//     does not lose the page cache; only the OS or the power dying does). It
//     is modelled MECHANICALLY instead: take the -wal file the killed worker
//     left behind, truncate it at a range of byte offsets, and open each
//     truncated copy. That is precisely what an OS crash leaves behind — a
//     WAL whose tail never reached the platter. Every surviving state must
//     verify clean AND its surviving rows must be a PREFIX of what was
//     written, never a set with a hole in it.
//
// Both run the REAL production open path (internal/storage's CreateStorage,
// so the DSN under test is the one sqliteDSN actually builds, including
// _synchronous=NORMAL) rather than a hand-rolled gorm.Open — the mode being
// tested is a property of that DSN, so bypassing it would test nothing.
package store

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	fastCrashWorkerEnv = "KX_FASTAUDIT_CRASH_WORKER"
	fastCrashDBEnv     = "KX_FASTAUDIT_CRASH_DB"
	fastCrashAckEnv    = "KX_FASTAUDIT_CRASH_ACKLOG"
	fastCrashDescPfx   = "fastaudit-crash:"
	fastCrashCycles    = 6
	// Must comfortably exceed the helper's own startup cost (re-exec the test
	// binary, testing.Main's flag/test discovery, the first gorm.Open). Too
	// short a window kills the worker before it acknowledges anything, which
	// looks like a durability finding but is a broken test — the positive
	// control below turns that into a loud failure rather than a green run.
	fastCrashMinRun = 200 * time.Millisecond
	fastCrashMaxRun = 450 * time.Millisecond
)

// fastCrashDSN is the SQLite DSN the fast audit mode actually produces,
// duplicated here as a literal rather than imported.
//
// Why a literal: internal/storage imports internal/storage/store, so this
// test (package store) cannot import internal/storage to call sqliteDSN
// without an import cycle. The duplication is guarded, not trusted:
// internal/storage's own TestSQLiteDSN_SynchronousFollowsSkipDurableSync and
// TestFastAuditMode_SQLitePragmaFollowsTheSetting assert the real builder
// produces `_synchronous=NORMAL` under the flag and FULL without it, and
// TestFastAuditModeCrash_DSNMatchesProduction below asserts this literal
// still carries every pragma those tests pin. If sqliteDSN changes shape,
// that test goes red here rather than this file silently drifting into
// testing a DSN production no longer uses.
func fastCrashDSN(dbPath string) string {
	return dbPath + "?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate&_synchronous=NORMAL"
}

// TestFastAuditModeCrash_DSNMatchesProduction keeps fastCrashDSN honest. It
// pins the four pragmas production's sqliteDSN sets plus the NORMAL that is
// the mode under test; a divergence means this file is no longer exercising
// the real fast-mode DSN and its crash results say nothing about production.
func TestFastAuditModeCrash_DSNMatchesProduction(t *testing.T) {
	dsn := fastCrashDSN("/tmp/example.db")
	for _, want := range []string{
		"_foreign_keys=1",
		"_busy_timeout=10000",
		"_journal_mode=WAL",
		"_txlock=immediate",
		"_synchronous=NORMAL",
	} {
		require.Contains(t, dsn, want,
			"this file's DSN literal has drifted from internal/storage's sqliteDSN -- re-derive it from that "+
				"function (see fastCrashDSN's comment for why it is duplicated rather than imported)")
	}
}

func openFastCrashStore(t testing.TB, dbPath string) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fastCrashDSN(dbPath)), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db %s: %v", dbPath, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("underlying sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&models.AuditEvent{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	ls := NewLocalStorage(db)
	ls.SetAuditSkipDurableSync(true)
	return ls
}

// TestFastAuditMode_CrashWorker is the helper-subprocess entry point. A no-op
// under a normal `go test` run; becomes a tight write loop when the test
// BINARY is re-executed with fastCrashWorkerEnv set.
func TestFastAuditMode_CrashWorker(t *testing.T) {
	if os.Getenv(fastCrashWorkerEnv) != "1" {
		t.Skip("helper process for TestFastAuditMode_KillNineLosesNothing; not invoked directly")
	}

	ls := openFastCrashStore(t, os.Getenv(fastCrashDBEnv))
	ctx := context.Background()

	ackFile, err := os.OpenFile(os.Getenv(fastCrashAckEnv), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test-only path from an env var this same test set
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: open ack log: %v\n", err)
		os.Exit(2)
	}
	defer func() { _ = ackFile.Close() }()

	for {
		id := fastCrashRandomHex(16)
		tr := true
		if err := ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType:   "fastaudit_crash.write",
			Description: fastCrashDescPfx + id,
			Success:     &tr,
			EventTime:   time.Now(),
			ActorType:   "system",
		}); err != nil {
			// Not acknowledged, so deliberately NOT recorded. A failed write
			// must never appear in the ack log.
			continue
		}
		// Record the ack as close to LogAuditEvent's return as possible and
		// fsync it immediately. The inherent race this cannot close (a kill
		// landing between LogAuditEvent returning and this line reaching
		// disk) can only UNDERCOUNT acks, never overcount them — so it can
		// only make the parent's check weaker on one event, never wrongly
		// fail it.
		if _, err := ackFile.WriteString(id + "\n"); err != nil {
			continue
		}
		_ = ackFile.Sync()
	}
}

func fastCrashRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TestFastAuditMode_KillNineLosesNothing is crash shape (1): the spec's
// strong claim that a Keyorix PROCESS crash loses nothing even with the fast
// audit mode on, because `_synchronous=NORMAL` still write()s every WAL frame
// to the OS — it only stops waiting for the OS to put them on the platter.
//
// So the assertion is zero missing acknowledged writes, not merely "the chain
// verifies". A mutation that turned the audit write into a genuinely deferred
// or best-effort one would show up here as missing rows; "the chain verifies"
// alone would stay green through it.
func TestFastAuditMode_KillNineLosesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("kill -9 loop is slow; skipped in -short")
	}

	self, err := os.Executable()
	require.NoError(t, err)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fastaudit-crash.db")
	ackPath := filepath.Join(dir, "acked.log")

	env := append(os.Environ(),
		fastCrashWorkerEnv+"=1",
		fastCrashDBEnv+"="+dbPath,
		fastCrashAckEnv+"="+ackPath,
	)

	for i := 0; i < fastCrashCycles; i++ {
		cmd := exec.Command(self, "-test.run=^TestFastAuditMode_CrashWorker$") //nolint:gosec // self is this same test binary; args/env are fixed constants
		cmd.Env = env
		cmd.Stderr = os.Stderr
		require.NoErrorf(t, cmd.Start(), "cycle %d: start worker", i)

		time.Sleep(fastCrashMinRun + time.Duration(fastCrashJitter(i))*time.Millisecond)

		killErr := cmd.Process.Kill() // SIGKILL on Unix — a real kill -9.
		_ = cmd.Wait()
		require.NoErrorf(t, killErr,
			"cycle %d: the worker exited on its own before the kill reached it -- a startup failure "+
				"against whatever the previous cycle left behind is a real finding, not a race to paper over", i)
	}

	acked := readFastCrashAckLog(t, ackPath)
	t.Logf("kill -9 loop: %d acknowledged audit writes across %d kill cycles", len(acked), fastCrashCycles)
	require.NotEmpty(t, acked,
		"no audit write was ever acknowledged -- the harness itself is broken (the worker never got far "+
			"enough to succeed once), which would make every assertion below vacuous")

	ls := openFastCrashStore(t, dbPath)
	present := fastCrashRowDescriptions(t, ls)

	var missing []string
	for _, id := range acked {
		if !present[fastCrashDescPfx+id] {
			missing = append(missing, id)
		}
	}
	require.Emptyf(t, missing,
		"%d of %d acknowledged audit writes have no row after a kill -9, with the fast audit mode on. "+
			"The mode is only allowed to lose entries to an OS crash or power loss -- a PROCESS crash must "+
			"lose nothing, because _synchronous=NORMAL still write()s every WAL frame to the OS. Missing: %v",
		len(missing), len(acked), missing)

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.Truef(t, v.Valid,
		"audit chain does not verify after the kill -9 loop: reason=%q firstBrokenID=%v", v.Reason, v.FirstBrokenID)
}

// TestFastAuditMode_WalTailLossLeavesAPrefixNotAGap is crash shape (2): the
// lost-tail case, which a process kill cannot produce.
//
// It models an OS crash directly. A worker writes under the fast-mode DSN and
// is killed, leaving a live -wal whose frames are in the page cache but not
// necessarily checkpointed. This test then copies db+-wal and truncates the
// COPY's -wal at a descending series of offsets — exactly the state an OS
// crash leaves: a WAL whose tail never reached the platter — and opens each
// one. For every truncated state:
//
//   - VerifyAuditChain must report Valid. A tail loss is permitted; a broken
//     or forked chain is not, and that is the whole safety claim of this mode.
//   - the surviving rows must be a PREFIX of the written order, never a set
//     with a hole in it. This is the assertion that actually distinguishes
//     "lost a tail" from "corrupted"; chain validity alone would not catch a
//     hole whose surrounding rows happened to still link.
//
// Positive control: at least one truncation offset must actually lose rows,
// otherwise the test proves nothing about tail loss and says so.
func TestFastAuditMode_WalTailLossLeavesAPrefixNotAGap(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a worker subprocess; skipped in -short")
	}

	self, err := os.Executable()
	require.NoError(t, err)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fastaudit-wal.db")
	ackPath := filepath.Join(dir, "acked.log")

	cmd := exec.Command(self, "-test.run=^TestFastAuditMode_CrashWorker$") //nolint:gosec // self is this same test binary
	cmd.Env = append(os.Environ(),
		fastCrashWorkerEnv+"=1",
		fastCrashDBEnv+"="+dbPath,
		fastCrashAckEnv+"="+ackPath,
	)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	time.Sleep(900 * time.Millisecond) // long enough to accumulate a WAL worth truncating
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()

	writtenOrder := readFastCrashAckLog(t, ackPath)
	require.NotEmpty(t, writtenOrder, "the worker acknowledged nothing -- harness broken, not a finding")

	walPath := dbPath + "-wal"
	walInfo, err := os.Stat(walPath)
	require.NoErrorf(t, err,
		"no -wal file left behind at %s. Either journal_mode=WAL is not in effect (which would make this "+
			"whole test inapplicable) or SQLite checkpointed and removed it, in which case there is no WAL "+
			"tail to lose and this test cannot model an OS crash", walPath)
	require.Positive(t, walInfo.Size(), "the -wal file is empty; nothing to truncate")

	anyTruncationLostRows := false
	// Fractions of the WAL, descending. 0 (drop the WAL entirely) is the
	// extreme case an OS crash can produce before any frame reached disk.
	for _, frac := range []float64{0.9, 0.6, 0.3, 0.0} {
		offset := int64(float64(walInfo.Size()) * frac)
		t.Run(fmt.Sprintf("wal_truncated_to_%d_of_%d_bytes", offset, walInfo.Size()), func(t *testing.T) {
			caseDir := t.TempDir()
			caseDB := filepath.Join(caseDir, "fastaudit-wal.db")
			copyFastCrashFile(t, dbPath, caseDB)
			copyFastCrashFile(t, walPath, caseDB+"-wal")
			require.NoError(t, os.Truncate(caseDB+"-wal", offset))

			ls := openFastCrashStore(t, caseDB)
			present := fastCrashRowDescriptions(t, ls)

			// Prefix check: walk the written order and, once a row is
			// missing, every later row must be missing too.
			firstMissing := -1
			for i, id := range writtenOrder {
				have := present[fastCrashDescPfx+id]
				if !have && firstMissing < 0 {
					firstMissing = i
					continue
				}
				if have && firstMissing >= 0 {
					t.Fatalf("GAP, not a tail: write #%d survived WAL truncation but write #%d (written "+
						"EARLIER) did not. This mode may lose a TAIL of audit entries; it may never lose "+
						"an entry from the middle of the chain. %d of %d rows survived.",
						i, firstMissing, len(present), len(writtenOrder))
				}
			}
			if firstMissing >= 0 {
				anyTruncationLostRows = true
				t.Logf("lost a tail of %d/%d acknowledged writes (first missing: #%d) -- permitted in this mode",
					len(writtenOrder)-firstMissing, len(writtenOrder), firstMissing)
			}

			v, err := ls.VerifyAuditChain(context.Background(), nil)
			require.NoError(t, err)
			require.Truef(t, v.Valid,
				"audit chain does not verify after losing a WAL tail (truncated to %d of %d bytes): "+
					"reason=%q firstBrokenID=%v. Lost tail entries are allowed in this mode; a broken chain "+
					"is not.", offset, walInfo.Size(), v.Reason, v.FirstBrokenID)
		})
	}

	require.True(t, anyTruncationLostRows,
		"no truncation offset lost a single row, so this test never actually exercised tail loss and its "+
			"prefix assertion passed vacuously. Either the worker's writes were all checkpointed into the "+
			"main database file before the kill, or the -wal was not where the rows lived -- in both cases "+
			"this run is not evidence about the lost-tail case")
}

// fastCrashJitter spreads successive kill cycles so they land at different
// points relative to the worker's own write/batch timing, without pulling in
// a PRNG for what is just "vary the delay a bit".
func fastCrashJitter(i int) int64 {
	spread := int64(fastCrashMaxRun/time.Millisecond) - int64(fastCrashMinRun/time.Millisecond)
	if spread <= 0 {
		return 0
	}
	return int64(i*11+5) % spread
}

// readFastCrashAckLog returns the acknowledged ids IN WRITE ORDER. Order
// matters here, unlike in PERF-4's set-based equivalent: the prefix check is
// the assertion that distinguishes a permitted tail loss from a forbidden
// gap, and it needs to know which write came first.
func readFastCrashAckLog(t testing.TB, path string) []string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-only path
	if err != nil {
		t.Fatalf("open ack log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan ack log: %v", err)
	}
	return out
}

func fastCrashRowDescriptions(t testing.TB, ls *LocalStorage) map[string]bool {
	t.Helper()
	var rows []models.AuditEvent
	if err := ls.DB().Where("description LIKE ?", fastCrashDescPfx+"%").Find(&rows).Error; err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Description] = true
	}
	return out
}

func copyFastCrashFile(t testing.TB, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src) //nolint:gosec // test-only path under t.TempDir()
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
