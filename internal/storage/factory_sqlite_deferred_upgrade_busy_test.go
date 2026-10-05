package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/require"
)

// deferredUpgradeBusyErr reports whether err looks like SQLite writer-lock
// contention (SQLITE_BUSY / "database is locked"), matching the driver-native
// message text -- the same approach internal/storage/store's isSQLiteBusyErr
// uses (unexported there, so duplicated rather than imported).
func deferredUpgradeBusyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// TestSQLiteDeferredTransaction_UpgradeFailsBusyDespiteBusyTimeout is the RED
// case (reproduces #1996's TestSessionCacheChokepoint_
// CoversEveryVulnerableCallSite flake mechanism on an UNFIXED DSN, i.e.
// without _txlock=immediate): a read-then-write transaction that starts
// DEFERRED only requests the write lock at its first write statement. If
// another connection commits a write after this transaction's read snapshot
// was taken, that lock request fails with SQLITE_BUSY (or "database is
// locked") IMMEDIATELY -- SQLite does not invoke the busy_timeout retry
// handler for this "stale snapshot" case (only for waiting on a currently
// held lock, which is a different condition), so a generous busy_timeout
// does not help. Proven here by asserting the failing write returns well
// under the configured busy_timeout: if the handler HAD been invoked, it
// would have retried for the full window before giving up.
func TestSQLiteDeferredTransaction_UpgradeFailsBusyDespiteBusyTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "deferred-upgrade.db")
	// Deliberately WITHOUT _txlock=immediate -- this is the pre-fix production DSN shape.
	const busyTimeoutMillis = 10000
	unfixedDSN := fmt.Sprintf("file:%s?_busy_timeout=%d&_journal_mode=WAL", dbPath, busyTimeoutMillis)

	setup, err := sql.Open("sqlite", unfixedDSN)
	require.NoError(t, err)
	_, err = setup.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = setup.Exec(`INSERT INTO t (id, v) VALUES (1, 0)`)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	connA, err := sql.Open("sqlite", unfixedDSN)
	require.NoError(t, err)
	defer func() { _ = connA.Close() }()
	connA.SetMaxOpenConns(1) // pin to one physical connection so Begin/Exec below share it

	connB, err := sql.Open("sqlite", unfixedDSN)
	require.NoError(t, err)
	defer func() { _ = connB.Close() }()
	connB.SetMaxOpenConns(1)

	txA, err := connA.Begin() // BEGIN (deferred -- no write lock yet)
	require.NoError(t, err)
	defer func() { _ = txA.Rollback() }()

	var v int
	require.NoError(t, txA.QueryRow(`SELECT v FROM t WHERE id = 1`).Scan(&v),
		"the read establishes A's snapshot without taking the write lock (WAL allows concurrent readers)")

	// A separate connection writes and commits AFTER A's snapshot was taken --
	// this is the exact interleaving AssignRole/AssignUserRole is exposed to
	// under concurrent grants.
	_, err = connB.Exec(`UPDATE t SET v = v + 1 WHERE id = 1`)
	require.NoError(t, err, "connB's write is uncontested: connA never took the write lock")

	start := time.Now()
	_, writeErr := txA.Exec(`UPDATE t SET v = v + 1 WHERE id = 1`)
	elapsed := time.Since(start)

	require.Error(t, writeErr, "connA's write must fail: its read snapshot is now stale relative to connB's committed write")
	require.True(t, deferredUpgradeBusyErr(writeErr), "expected a SQLITE_BUSY/'database is locked' error, got: %v", writeErr)
	require.Less(t, elapsed, 2*time.Second,
		"a busy_timeout-retried failure would take close to the full %dms window; finishing in %s proves the busy handler was never invoked for this lock-upgrade case", busyTimeoutMillis, elapsed)
}

// TestSQLiteImmediateTxlock_ClosesTheDeferredUpgradeBusyWindow is the GREEN
// case: with _txlock=immediate (via the production sqliteDSN builder, not a
// hand-copied DSN), the same read-then-write transaction claims the write
// lock at BEGIN, before its own read -- so no other connection can commit an
// intervening write that would make its snapshot stale, and its own write
// always succeeds. Proven by giving connB an intentionally tiny busy_timeout:
// while connA holds the write lock (from BEGIN IMMEDIATE through its own
// write), connB's write must fail fast (proving connA really does hold the
// lock immediately, not just eventually) -- and once connA commits, the
// identical connB write must succeed.
func TestSQLiteImmediateTxlock_ClosesTheDeferredUpgradeBusyWindow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "immediate-fix.db")
	fixedDSN := sqliteDSN("file:" + dbPath) // the actual production DSN builder

	setup, err := sql.Open("sqlite", fixedDSN)
	require.NoError(t, err)
	_, err = setup.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = setup.Exec(`INSERT INTO t (id, v) VALUES (1, 0)`)
	require.NoError(t, err)
	require.NoError(t, setup.Close())

	connA, err := sql.Open("sqlite", fixedDSN)
	require.NoError(t, err)
	defer func() { _ = connA.Close() }()
	connA.SetMaxOpenConns(1)

	// connB shares the same file but with a deliberately tiny busy_timeout, so
	// a write blocked behind connA's held lock fails immediately instead of
	// waiting -- turning "connA truly holds the write lock right now" into a
	// fast, deterministic assertion instead of a sleep-based race.
	shortBusyDSN := "file:" + dbPath + "?_busy_timeout=1&_journal_mode=WAL&_txlock=immediate"
	connB, err := sql.Open("sqlite", shortBusyDSN)
	require.NoError(t, err)
	defer func() { _ = connB.Close() }()
	connB.SetMaxOpenConns(1)

	txA, err := connA.Begin() // BEGIN IMMEDIATE -- claims the write lock right away
	require.NoError(t, err)

	var v int
	require.NoError(t, txA.QueryRow(`SELECT v FROM t WHERE id = 1`).Scan(&v))

	_, err = connB.Exec(`UPDATE t SET v = v + 1 WHERE id = 1`)
	require.Error(t, err, "connB must be locked out immediately: connA already holds the write lock via BEGIN IMMEDIATE, before its own read even ran")
	require.True(t, deferredUpgradeBusyErr(err), "expected a SQLITE_BUSY/'database is locked' error, got: %v", err)

	_, err = txA.Exec(`UPDATE t SET v = v + 1 WHERE id = 1`)
	require.NoError(t, err, "connA's own write must succeed -- no other writer could have intervened between its read and its write")
	require.NoError(t, txA.Commit())

	_, err = connB.Exec(`UPDATE t SET v = v + 1 WHERE id = 1`)
	require.NoError(t, err, "once connA released the write lock, the identical connB write must now succeed")
}
