// factory_sqlite_migration_lock.go — cross-process exclusive lock guarding a
// local SQLite database's connect-and-migrate critical section
// (#STORAGE-FACTORY-003).
//
// migrationMu (see factory.go) only serializes createLocalStorage/migrateDatabase
// across goroutines WITHIN A SINGLE OS PROCESS; its own doc comment rests on the
// assumption that "SQLite deployments are single-process-per-file by
// construction" — but that assumption was never actually enforced anywhere.
// Nothing previously stopped two separate Keyorix OS processes pointed at the
// same local SQLite file (a misconfigured multi-replica deployment, or a
// `keyorix encryption ...` CLI invocation run concurrently with a live server
// process) from racing gorm.Open's WAL-mode switch and migrateDatabase's DDL
// statements against each other, unlike the Postgres path which already gets an
// additional cross-process protection via withMigrationLock's session-level
// advisory lock.
package storage

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// sqliteMigrationLockSuffix is appended to the configured SQLite database path
// to build the sidecar lock file acquireSQLiteMigrationLock takes an flock(2) on.
const sqliteMigrationLockSuffix = ".migration.lock"

// sqliteMigrationLock holds an acquired exclusive flock(2) on a local SQLite
// database's migration lock sidecar file.
type sqliteMigrationLock struct {
	f *os.File
}

// release unlocks the flock and closes the underlying file descriptor. Safe to
// call on a nil receiver or a lock whose file is nil (defensive; every actual
// caller only calls this after a successful acquireSQLiteMigrationLock).
func (l *sqliteMigrationLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}

// acquireSQLiteMigrationLock takes a NON-BLOCKING exclusive flock(2) on
// <dbPath>.migration.lock, mirroring keymanager_filelock.go's DEK lock (flock is
// owned by the open file descriptor and released automatically by the kernel on
// process exit/crash/kill -9 — no stale-lock/PID-liveness bookkeeping to get
// wrong) and local_bootstrap_lock.go's cross-process critical-section pattern.
//
// Unlike keymanager_filelock.go's lock (which falls back to a blocking wait),
// this is non-blocking ONLY: a second process racing to connect/migrate the same
// local SQLite file must fail loud and fast at boot with an actionable error,
// not hang indefinitely waiting on a lock that may never be released (e.g. a
// wedged sibling process would otherwise stall this process's boot forever) —
// matching this file's fail-loud-over-silently-degrading design convention
// (warnIfDuplicatesExist, the invalid storage.type branch in CreateStorage,
// etc.) rather than the blocking-with-a-log-line convention used for the DEK
// lock, since a lock held here is expected to be brief (a single boot's connect
// + migrate) rather than an operator-triggered rotate/migrate-provider run.
//
// dbPath is the raw storage.database.path value, which — per sqliteDSN's own
// doc comment — may already carry DSN query parameters (an operator-supplied
// "?_pragma=..." suffix) or denote a private/shared in-memory database
// ("file:name?mode=memory[&cache=shared]" or ":memory:", both used throughout
// this package's own test suite). Neither case names a real on-disk file this
// lock can meaningfully protect:
//   - a query-string suffix is not part of the actual filesystem path, so it is
//     stripped before building the lock filename (otherwise the lock file's own
//     name would embed literal "?"/"&" characters from the DSN);
//   - an in-memory database is confined to the process (and, for a shared
//     cache, the process's connection pool) that opened it by construction —
//     there is no second OS process that could ever share it, so no lock is
//     needed at all and none is taken (acquireSQLiteMigrationLock returns a
//     nil lock and a nil error; release() on a nil lock is a no-op).
func acquireSQLiteMigrationLock(dbPath string) (*sqliteMigrationLock, error) {
	base := dbPath
	if idx := strings.IndexByte(base, '?'); idx != -1 {
		base = base[:idx]
	}
	if base == "" || base == ":memory:" || strings.Contains(dbPath, "mode=memory") {
		return nil, nil
	}

	lockPath := base + sqliteMigrationLockSuffix
	// #nosec G304 -- lockPath is derived from the operator-configured SQLite
	// database path (storage.database.path), not attacker input.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open SQLite migration lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf(
			"another process already holds the migration lock on %s — only one Keyorix process (server or CLI) may connect to/migrate a local SQLite database at a time; stop the other process before starting this one",
			lockPath,
		)
	}
	return &sqliteMigrationLock{f: f}, nil
}
