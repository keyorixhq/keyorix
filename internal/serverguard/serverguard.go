// Package serverguard detects whether a live Keyorix server process is
// currently attached to a given database, so that `keyorix-server admin`
// commands (ADR-108 §B, PR 11) can refuse to run concurrently with one
// unless the operator explicitly overrides with --force.
//
// Mechanism: a reader/writer advisory lock, held in SHARED mode by every
// live server process for its whole lifetime (acquired at boot, released at
// shutdown) and probed with a non-blocking EXCLUSIVE request by admin
// commands. Any number of server replicas may hold the shared lock at once
// (this must not break the already-supported multi-replica Postgres HA
// topology, ADR-039) — the exclusive probe only succeeds when NO shared (or
// exclusive) holder exists at all, which is exactly "no server is running
// against this database" regardless of how many replicas that would have
// been.
//
//   - Local SQLite: flock(2) SHARED/EXCLUSIVE on a dedicated sidecar file
//     next to the database (<db path>.server.lock — distinct from the
//     migration-only lock factory.go's withMigrationLock takes during
//     migrateDatabase, and from internal/encryption's dek.lock, which is
//     encryption-specific and unconditional-encryption-disabled deployments
//     never touch).
//   - PostgreSQL: pg_advisory_lock_shared / pg_try_advisory_lock, a
//     session-scoped advisory lock keyed by serverPresenceLockKey (distinct
//     from internal/storage/factory.go's postgresMigrationLockKey).
//     Session-scoped means a crashed or killed server's lock is released by
//     Postgres itself the moment its connection drops — there is no stale
//     lock to clean up after an unclean shutdown.
//   - Remote storage (storage.type: remote) has no local database to guard;
//     AcquirePresence/ProbeRunning are no-ops for it.
//
// Limits (stated per this repo's "ask of any mechanism what it silently
// skips" convention):
//   - Purely advisory/cooperative. Nothing stops a process that doesn't use
//     this package — an old server binary predating this guard, or a tool
//     that opens the database file/connection directly — from running
//     unseen. This is a safety net between this codebase's own processes,
//     not a security boundary.
//   - flock(2) semantics are unreliable on some network filesystems (NFS);
//     a SQLite database on such a mount already has other correctness
//     problems this guard does not add to or fix.
//   - Postgres advisory locks share one numeric keyspace across the whole
//     database cluster, not namespaced per application. A collision with an
//     unrelated application choosing the same key is possible in principle;
//     mitigated, not eliminated, by using an arbitrary fixed constant here.
package serverguard

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// serverPresenceLockKey is the Postgres advisory-lock key for this guard.
// Arbitrary but fixed, distinct from internal/storage/factory.go's
// postgresMigrationLockKey (872341) — the two locks serve different purposes
// (migration-in-progress vs. server-is-running) and must not collide.
const serverPresenceLockKey = 872342

// serverLockSuffix names the SQLite sidecar lock file, appended to the
// database path.
const serverLockSuffix = ".server.lock"

// Presence represents an acquired SHARED "a server is running" lock, held
// for the caller's lifetime. Release must be called on shutdown; the zero
// value (and a nil *Presence) is a safe no-op for remote storage.
type Presence struct {
	release func() error
}

// Release releases the presence lock. Safe to call on a nil Presence.
func (p *Presence) Release() error {
	if p == nil || p.release == nil {
		return nil
	}
	return p.release()
}

// AcquirePresence marks this process as a live server attached to cfg's
// database, in SHARED mode (concurrent server replicas do not conflict with
// each other). Returns an error only if the lock is already held
// EXCLUSIVELY — which this package never does on the server's own behalf,
// so in practice this only fails if the sidecar/advisory lock is somehow
// wedged by a non-cooperating process holding it exclusively via the same
// mechanism (e.g. a `keyorix-server admin` command's own exclusive probe
// racing this call at the exact same instant — vanishingly unlikely, and
// self-resolving on retry).
func AcquirePresence(cfg *config.Config) (*Presence, error) {
	switch cfg.Storage.Type {
	case "remote":
		return &Presence{}, nil
	case "postgres", "postgresql":
		return acquirePostgresPresence(cfg)
	default: // "local", "sqlite", ""
		return acquireSQLitePresence(cfg)
	}
}

// ProbeRunning reports whether a live server currently holds the presence
// lock for cfg's database, by attempting to acquire the SAME lock
// EXCLUSIVELY and non-blocking. Acquiring it means no server (nor another
// concurrent probe) currently holds it — released immediately, running is
// false. Failing to acquire it means some process holds it (shared or
// exclusive) — running is true. Remote storage always reports not running
// (no local database to guard).
func ProbeRunning(cfg *config.Config) (running bool, detail string, err error) {
	switch cfg.Storage.Type {
	case "remote":
		return false, "", nil
	case "postgres", "postgresql":
		return probePostgresRunning(cfg)
	default:
		return probeSQLiteRunning(cfg)
	}
}

// sqliteLockPath resolves the sidecar lock path for cfg's configured
// database, mirroring internal/storage/factory.go's localStorageDBFile: an
// in-memory database (no real on-disk file) has nothing to guard.
func sqliteLockPath(cfg *config.Config) (path string, isRealFile bool) {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	base := dbPath
	if idx := strings.IndexByte(base, '?'); idx != -1 {
		base = base[:idx]
	}
	if base == "" || base == ":memory:" || strings.Contains(dbPath, "mode=memory") {
		return "", false
	}
	return base + serverLockSuffix, true
}

func openLockFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create directory for server lock %q: %w", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- operator-configured database path, not user input
	if err != nil {
		return nil, fmt.Errorf("open server lock file %q: %w", path, err)
	}
	return f, nil
}

func acquireSQLitePresence(cfg *config.Config) (*Presence, error) {
	path, isRealFile := sqliteLockPath(cfg)
	if !isRealFile {
		return &Presence{}, nil
	}
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	// Blocking, not LOCK_NB: the only thing that ever holds this lock
	// EXCLUSIVELY is another process's brief, near-instantaneous
	// ProbeRunning call (acquire, check, release) — a server startup
	// racing that microsecond-scale window should wait it out rather than
	// fail to boot over it.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire shared server-presence lock on %q: %w", path, err)
	}
	return &Presence{release: func() error {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}}, nil
}

func probeSQLiteRunning(cfg *config.Config) (bool, string, error) {
	path, isRealFile := sqliteLockPath(cfg)
	if !isRealFile {
		return false, "", nil
	}
	f, err := openLockFile(path)
	if err != nil {
		return false, "", err
	}
	defer f.Close() //nolint:errcheck
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true, fmt.Sprintf("a process holds the server-presence lock at %s (SQLite database %s)", path, cfg.Storage.Database.Path), nil
	}
	// Acquired it — no holder. Release immediately; this was a probe, not a claim.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, "", nil
}

// pgConn opens a single dedicated connection to cfg's Postgres database,
// separate from the application's own pooled connection (opened later, if
// at all, by internal/storage's factory) — this guard's connection exists
// solely to hold or probe the session-scoped advisory lock and is closed
// with the guard.
func pgConn(cfg *config.Config) (*sql.DB, *sql.Conn, error) {
	dsn := config.BuildPostgresDSN(&cfg.Storage.Database)
	if dsn == "" {
		return nil, nil, fmt.Errorf("postgres storage requires a DSN or host/name/user fields")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, nil, fmt.Errorf("connect to postgres for server-presence check: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		_ = sqlDB.Close()
		return nil, nil, fmt.Errorf("acquire dedicated connection for server-presence check: %w", err)
	}
	return sqlDB, conn, nil
}

func acquirePostgresPresence(cfg *config.Config) (*Presence, error) {
	sqlDB, conn, err := pgConn(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock_shared($1)", serverPresenceLockKey); err != nil {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, fmt.Errorf("acquire shared server-presence advisory lock: %w", err)
	}
	return &Presence{release: func() error {
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		_, _ = conn.ExecContext(relCtx, "SELECT pg_advisory_unlock_shared($1)", serverPresenceLockKey)
		_ = conn.Close()
		return sqlDB.Close()
	}}, nil
}

func probePostgresRunning(cfg *config.Config) (bool, string, error) {
	sqlDB, conn, err := pgConn(cfg)
	if err != nil {
		return false, "", err
	}
	defer func() {
		_ = conn.Close()
		_ = sqlDB.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", serverPresenceLockKey).Scan(&acquired); err != nil {
		return false, "", fmt.Errorf("probe server-presence advisory lock: %w", err)
	}
	if !acquired {
		return true, "a process holds the server-presence advisory lock (PostgreSQL, key " + fmt.Sprint(serverPresenceLockKey) + ")", nil
	}
	_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", serverPresenceLockKey)
	return false, "", nil
}
