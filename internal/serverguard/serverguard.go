// Package serverguard detects whether a live Keyorix server process is
// currently attached to a given database, so that `keyorix-server admin`
// commands (ADR-108 §B, PR 11) can refuse to run concurrently with one
// unless the operator explicitly overrides with --force -- and, the other
// direction, so a server refuses to start while an admin command is
// mid-operation against the same database, rather than racing it.
//
// Mechanism: a reader/writer advisory lock, held in SHARED mode by every
// live server process for its whole lifetime (acquired at boot, released at
// shutdown) and held in EXCLUSIVE mode by an admin command for the WHOLE
// DURATION of its run (acquired before touching the database, released on
// exit) -- not merely probed and released before doing the actual work.
// AcquireExclusive returning successfully IS the admin command's guarantee
// that no server (and no other admin command) can attach for as long as the
// returned handle is held; a probe-then-release design would leave a window
// between the check and the work in which a server could start, which is
// exactly the race this guard exists to close (found in review before this
// package's first use landed: the original version had admin commands call
// ProbeRunning, release immediately, and then run unlocked).
//
// Any number of server replicas may hold the shared lock at once (this must
// not break the already-supported multi-replica Postgres HA topology,
// ADR-039) -- an exclusive request only succeeds when NO shared (or other
// exclusive) holder exists at all, which is exactly "no server, and no other
// admin command, is attached" regardless of how many replicas that would
// have been. Symmetrically, a shared request (a server booting) only fails
// when an EXCLUSIVE holder exists -- since this package never grants
// exclusive to anything other than an admin command, that failure has an
// unambiguous cause: report it as such, not as a generic lock error.
//
//   - Local SQLite: flock(2) SHARED/EXCLUSIVE, both non-blocking, on a
//     dedicated sidecar file next to the database (<db path>.server.lock --
//     distinct from the migration-only lock factory.go's withMigrationLock
//     takes during migrateDatabase, and from internal/encryption's
//     dek.lock, which is encryption-specific and unconditional-encryption-
//     disabled deployments never touch). Non-blocking on BOTH sides: a
//     server startup that lost the race to an admin command's exclusive
//     hold must fail fast with a clear message, never hang waiting for an
//     admin operation (which could run for as long as a migration or a KEK
//     rotation takes) to finish.
//   - PostgreSQL: pg_try_advisory_lock_shared / pg_try_advisory_lock (both
//     non-blocking), a session-scoped advisory lock keyed by
//     serverPresenceLockKey (distinct from internal/storage/factory.go's
//     postgresMigrationLockKey). Session-scoped means a crashed or killed
//     holder's lock is released by Postgres the moment its connection
//     drops -- there is no stale lock to clean up after an unclean
//     shutdown, on either side. Confirmed for AcquireExclusive specifically
//     (the guarantee task 4 of the review that added this asked to
//     verify): killing the process holding either an flock or an advisory
//     lock releases it immediately -- see
//     TestSQLite_KilledHolderProcess_ReleasesLock and
//     TestPostgres_KilledHolderProcess_ReleasesLock.
//   - Remote storage (storage.type: remote) has no local database to guard;
//     AcquirePresence/AcquireExclusive/ProbeRunning are no-ops for it.
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
//   - The SQLite sidecar is named after the configured path string. Every
//     spelling that resolves into the database's own directory (relative or
//     absolute, "." or "..", a symlinked directory, DSN query parameters)
//     meets on one lock file (TestSQLitePathSpellings_MeetOnTheSameLock). A
//     symlink to the database FILE, or a hard link, used by only one side does
//     not: the two sides then lock different sidecar files. "file:" URI
//     spellings resolve to the file SQLite opens
//     (TestSQLiteURISpellings_MeetOnTheSameLock).
//   - The SQLite lock lives on the sidecar's inode, not its name. Deleting or
//     replacing <db path>.server.lock while a server holds it (taking it for a
//     stale lock file: it never is, an flock ends with its process) leaves the
//     server on the old inode (REVIEW-SERVERGUARD-RECOVERYKEY-1 F4). A running
//     server checks every config.PinnedLockPingInterval (5 s) that the path
//     still names the file it holds, and otherwise re-creates it and takes the
//     lock again, or, when an admin command already holds the new file, closes
//     Presence.Lost so the server stops (sidecarWatch). An admin command that
//     starts AND finishes inside that interval is not detected. An admin
//     command's own exclusive hold is not watched. Both sides check, after the
//     flock, that the path still names the file they locked, so an unlink
//     between open and flock cannot leave one on a deleted file (lockSidecar).
//     A filesystem without flock support or inode numbers is refused at start
//     with an error saying so.
//   - Postgres advisory locks share one numeric keyspace across the whole
//     database cluster, not namespaced per application. A collision with an
//     unrelated application choosing the same key is possible in principle;
//     mitigated, not eliminated, by using an arbitrary fixed constant here.
//   - --force (a caller-side policy, not enforced by this package) still
//     ATTEMPTS AcquireExclusive first; only if that fails does the caller
//     proceed unprotected. A caller that skips the attempt entirely under
//     --force reopens exactly the race this package exists to close.
package serverguard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/sqlitepath"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// lockHeldErr marks an AcquireExclusive failure that means another live server or admin
// command genuinely holds this guard's lock -- as opposed to any other acquisition failure
// (a connection error, bad credentials, a misconfigured DSN), which means presence could not
// be determined at all. #2362: the admin pre-flight check reported "a Keyorix server ...
// appears to be using this database" even for a plain Postgres auth failure (SQLSTATE
// 28P01) -- misleading, since nothing established whether a server was actually attached.
// IsLockHeld lets a caller choose an accurate top-level message for each case while still
// failing closed either way.
type lockHeldErr struct{ err error }

func (e *lockHeldErr) Error() string { return e.err.Error() }
func (e *lockHeldErr) Unwrap() error { return e.err }

// IsLockHeld reports whether err (as returned by AcquireExclusive) means another live server
// or admin command genuinely holds the lock, as opposed to any other acquisition failure.
func IsLockHeld(err error) bool {
	var e *lockHeldErr
	return errors.As(err, &e)
}

// lockFileErr marks an AcquireExclusive failure on the SQLite sidecar lock file
// itself (it cannot be created, opened, statted or flocked: a foreign-owned or
// unreadable .server.lock, a filesystem without flock or inode numbers), as
// opposed to a held lock or a database connection failure. Fails closed like
// every other acquisition failure; IsLockFileError lets a caller say what
// actually went wrong (REVIEW-SERVERGUARD-RECOVERYKEY-1 F7: the admin refusal
// called an EACCES on the lock file "cannot connect to the database").
type lockFileErr struct{ err error }

func (e *lockFileErr) Error() string { return e.err.Error() }
func (e *lockFileErr) Unwrap() error { return e.err }

// IsLockFileError reports whether err (as returned by AcquireExclusive) is a
// failure on the SQLite server lock file itself.
func IsLockFileError(err error) bool {
	var e *lockFileErr
	return errors.As(err, &e)
}

// serverPresenceLockKey is the Postgres advisory-lock key for this guard.
// Arbitrary but fixed, distinct from internal/storage/factory.go's
// postgresMigrationLockKey (872341) — the two locks serve different purposes
// (migration-in-progress vs. server-or-admin-attached) and must not collide.
const serverPresenceLockKey = 872342

// serverLockSuffix names the SQLite sidecar lock file, appended to the
// database path.
const serverLockSuffix = ".server.lock"

// Presence represents an acquired SHARED "a server is attached" lock, held
// for the caller's lifetime. Release must be called on shutdown; the zero
// value (and a nil *Presence) is a safe no-op for remote storage.
type Presence struct {
	release func() error
	lost    chan struct{} // closed when the lock is found lost; nil if it cannot be
}

// Lost is closed when the presence lock is found lost while held. PostgreSQL:
// a pg_terminate_backend, a PostgreSQL restart or failover, a network
// partition or (pgbouncer-transaction) a PgBouncer timeout ends the lock's
// backend or its transaction without any other signal to the holder. From that
// moment an admin command can start beside this server, so the caller should
// stop serving. On SQLite it is closed when the sidecar lock file was deleted
// or replaced and the server could not take the lock on the new file (an admin
// command holds it: see sidecarWatch). A nil channel (a receive blocks
// forever) for remote storage and an in-memory SQLite database; never closed
// after Release.
func (p *Presence) Lost() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.lost
}

// Release releases the presence lock. Safe to call on a nil Presence.
func (p *Presence) Release() error {
	if p == nil || p.release == nil {
		return nil
	}
	return p.release()
}

// Exclusive represents an acquired EXCLUSIVE "an admin operation is
// attached" lock, held for the CALLER'S ENTIRE OPERATION -- acquire before
// touching the database, defer Release on every return path, including
// error paths. A nil *Exclusive (e.g. remote storage, or --force proceeding
// after a failed acquisition) is a safe no-op to Release.
type Exclusive struct {
	release func() error
	lost    chan struct{} // closed when the lock is found lost; nil if it cannot be
}

// Lost is closed when the PostgreSQL exclusive lock is found lost while held
// (the same causes as Presence.Lost). From that moment a server can start
// beside the admin command, and with storage.encryption.key_dir_lock: database
// this lock is the only thing that keeps a replica off the key files a
// rotation is rewriting (docs/multi-replica-keys.md), so the caller should
// stop. A nil channel for SQLite, remote storage and a nil *Exclusive; never
// closed after Release.
func (e *Exclusive) Lost() <-chan struct{} {
	if e == nil {
		return nil
	}
	return e.lost
}

// Release releases the exclusive lock. Safe to call on a nil Exclusive.
func (e *Exclusive) Release() error {
	if e == nil || e.release == nil {
		return nil
	}
	return e.release()
}

// AcquirePresence marks this process as a live server attached to cfg's
// database, in SHARED mode (concurrent server replicas do not conflict with
// each other). Returns an error when an admin command currently holds the
// EXCLUSIVE lock -- the only thing this package ever grants exclusive to --
// so the error is reported as exactly that, not a generic lock failure.
// Non-blocking: a server that loses this race fails fast rather than
// waiting out an admin operation of unknown duration.
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

// AcquireExclusive marks this process as an admin operation attached to
// cfg's database, in EXCLUSIVE mode -- conflicts with a live server's
// SHARED hold and with any other admin command's own EXCLUSIVE hold.
// Callers MUST hold the returned handle for their entire operation (not
// merely check it and release), and MUST Release it on every return path.
// Non-blocking: fails immediately if a server or another admin command
// already holds it, rather than queueing behind one of unknown duration.
func AcquireExclusive(cfg *config.Config) (*Exclusive, error) {
	switch cfg.Storage.Type {
	case "remote":
		return &Exclusive{}, nil
	case "postgres", "postgresql":
		return acquirePostgresExclusive(cfg)
	default:
		return acquireSQLiteExclusive(cfg)
	}
}

// ProbeRunning reports whether a live server or admin operation currently
// holds this guard's lock for cfg's database, WITHOUT holding it itself --
// acquires AcquireExclusive and immediately releases if successful. This is
// a read-only convenience for observability/tests; production admin-command
// code must call AcquireExclusive directly and hold what it gets, not this
// function, or it reopens the exact check-then-act race this package exists
// to close.
func ProbeRunning(cfg *config.Config) (running bool, detail string, err error) {
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		return true, err.Error(), nil
	}
	_ = lock.Release()
	return false, "", nil
}

// sqliteLockPath resolves the sidecar lock path for cfg's configured
// database through sqlitepath.DatabaseFile, the resolver internal/storage uses for
// the database file itself: an in-memory database has nothing to guard, and a
// SQLite URI filename meets a plain spelling of the same path on one sidecar
// (TestSQLiteURISpellings_MeetOnTheSameLock).
func sqliteLockPath(cfg *config.Config) (path string, isRealFile bool) {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	base, isRealFile := sqlitepath.DatabaseFile(dbPath)
	if !isRealFile {
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

// Test seams. Production never changes them: afterLockFileOpen runs between
// opening the sidecar and locking it (where an unlink races the flock),
// flockFn takes the lock, lockFileInode reads a file's inode number.
var (
	afterLockFileOpen func(path string)
	flockFn           = syscall.Flock
	lockFileInode     = inodeOf
)

// lockFileAttempts bounds lockSidecar's retries when the sidecar is replaced
// between opening and locking it.
const lockFileAttempts = 3

// errSidecarHeld means another process holds the sidecar in a conflicting
// mode (flock EWOULDBLOCK): the one outcome that is "held", not "broken".
var errSidecarHeld = errors.New("server lock file is held")

func inodeOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return 0, false
	}
	return st.Ino, true
}

// pathNamesFile reports whether path currently names the file fi describes
// (false, not an error, when path no longer exists).
func pathNamesFile(path string, fi os.FileInfo) (bool, error) {
	cur, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat server lock file %q: %w", path, err)
	}
	return os.SameFile(fi, cur), nil
}

// lockSidecar opens the sidecar at path and flocks it non-blocking (how is
// LOCK_SH or LOCK_EX), then checks that path still names the file it locked.
// The lock lives on the inode: a sidecar unlinked or replaced between the
// open and the flock would leave the caller holding a lock on a file nobody
// else can open (REVIEW-SERVERGUARD-RECOVERYKEY-1 F4), so it tries again, up
// to lockFileAttempts times. errSidecarHeld means a conflicting holder; any
// other error means the guard cannot work here (a filesystem without flock
// support or inode numbers, a lock file that keeps being replaced), said
// loudly at start rather than run unguarded.
func lockSidecar(path string, how int) (*os.File, error) {
	for range lockFileAttempts {
		f, err := openLockFile(path)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("stat server lock file %q: %w", path, err)
		}
		if _, ok := lockFileInode(fi); !ok {
			_ = f.Close()
			return nil, fmt.Errorf("server lock file %q: the filesystem reports no inode numbers, so a deleted or replaced lock file cannot be detected; put the SQLite database on a local filesystem, or use storage.type: postgres", path)
		}
		if hook := afterLockFileOpen; hook != nil {
			hook(path)
		}
		if err := flockFn(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
			_ = f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, errSidecarHeld
			}
			return nil, fmt.Errorf("lock server lock file %q: %w: the filesystem holding it does not support file locks (flock), so a server and an admin command cannot exclude each other; put the SQLite database on a local filesystem, or use storage.type: postgres", path, err)
		}
		same, err := pathNamesFile(path, fi)
		if err == nil && same {
			return f, nil
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("server lock file %q was replaced between opening and locking it %d times in a row: another process keeps deleting or replacing it (it is never a stale lock file; do not delete it), or the filesystem does not keep inode numbers stable (put the SQLite database on a local filesystem, or use storage.type: postgres)", path, lockFileAttempts)
}

func acquireSQLitePresence(cfg *config.Config) (*Presence, error) {
	path, isRealFile := sqliteLockPath(cfg)
	if !isRealFile {
		return &Presence{}, nil
	}
	// Non-blocking: the only thing that can hold this EXCLUSIVELY is an
	// admin command (this package never takes exclusive on a server's own
	// behalf) -- a server startup that loses this race must fail fast with
	// that specific, actionable message, not hang waiting for an admin
	// operation of unknown duration to finish.
	f, err := lockSidecar(path, syscall.LOCK_SH)
	if errors.Is(err, errSidecarHeld) {
		return nil, fmt.Errorf("an admin operation is running against this database (%s); retry when it finishes", path)
	}
	if err != nil {
		return nil, err
	}
	w := &sidecarWatch{path: path, f: f, lost: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	go w.run(config.PinnedLockPingInterval)
	return &Presence{lost: w.lost, release: w.release}, nil
}

// sidecarWatch keeps a server's SQLite presence lock on the file its path
// names (REVIEW-SERVERGUARD-RECOVERYKEY-1 F4). Every interval (the PostgreSQL
// presence watch's, config.PinnedLockPingInterval) it checks that the path
// still names the inode it holds. If the sidecar was deleted or replaced, it
// opens (re-creating) the file the path now names and takes LOCK_SH on it,
// then lets the old one go. If that fails, an admin command already holds the
// new file exclusively (or the file cannot be locked at all), so the server
// is no longer excluding admin commands: lost is closed, and the server stops
// as on a lost PostgreSQL presence lock (server/lock_loss.go).
//
// Not covered: an admin command that starts and finishes inside one interval
// after the deletion ran beside the server, and nothing can tell afterwards.
// Only the watcher goroutine uses f until release has stopped it.
type sidecarWatch struct {
	path string
	f    *os.File
	lost chan struct{}
	stop chan struct{}
	done chan struct{}

	releaseOnce sync.Once
	releaseErr  error
}

func (w *sidecarWatch) run(interval time.Duration) {
	defer close(w.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
		}
		err := w.check()
		select {
		case <-w.stop: // a loss found after Release is not reported
			return
		default:
		}
		if err != nil {
			log.Printf("serverguard presence lock: %v, so the lock is lost", err)
			close(w.lost)
			return
		}
	}
}

func (w *sidecarWatch) check() error {
	fi, err := w.f.Stat()
	if err == nil {
		if same, serr := pathNamesFile(w.path, fi); serr == nil && same {
			return nil
		}
	}
	nf, err := lockSidecar(w.path, syscall.LOCK_SH)
	switch {
	case err == nil:
		_ = syscall.Flock(int(w.f.Fd()), syscall.LOCK_UN)
		_ = w.f.Close()
		w.f = nf
		log.Printf("serverguard: WARNING: %s was deleted or replaced while this server held it; re-created it and took the presence lock again. It is never a stale lock file: do not delete it", w.path)
		return nil
	case errors.Is(err, errSidecarHeld):
		return fmt.Errorf("%s was deleted or replaced while this server held it, and an admin command now holds the new file exclusively", w.path)
	default:
		return fmt.Errorf("%s was deleted or replaced while this server held it, and taking it again failed: %w", w.path, err)
	}
}

// release stops the watch and lets the lock go. Safe to call more than once.
func (w *sidecarWatch) release() error {
	w.releaseOnce.Do(func() {
		close(w.stop)
		<-w.done
		_ = syscall.Flock(int(w.f.Fd()), syscall.LOCK_UN)
		w.releaseErr = w.f.Close()
	})
	return w.releaseErr
}

func acquireSQLiteExclusive(cfg *config.Config) (*Exclusive, error) {
	path, isRealFile := sqliteLockPath(cfg)
	if !isRealFile {
		return &Exclusive{}, nil
	}
	f, err := lockSidecar(path, syscall.LOCK_EX)
	if errors.Is(err, errSidecarHeld) {
		return nil, &lockHeldErr{fmt.Errorf("another process holds this database (a live server, or another admin command) via %s", path)}
	}
	if err != nil {
		return nil, &lockFileErr{err}
	}
	return &Exclusive{release: func() error {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}}, nil
}

// pgConn opens a single dedicated connection to cfg's Postgres database,
// separate from the application's own pooled connection (opened later, if
// at all, by internal/storage's factory) — this guard's connection exists
// solely to hold the session-scoped advisory lock and is closed with the
// guard (or, for AcquireExclusive, held open for the caller's entire
// operation).
func pgConn(cfg *config.Config) (*sql.DB, *sql.Conn, error) {
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return nil, nil, err
	}
	// From the parsed config, never a DSN string: the resolved password is
	// set on it and cannot change any other connection setting.
	pool := stdlib.OpenDB(*cc)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		_ = pool.Close()
		if classified := config.ClassifyPostgresConnectErrorConfig(err, cc); classified != err {
			return nil, nil, classified
		}
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
		if classified := config.ClassifyPostgresConnectErrorConfig(err, cc); classified != err {
			return nil, nil, classified
		}
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
	xact := cfg.Storage.Database.TransactionPooling()
	if xact {
		if err := beginPinnedLockTx(ctx, conn); err != nil {
			_ = conn.Close()
			_ = sqlDB.Close()
			return nil, fmt.Errorf("acquire shared server-presence advisory lock: %w", err)
		}
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, pgLockSQL("pg_try_advisory_lock_shared", xact), pgLockArgs(xact)...).Scan(&acquired); err != nil {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, fmt.Errorf("acquire shared server-presence advisory lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, fmt.Errorf("an admin operation is running against this database (postgres advisory lock %d); retry when it finishes", serverPresenceLockKey)
	}
	// Watched in both shapes: a session lock ends with its backend exactly as
	// the transaction-scoped one does, and nothing runs on conn to notice.
	lost := make(chan struct{})
	stopWatch := config.WatchPinnedLockConn(conn, "serverguard presence lock", func(error) { close(lost) })
	return &Presence{lost: lost, release: func() error {
		stopWatch() // before the ROLLBACK below, which needs the connection to itself
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		// Explicit and synchronous: by the time this call returns, the lock
		// is released server-side -- callers don't need to rely on Postgres
		// noticing the connection close below (which happens too, as a
		// fallback for a crash that skips this call entirely, but is not the
		// primary release path and can lag it). If this ever fails (e.g. a
		// timeout under load), the connection is still closed immediately
		// after, so release still eventually happens via that fallback --
		// but silently, with no signal that the fast path didn't fire. Log
		// it so that's visible rather than invisible.
		if xact {
			endPinnedLockTx(relCtx, conn)
		} else if _, err := conn.ExecContext(relCtx, "SELECT pg_advisory_unlock_shared($1)", serverPresenceLockKey); err != nil {
			log.Printf("serverguard: explicit pg_advisory_unlock_shared(%d) failed, falling back to connection-close release: %v", serverPresenceLockKey, err)
		}
		_ = conn.Close()
		return sqlDB.Close()
	}}, nil
}

func acquirePostgresExclusive(cfg *config.Config) (*Exclusive, error) {
	sqlDB, conn, err := pgConn(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	xact := cfg.Storage.Database.TransactionPooling()
	if xact {
		if err := beginPinnedLockTx(ctx, conn); err != nil {
			_ = conn.Close()
			_ = sqlDB.Close()
			return nil, fmt.Errorf("probe server-presence advisory lock: %w", err)
		}
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, pgLockSQL("pg_try_advisory_lock", xact), pgLockArgs(xact)...).Scan(&acquired); err != nil {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, fmt.Errorf("probe server-presence advisory lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		_ = sqlDB.Close()
		return nil, &lockHeldErr{fmt.Errorf("another process holds this database (a live server, or another admin command) via postgres advisory lock %d", serverPresenceLockKey)}
	}
	// Watched like the presence lock (INV-STORAGE-session-advisory-lock-loss):
	// the admin command's own work runs on other connections, so nothing else
	// would notice this one's backend ending.
	lost := make(chan struct{})
	stopWatch := config.WatchPinnedLockConn(conn, "serverguard admin exclusive lock", func(error) { close(lost) })
	return &Exclusive{lost: lost, release: func() error {
		stopWatch() // before the unlock below, which needs the connection to itself
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		// See acquirePostgresPresence's release closure for why this is
		// logged rather than swallowed: an admin command's exclusive hold
		// outliving this explicit unlock (falling back to connection-close
		// detection) is exactly the kind of availability gap a server
		// startup racing the release would notice as "still refused" for
		// longer than expected.
		if xact {
			endPinnedLockTx(relCtx, conn)
		} else if _, err := conn.ExecContext(relCtx, "SELECT pg_advisory_unlock($1)", serverPresenceLockKey); err != nil {
			log.Printf("serverguard: explicit pg_advisory_unlock(%d) failed, falling back to connection-close release: %v", serverPresenceLockKey, err)
		}
		_ = conn.Close()
		return sqlDB.Close()
	}}, nil
}

// pgLockSQL is the try-lock statement for fn ("pg_try_advisory_lock" or
// "pg_try_advisory_lock_shared"), in its transaction-scoped form when xact.
//
// storage.database.pooler: pgbouncer-transaction makes every lock here
// transaction-scoped, inside a transaction held open for the lock's whole life
// (beginPinnedLockTx). A transaction-mode pooler keeps a client on one server
// connection only while a transaction is open: a session lock taken in
// autocommit would stay on a server connection the pooler then hands to other
// clients, the unlock could run on another one, and closing this client would
// not end the backend, so "a killed holder's lock is released" would no longer
// hold. Inside the open transaction it does: the pooler closes the server
// connection when its client disconnects mid-transaction. Holding a
// transaction open for the server's lifetime keeps one server connection per
// replica (docs/postgresql-poolers.md).
func pgLockSQL(fn string, xact bool) string {
	if xact {
		fn = strings.Replace(fn, "advisory_lock", "advisory_xact_lock", 1)
	}
	return "SELECT " + fn + "($1)"
}

// pgLockArgs are pgLockSQL's arguments. In its transaction-scoped form the
// statement goes over the simple query protocol: an extended-protocol SELECT
// inside a transaction block leaves its unnamed portal, and that portal's
// snapshot, open until the transaction ends, so a lock transaction held for
// the server's lifetime would pin the database's xmin as long (VACUUM keeps
// dead rows; every CREATE INDEX CONCURRENTLY waits for it).
func pgLockArgs(xact bool) []any {
	if xact {
		return []any{pgx.QueryExecModeSimpleProtocol, serverPresenceLockKey}
	}
	return []any{serverPresenceLockKey}
}

// beginPinnedLockTx opens the transaction a transaction-scoped presence lock
// lives in. It is idle for the whole hold, so idle_in_transaction_session_timeout
// and (PostgreSQL 17+) transaction_timeout are 0 for it alone: a server-side
// timeout ending it would silently drop the lock (config.PinnedLockTxSetupSQL).
func beginPinnedLockTx(ctx context.Context, conn *sql.Conn) error {
	return config.BeginPinnedLockTx(ctx, conn)
}

// endPinnedLockTx ends the lock transaction, releasing the lock. If that fails
// the connection is closed right after by the caller, which ends the
// transaction too (the pooler closes the server connection of a client that
// disconnects mid-transaction).
func endPinnedLockTx(ctx context.Context, conn *sql.Conn) {
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		log.Printf("serverguard: ending the presence lock transaction failed, falling back to connection-close release: %v", err)
	}
}
