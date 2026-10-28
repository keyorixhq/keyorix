package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/sqlitepath"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// sqliteBusyTimeoutMillis is how long a SQLite connection waits for a lock held by
// another connection before returning SQLITE_BUSY (#465). SQLite's own default is 0
// (fail immediately), which surfaces as spurious write failures under the concurrent
// goroutines/HTTP handlers this server routinely runs against a single local SQLite
// file. 10s matches the value the storage package's own file-backed-SQLite
// concurrency tests already use (see internal/storage/store/concurrency_*_test.go),
// which is a real, empirically-exercised value for this exact workload rather than an
// invented one.
const sqliteBusyTimeoutMillis = 10000

// sqliteDSN builds the gorm-sqlite (modernc.org/sqlite, ADR-048) DSN for a local SQLite database
// file, appending the DSN-level pragmas needed for correctness/robustness on the
// default local-storage backend:
//
//   - _foreign_keys=1 (#436): SQLite defaults foreign-key CONSTRAINT enforcement to
//     OFF per-connection unless explicitly enabled. This is table-stakes hygiene
//     regardless of which constraints exist today: any FOREIGN KEY declared on this
//     connection (now or in a future migration/model change) is silently
//     unenforced without it, so a raw DELETE/UPDATE that bypasses the application's
//     own cascade logic could orphan dependent rows with zero DB-level backstop and
//     no visible error. See factory_sqlite_pragma_test.go for the scope note on
//     what this codebase's GORM-generated schema currently declares.
//
//   - _busy_timeout=<ms> (#465): see sqliteBusyTimeoutMillis above.
//
//   - _journal_mode=WAL (#465): the default rollback-journal mode blocks readers
//     during a write and vice versa, increasing SQLITE_BUSY frequency under
//     concurrent access; WAL lets readers proceed concurrently with a writer.
//
//   - _txlock=immediate: SQLite's default BEGIN is DEFERRED — a transaction that
//     reads first and writes second (e.g. AssignRole's existing-grant check
//     before its Create) only requests the write lock at that first write
//     statement, mid-transaction. If another connection committed a write after
//     this transaction's read snapshot was taken, that lock request returns
//     SQLITE_BUSY immediately: the busy handler backing _busy_timeout is NEVER
//     invoked for a lock upgrade (only for an initial lock acquisition, so two
//     transactions each waiting to upgrade the other's read lock can't
//     deadlock in the handler) — so a spuriously-failed read-then-write
//     transaction is possible even with a generous busy_timeout configured.
//     BEGIN IMMEDIATE claims the write lock upfront, when _busy_timeout's
//     retry loop is actually consulted, converting that failure mode into an
//     ordinary bounded wait. Root-caused via TestSessionCacheChokepoint_
//     CoversEveryVulnerableCallSite flaking on PR #1996's branch (CI runs
//     35871480798, 35840030029: "grant victim ...: database is locked (5)
//     (SQLITE_BUSY)" from AssignUserRole) despite _busy_timeout already
//     being set.
//
//   - _synchronous=FULL (SESSION-PERF, 2026-10-02): without this, `synchronous`
//     is never touched by this DSN and falls through to the driver/library
//     default — which modernc.org/sqlite v1.59.0 leaves unset when the DSN
//     omits it, so it resolves to SQLite's own compiled-in default of FULL (2)
//     (confirmed empirically: a connection opened with the DSN as it stood
//     before this change reports `PRAGMA synchronous` = 2). So this change does
//     NOT alter runtime behaviour — FULL was already in effect. What it fixes
//     is that the guarantee was implicit and unasserted: nothing stopped a
//     future dependency bump, or someone "optimizing" this DSN, from silently
//     weakening it to NORMAL. FULL, not NORMAL, is required here specifically
//     because this database carries the audit hash-chain
//     (internal/storage/store/local_audit_chain.go): in WAL mode, NORMAL only
//     fsyncs at checkpoint boundaries, not on every COMMIT — a transaction can
//     report success to the audit-chain writer while its WAL frame is still
//     only in the OS page cache, surviving an application crash but NOT an OS
//     crash or power loss before the next checkpoint. FULL fsyncs the WAL on
//     every commit, so "the audit entry was written" and "the audit entry
//     survives a host crash" stay the same claim. See
//     factory_sqlite_pragma_test.go for the test asserting this, and
//     docs/g80-remediation-notes.md's SESSION-PERF entry for the measured
//     before/after (no throughput delta, as expected, since the pragma value
//     is unchanged — this closes an unasserted-guarantee gap, not a bug).
//
//     NOT RELAXABLE BY CONFIGURATION. storage.database.audit_durability's
//     standard level (ADR-112 Amendments 1 and 3) is PostgreSQL-ONLY and
//     config validation REFUSES TO START a SQLite backend set to it
//     (internal/config's auditDurabilityStandardSQLiteUnsupportedError), so this
//     DSN has no NORMAL branch at all and never had one in a shipped build.
//     Two reasons it is not offered here, both measured or structural:
//     `synchronous` is a PER-CONNECTION property set once per DSN and the pool
//     is shared by every query, so NORMAL would relax commit durability for
//     the WHOLE database — a power loss could undo a just-committed secret
//     rotation or revocation, not merely lose audit entries; and the measured
//     p99 got WORSE under concurrency anyway (328.8->518.0ms at c=10,
//     703.7->919.0ms at c=50 on pve01), so it was not even a clean latency
//     win. Postgres's own path confines the equivalent change to the audit
//     transaction alone (SET LOCAL synchronous_commit, see
//     internal/storage/store/local_audit_chain.go), which is why it IS offered
//     there.
//
// Postgres has no equivalent opt-out (FK enforcement is always on) and no analogous
// pragmas, so this is intentionally SQLite-only — never applied to the Postgres
// connection path.
func sqliteDSN(dbPath string) string {
	sep := "?"
	if strings.Contains(dbPath, "?") {
		// The operator already supplied their own DSN query parameters (e.g. a
		// custom path with embedded pragmas) — append rather than clobber them.
		sep = "&"
	}
	return fmt.Sprintf("%s%s_foreign_keys=1&_busy_timeout=%d&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL", dbPath, sep, sqliteBusyTimeoutMillis)
}

// secureLocalStoragePerm is the mode the SQLite database and its -wal/-shm sidecars must
// never exceed: owner read/write only. See prepareLocalStorageFile / tightenSidecarPerms
// and #1647.
const secureLocalStoragePerm = 0o600

// localStorageDBFile resolves dbPath to the file SQLite opens and reports whether there is
// one at all: false for an in-memory database (":memory:", or a "file:" URI whose last "mode" key
// is "memory", both used throughout this package's own test suite; a plain name's query is dropped
// by the driver, so it is a real file). Neither #1647 concern (an insecure inherited
// mode, a mode left over from before this fix) applies to a database that was never written to
// disk. It is sqlitepath.DatabaseFile, the resolver the server lock sidecar uses, so a
// SQLite "file:" URI names the real database here too: before, "file:/data/secrets.db" made
// prepareLocalStorageFile pre-create a junk relative "file:/data/secrets.db" path while the real
// database was born at the process umask until tightenExistingLocalStorageFiles fixed it.
func localStorageDBFile(dbPath string) (path string, isRealFile bool) {
	return sqlitepath.DatabaseFile(dbPath)
}

// prepareLocalStorageFile ensures dbPath's parent directory exists at a safe mode and, if
// the database file does not already exist, pre-creates it at secureLocalStoragePerm
// BEFORE gorm.Open ever touches it. modernc.org/sqlite's VFS creates a file it opens with
// mode 0, which becomes SQLITE_DEFAULT_FILE_PERMISSIONS (0644) masked by the process's
// (possibly lax) inherited umask -- main()'s explicit syscall.Umask(0o077) closes that for
// every NEW file this process creates, but this pre-creation is a second, independent
// layer: it means the database is born at 0600 even if that startup umask call is ever
// missing, skipped, or reverted by something later in the process (#1647).
//
// If the file already exists from before this fix shipped, its mode is left untouched
// here -- see tightenExistingLocalStorageFiles, which runs after Open and decides whether
// to correct it, since that decision needs the file to exist first.
func prepareLocalStorageFile(dbPath string) error {
	path, isRealFile := localStorageDBFile(dbPath)
	if !isRealFile {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create database directory %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, secureLocalStoragePerm) // #nosec G304 -- operator-configured storage.database.path, the same value gorm.Open uses immediately after
	if err != nil {
		if os.IsExist(err) {
			return nil // pre-existing file — tightenExistingLocalStorageFiles handles it after Open
		}
		return fmt.Errorf("failed to pre-create database file %q: %w", path, err)
	}
	return f.Close()
}

// tightenExistingLocalStorageFiles corrects the mode of dbPath and its -wal/-shm sidecars
// if any is more permissive than secureLocalStoragePerm — the case of a database created
// before this fix shipped, which keeps whatever mode it was originally given (#1647). This
// runs on every local-storage open (server boot AND every CLI invocation, since both share
// this one factory function) rather than as an opt-in check: unlike most security
// hardening, tightening a file's mode to 0600 can never break the owning process's own
// access to it, so there is no operational reason to make correction conditional or to
// refuse to start over it — only to make sure it is never SILENT. Each correction is
// logged loudly so an operator relying on some other process (backup tooling running as a
// different user, for instance) to read the file finds out immediately, not by that other
// process mysteriously losing access.
func tightenExistingLocalStorageFiles(dbPath string) {
	dbPath, isRealFile := localStorageDBFile(dbPath)
	if !isRealFile {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		info, err := os.Stat(path)
		if err != nil {
			continue // doesn't exist (yet, or ever, e.g. no -shm outside WAL mode) — nothing to tighten
		}
		if info.Mode().Perm() == secureLocalStoragePerm {
			continue
		}
		oldMode := info.Mode().Perm()
		if err := os.Chmod(path, secureLocalStoragePerm); err != nil {
			log.Printf("SECURITY: failed to tighten permissions on %s (mode %04o, expected %04o): %v", path, oldMode, secureLocalStoragePerm, err)
			continue
		}
		log.Printf("SECURITY: corrected %s permissions from %04o to %04o (see #1647 -- this file predates an explicit-mode fix and previously relied on the inherited process umask)", path, oldMode, secureLocalStoragePerm)
	}
}

// localBackend is storage.type "local" (or "sqlite").
//
// #1640: "sqlite" is an accepted alias for "local" (the shipped
// configs/keyorix.yaml.tpl documents "sqlite" as the value to set,
// matching postgresBackend's "postgres"/"postgresql" dual spelling --
// operators write the storage engine's name, not this codebase's
// internal term for it).
var localBackend = storageBackend{
	names:  []string{"local", "sqlite"},
	create: (*DefaultStorageFactory).createLocalStorage,
}

// createLocalStorage creates a SQLite-backed local storage instance
func (f *DefaultStorageFactory) createLocalStorage(cfg *config.Config) (storage.Storage, error) {
	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}

	// #1636: log which file is actually about to be opened, and whether it
	// already existed, BEFORE anything below creates it -- both
	// prepareLocalStorageFile's O_CREATE pre-create (#1647) and gorm.Open's
	// implicit create-if-missing make that distinction unrecoverable. This
	// stat must stay ahead of prepareLocalStorageFile: #1652 originally landed
	// that call above it, so every missing path was reported as "opening
	// existing" and the warning below never fired (#2504; guarded by
	// TestCreateLocalStorage_MissingPath_LogsNewEmptyDatabase). dbPath itself
	// is deliberately left untouched here (still cwd-relative if configured
	// that way, still fed as-is into sqliteDSN/withMigrationLock below) --
	// this is diagnostics only, not a fix for the underlying resolution
	// defect (tracked separately). Best-effort: filepath.Abs only fails if
	// os.Getwd() fails, which would already be a more fundamental problem
	// than this log line; never block startup on it.
	//
	// The existence question is asked through localStorageDBFile, not
	// os.Stat(dbPath) directly: database.path may legitimately carry a DSN
	// query suffix ("file:secrets.db?_busy_timeout=...", see
	// TestCreateLocalStorage_S27_ExistingDSNQueryString), which os.Stat can
	// never resolve, so the raw-path form reported EVERY such configuration as
	// "no database found" even when the file was right there. Same helper
	// acquireSQLiteMigrationLock and prepareLocalStorageFile already use, and
	// it also answers "is there a file to pre-exist at all" for the in-memory
	// shapes below.
	statPath, isRealFile := localStorageDBFile(dbPath)
	logDbPath := statPath
	if logDbPath == "" {
		logDbPath = dbPath
	}
	if abs, aerr := filepath.Abs(logDbPath); aerr == nil && isRealFile {
		logDbPath = abs
	}
	dbFileExists := false
	if isRealFile {
		if _, statErr := os.Stat(statPath); statErr == nil {
			dbFileExists = true
		}
	}
	switch {
	case !isRealFile:
		log.Printf("storage: opening in-memory SQLite database (configured: %q)", cfg.Storage.Database.Path)
	case dbFileExists:
		log.Printf("storage: opening existing SQLite database at %s (configured: %q)", logDbPath, cfg.Storage.Database.Path)
	default:
		log.Printf("storage: no database found at %s (configured: %q) -- a NEW, EMPTY database will be created here", logDbPath, cfg.Storage.Database.Path)
	}

	// INV-STORAGE-22 / ADR-095 Task 3 (#2504): refuse rather than vivify, when
	// the operator has asked for that. An absolute path is not enough on its
	// own -- it stops two processes diverging onto two files, but a single
	// mistyped path (or a volume mount that silently failed to attach) still
	// produces a fresh, empty, healthy-looking store, with the real data still
	// sitting untouched where it was meant to be read from. Opt-in because
	// nothing in the supported first-boot paths creates the file beforehand;
	// see DatabaseConfig.RequireExistingPath's own doc comment for why the
	// default is NOT flipped here. In-memory DSNs are exempt by construction
	// (nothing to pre-exist) rather than by a carve-out.
	if cfg.Storage.Database.RequireExistingPath && isRealFile && !dbFileExists {
		return nil, fmt.Errorf("no database found at %s (configured database.path: %q) and database.require_existing_path is set: "+
			"run 'keyorix-server admin init' to create one deliberately, or verify database.path and the working directory "+
			"-- refusing to create a new, empty database in its place (INV-STORAGE-22, ADR-095 Task 3)",
			logDbPath, cfg.Storage.Database.Path)
	}

	if err := prepareLocalStorageFile(dbPath); err != nil {
		return nil, err
	}

	// Hold migrationMu across gorm.Open too, not just the migration that follows
	// (#465 follow-up). gorm.Open eagerly establishes a physical connection and
	// applies the SQLite DSN pragmas, including the journal_mode=WAL switch added
	// above — and unlike ordinary write-lock contention, that mode switch does NOT
	// participate in SQLite's busy-timeout retry loop: on a fresh (not-yet-WAL)
	// database file it can fail immediately with "database is locked" instead of
	// waiting, if another connection races to switch modes at the same instant.
	// migrationMu's own doc comment describes exactly this scenario in production —
	// startHTTPServer and startGRPCServer both call CreateStorage as separate
	// in-process goroutines when both are enabled — so this is a real deployment
	// race, not just a test artifact (empirically reproduced standalone against the
	// mattn/go-sqlite3 driver directly, ~1-in-5 under concurrent fresh-file opens).
	// Serializing here is driver-agnostic protection either way (ADR-048 swapped
	// the driver to modernc.org/sqlite; this lock is kept regardless of outcome).
	// Serializing Open ensures only one goroutine ever performs the actual mode
	// switch; every later Open against an already-WAL file is a same-mode pragma
	// no-op that always succeeds immediately, regardless of other open connections.
	migrationMu.Lock()
	db, err := openSQLiteGorm(sqliteDSN(dbPath))
	migrationMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	// The WAL pragma above (in sqliteDSN) creates -wal/-shm during Open, and a
	// pre-existing database from before this fix shipped keeps whatever mode it
	// originally had — tighten both cases here, after the file(s) are known to exist.
	tightenExistingLocalStorageFiles(dbPath)

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}
	if sqlDB, dbErr := db.DB(); dbErr == nil {
		registerPoolMetrics(poolRequest, sqlDB)
	}

	if err := withMigrationLock(db, false, dbPath, f.migrateSQLite); err != nil {
		return nil, migrateError(err)
	}

	ls := store.NewLocalStorage(db)
	ls.SetAuditFlusherLingerWindow(cfg.Storage.Database.GetAuditFlusherLingerWindow())
	ls.SetSoftDeleteRetentionDays(cfg.SoftDelete.GetRetentionDays())
	// No SetAuditSkipDurableSync here, deliberately: audit_durability standard
	// is PostgreSQL-only and config validation refuses to start a SQLite
	// backend set to it (SQLite is strict only), so there is nothing to propagate --
	// and leaving the zero value (false, durable) means a config that somehow
	// bypassed validation still gets durable commits rather than a half-
	// applied weak mode.
	return ls, nil
}

// migrateSQLite is migrateDatabase plus the audit list indexes, inside the
// same SQLite migration lock and transaction (docs/specs/audit-list-keyset.md
// §4). They are created after migrateDatabase because a fresh install creates
// audit_events only in its final AutoMigrate step.
func (f *DefaultStorageFactory) migrateSQLite(db *gorm.DB) error {
	if err := f.migrateDatabase(db); err != nil {
		return err
	}
	if err := store.EnsureAuditListIndexesSQLite(db, log.Printf); err != nil {
		return err
	}
	return runAfterMigrateHook(db)
}
