package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// postgresBackend is storage.type "postgres" (or "postgresql").
var postgresBackend = storageBackend{
	names:  []string{"postgres", "postgresql"},
	create: (*DefaultStorageFactory).createPostgresStorage,
}

// createPostgresStorage creates a PostgreSQL-backed local storage instance
func (f *DefaultStorageFactory) createPostgresStorage(cfg *config.Config) (_ storage.Storage, err error) {
	db, err := openPostgresGorm(&cfg.Storage.Database, gormConfig())
	if err != nil {
		return nil, err
	}
	// Every pool opened here is closed again if the factory fails, so a failed
	// start leaks no Postgres connections. On success LocalStorage.Close owns them.
	var opened []*sql.DB
	if sqlDB, dbErr := db.DB(); dbErr == nil {
		opened = append(opened, sqlDB)
	}
	defer func() {
		if err != nil {
			for _, p := range opened {
				_ = p.Close()
			}
		}
	}()

	if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
		return nil, err
	}
	warnPostgresPoolHeadroom(db, &cfg.Storage.Database)
	if msg := config.PoolerStartupParamWarning(&cfg.Storage.Database); msg != "" {
		log.Print(msg)
	}
	if err := refuseUndeclaredTransactionPooler(&cfg.Storage.Database); err != nil {
		return nil, err
	}
	if err := refuseNonOriginReplicationRole(db); err != nil {
		return nil, err
	}

	if err := withMigrationLockPooled(db, true, cfg.Storage.Database.TransactionPooling(), "", f.migratePostgres); err != nil {
		return nil, migrateError(err)
	}

	schedulerLockDB, _, err := openPostgresSQLDB(&cfg.Storage.Database)
	if err != nil {
		return nil, err
	}
	opened = append(opened, schedulerLockDB)
	applyLockPoolSettings(schedulerLockDB, SchedulerLockPoolSize, &cfg.Storage.Database)
	namedLockDB, _, err := openPostgresSQLDB(&cfg.Storage.Database)
	if err != nil {
		return nil, err
	}
	opened = append(opened, namedLockDB)
	applyLockPoolSettings(namedLockDB, NamedLockPoolSize, &cfg.Storage.Database)
	if len(opened) > 0 {
		registerPoolMetrics(poolRequest, opened[0])
	}
	registerPoolMetrics(poolSchedulerLock, schedulerLockDB)
	registerPoolMetrics(poolNamedLock, namedLockDB)

	nativeReads, err := openPostgresNativeReadPool(&cfg.Storage.Database, nativeReadPoolSize(effectiveMaxOpenConns(db, &cfg.Storage.Database), cfg.Storage.Database.NativeReadPoolMax))
	if err != nil {
		return nil, err
	}

	ls := store.NewLocalStorage(db)
	ls.SetAuditFlusherLingerWindow(cfg.Storage.Database.GetAuditFlusherLingerWindow())
	ls.SetSoftDeleteRetentionDays(cfg.SoftDelete.GetRetentionDays())
	ls.SetSchedulerLockDB(schedulerLockDB)
	ls.SetNamedLockDB(namedLockDB)
	ls.SetNativeReadPool(nativeReads)
	ls.SetTransactionPooling(cfg.Storage.Database.TransactionPooling())
	// ADR-112 Amendment 3: the effective audit_durability level, read through
	// the same function the start-up line, posture report and API use, so the
	// level reported cannot differ from the level run. Standard -- the
	// PostgreSQL default -- skips only the audit commit's wait for the disk sync.
	ls.SetAuditSkipDurableSync(cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).Level == config.AuditDurabilityStandard)
	ensureAuditListIndexesPostgres(ls, db, func() (*sql.DB, error) {
		bdb, _, err := openPostgresSQLDB(&cfg.Storage.Database)
		return bdb, err
	})
	return ls, nil
}

// migratePostgres is migrateDatabase plus the test-only after-migrate hook.
func (f *DefaultStorageFactory) migratePostgres(db *gorm.DB) error {
	if err := f.migrateDatabase(db); err != nil {
		return err
	}
	return runAfterMigrateHook(db)
}

// auditIndexSyncBuildMaxRows is the audit_events size (row estimate) below
// which the Postgres audit index build runs before the server serves: a fresh
// install or a small table builds in about a second. A larger table is built in
// the background (store.LocalStorage.StartAuditListIndexBuild). A var so tests
// can move the threshold.
var auditIndexSyncBuildMaxRows int64 = 200_000

// auditIndexSyncBuildTimeout bounds that synchronous build. CREATE INDEX
// CONCURRENTLY waits for every transaction already writing to the table, so one
// idle-in-transaction session elsewhere could otherwise hold the server's start
// forever. Past the timeout the build is cancelled (leaving an INVALID index)
// and continues in the background, which drops and rebuilds it.
var auditIndexSyncBuildTimeout = 30 * time.Second

// ensureAuditListIndexesPostgres brings the audit list indexes up to date after
// the migration transaction has committed: CREATE INDEX CONCURRENTLY never runs
// inside a transaction, and never blocks audit writes. Nothing here is fatal:
// a missing index costs speed, not correctness, and the next start retries.
// openBuildDB opens the dedicated pool a background build runs on.
func ensureAuditListIndexesPostgres(ls *store.LocalStorage, db *gorm.DB, openBuildDB func() (*sql.DB, error)) {
	ctx := context.Background()
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("audit index build: skipped: %v", err)
		return
	}
	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	if err != nil {
		log.Printf("audit index build: skipped, catalog check failed: %v", err)
		return
	}
	if !pending {
		return
	}
	rows, err := store.AuditEventsRowEstimate(ctx, db)
	if err != nil {
		log.Printf("audit index build: skipped, row estimate failed: %v", err)
		return
	}
	if rows < auditIndexSyncBuildMaxRows {
		sctx, cancel := context.WithTimeout(ctx, auditIndexSyncBuildTimeout)
		err := store.BuildAuditListIndexesPostgres(sctx, sqlDB, ls.TransactionPooling(), log.Printf)
		timedOut := sctx.Err() != nil
		cancel()
		switch {
		case err == nil:
			return
		case errors.Is(err, store.ErrAuditIndexBuildLockHeld):
			log.Printf("audit index build: another process is building the audit indexes")
			return
		case !timedOut:
			log.Printf("audit index build: failed, retried at the next start: %v", err)
			return
		}
		log.Printf("audit index build: not finished within %s (a long-running transaction on audit_events?); continuing in the background", auditIndexSyncBuildTimeout)
	} else {
		log.Printf("audit index build: audit_events has ~%d rows; building in the background while the server serves", rows)
	}
	bdb, err := openBuildDB()
	if err != nil {
		log.Printf("audit index build: skipped, cannot open a build connection: %v", err)
		return
	}
	bdb.SetMaxOpenConns(2) // the build lock's connection and the DDL's
	ls.StartAuditListIndexBuild(bdb, log.Printf)
}

// SchedulerLockPoolSize caps the separate Postgres pool that holds scheduler
// advisory-lock sessions (store.LocalStorage.SetSchedulerLockDB). A scheduler job
// pins one lock session for its whole run while its own queries use the request
// pool; with both on one pool, enough jobs ticking at once (about 20 start
// together at boot) pinned every connection and each waited for one more, a
// permanent hang (POOL-HANG-1, Detected-by: PERF-6). On its own pool a job
// waiting for a lock session holds nothing, so nothing can deadlock; jobs beyond
// this cap queue for a session and run a little later. It is not configurable:
// the request pool is the knob operators size, and this one only bounds how many
// jobs run their lock-held section at the same time.
const SchedulerLockPoolSize = 4

// NamedLockPoolSize caps the separate Postgres pool that holds WithNamedLock's
// advisory-lock sessions (store.LocalStorage.SetNamedLockDB). A holder pins one
// lock session for its critical section while fn's queries use the request
// pool; with both on one pool, as many distinct keys held at once as the pool
// had connections hung the server for good (NAMEDLOCK-POOL-1, the same
// hold-and-wait as POOL-HANG-1). It is a pool of its own, not the scheduler
// lock pool, because scheduler jobs take named locks inside their own
// lock-held section. It bounds how many distinct keys one process holds at
// once; callers beyond it queue for a session holding no connection. Not
// configurable, like SchedulerLockPoolSize.
const NamedLockPoolSize = 8

// NativeReadPoolMaxSize caps the pgxpool the hottest read-path statements run
// on (store.LocalStorage.SetNativeReadPool): the machine credential lookup,
// with or without the folded node read, and the node-stamp read. Each request
// runs at most two of them, each one short statement, so a few connections
// carry them at any request rate the request pool can feed. Never more than the
// request pool's own cap (nativeReadPoolSize), so an operator who sizes
// max_open_conns small keeps a small footprint. This is the default;
// storage.database.native_read_pool_max raises or lowers it (the lock pools are
// not configurable).
const NativeReadPoolMaxSize = config.DefaultNativeReadPoolMax

// nativeReadPoolSize is the native read pool's cap for a request pool of maxOpen
// and a configured native_read_pool_max (0: NativeReadPoolMaxSize).
func nativeReadPoolSize(maxOpen, configured int) int {
	if configured <= 0 {
		configured = NativeReadPoolMaxSize
	}
	return min(maxOpen, configured)
}

// lockPoolMaxIdleTime closes lock sessions left idle, so the lock pools do not
// keep Postgres backends open between scheduler intervals or bursts of writes.
const lockPoolMaxIdleTime = time.Minute

// applyLockPoolSettings sizes a lock pool and applies the operator's connection
// lifetime to it, like applyPoolSettings for the request pool.
func applyLockPoolSettings(lockDB *sql.DB, size int, dbCfg *config.DatabaseConfig) {
	lockDB.SetMaxOpenConns(size)
	lockDB.SetMaxIdleConns(size)
	lockDB.SetConnMaxIdleTime(lockPoolMaxIdleTime)
	if dbCfg.ConnMaxLifetimeMinutes > 0 {
		lockDB.SetConnMaxLifetime(time.Duration(dbCfg.ConnMaxLifetimeMinutes) * time.Minute)
	}
}

// warnPostgresPoolHeadroom logs a startup warning when this process's pool alone
// can exceed the Postgres server's usable connection slots (max_connections minus
// superuser_reserved_connections). Past that point requests fail with SQLSTATE
// 53300 "sorry, too many clients already" instead of queueing in the pool, measured
// at max_open_conns 100 against a default max_connections of 100 (#2631). It is a
// warning, not a refusal: the server's limit can be raised later without a restart
// of this process, and a lookup failure must never block boot. It cannot see other
// replicas' pools, and the message says so.
func warnPostgresPoolHeadroom(db *gorm.DB, dbCfg *config.DatabaseConfig) {
	var maxConn, reserved int
	if err := db.Raw("SELECT current_setting('max_connections')::int").Scan(&maxConn).Error; err != nil {
		return
	}
	if err := db.Raw("SELECT current_setting('superuser_reserved_connections')::int").Scan(&reserved).Error; err != nil {
		return
	}
	if msg := postgresPoolHeadroomWarning(effectiveMaxOpenConns(db, dbCfg), dbCfg.NativeReadPoolMax, maxConn, reserved); msg != "" {
		log.Print(msg)
	}
}

// postgresPoolHeadroomWarning is warnPostgresPoolHeadroom's decision, separated so
// it is testable without a server. Empty means no warning.
// The process opens maxOpen plus extraPoolsSize(maxOpen, nativeReadPoolMax) connections at most.
func postgresPoolHeadroomWarning(maxOpen, nativeReadPoolMax, maxConnections, reserved int) string {
	usable := maxConnections - reserved
	extra := extraPoolsSize(maxOpen, nativeReadPoolMax)
	if maxConnections <= 0 || maxOpen+extra <= usable {
		return ""
	}
	return fmt.Sprintf("WARNING: storage.database.max_open_conns is %d, plus %d for the lock and native read pools, but the "+
		"Postgres server allows only %d non-superuser connections (max_connections=%d minus "+
		"superuser_reserved_connections=%d). Under load, requests past that fail with SQLSTATE 53300 \"too many "+
		"clients\" instead of queueing. Lower max_open_conns so that (replicas x (max_open_conns + %d)) stays "+
		"below %d, or raise max_connections.",
		maxOpen, extra, usable, maxConnections, reserved, extra, usable)
}

// extraPoolsSize is the most connections the pools beside the request pool open
// together: the scheduler and named lock pools and the native read pool.
func extraPoolsSize(maxOpen, nativeReadPoolMax int) int {
	return lockPoolsSize + nativeReadPoolSize(maxOpen, nativeReadPoolMax)
}

// lockPoolsSize is the most connections the scheduler and named lock pools open together.
const lockPoolsSize = SchedulerLockPoolSize + NamedLockPoolSize
