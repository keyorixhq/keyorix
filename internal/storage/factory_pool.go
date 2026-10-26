package storage

// Connection-pool settings for the gorm pools CreateStorage opens (moved
// verbatim from factory.go).

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
)

// DefaultSQLiteMaxOpenConns and DefaultPostgresMaxOpenConns bound the DB connection
// pool when the operator hasn't set max_open_conns. Go's own default is unlimited,
// which lets a request flood exhaust the backing database's connection limit.
// Exported so test harnesses that must mirror production's pool (e.g.
// server/http's linearizability fuzzer) reference them instead of copying a number.
//
// The two dialects get different values because they fail differently (#2631,
// Detected-by: PERF-2; measured with the real server over HTTP, 30s runs, 4 vCPU,
// docs/CONFIGURATION.md has the tables):
//
//   - SQLite: 8. One writer at a time, and modernc.org/sqlite is pure Go, so every
//     connection's query work competes for the same CPUs; past ~2x the cores, more
//     connections only add contention. Against the old 25, in both harnesses (the
//     real server over HTTP, and BenchmarkPoolSize through core), 8 did more total
//     work per second and roughly halved read p99 (BenchmarkPoolSize: 469-654ms vs
//     912-948ms). How the gain splits between reads and writes depends on the mix,
//     so no per-side claim is made. 4 was within noise of 8 in-process but slower
//     for reads over HTTP; 8 is the measured middle.
//   - Postgres: 25, unchanged. 10, 25 and 50 are within run-to-run noise of each
//     other for reads; 25 was best for writes. 100 failed requests outright
//     (SQLSTATE 53300 "too many clients"): Postgres's own max_connections defaults
//     to 100, and every replica brings its own pool. See warnPostgresPoolHeadroom.
const (
	DefaultSQLiteMaxOpenConns   = 8
	DefaultPostgresMaxOpenConns = 25
)

// defaultMaxOpenConnsFor returns the dialect's default max_open_conns.
func defaultMaxOpenConnsFor(dialect string) int {
	if dialect == "postgres" {
		return DefaultPostgresMaxOpenConns
	}
	return DefaultSQLiteMaxOpenConns
}

// effectiveMaxOpenConns is the pool cap applyPoolSettings sets: the operator's
// max_open_conns when positive, else the dialect default.
func effectiveMaxOpenConns(db *gorm.DB, dbCfg *config.DatabaseConfig) int {
	if dbCfg.MaxOpenConns > 0 {
		return dbCfg.MaxOpenConns
	}
	return defaultMaxOpenConnsFor(db.Dialector.Name())
}

// applyPoolSettings (below) matches MaxIdleConns to the EFFECTIVE MaxOpenConns
// (whichever of the operator's own max_open_conns or the dialect default above is
// in force) when the operator hasn't set max_idle_conns (SESSION-PERF, #2403
// follow-up). Go's own idle default is 2 — far below any sensible open ceiling —
// so without this, a deployment that never sets max_idle_conns (the shipped
// keyorix.docker.yaml does not) churns connections under any concurrency above
// ~2: each request beyond the idle cap opens a fresh connection (full TCP
// handshake + Postgres SCRAM-SHA-256/PBKDF2 authentication) only to have it
// closed, rather than kept warm, the moment it's returned. Measured cost of the
// gap this closes: at c=50 concurrent reads, Postgres's own connection log showed
// ~1 new-connection+disconnect cycle per 3.5 requests, and a CPU profile
// attributed 5.28% of total server CPU time to PBKDF2/SCRAM connection
// handshakes alone.

// applyPoolSettings configures the connection pool on the underlying *sql.DB
func applyPoolSettings(db *gorm.DB, dbCfg *config.DatabaseConfig) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	// Always cap open connections. Go's default is UNLIMITED, so without a cap a flood of
	// concurrent requests (even unauthenticated ones like /readyz, which pings the DB) can
	// open connections without bound and exhaust the backing database's max_connections.
	maxOpen := effectiveMaxOpenConns(db, dbCfg)
	sqlDB.SetMaxOpenConns(maxOpen)
	// Match the idle cap to the EFFECTIVE open cap by default (whether that came from the
	// operator's own max_open_conns or the dialect default), not a separate fixed
	// constant — see defaultMaxIdleConns' doc comment. This keeps a connection, once
	// opened, warm for reuse rather than opened and immediately closed again under any
	// concurrency above Go's built-in default of 2, for whatever open ceiling is actually
	// in effect. (database/sql itself silently caps idle to open if idle is ever set
	// higher than open, so this can never exceed maxOpen regardless.)
	if dbCfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(dbCfg.MaxIdleConns)
	} else {
		sqlDB.SetMaxIdleConns(maxOpen)
	}
	if dbCfg.ConnMaxLifetimeMinutes > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(dbCfg.ConnMaxLifetimeMinutes) * time.Minute)
	}
	return nil
}
