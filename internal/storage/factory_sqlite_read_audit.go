// factory_sqlite_read_audit.go — the SQLite read-audit connection of
// storage.database.audit_durability standard (ADR-112 Amendment 7).
package storage

import (
	"fmt"
	"log"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// SQLite's PRAGMA synchronous values (https://sqlite.org/pragma.html#pragma_synchronous).
const (
	sqliteSynchronousNormal = 1
	sqliteSynchronousFull   = 2
)

// sqliteReadAuditDSN is sqliteDSN with _synchronous=NORMAL instead of FULL, for
// the one connection openSQLiteReadAuditDB opens. Every other pragma is the
// same, so the connection sees the same file in the same WAL mode with the same
// busy timeout and BEGIN IMMEDIATE.
func sqliteReadAuditDSN(dbPath string) string {
	return sqliteDSNWithSynchronous(dbPath, "NORMAL")
}

// openSQLiteReadAuditDB opens the connection the audit flusher commits batches
// of successful secret-value read audits on, at audit_durability standard
// (ADR-112 Amendment 7). It returns nil, nil when the level is strict (the
// SQLite default: nothing is opened and every commit stays FULL) and when the
// database is in memory (a second connection to ":memory:" would be a second,
// empty database, so its rows would be outside the chain).
//
// The connection:
//   - is its own *sql.DB of exactly one connection, never the shared pool, so
//     the relaxed pragma cannot reach any other transaction (Amendment 1's
//     first reason for rejecting SQLite);
//   - has the pragma fixed in its DSN for its whole life; nothing flips it
//     per transaction (Amendment 1's second reason);
//   - opens the SAME file, so its commits go into the same -wal file as the
//     shared pool's and a later FULL commit's fsync makes them durable (the
//     WAL-prefix argument of Amendment 7);
//   - passes the shared pool's write gate, so the two queue in one FIFO
//     order rather than meeting in SQLite's busy handler.
//
// Both pragmas are read back before the storage is returned, and a mismatch
// refuses to start: the shared pool must report FULL (an operator DSN suffix
// or a driver change must not have weakened it) and the read-audit connection
// NORMAL (otherwise the start-up line would claim a level that is not in
// effect).
func openSQLiteReadAuditDB(cfg *config.Config, dbPath string, shared *gorm.DB) (*gorm.DB, error) {
	if cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type).Level != config.AuditDurabilityStandard {
		return nil, nil
	}
	if _, isRealFile := localStorageDBFile(dbPath); !isRealFile {
		log.Printf("storage: audit_durability standard has no effect on an in-memory SQLite database: every commit stays synchronous=FULL")
		return nil, nil
	}
	if err := requireSQLiteSynchronous(shared, sqliteSynchronousFull); err != nil {
		return nil, fmt.Errorf("shared SQLite pool: %w", err)
	}
	gate, err := sqliteWriteGateOf(shared)
	if err != nil {
		return nil, err
	}
	readDB, err := openSQLiteGormWithGate(sqliteReadAuditDSN(dbPath), gate)
	if err != nil {
		return nil, fmt.Errorf("failed to open the SQLite read-audit connection: %w", err)
	}
	sqlDB, err := readDB.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := requireSQLiteSynchronous(readDB, sqliteSynchronousNormal); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("SQLite read-audit connection: %w", err)
	}
	log.Printf("storage: audit_durability standard: successful secret-read audits commit on a dedicated synchronous=NORMAL connection; every other transaction stays synchronous=FULL (ADR-112 Amendment 7)")
	return readDB, nil
}

// requireSQLiteSynchronous fails unless db's connection reports PRAGMA
// synchronous = want.
func requireSQLiteSynchronous(db *gorm.DB, want int) error {
	var got int
	if err := db.Raw("PRAGMA synchronous").Scan(&got).Error; err != nil {
		return fmt.Errorf("reading PRAGMA synchronous: %w", err)
	}
	if got != want {
		return fmt.Errorf("PRAGMA synchronous is %d, want %d -- refusing to start rather than run at a durability the configuration does not say", got, want)
	}
	return nil
}

// attachSQLiteReadAuditDB opens the read-audit connection (see
// openSQLiteReadAuditDB) and hands it to ls; a nil connection leaves ls
// committing every batch on the shared pool.
func attachSQLiteReadAuditDB(cfg *config.Config, dbPath string, ls *store.LocalStorage) error {
	readDB, err := openSQLiteReadAuditDB(cfg, dbPath, ls.DB())
	if err != nil || readDB == nil {
		return err
	}
	ls.SetSQLiteReadAuditDB(readDB)
	return nil
}
