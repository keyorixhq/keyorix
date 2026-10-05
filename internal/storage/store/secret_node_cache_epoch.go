// secret_node_cache_epoch.go — secret_nodes.cache_epoch and the database
// trigger that maintains it: the generation stamp for the read-path
// secret-metadata cache.
//
// This lives in package store, not in internal/storage's migrateDatabase, so
// that there is exactly ONE definition of the column and the trigger for
// production and tests alike: internal/storage already imports this package, so
// the real migration calls straight into EnsureSecretNodeCacheEpoch, and the
// cache's own tests (which live here) build their schema with the same call
// rather than a second copy of the SQL that could drift.
//
// The column IS a field on models.SecretNode — read-only to GORM, see its doc
// comment there — so AutoMigrate creates it everywhere. The TRIGGER is not
// something AutoMigrate can know about, which is why
// SecretNodeCacheEpochTriggerPresent exists and why its absence disables the
// node cache rather than silently freezing its stamp.
package store

import (
	"fmt"
	"sync"

	"gorm.io/gorm"
)

// Trigger and function names, exported so a test can drop them to prove the
// guard that depends on them actually goes red.
const (
	SecretNodeCacheEpochColumn  = "cache_epoch"
	SecretNodeCacheEpochTrigger = "trg_secret_nodes_cache_epoch" // #nosec G101 -- database trigger name, not a credential
	secretNodeCacheEpochFunc    = "keyorix_secret_nodes_bump_cache_epoch"
)

// EnsureSecretNodeCacheEpoch adds secret_nodes.cache_epoch and the trigger that
// bumps it on EVERY update to the row, on both backends. Idempotent: safe on a
// fresh database and on one that already has both. A no-op if secret_nodes does
// not exist yet.
//
// # Why a database trigger, and why no Go code owns this column
//
// The cache's requirement is "the stamp changes whenever ANY column of the
// cached row changes". Every Go-side mechanism for that has a hole, and this
// repo hit three of them in a row on #2764:
//
//   - updated_at alone misses UpdateColumn/UpdateColumns, which bypass GORM's
//     auto-timestamp callback. That is how a stale read_count got served and
//     reset a burn-after-N-reads budget (#133).
//   - A GORM BeforeUpdate hook calling SetColumn is SILENTLY A NO-OP for a
//     full-struct Save() — which is exactly what UpdateSecret uses.
//   - Bumping it at each write site needs every current AND future writer to
//     remember, raw db.Exec SQL included: opt-in correctness, the recurring
//     defect shape here.
//
// A trigger has none of those holes: the database does it, so Save(),
// Updates(), UpdateColumn() and raw SQL are covered identically, with no Go
// code to forget and nothing for a new writer to opt into. Keeping the column
// off models.SecretNode means no Go write can set it even by accident — and on
// Postgres the BEFORE trigger overwrites whatever a client sent anyway.
//
// # The two dialect forms, both load-bearing
//
// Postgres: a BEFORE UPDATE trigger assigning NEW.cache_epoch directly.
//
// SQLite CANNOT do that — a SQLite trigger body may only run
// INSERT/UPDATE/DELETE/SELECT, it cannot assign to NEW — so there it is an
// AFTER UPDATE trigger issuing a nested single-row UPDATE. The
// `WHEN NEW.cache_epoch = OLD.cache_epoch` guard is what stops that nested
// write re-firing the trigger: the nested write changes cache_epoch, so the
// guard is false for it. Deliberately NOT left to SQLite's recursive_triggers
// pragma (off by default, but a pragma is not something a migration should
// depend on).
//
// DROP then CREATE rather than CREATE IF NOT EXISTS: Postgres has no
// CREATE TRIGGER IF NOT EXISTS before 14, and DROP+CREATE additionally
// CONVERGES an install whose trigger body predates a change to it instead of
// leaving the old body in place forever. Each statement is its own Exec because
// neither driver is guaranteed to accept a multi-statement string.
func EnsureSecretNodeCacheEpoch(db *gorm.DB) error {
	if !secretNodesTableExists(db) {
		return nil
	}
	if !secretNodeCacheEpochColumnExists(db) {
		// NOT NULL DEFAULT 0 so existing rows get a usable stamp immediately and
		// no backfill pass is needed: a row reads as epoch 0 until its first
		// update, which is a perfectly valid stamp — it only ever has to CHANGE
		// when the row does.
		if err := db.Exec("ALTER TABLE secret_nodes ADD COLUMN cache_epoch BIGINT NOT NULL DEFAULT 0").Error; err != nil {
			return fmt.Errorf("failed to add secret_nodes.cache_epoch: %w", err)
		}
	}

	if db.Dialector.Name() == "postgres" {
		// Dollar-quoted with a NAMED tag rather than bare $$, so the body can
		// never be mistaken for a pgx $N placeholder.
		if err := db.Exec(`CREATE OR REPLACE FUNCTION ` + secretNodeCacheEpochFunc + `() RETURNS trigger
LANGUAGE plpgsql AS $keyorix$
BEGIN
  NEW.cache_epoch := OLD.cache_epoch + 1;
  RETURN NEW;
END;
$keyorix$`).Error; err != nil {
			return fmt.Errorf("failed to create %s(): %w", secretNodeCacheEpochFunc, err)
		}
		if err := db.Exec("DROP TRIGGER IF EXISTS " + SecretNodeCacheEpochTrigger + " ON secret_nodes").Error; err != nil {
			return fmt.Errorf("failed to drop %s: %w", SecretNodeCacheEpochTrigger, err)
		}
		// EXECUTE PROCEDURE, not EXECUTE FUNCTION: the latter is Postgres 11+
		// only, while the former is still accepted (a documented synonym) by
		// every version including 16 — so this works across the whole range.
		if err := db.Exec("CREATE TRIGGER " + SecretNodeCacheEpochTrigger +
			" BEFORE UPDATE ON secret_nodes FOR EACH ROW EXECUTE PROCEDURE " + secretNodeCacheEpochFunc + "()").Error; err != nil {
			return fmt.Errorf("failed to create %s: %w", SecretNodeCacheEpochTrigger, err)
		}
		return nil
	}

	if err := db.Exec("DROP TRIGGER IF EXISTS " + SecretNodeCacheEpochTrigger).Error; err != nil {
		return fmt.Errorf("failed to drop %s: %w", SecretNodeCacheEpochTrigger, err)
	}
	if err := db.Exec(`CREATE TRIGGER ` + SecretNodeCacheEpochTrigger + `
AFTER UPDATE ON secret_nodes FOR EACH ROW
WHEN NEW.cache_epoch = OLD.cache_epoch
BEGIN
  UPDATE secret_nodes SET cache_epoch = OLD.cache_epoch + 1 WHERE id = NEW.id;
END`).Error; err != nil {
		return fmt.Errorf("failed to create %s: %w", SecretNodeCacheEpochTrigger, err)
	}
	return nil
}

// SecretNodeCacheEpochTriggerPresent reports whether the cache_epoch trigger
// actually exists on this database. Queried once, at NewLocalStorage, and the
// node read-path cache is DISABLED for the lifetime of that store if the answer
// is no.
//
// This is fail-closed detection, not defensiveness for its own sake. The stamp
// is only a stamp because the trigger maintains it; a database that has the
// COLUMN but not the TRIGGER has a stamp frozen at 0 forever, so every cache
// hit would serve the row as it was when first read — indefinitely, with no
// error and no symptom. Two ways that happens for real:
//
//   - A Postgres restore that omits triggers. `pg_restore --disable-triggers`,
//     a schema-only restore, or a dump loaded into a database whose migration
//     has not run yet all leave the column (it is a plain column) without the
//     trigger.
//   - Any test schema built with a bare db.AutoMigrate(). The column is a model
//     field so AutoMigrate creates it; the trigger is not, so it does not. That
//     is how this check got written: internal/core's suspend/ownership tests
//     started serving a stale `status` after SuspendSecret, because their
//     hand-rolled schema had a stamp that never moved.
//
// An absent trigger is therefore treated the way every other uncertainty in
// this cache is treated — as a permanent miss. Correct, slower, and loud enough
// to find (the cache simply never hits) rather than silently wrong.
func SecretNodeCacheEpochTriggerPresent(db *gorm.DB) bool {
	if db == nil {
		return false
	}
	// A catalog query, NOT db.Migrator(): this package's own
	// sqlitedialect.Migrator.HasTable calls Row().Scan() without checking
	// Row()'s error, so it PANICS on a store whose *gorm.DB has no usable
	// connection — which several tests legitimately construct (the dialect-SQL
	// tests build a DryRun/unconnected handle on purpose). A Raw().Scan()
	// surfaces that as an error instead, and any error here means "cannot
	// confirm the trigger", i.e. false. Same reason internal/storage/factory.go
	// hand-rolls tableExists/columnExists rather than using the Migrator.
	//
	// Asking only about the TRIGGER is sufficient: its body references
	// cache_epoch, so a trigger cannot exist without the column.
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM pg_trigger WHERE NOT tgisinternal AND tgname = ?"
	}
	if err := db.Raw(q, SecretNodeCacheEpochTrigger).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// secretNodesTableExists / secretNodeCacheEpochColumnExists are raw catalog
// lookups for the same reason SecretNodeCacheEpochTriggerPresent is one: the
// Migrator path panics rather than erroring on an unusable handle. Any error is
// read as "not there", so the caller's next step is to create it — which is
// idempotent, and fails loudly if the real reason was something else.
func secretNodesTableExists(db *gorm.DB) bool {
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'secret_nodes'"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'secret_nodes' AND table_schema = CURRENT_SCHEMA()"
	}
	if err := db.Raw(q).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

func secretNodeCacheEpochColumnExists(db *gorm.DB) bool {
	var count int64
	if db.Dialector.Name() == "postgres" {
		if err := db.Raw(
			"SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'secret_nodes' AND column_name = ? AND table_schema = CURRENT_SCHEMA()",
			SecretNodeCacheEpochColumn).Scan(&count).Error; err != nil {
			return false
		}
		return count > 0
	}
	// SQLite: pragma_table_info is the portable way to ask without parsing DDL.
	if err := db.Raw(
		"SELECT COUNT(*) FROM pragma_table_info('secret_nodes') WHERE name = ?",
		SecretNodeCacheEpochColumn).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// nodeStampProbe caches the one-shot answer to "does this database maintain
// cache_epoch". One query per LocalStorage, resolved on first use.
type nodeStampProbe struct {
	once    sync.Once
	trusted bool
}

// nodeStampTrusted reports whether this store may use the node read-path cache.
// Fail-closed on every uncertainty: a derived store (nil probe) never trusts
// it, and a database with no trigger never does either.
func (ls *LocalStorage) nodeStampTrusted() bool {
	if ls.nodeStampProbe == nil {
		return false
	}
	ls.nodeStampProbe.once.Do(func() {
		ls.nodeStampProbe.trusted = SecretNodeCacheEpochTriggerPresent(ls.db)
	})
	return ls.nodeStampProbe.trusted
}
