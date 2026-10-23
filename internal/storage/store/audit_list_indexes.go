// audit_list_indexes.go — the audit_events time indexes behind GetAuditLogs'
// newest-first order, and how they are built without blocking audit writes
// (docs/specs/audit-list-keyset.md §4).
//
// They are declared here, once, and created by code rather than by gorm tags:
// a tag is a plain CREATE INDEX inside the migration transaction, which on
// Postgres takes a SHARE lock and blocks every audit INSERT (every secret read)
// for the whole build. On Postgres they are built with CREATE INDEX
// CONCURRENTLY, outside any transaction; on SQLite (one writer, built before
// the server listens) with a plain CREATE INDEX inside the migration.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AuditListIndex is one index the build step below maintains. Table is
// audit_events unless set; Using is the access method, btree unless set.
type AuditListIndex struct {
	Name    string
	Table   string
	Columns []string
	Using   string
}

func (ix AuditListIndex) table() string {
	if ix.Table == "" {
		return "audit_events"
	}
	return ix.Table
}

func (ix AuditListIndex) CreateSQL(concurrently bool) string {
	conc := ""
	if concurrently {
		conc = "CONCURRENTLY "
	}
	using := ""
	if ix.Using != "" {
		using = " USING " + ix.Using
	}
	return fmt.Sprintf("CREATE INDEX %sIF NOT EXISTS %s ON %s%s (%s)", conc, ix.Name, ix.table(), using, ix.columnList())
}

// replacedIndex is an index the build step drops once its replacements are valid.
type replacedIndex struct{ Name, Table string }

// indexPlan is one table's share of the build: every Want index must be valid
// before any Replaced index is dropped, so no point in an upgrade loses an index a
// query uses.
type indexPlan struct {
	Table    string
	Want     []AuditListIndex
	Replaced []replacedIndex
}

// SecretAccessLogIndexes are the secret_access_logs indexes on every backend
// (PERF-INDEX-1). One composite replaces (secret_node_id, access_time), which
// serves per-secret history and the anomaly windows, and (secret_node_id,
// action), which served total_reads on every single-secret GET: with action as
// the last key column total_reads is still answered from the index alone.
var SecretAccessLogIndexes = []AuditListIndex{
	{Name: "idx_secret_access_logs_secret_time_action", Table: "secret_access_logs", Columns: []string{"secret_node_id", "access_time", "action"}},
}

// SecretAccessLogIndexesPostgres are the extra Postgres-only indexes: a BRIN on
// access_time replaces the (access_time, secret_node_id) btree. The column is
// append-only and written in time order, so BRIN answers the anomaly candidate
// and window scans as fast as the btree at a fraction of its write cost.
// SQLite has no BRIN and keeps the btree (idx_secret_access_logs_access_time).
var SecretAccessLogIndexesPostgres = []AuditListIndex{
	{Name: "idx_secret_access_logs_access_time_brin", Table: "secret_access_logs", Columns: []string{"access_time"}, Using: "brin"},
}

// SecretAccessLogIndexesSQLite keeps the (access_time, secret_node_id) btree on
// SQLite, where there is no BRIN: it serves the anomaly candidate scan
// (ListSecretIDsAccessedSince) and the time-window aggregates, covering.
var SecretAccessLogIndexesSQLite = []AuditListIndex{
	{Name: "idx_secret_access_logs_access_time", Table: "secret_access_logs", Columns: []string{"access_time", "secret_node_id"}},
}

// SecretAccessLogReplacedIndexes are dropped on every backend,
// SecretAccessLogReplacedIndexesPostgres on Postgres only.
var (
	SecretAccessLogReplacedIndexes         = []string{"idx_secret_access_logs_secret_time", "idx_secret_access_logs_secret_action"}
	SecretAccessLogReplacedIndexesPostgres = []string{"idx_secret_access_logs_access_time"}
)

func replacedOn(table string, names ...[]string) []replacedIndex {
	var out []replacedIndex
	for _, l := range names {
		for _, n := range l {
			out = append(out, replacedIndex{Name: n, Table: table})
		}
	}
	return out
}

func indexPlansSQLite() []indexPlan {
	return []indexPlan{
		{Table: "audit_events", Want: AuditListIndexes, Replaced: replacedOn("audit_events", AuditListReplacedIndexes)},
		{Table: "secret_access_logs", Want: append(append([]AuditListIndex{}, SecretAccessLogIndexes...), SecretAccessLogIndexesSQLite...), Replaced: replacedOn("secret_access_logs", SecretAccessLogReplacedIndexes)},
	}
}

func indexPlansPostgres() []indexPlan {
	want := append(append([]AuditListIndex{}, SecretAccessLogIndexes...), SecretAccessLogIndexesPostgres...)
	return []indexPlan{
		{Table: "audit_events", Want: AuditListIndexes, Replaced: replacedOn("audit_events", AuditListReplacedIndexes)},
		{Table: "secret_access_logs", Want: want, Replaced: replacedOn("secret_access_logs", SecretAccessLogReplacedIndexes, SecretAccessLogReplacedIndexesPostgres)},
	}
}

// AuditListIndexes are the indexes GetAuditLogs' plans rely on. Every key is
// monotonic in time, so inserts append at the right edge of each b-tree.
var AuditListIndexes = []AuditListIndex{
	{Name: "idx_audit_events_event_time_id", Columns: []string{"event_time", "id"}},
	{Name: "idx_audit_events_project_event_time", Columns: []string{"project_id", "event_time"}},
	{Name: "idx_audit_events_secret_event_time", Columns: []string{"secret_node_id", "event_time"}},
}

// AuditListReplacedIndexes are the indexes no query uses any more: the
// single-column indexes the composites above make redundant, and
// idx_audit_events_machine_event_time (machine_identity_id, event_time), which
// no code path ever filtered on (PERF-INDEX-1: AuditFilter has no machine
// field, and the actor-kind predicate only tests machine_identity_id IS NULL)
// while costing every audit INSERT one btree update. They are dropped only
// after every AuditListIndexes entry is valid, so no point in the upgrade loses
// an index a query uses. The machine_identity_id column stays; a future
// "everything this identity did" view builds its index CONCURRENTLY.
var AuditListReplacedIndexes = []string{
	"idx_audit_events_project_id",
	"idx_audit_events_machine_identity_id",
	"idx_audit_events_machine_event_time",
}

// auditIndexBuildLockKey is the Postgres advisory lock that lets one
// replica build while the others skip. It differs from the migration lock
// (postgresMigrationLockKey, internal/storage): the build runs after the
// migration transaction has committed and released that one.
const auditIndexBuildLockKey = 0x4B455941_49445842 // "KEYAIDXB"

// The pg_locks classid/objid halves of auditIndexBuildLockKey (a bigint advisory
// key is stored as its high and low 32 bits), for tests that assert the lock is
// released.
const (
	AuditIndexBuildLockClassID = auditIndexBuildLockKey >> 32
	AuditIndexBuildLockObjID   = auditIndexBuildLockKey & 0xFFFFFFFF
)

// ErrAuditIndexBuildLockHeld: another session holds auditIndexBuildLockKey, so
// that process is building. Nothing was changed.
var ErrAuditIndexBuildLockHeld = errors.New("audit index build: another session holds the build lock")

func (ix AuditListIndex) columnList() string { return strings.Join(ix.Columns, ", ") }

// AuditEventsRowEstimate is MAX(id)-MIN(id)+1 of audit_events (two primary-key
// lookups): a cheap upper bound of the row count, used to log what a build will
// cover and to decide whether a Postgres build can run before serving.
func AuditEventsRowEstimate(ctx context.Context, db *gorm.DB) (int64, error) {
	return tableRowEstimate(ctx, db, "audit_events")
}

func tableRowEstimate(ctx context.Context, db *gorm.DB, table string) (int64, error) {
	var r struct {
		Lo *int64
		Hi *int64
	}
	if err := db.WithContext(ctx).Raw("SELECT MIN(id) AS lo, MAX(id) AS hi FROM " + table).Scan(&r).Error; err != nil {
		return 0, err
	}
	if r.Lo == nil || r.Hi == nil {
		return 0, nil
	}
	return *r.Hi - *r.Lo + 1, nil
}

// EnsureAuditListIndexesSQLite creates the missing indexes of every plan
// (audit_events, secret_access_logs) with a plain CREATE INDEX IF NOT EXISTS (one
// progress line per index built) and then drops the replaced ones. It runs inside
// the SQLite migration transaction, before the server listens; SQLite has a
// single writer, so the build holds the database for its duration either way.
func EnsureAuditListIndexesSQLite(db *gorm.DB, logf func(string, ...any)) error {
	for _, pl := range indexPlansSQLite() {
		if !db.Migrator().HasTable(pl.Table) {
			continue
		}
		var rows int64 = -1
		for _, ix := range pl.Want {
			if db.Migrator().HasIndex(pl.Table, ix.Name) || !hasColumns(db, pl.Table, ix.Columns) {
				continue
			}
			if rows < 0 {
				var err error
				if rows, err = tableRowEstimate(context.Background(), db, pl.Table); err != nil {
					return fmt.Errorf("audit index build: estimate rows: %w", err)
				}
			}
			// An empty table (a fresh install) builds instantly; only a real build
			// is worth a progress line.
			if rows > 0 {
				logf("audit index build: creating %s on %s (~%d rows); the database is busy until it finishes", ix.Name, pl.Table, rows)
			}
			start := time.Now()
			if err := db.Exec(ix.CreateSQL(false)).Error; err != nil {
				return fmt.Errorf("audit index build: create %s: %w", ix.Name, err)
			}
			if rows > 0 {
				logf("audit index build: %s done in %s", ix.Name, time.Since(start).Round(time.Millisecond))
			}
		}
		for _, r := range pl.Replaced {
			if err := db.Exec("DROP INDEX IF EXISTS " + r.Name).Error; err != nil {
				return fmt.Errorf("audit index build: drop %s: %w", r.Name, err)
			}
		}
	}
	return nil
}

func hasColumns(db *gorm.DB, table string, cols []string) bool {
	for _, c := range cols {
		if !db.Migrator().HasColumn(table, c) {
			return false
		}
	}
	return true
}

// pgIndexState is "absent", "valid" or "invalid" (an interrupted CREATE INDEX
// CONCURRENTLY leaves an INVALID index that queries never use).
func pgIndexState(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table, name string) (string, error) {
	var valid bool
	err := q.QueryRowContext(ctx, `SELECT i.indisvalid FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		WHERE i.indrelid = to_regclass($1) AND c.relname = $2`, table, name).Scan(&valid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "absent", nil
	case err != nil:
		return "", err
	case valid:
		return "valid", nil
	default:
		return "invalid", nil
	}
}

// AuditListIndexesPendingPostgres reports whether a Postgres build has work to
// do: an AuditListIndexes entry absent or invalid, or a replaced index still
// present. Catalog reads only.
func AuditListIndexesPendingPostgres(ctx context.Context, db *sql.DB) (bool, error) {
	for _, pl := range indexPlansPostgres() {
		for _, ix := range pl.Want {
			st, err := pgIndexState(ctx, db, pl.Table, ix.Name)
			if err != nil {
				return false, err
			}
			if st != "valid" {
				return true, nil
			}
		}
		for _, r := range pl.Replaced {
			st, err := pgIndexState(ctx, db, pl.Table, r.Name)
			if err != nil {
				return false, err
			}
			if st != "absent" {
				return true, nil
			}
		}
	}
	return false, nil
}

// BuildAuditListIndexesPostgres brings AuditListIndexes to valid and then drops
// AuditListReplacedIndexes, every statement CONCURRENTLY and in autocommit on
// one dedicated connection, never inside a transaction. CONCURRENTLY takes
// SHARE UPDATE EXCLUSIVE, which does not conflict with an INSERT's ROW
// EXCLUSIVE, so audit writes continue throughout. An INVALID index (a build
// interrupted by a crash or a cancelled ctx) is dropped and rebuilt. When
// another process holds the build lock it returns without doing anything: that
// process is building, and an INVALID index seen meanwhile is its build in
// progress, not a leftover; it returns ErrAuditIndexBuildLockHeld. Idempotent:
// with everything in place it issues no DDL.
//
// The build lock is held through advisoryLockSession on a second connection
// that stays idle while the DDL runs: a session lock by default, and with xact
// (storage.database.pooler: pgbouncer-transaction, INV-STORE-advisory-lock-
// pooler-scope) a transaction-scoped one inside a pinned READ COMMITTED
// transaction, which holds no snapshot between statements, so CREATE INDEX
// CONCURRENTLY never waits for it. A cancelled ctx aborts the DDL on its own
// connection; the lock connection never runs the cancelled statement, so the
// lock is released (unlock, or ROLLBACK) before this returns. db must allow
// two open connections.
func BuildAuditListIndexesPostgres(ctx context.Context, db *sql.DB, xact bool, logf func(string, ...any)) error {
	lockConn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lockConn.Close() }()
	sess, err := openAdvisoryLockSession(ctx, lockConn, xact)
	if err != nil {
		return fmt.Errorf("audit index build: lock: %w", err)
	}
	defer sess.close(ctx)
	if xact {
		// Not left to default_transaction_isolation: a REPEATABLE READ lock
		// transaction keeps its snapshot, and CREATE INDEX CONCURRENTLY would
		// wait for it, that is for itself.
		if _, err := lockConn.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
			return fmt.Errorf("audit index build: lock: %w", err)
		}
	}
	locked, err := sess.tryLock(ctx, auditIndexBuildLockKey)
	if err != nil {
		return fmt.Errorf("audit index build: lock: %w", err)
	}
	if !locked {
		return ErrAuditIndexBuildLockHeld
	}
	defer sess.unlock(ctx, auditIndexBuildLockKey, "audit index build")

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	wctx, finish := sess.watch(ctx, "audit index build lock")
	return finish(buildAuditListIndexes(wctx, conn, logf))
}

// buildAuditListIndexes is BuildAuditListIndexesPostgres' DDL on conn, run with
// the build lock held.
func buildAuditListIndexes(ctx context.Context, conn *sql.Conn, logf func(string, ...any)) error {
	for _, pl := range indexPlansPostgres() {
		if err := buildIndexPlan(ctx, conn, pl, logf); err != nil {
			return err
		}
	}
	return nil
}

func buildIndexPlan(ctx context.Context, conn *sql.Conn, pl indexPlan, logf func(string, ...any)) error {
	var exists bool
	if err := conn.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", pl.Table).Scan(&exists); err != nil {
		return fmt.Errorf("audit index build: inspect %s: %w", pl.Table, err)
	}
	if !exists {
		return nil
	}
	for _, ix := range pl.Want {
		st, err := pgIndexState(ctx, conn, pl.Table, ix.Name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s: %w", ix.Name, err)
		}
		if st == "valid" {
			continue
		}
		if st == "invalid" {
			logf("audit index build: %s is INVALID (an interrupted build); dropping it to rebuild", ix.Name)
			if _, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+ix.Name); err != nil {
				return fmt.Errorf("audit index build: drop invalid %s: %w", ix.Name, err)
			}
		}
		logf("audit index build: creating %s CONCURRENTLY (writes to %s continue)", ix.Name, pl.Table)
		start := time.Now()
		if _, err := conn.ExecContext(ctx, ix.CreateSQL(true)); err != nil {
			return fmt.Errorf("audit index build: create %s: %w", ix.Name, err)
		}
		after, err := pgIndexState(ctx, conn, pl.Table, ix.Name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s after build: %w", ix.Name, err)
		}
		if after != "valid" {
			return fmt.Errorf("audit index build: %s not valid after build (state %q)", ix.Name, after)
		}
		logf("audit index build: %s done in %s", ix.Name, time.Since(start).Round(time.Millisecond))
	}
	for _, r := range pl.Replaced {
		st, err := pgIndexState(ctx, conn, pl.Table, r.Name)
		if err != nil {
			return fmt.Errorf("audit index build: inspect %s: %w", r.Name, err)
		}
		if st == "absent" {
			continue
		}
		if _, err := conn.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+r.Name); err != nil {
			return fmt.Errorf("audit index build: drop replaced %s: %w", r.Name, err)
		}
		logf("audit index build: dropped %s (replaced)", r.Name)
	}
	return nil
}
