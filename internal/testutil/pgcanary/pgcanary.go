// Package pgcanary is the PostgreSQL world of the canary-leak fuzz targets. The
// SQLite targets (FuzzCoreSecretOpsCanaryLeak and siblings) copy a prebuilt database
// file per execution and scan it afterwards; none of that exists on a server, so
// this package supplies the equivalents:
//
//   - Open clones a migrated database into a uniquely named w7_* database (prefix
//     chosen so the harness cannot touch another session's database on a shared
//     server) and opens it with the production gorm configuration and a pgx tracer.
//   - Snapshot and Reset restore the seeded state between executions in one round
//     trip, so a saved input still replays alone.
//   - Dump returns every column of every table, the stand-in for the raw database
//     file scan (a server's data files cannot be read from here).
//   - Tracer records every error the server or the driver produced: the evidence
//     that a provocation really reached PostgreSQL, and what the server said, which
//     includes the fields (DETAIL, WHERE) that pgconn.PgError.Error() leaves out.
//
// Test-only: nothing outside *_test.go files may import this package.
package pgcanary

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/pgpriv"
)

const (
	// PGDSNEnv names the server. A run without it skips: this package never falls back
	// to SQLite, because the point of it is PostgreSQL's error text. It is not called
	// DSNEnv: server's secret-file guard resolves a selector by its field name
	// module-wide, so a const of that name would hide config's DSNEnv lookup site.
	PGDSNEnv = "KEYORIX_TEST_PG_DSN"

	// Prefix starts the name of every database this package creates.
	Prefix = "w7_"

	baseDatabase = Prefix + "canary_base"
	snapSchema   = "w7snap"

	// resetTimeout bounds one Reset; the tunnel to the lab server is slow but the
	// statement is small.
	resetTimeout = 30 * time.Second
)

// Entry is one error observed at the driver: what the server said, field by field,
// or the text of a client-side failure (for example an encode error, which has no
// SQLSTATE and quotes the value it could not encode).
type Entry struct {
	Op                                                              string
	SQLState, Message, Detail, Hint, Where, Table, Constraint, Text string
}

// Tracer implements pgx.QueryTracer and pgx.PrepareTracer. It records errors only.
type Tracer struct {
	mu      sync.Mutex
	entries []Entry
	pause   *pausePoint
}

// pausePoint holds the first statement containing substr until released: the way a
// concurrent pair is given a defined order without any hook in production code.
type pausePoint struct {
	substr   string
	reached  chan struct{}
	released chan struct{}
	fired    bool
}

// pauseLimit keeps a pause from outliving a broken run. It is short because a pause
// that holds a row or named lock the other request needs can only end this way.
const pauseLimit = 4 * time.Second

// RunLimit is the budget of one RunGuarded call. Every statement crosses the tunnel
// to the lab server, so a program of many operations takes tens of seconds.
const RunLimit = 5 * time.Minute

// RunGuarded runs fn and reports a hang through fatalf, re-panicking a panic on the
// caller's goroutine.
func RunGuarded(fatalf func(format string, args ...any), label string, fn func()) {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	select {
	case p := <-done:
		if p != nil {
			panic(p)
		}
	case <-time.After(RunLimit):
		fatalf("%s exceeded %s", label, RunLimit)
	}
}

// PauseOn makes the next statement containing substr wait until release is called.
// reached closes when a statement has stopped there.
func (t *Tracer) PauseOn(substr string) (reached <-chan struct{}, release func()) {
	p := &pausePoint{substr: substr, reached: make(chan struct{}), released: make(chan struct{})}
	t.mu.Lock()
	t.pause = p
	t.mu.Unlock()
	return p.reached, sync.OnceFunc(func() {
		t.mu.Lock()
		if t.pause == p {
			t.pause = nil
		}
		t.mu.Unlock()
		close(p.released)
	})
}

// TraceQueryStart implements pgx.QueryTracer.
func (t *Tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	t.mu.Lock()
	p := t.pause
	match := p != nil && !p.fired && strings.Contains(data.SQL, p.substr)
	if match {
		p.fired = true
	}
	t.mu.Unlock()
	if match {
		close(p.reached)
		select {
		case <-p.released:
		case <-time.After(pauseLimit):
		}
	}
	return ctx
}

// TraceQueryEnd implements pgx.QueryTracer.
func (t *Tracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	t.record("query", data.Err)
}

// TracePrepareStart implements pgx.PrepareTracer.
func (t *Tracer) TracePrepareStart(ctx context.Context, _ *pgx.Conn, _ pgx.TracePrepareStartData) context.Context {
	return ctx
}

// TracePrepareEnd implements pgx.PrepareTracer.
func (t *Tracer) TracePrepareEnd(_ context.Context, _ *pgx.Conn, data pgx.TracePrepareEndData) {
	t.record("prepare", data.Err)
}

func (t *Tracer) record(op string, err error) {
	if err == nil || errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return
	}
	e := Entry{Op: op, Text: err.Error()}
	if pg, ok := errors.AsType[*pgconn.PgError](err); ok {
		e.SQLState, e.Message, e.Detail, e.Hint, e.Where, e.Table, e.Constraint = pg.Code, pg.Message, pg.Detail, pg.Hint, pg.Where, pg.TableName, pg.ConstraintName
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append(t.entries, e)
}

// Drain returns the entries recorded since the last Drain.
func (t *Tracer) Drain() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.entries
	t.entries = nil
	return out
}

// RawOutputs turns entries into canary outputs, one channel per field, named
// "pg-raw:<field>". These are what the server handed the driver, not something the
// product wrote, so a target never judges them: they show which canaries a
// provocation really put into PostgreSQL's error fields. Text is "pg-raw:text"; for
// a server error it is what pgconn.PgError.Error() returns.
func RawOutputs(entries []Entry) []canary.Output {
	fields := map[string][]byte{}
	add := func(name, v string) {
		if v != "" {
			fields[name] = append(append(fields[name], v...), '\n')
		}
	}
	for _, e := range entries {
		add("message", e.Message)
		add("detail", e.Detail)
		add("hint", e.Hint)
		add("where", e.Where)
		add("text", e.Text)
	}
	out := make([]canary.Output, 0, len(fields))
	for name, data := range fields {
		out = append(out, canary.Output{Channel: "pg-raw:" + name, Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Channel < out[j].Channel })
	return out
}

// World is one migrated, seeded database reused across a worker's executions.
type World struct {
	DSN    string
	DB     *gorm.DB
	Pool   *pgxpool.Pool
	Tracer *Tracer

	resetSQL string
	tables   []string
}

// baseDSN returns the DSN of the database the templates and clones are created
// from, creating it on first use. Connecting to it instead of the server's default
// database also scopes pgdsn's advisory locks to this harness.
func baseDSN(tb testing.TB) string {
	tb.Helper()
	dsn := os.Getenv(PGDSNEnv)
	if dsn == "" {
		tb.Skipf("%s not set: the PostgreSQL canary targets need a server", PGDSNEnv)
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("connect to %s: %v", PGDSNEnv, err)
	}
	if sqlDB, e := admin.DB(); e == nil {
		defer func() { _ = sqlDB.Close() }()
	}
	err = admin.Exec("CREATE DATABASE " + baseDatabase + " TEMPLATE template0").Error
	if pg, ok := errors.AsType[*pgconn.PgError](err); ok && (pg.Code == "42P04" || pg.Code == "23505") {
		err = nil // already there; 23505 is the race of two workers creating it
	}
	if err != nil {
		tb.Fatalf("create %s: %v", baseDatabase, err)
	}
	return pgdsn.PGReplaceDBName(dsn, baseDatabase)
}

// Open clones a migrated database named w7_<purpose>_<pid>_<n> and opens it the way
// storage.createPostgresStorage does: gormConfig's logger, QueryFields and NowFunc,
// and a native read pool beside the request pool, each carrying the tracer.
//
// isolation, when not empty, becomes the connections' default_transaction_isolation.
// The product runs at READ COMMITTED; a serialization failure there needs a server
// or role configured otherwise, which is a thing a DBA can do.
func Open(tb testing.TB, purpose, isolation string) *World {
	tb.Helper()
	dsn := pgdsn.MigratedDatabase(tb, baseDSN(tb), Prefix+purpose, pgdsn.SchemaFingerprint(), kxstorage.MigrateExisting)

	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		tb.Fatalf("parse dsn: %v", err)
	}
	tracer := &Tracer{}
	cc.Tracer = tracer
	if isolation != "" {
		cc.RuntimeParams["default_transaction_isolation"] = isolation
	}
	sqlDB := stdlib.OpenDB(*cc)
	sqlDB.SetMaxOpenConns(8)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		QueryFields: true,
		NowFunc:     func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		tb.Fatalf("open %s: %v", pgdsn.DatabaseName(dsn), err)
	}
	// Reset restores the snapshot under session_replication_role = replica, so every
	// target needs the privilege: skip on a role without it (fail under CI=true).
	pgpriv.RequireReplicationRolePrivilege(tb, db)
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		tb.Fatalf("parse pool config: %v", err)
	}
	pc.ConnConfig.Tracer = tracer
	if isolation != "" {
		pc.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
	}
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		tb.Fatalf("open native pool: %v", err)
	}
	// Registered after MigratedDatabase's drop, so the pools close first.
	tb.Cleanup(func() {
		pool.Close()
		_ = sqlDB.Close()
	})
	return &World{DSN: dsn, DB: db, Pool: pool, Tracer: tracer}
}

// EmptyDatabase creates an empty w7_<purpose>_<pid>_<n> database, for a harness that
// migrates it itself, and returns its DSN.
func EmptyDatabase(tb testing.TB, purpose string) string {
	tb.Helper()
	return pgdsn.IsolatedDatabase(tb, baseDSN(tb), Prefix+purpose)
}

// Storage returns a new LocalStorage over the world, with the native read pool
// wired as production wires it. LocalStorage holds per-instance caches, so an
// execution takes its own.
func (w *World) Storage() *store.LocalStorage {
	ls := store.NewLocalStorage(w.DB)
	ls.SetNativeReadPool(w.Pool)
	return ls
}

// Snapshot records the current contents of the database (after the fixture has
// seeded it) as the state Reset restores.
func (w *World) Snapshot(tb testing.TB) {
	tb.Helper()
	exec := func(stmt string) {
		tb.Helper()
		if err := w.DB.Exec(stmt).Error; err != nil {
			tb.Fatalf("snapshot: %q: %v", stmt, err)
		}
	}
	var tables []string
	if err := w.DB.Raw(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`).Scan(&tables).Error; err != nil {
		tb.Fatalf("list tables: %v", err)
	}
	if len(tables) == 0 {
		tb.Fatalf("snapshot: the migrated database has no tables")
	}
	w.tables = tables

	exec("DROP SCHEMA IF EXISTS " + snapSchema + " CASCADE")
	exec("CREATE SCHEMA " + snapSchema)
	var restore []string
	for _, t := range tables {
		id := ident(t)
		var rows int64
		if err := w.DB.Raw("SELECT count(*) FROM public." + id).Scan(&rows).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- identifier from pg_tables in a test helper
			tb.Fatalf("count %s: %v", t, err)
		}
		if rows == 0 {
			continue
		}
		exec("CREATE TABLE " + snapSchema + "." + id + " AS TABLE public." + id)
		// ON CONFLICT: a production trigger that is ENABLE ALWAYS can re-create a row
		// of system_metadata during the TRUNCATE; keeping that row is enough.
		restore = append(restore, "INSERT INTO public."+id+" SELECT * FROM "+snapSchema+"."+id+" ON CONFLICT DO NOTHING")
	}

	type serial struct{ Tbl, Col, Seq string }
	var serials []serial
	if err := w.DB.Raw(`SELECT c.relname AS tbl, a.attname AS col, pg_get_serial_sequence(quote_ident(c.relname), a.attname) AS seq
		FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		  AND pg_get_serial_sequence(quote_ident(c.relname), a.attname) IS NOT NULL`).Scan(&serials).Error; err != nil {
		tb.Fatalf("list sequences: %v", err)
	}
	for _, s := range serials {
		var maxID int64
		if err := w.DB.Raw("SELECT COALESCE(MAX(" + ident(s.Col) + "), 0) FROM public." + ident(s.Tbl)).Scan(&maxID).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- identifiers from the catalog in a test helper
			tb.Fatalf("max %s.%s: %v", s.Tbl, s.Col, err)
		}
		if maxID > 0 {
			restore = append(restore, fmt.Sprintf("SELECT setval('%s', %d, true)", strings.ReplaceAll(s.Seq, "'", "''"), maxID))
		}
	}

	all := make([]string, len(tables))
	for i, t := range tables {
		all[i] = "public." + ident(t)
	}
	// replica mode: the restore bypasses the foreign keys (row order is arbitrary) and
	// the triggers that guard append-only tables in production. It is LOCAL, so it ends
	// with the transaction.
	w.resetSQL = "BEGIN; SET LOCAL session_replication_role = replica; TRUNCATE TABLE " + strings.Join(all, ", ") + " RESTART IDENTITY CASCADE; " + strings.Join(restore, "; ") + "; COMMIT"
}

// Reset restores Snapshot's state. It is one statement batch, so it costs one round
// trip. Every connection is left as it was; pooled prepared statements stay valid.
func (w *World) Reset() error {
	if w.resetSQL == "" {
		return errors.New("pgcanary: Reset before Snapshot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()
	if err := w.DB.WithContext(ctx).Exec(w.resetSQL).Error; err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	w.Tracer.Drain() // the reset's own errors, if any, belong to no execution
	return nil
}

// Dump returns every row of every table as "db:<table>" outputs: the cells render
// through to_jsonb, so a bytea cell is searched as hex, which the scanner matches. A
// table that cannot be read fails the whole dump; a column that cannot be read must
// not look like a clean one.
//
// Tables are re-listed from the catalogue at dump time, not reused from Snapshot's
// list: a leak that writes into a table created after the snapshot (the raw-file
// scan's SQLite equivalent would have caught it in the file) must not be invisible
// here.
func (w *World) Dump() ([]canary.Output, error) {
	if len(w.tables) == 0 {
		return nil, errors.New("pgcanary: Dump before Snapshot")
	}
	var tables []string
	if err := w.DB.Raw(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`).Scan(&tables).Error; err != nil {
		return nil, fmt.Errorf("dump: list tables: %w", err)
	}
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		parts = append(parts, fmt.Sprintf("SELECT %s AS t, to_jsonb(x)::text AS j FROM public.%s x", quoteLiteral(t), ident(t)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()
	rows, err := w.DB.WithContext(ctx).Raw(strings.Join(parts, " UNION ALL ")).Rows() // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- identifiers from pg_tables in a test helper
	if err != nil {
		return nil, fmt.Errorf("dump: %w", err)
	}
	defer func() { _ = rows.Close() }()
	cells := map[string][]byte{}
	for rows.Next() {
		var t, j string
		if err := rows.Scan(&t, &j); err != nil {
			return nil, fmt.Errorf("dump scan: %w", err)
		}
		cells[t] = append(append(cells[t], j...), '\n')
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dump rows: %w", err)
	}
	out := make([]canary.Output, 0, len(cells))
	for t, data := range cells {
		out = append(out, canary.Output{Channel: canary.ChannelDBPrefix + t, Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Channel < out[j].Channel })
	return out, nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// PostgresVersion and ServerLogSettings are recorded in the report: the server's own
// log is the one place DETAIL and statement text are written that no harness here
// can read.
func (w *World) PostgresVersion() (string, error) {
	var v string
	err := w.DB.Raw("SELECT version()").Scan(&v).Error
	return v, err
}

// ServerLogSettings reads the settings that decide what the server logs.
func (w *World) ServerLogSettings() (map[string]string, error) {
	type row struct{ Name, Setting string }
	var rows []row
	err := w.DB.Raw(`SELECT name, setting FROM pg_settings WHERE name IN ('log_min_error_statement','log_min_messages','log_statement','log_error_verbosity','log_parameter_max_length_on_error','log_parameter_max_length')`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Name] = r.Setting
	}
	return out, nil
}

// SweepStale drops every database of this harness (name starting with Prefix) left
// on the server by a killed run. It refuses to touch any other name, but it cannot
// tell a stale database from another session's live one: run it only as an operator
// tool on a server nobody else is testing against.
func SweepStale(tb testing.TB) []string {
	tb.Helper()
	dsn := os.Getenv(PGDSNEnv)
	if dsn == "" {
		tb.Skipf("%s not set", PGDSNEnv)
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("connect: %v", err)
	}
	if sqlDB, e := admin.DB(); e == nil {
		defer func() { _ = sqlDB.Close() }()
	}
	var names []string
	if err := admin.Raw(`SELECT datname FROM pg_database WHERE starts_with(datname, $1) ORDER BY datname`, Prefix).Scan(&names).Error; err != nil {
		tb.Fatalf("list databases: %v", err)
	}
	for _, name := range names {
		if !strings.HasPrefix(name, Prefix) {
			tb.Fatalf("refusing to drop %q", name)
		}
		id := ident(name)
		_ = admin.Exec("ALTER DATABASE " + id + " WITH IS_TEMPLATE false ALLOW_CONNECTIONS true").Error
		if err := admin.Exec("DROP DATABASE IF EXISTS " + id + " WITH (FORCE)").Error; err != nil {
			tb.Errorf("drop %s: %v", name, err)
		}
	}
	return names
}
