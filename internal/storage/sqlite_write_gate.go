// sqlite_write_gate.go — in-process FIFO serialization of SQLite write transactions
// (#2630, Detected-by: PERF-2 performance study).
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
)

// ErrSQLiteWriteContention is returned when a write transaction waited
// sqliteWriteGateMaxWait for the SQLite write lock without getting it: the
// clear, bounded failure that replaces an unbounded stall. Callers may retry.
//
// An alias, not a second error value: the sentinel itself lives in
// internal/core/storage so internal/storage/store's isSQLiteBusyErr can match
// it with errors.Is (this package imports that one, so the dependency cannot
// run the other way). Kept under this name because it is this package's own
// gate that returns it, and because the gate's tests read better for it.
var ErrSQLiteWriteContention = corestorage.ErrSQLiteWriteContention

// sqliteWriteGateMaxWait bounds how long a write transaction queues for the gate.
// It equals the busy_timeout the DSN already gives SQLite itself (an in-process
// waiter could previously wait exactly that long inside SQLite's busy handler),
// so the worst case is unchanged. What changes is how long the typical waiter
// waits: see sqliteWriteGate.
//
// An atomic, not a plain var: it is a var at all only so a test can shorten the
// bound, and the two tests that do so wrote it while another goroutine in the
// same test was reading it inside gateWriteSlot. Harmless today because nothing
// in this package calls t.Parallel(), and a data race the moment anything does —
// which is not a property worth depending on (coordinator review of #2637).
var sqliteWriteGateMaxWait atomic.Int64

func init() {
	sqliteWriteGateMaxWait.Store(int64(time.Duration(sqliteBusyTimeoutMillis) * time.Millisecond))
}

// writeGateMaxWait reads the bound. Separate accessor so every read goes through
// the atomic and a future direct read cannot reintroduce the race.
func writeGateMaxWait() time.Duration {
	return time.Duration(sqliteWriteGateMaxWait.Load())
}

// SetWriteGateMaxWaitForTest shortens the gate's wait bound so a test that
// saturates the gate (holds one write transaction open) sees
// ErrSQLiteWriteContention in milliseconds instead of after the production 10s.
// It returns the function that restores the previous bound. Test-only: nothing
// in production calls it, and it lives here (not in a _test.go file) because
// the HTTP/gRPC contention tests that need it are in other packages.
func SetWriteGateMaxWaitForTest(d time.Duration) (restore func()) {
	prev := sqliteWriteGateMaxWait.Swap(int64(d))
	return func() { sqliteWriteGateMaxWait.Store(prev) }
}

// sqliteWriteGate serializes this process's SQLite write transactions through a
// FIFO queue before they reach SQLite.
//
// Why: SQLite allows one writer at a time. With every transaction BEGIN IMMEDIATE
// (sqliteDSN's _txlock=immediate) and a pool of up to 25 connections (the pool this
// was measured on; the default is now DefaultSQLiteMaxOpenConns = 8), that many
// goroutines at a time waited for that one lock inside SQLite's busy handler, which polls: each
// waiter sleeps 1, 2, 5, 10, ... up to 100ms between attempts and has no queue
// position. A lock released after 1ms of work sat idle until some sleeper happened
// to wake, the newest arrivals (still on 1–2ms sleeps) overtook waiters already
// backed off to 100ms, and the effective write-transaction time grew ~30x (0.8ms
// uncontended vs. ~30ms under load). CreateSecret runs one such transaction while
// holding its per-environment named lock, so that inflation became a growing queue
// of creates and, under sustained load, writes stalled to the client's 10s timeout
// (PERF-2: 2.7% failures at 10 clients, 6.4% at 50).
//
// A buffered channel of capacity 1 is the gate: goroutines blocked sending on it are
// woken in arrival order, and the hand-off happens the instant the previous holder
// commits. Only write transactions pass through it. Read-only transactions and
// plain queries never do, so WAL readers keep their concurrency and the full pool.
// SQLite's own busy_timeout is unchanged and still covers a SECOND process using
// the same file (the CLI admin commands), which this in-process gate cannot see.
//
// What it does NOT cover, stated so nobody assumes it: autocommit write statements
// issued outside a transaction (a raw db.Exec("UPDATE ...") on the root handle).
// They still contend through the busy handler as before: correct, just not
// queue-fair. GORM wraps every Create/Update/Delete in a transaction (no caller sets
// SkipDefaultTransaction), so those all go through BeginTx and are gated.
type sqliteWriteGate struct {
	slot chan struct{}
}

func newSQLiteWriteGate() *sqliteWriteGate {
	return &sqliteWriteGate{slot: make(chan struct{}, 1)}
}

// acquire waits, in FIFO order, for the gate. It gives up with ctx's error if ctx
// ends first, or with ErrSQLiteWriteContention after sqliteWriteGateMaxWait.
func (g *sqliteWriteGate) acquire(ctx context.Context) error {
	select {
	case g.slot <- struct{}{}:
		return nil
	default:
	}
	timer := time.NewTimer(writeGateMaxWait())
	defer timer.Stop()
	select {
	case g.slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("sqlite write gate: %w", ctx.Err())
	case <-timer.C:
		corestorage.NoteWriteContention(ctx)
		return ErrSQLiteWriteContention
	}
}

func (g *sqliteWriteGate) release() { <-g.slot }

// gatedSQLitePool is the gorm.ConnPool for a SQLite *sql.DB: every query passes
// straight through, and BeginTx for a write transaction first acquires the gate.
type gatedSQLitePool struct {
	*sql.DB
	gate *sqliteWriteGate
}

var (
	_ gorm.ConnPool         = (*gatedSQLitePool)(nil)
	_ gorm.ConnPoolBeginner = (*gatedSQLitePool)(nil)
	_ gorm.GetDBConnector   = (*gatedSQLitePool)(nil)
	_ gorm.Tx               = (*gatedSQLiteTx)(nil)
	_ gorm.GetDBConnector   = (*gatedSQLiteTx)(nil)
)

// GetDBConn lets gorm.DB.DB() return the underlying *sql.DB (pool settings,
// health checks, Close) exactly as before the wrapper existed.
func (p *gatedSQLitePool) GetDBConn() (*sql.DB, error) { return p.DB, nil }

// BeginTx implements gorm.ConnPoolBeginner. A read-only transaction is never gated:
// the driver begins it DEFERRED and it cannot take the write lock.
func (p *gatedSQLitePool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	if opts != nil && opts.ReadOnly {
		return p.DB.BeginTx(ctx, opts)
	}
	if err := p.gate.acquire(ctx); err != nil {
		return nil, err
	}
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		p.gate.release()
		return nil, err
	}
	t := &gatedSQLiteTx{Tx: tx, db: p.DB}
	var once sync.Once
	t.release = func() { once.Do(p.gate.release) }
	// database/sql rolls a transaction back by itself when its ctx ends; release the
	// gate then too, so a caller that never reaches Commit/Rollback cannot wedge every
	// other writer in the process.
	t.stopAfter = context.AfterFunc(ctx, t.release)
	return t, nil
}

// gatedSQLiteTx is a write transaction holding the gate until it ends.
type gatedSQLiteTx struct {
	*sql.Tx
	db        *sql.DB
	release   func()
	stopAfter func() bool
}

func (t *gatedSQLiteTx) GetDBConn() (*sql.DB, error) { return t.db, nil }

func (t *gatedSQLiteTx) Commit() error {
	defer t.done()
	return t.Tx.Commit()
}

func (t *gatedSQLiteTx) Rollback() error {
	defer t.done()
	return t.Tx.Rollback()
}

func (t *gatedSQLiteTx) done() {
	t.stopAfter()
	t.release()
}

// openSQLiteGorm opens dsn with the modernc driver behind a fresh write gate. Every
// production SQLite open goes through here (createLocalStorage, OpenGormDB), so one
// process-local gate covers each *sql.DB.
func openSQLiteGorm(dsn string) (*gorm.DB, error) {
	sqlDB, err := sql.Open(sqlite.DriverName, dsn)
	if err != nil {
		return nil, err
	}
	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: &gatedSQLitePool{DB: sqlDB, gate: newSQLiteWriteGate()}}), gormConfig())
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}
