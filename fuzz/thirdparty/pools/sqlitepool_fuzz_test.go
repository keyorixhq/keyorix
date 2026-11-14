// Package pools holds the task-SC1 concurrency/linearizability fuzzers for the
// THIRD-PARTY connection pools and clients Keyorix shares across goroutines in
// production:
//
//   - database/sql + modernc.org/sqlite (this file) — the SQLite request pool
//     every non-Postgres deployment runs on (internal/storage/factory.go's
//     sqliteDSN, WAL + _busy_timeout + up to storage.DefaultSQLiteMaxOpenConns
//     connections).
//   - github.com/jackc/pgx/v5/pgxpool (pgxpool_fuzz_test.go) — the native read
//     pool Keyorix opens on Postgres for its hottest read statements
//     (internal/storage/store/native_reads.go, wired in factory_postgres.go).
//   - gorm.io/gorm transactions (gormtx_fuzz_test.go) — WithTransaction /
//     WithContext(...).Transaction, the row-locking read-modify-write path
//     (TryAcquireSchedulerLock's SELECT ... FOR UPDATE, storeNextSecretVersion).
//
// These extend the in-tree porcupine approach
// (server/http/concurrent_linearizable_fuzz_test.go, which fuzzes the
// KeyorixCore layer) DOWN to the library/pool layer itself: a seeded scheduler
// (internal/testutil/schedfuzz) drives concurrent operation histories, the
// history is checked for linearizability against a sequential KV model, and a
// set of oracles watches for connection/goroutine leaks and deadlocks. Run
// under -race.
//
// Redis (go-redis) is deliberately NOT fuzzed here: Keyorix never shares a
// go-redis client across goroutines (internal/rotation/redis.go constructs one
// per rotation call and closes it immediately), and no in-process test server
// (miniredis / alicebob) is present in the offline module cache, so a
// concurrency harness could neither reach a live Keyorix caller nor run without
// network. gRPC client conns are likewise absent: Keyorix is a gRPC SERVER, it
// opens no shared client ClientConn. Both are recorded as negative results in
// the SC1 report rather than fuzzed against an unreachable shape.
//
// ORACLES (and, for each, what it does NOT verify):
//
//   - Linearizability (regModel): the recorded write/read history admits some
//     sequential order consistent with real-time. Does NOT verify: durability,
//     isolation of multi-statement transactions (that is the counter model in
//     gormtx), performance, or fairness. Cancelled ops are leak-probes only and
//     are NOT recorded (their effect is indeterminate), so this oracle says
//     nothing about a cancelled op's success/failure.
//   - Pool returns to baseline (assertSQLPoolDrained): after the concurrent
//     phase every connection is back in the pool (InUse == 0). Does NOT verify
//     that OpenConnections shrinks (idle pooled conns legitimately remain), nor
//     anything about pool sizing/wait time.
//   - No connection leak after mid-query cancellation: the same drain check,
//     after a phase that cancels a fraction of queries mid-flight. Does NOT
//     verify the cancelled query's result, nor that cancellation was timely.
//   - No goroutine leak (schedfuzz.SettleGoroutines): goroutine count returns
//     to baseline+slack. Does NOT identify WHICH goroutine leaked, and tolerates
//     a bounded slack for pool-internal goroutines.
//   - No deadlock within timeout (schedfuzz.RunBounded): all goroutines finish
//     within the watchdog. Does NOT prove liveness beyond the timeout, and a
//     merely slow (not deadlocked) run near the bound can read as a false
//     positive — the timeout is set generously for that reason.
package pools

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	_ "modernc.org/sqlite"

	"github.com/keyorixhq/keyorix/internal/testutil/schedfuzz"
)

const (
	poolMaxGoroutines      = 8
	poolMaxOpsPerGoroutine = 6
	poolNumKeys            = 4
	// Mirrors internal/storage/factory.go's production SQLite pool shape as
	// closely as a bare database/sql harness can: WAL, a busy timeout, and a
	// multi-connection pool (the whole point — a single-connection pool would
	// serialize everything and make the fuzzer race-free by construction).
	sqliteBusyTimeoutMillis = 10000
	sqliteMaxOpenConns      = 8
	deadlockTimeout         = 30 * time.Second
	goroutineSlack          = 8
)

var poolValSeq atomic.Int64 // globally-unique written values, so a read's value pins the exact write that produced it

func openSQLitePool(t testing.TB) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pool.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate",
		dbPath, sqliteBusyTimeoutMillis)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite pool: %v", err)
	}
	db.SetMaxOpenConns(sqliteMaxOpenConns)
	db.SetMaxIdleConns(sqliteMaxOpenConns)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '', n BIGINT NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("create kv: %v", err)
	}
	return db
}

// assertSQLPoolDrained is the pool-baseline / connection-leak oracle for a
// database/sql pool: after the concurrent phase, no connection may still be
// checked out. InUse==0 is the invariant; OpenConnections staying >0 (idle,
// pooled) is fine and expected.
// sqlPoolDrains reports whether the pool returns to zero checked-out
// connections within a short settle window. Shared by the fatal oracle below
// and by the connection-leak red/green proof (oracles_test.go).
func sqlPoolDrains(db *sql.DB) bool {
	for i := 0; i < 200; i++ {
		if db.Stats().InUse == 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return db.Stats().InUse == 0
}

func assertSQLPoolDrained(t *testing.T, db *sql.DB, where string) {
	t.Helper()
	if sqlPoolDrains(db) {
		return
	}
	s := db.Stats()
	t.Fatalf("CONNECTION LEAK (%s): pool did not drain, InUse=%d OpenConnections=%d WaitCount=%d",
		where, s.InUse, s.OpenConnections, s.WaitCount)
}

// runSQLiteRegisterIteration runs one decoded program against the pool and
// returns the per-key history. cancelFrac selects how aggressively ops are run
// under a mid-flight-cancelled context (leak probes, not recorded).
func runSQLiteRegisterIteration(t *testing.T, db *sql.DB, prog schedfuzz.Program) *history {
	t.Helper()
	// The pool (and its kv table) is built once and reused across every fuzz
	// iteration, so the recorded keys must be cleared to "" first — otherwise a
	// read in this iteration could observe a value a PRIOR iteration wrote, which
	// is not in this history and regModel's Init:"" would (correctly) reject.
	// Fixing the fixture, not the oracle: the oracle caught exactly this on first
	// contact. Done before the concurrent phase, single-threaded.
	if _, err := db.Exec(`DELETE FROM kv`); err != nil {
		t.Fatalf("reset kv: %v", err)
	}
	hist := newHistory()
	start := time.Now()

	completed := schedfuzz.RunBounded(t, len(prog.Goroutines), deadlockTimeout, func(gi int) {
		for _, op := range prog.Goroutines[gi] {
			schedfuzz.Pace(op)
			sqliteRegisterOp(t, db, hist, start, gi, op)
		}
	})
	if !completed {
		t.Fatalf("DEADLOCK: goroutines did not finish within %s (sqlite register)", deadlockTimeout)
	}
	return hist
}

func sqliteRegisterOp(t *testing.T, db *sql.DB, hist *history, start time.Time, gi int, op schedfuzz.Op) {
	t.Helper()
	key := op.Key
	kStr := fmt.Sprintf("k%d", key)
	switch op.Kind % 4 {
	case 0: // write
		val := fmt.Sprintf("v%d", poolValSeq.Add(1))
		call := time.Since(start).Nanoseconds()
		_, err := db.ExecContext(context.Background(),
			`INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, kStr, val)
		ret := time.Since(start).Nanoseconds()
		if err != nil {
			t.Fatalf("sqlite write: %v", err)
		}
		hist.add(key, porcupine.Operation{ClientId: gi, Input: regOp{write: true, value: val}, Call: call, Output: val, Return: ret})
	case 1: // read
		call := time.Since(start).Nanoseconds()
		var v string
		err := db.QueryRowContext(context.Background(), `SELECT v FROM kv WHERE k=?`, kStr).Scan(&v)
		ret := time.Since(start).Nanoseconds()
		if err == sql.ErrNoRows {
			v = ""
			err = nil
		}
		if err != nil {
			t.Fatalf("sqlite read: %v", err)
		}
		hist.add(key, porcupine.Operation{ClientId: gi, Input: regOp{write: false}, Call: call, Output: v, Return: ret})
	case 2: // write under a context cancelled mid-flight — leak probe, NOT recorded.
		// Writes to a DISJOINT "probe" keyspace the register model never reads or
		// records: a cancelled write may still commit (cancellation races the
		// statement), so letting it touch a recorded key would mutate the
		// register unobserved and manufacture a false non-linearizable history.
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(time.Duration(1+int(op.Val)%20) * time.Microsecond); cancel() }()
		val := fmt.Sprintf("v%d", poolValSeq.Add(1))
		_, _ = db.ExecContext(ctx, `INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, "probe"+kStr, val)
		cancel()
	default: // 3: read under a cancelled context — leak probe, NOT recorded
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(time.Duration(1+int(op.Val)%20) * time.Microsecond); cancel() }()
		var v string
		_ = db.QueryRowContext(ctx, `SELECT v FROM kv WHERE k=?`, kStr).Scan(&v)
		cancel()
	}
}

func FuzzSQLitePoolLinearizable(f *testing.F) {
	db := openSQLitePool(f)
	f.Cleanup(func() { _ = db.Close() })
	baseGoroutines := schedfuzz.GoroutineBaseline()

	f.Add([]byte{3, 2, 0, 0, 1, 0, 1, 1, 1, 1, 0, 2, 0, 0, 0, 1, 1, 0, 1, 1})
	f.Add([]byte{7, 0, 2, 0, 1, 0, 3, 1, 1, 0, 0, 0, 0, 2, 0, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		prog := schedfuzz.Decode(program, poolMaxGoroutines, poolMaxOpsPerGoroutine, poolNumKeys)
		if len(prog.Goroutines) == 0 {
			return
		}
		prev := runtime.GOMAXPROCS(prog.GOMAXPROCS)
		defer runtime.GOMAXPROCS(prev)

		hist := runSQLiteRegisterIteration(t, db, prog)

		checkAll(t, "sqlite register", regModel, hist)
		assertSQLPoolDrained(t, db, "after iteration")
		if n, ok := schedfuzz.SettleGoroutines(baseGoroutines, goroutineSlack); !ok {
			t.Fatalf("GOROUTINE LEAK (sqlite): %d goroutines, baseline %d (+%d slack)", n, baseGoroutines, goroutineSlack)
		}
	})
}
