// FuzzPgxPoolLinearizable — concurrency/linearizability fuzzer for
// github.com/jackc/pgx/v5/pgxpool, the pool Keyorix opens for its hottest
// Postgres read statements (internal/storage/store/native_reads.go, wired in
// internal/storage/factory_postgres.go). Live caller: a running Keyorix server
// on Postgres shares exactly one *pgxpool.Pool across every HTTP/gRPC handler
// goroutine for those reads.
//
// Runs only when KEYORIX_TEST_PG_DSN is set; otherwise skipped with a stated
// reason. All state lives in a per-run schema (sc1_pool_<pid>_<seq>) dropped on
// cleanup — no database is created, and no object outside that schema is
// touched.
//
// Oracles are the same five as the sqlite target (see sqlitepool_fuzz_test.go's
// package doc for each oracle's "what it does NOT verify"), with the pool
// drained-to-baseline check reading pgxpool's own Stat().AcquiredConns() == 0
// instead of database/sql's InUse.
package pools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/keyorixhq/keyorix/internal/testutil/schedfuzz"
)

const pgxPoolMaxConns = 8

func openPgxPool(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — pgxpool backend skipped")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("sc1_pool_%d_%d", os.Getpid(), poolValSeq.Add(1))

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("pgx connect (admin) failed, skipping pgx backend: %v", err)
	}
	if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pgx config: %v", err)
	}
	cfg.MaxConns = pgxPoolMaxConns
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pgxpool: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '', n BIGINT NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("create kv: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	return pool, schema
}

// assertPgxPoolDrained is the pool-baseline / connection-leak oracle for a
// pgxpool: after the concurrent phase no connection may still be acquired.
func assertPgxPoolDrained(t *testing.T, pool *pgxpool.Pool, where string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if pool.Stat().AcquiredConns() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s := pool.Stat()
	t.Fatalf("CONNECTION LEAK (%s): pgxpool did not drain, Acquired=%d Total=%d Idle=%d",
		where, s.AcquiredConns(), s.TotalConns(), s.IdleConns())
}

func pgxRegisterOp(t *testing.T, pool *pgxpool.Pool, hist *history, start time.Time, gi int, op schedfuzz.Op) {
	t.Helper()
	ctx := context.Background()
	kStr := fmt.Sprintf("k%d", op.Key)
	switch op.Kind % 4 {
	case 0: // write
		val := fmt.Sprintf("v%d", poolValSeq.Add(1))
		call := time.Since(start).Nanoseconds()
		_, err := pool.Exec(ctx, `INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT(k) DO UPDATE SET v=EXCLUDED.v`, kStr, val)
		ret := time.Since(start).Nanoseconds()
		if err != nil {
			t.Fatalf("pgx write: %v", err)
		}
		hist.add(op.Key, porcupine.Operation{ClientId: gi, Input: regOp{write: true, value: val}, Call: call, Output: val, Return: ret})
	case 1: // read
		call := time.Since(start).Nanoseconds()
		var v string
		err := pool.QueryRow(ctx, `SELECT v FROM kv WHERE k=$1`, kStr).Scan(&v)
		ret := time.Since(start).Nanoseconds()
		if errors.Is(err, pgx.ErrNoRows) {
			v, err = "", nil
		}
		if err != nil {
			t.Fatalf("pgx read: %v", err)
		}
		hist.add(op.Key, porcupine.Operation{ClientId: gi, Input: regOp{write: false}, Call: call, Output: v, Return: ret})
	case 2: // write under a mid-flight-cancelled context — leak probe, NOT recorded
		ctx2, cancel := context.WithCancel(ctx)
		go func() { time.Sleep(time.Duration(1+int(op.Val)%20) * time.Microsecond); cancel() }()
		val := fmt.Sprintf("v%d", poolValSeq.Add(1))
		_, _ = pool.Exec(ctx2, `INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT(k) DO UPDATE SET v=EXCLUDED.v`, kStr, val)
		cancel()
	default: // 3: read under a cancelled context — leak probe, NOT recorded
		ctx2, cancel := context.WithCancel(ctx)
		go func() { time.Sleep(time.Duration(1+int(op.Val)%20) * time.Microsecond); cancel() }()
		var v string
		_ = pool.QueryRow(ctx2, `SELECT v FROM kv WHERE k=$1`, kStr).Scan(&v)
		cancel()
	}
}

func FuzzPgxPoolLinearizable(f *testing.F) {
	pool, _ := openPgxPool(f)
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

		hist := newHistory()
		start := time.Now()
		completed := schedfuzz.RunBounded(t, len(prog.Goroutines), deadlockTimeout, func(gi int) {
			for _, op := range prog.Goroutines[gi] {
				schedfuzz.Pace(op)
				pgxRegisterOp(t, pool, hist, start, gi, op)
			}
		})
		if !completed {
			t.Fatalf("DEADLOCK: goroutines did not finish within %s (pgx register)", deadlockTimeout)
		}

		checkAll(t, "pgx register", regModel, hist)
		assertPgxPoolDrained(t, pool, "after iteration")
		if n, ok := schedfuzz.SettleGoroutines(baseGoroutines, goroutineSlack); !ok {
			t.Fatalf("GOROUTINE LEAK (pgx): %d goroutines, baseline %d (+%d slack)", n, baseGoroutines, goroutineSlack)
		}
	})
}
