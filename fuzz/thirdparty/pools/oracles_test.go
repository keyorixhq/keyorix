// Red/green proofs for every oracle in the SC1 pool fuzzers. Each test plants a
// defect (a non-linearizable history, a lost update from a non-transactional
// RMW, a leaked connection, a blocked goroutine) and asserts the matching
// oracle FIRES, then asserts the unmodified/good path is GREEN. A guard nobody
// has watched fail is not a guard — these are where we watch them fail.
//
// The plants live only inside these tests (a deliberately-bad history, the
// gormIncrementUnsafe helper, a Conn deliberately not closed). No production
// code path is modified, and the fuzz targets themselves never use them.
package pools

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"

	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/schedfuzz"
)

// --- Linearizability oracle (register + counter models) --------------------

func TestOracle_Linearizability_RegisterRedGreen(t *testing.T) {
	// GREEN: a legal history — write(a) then read()->a.
	legal := []porcupine.Operation{
		{ClientId: 0, Input: regOp{write: true, value: "a"}, Call: 0, Output: "a", Return: 10},
		{ClientId: 1, Input: regOp{write: false}, Call: 11, Output: "a", Return: 20},
	}
	if res, _ := porcupine.CheckOperationsVerbose(regModel, legal, 2*time.Second); res != porcupine.Ok {
		t.Fatalf("register oracle FALSE POSITIVE: legal history reported %v, want Ok", res)
	}
	// RED: a read that returns a value never written, strictly after the only write.
	illegal := []porcupine.Operation{
		{ClientId: 0, Input: regOp{write: true, value: "a"}, Call: 0, Output: "a", Return: 10},
		{ClientId: 1, Input: regOp{write: false}, Call: 11, Output: "ghost", Return: 20},
	}
	if res, _ := porcupine.CheckOperationsVerbose(regModel, illegal, 2*time.Second); res != porcupine.Illegal {
		t.Fatalf("register oracle FAILED TO FIRE: stale/ghost read reported %v, want Illegal", res)
	}
}

func TestOracle_Linearizability_CounterRedGreen(t *testing.T) {
	// GREEN: two increments returning 1 then 2 (non-overlapping, well ordered).
	legal := []porcupine.Operation{
		{ClientId: 0, Input: counterOp{}, Call: 0, Output: int64(1), Return: 10},
		{ClientId: 1, Input: counterOp{}, Call: 11, Output: int64(2), Return: 20},
	}
	if res, _ := porcupine.CheckOperationsVerbose(counterModel, legal, 2*time.Second); res != porcupine.Ok {
		t.Fatalf("counter oracle FALSE POSITIVE: legal history reported %v, want Ok", res)
	}
	// RED: a lost update — two concurrent increments both return 1.
	illegal := []porcupine.Operation{
		{ClientId: 0, Input: counterOp{}, Call: 0, Output: int64(1), Return: 20},
		{ClientId: 1, Input: counterOp{}, Call: 0, Output: int64(1), Return: 20},
	}
	if res, _ := porcupine.CheckOperationsVerbose(counterModel, illegal, 2*time.Second); res != porcupine.Illegal {
		t.Fatalf("counter oracle FAILED TO FIRE: lost update reported %v, want Illegal", res)
	}
}

// --- Transaction-isolation oracle (gorm, real DB) --------------------------

// openGormSQLite builds a standalone SQLite gorm world with the kv table for
// the isolation proofs (no Postgres needed; the lost-update defect reproduces
// on SQLite just as well).
func openGormSQLite(t *testing.T) *fuzzworld.World {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "iso.db")
	dsn := dbPath + "?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	w := &fuzzworld.World{Backend: fuzzworld.BackendSQLite, DB: fuzzworld.OpenSQLite(t, dsn, sqliteMaxOpenConns)}
	if err := w.DB.AutoMigrate(&gormKV{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := w.DB.Create(&gormKV{K: "k0", N: 0}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return w
}

func TestOracle_Isolation_FiresWithoutLock(t *testing.T) {
	w := openGormSQLite(t)
	// Barrier: both goroutines read n=0 before either writes, forcing a lost
	// update deterministically. This is the DEFECT (gormIncrementUnsafe).
	var readWG sync.WaitGroup
	readWG.Add(2)
	gate := make(chan struct{})
	var once sync.Once
	beforeWrite := func() {
		readWG.Done()
		once.Do(func() { readWG.Wait(); close(gate) })
		<-gate
	}
	hist := newHistory()
	var mu sync.Mutex
	start := time.Now()
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			call := time.Since(start).Nanoseconds()
			n, err := gormIncrementUnsafe(context.Background(), w.DB, "k0", beforeWrite)
			ret := time.Since(start).Nanoseconds()
			if err != nil {
				t.Errorf("unsafe increment: %v", err)
				return
			}
			mu.Lock()
			hist.add(0, porcupine.Operation{ClientId: gi, Input: counterOp{}, Call: call, Output: n, Return: ret})
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Prove a lost update actually happened in the DB (both wrote 1).
	var row gormKV
	if err := w.DB.Where("k = ?", "k0").Take(&row).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if row.N != 1 {
		t.Fatalf("expected lost update to leave n=1 after 2 increments, got n=%d — barrier did not force the race", row.N)
	}
	// The isolation oracle must flag this history as NOT linearizable.
	res, _ := porcupine.CheckOperationsVerbose(counterModel, hist.ops[0], 2*time.Second)
	if res != porcupine.Illegal {
		t.Fatalf("isolation oracle FAILED TO FIRE on a real lost update: reported %v, want Illegal", res)
	}
}

func TestOracle_Isolation_GreenWithLock(t *testing.T) {
	w := openGormSQLite(t)
	hist := newHistory()
	var mu sync.Mutex
	start := time.Now()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for range 5 {
				call := time.Since(start).Nanoseconds()
				n, err := gormIncrement(context.Background(), w.DB, "k0")
				ret := time.Since(start).Nanoseconds()
				if err != nil {
					continue
				}
				mu.Lock()
				hist.add(0, porcupine.Operation{ClientId: gi, Input: counterOp{}, Call: call, Output: n, Return: ret})
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	res, _ := porcupine.CheckOperationsVerbose(counterModel, hist.ops[0], 5*time.Second)
	if res == porcupine.Illegal {
		t.Fatalf("isolation oracle FALSE POSITIVE: production locking RMW reported NOT linearizable")
	}
}

// --- Connection-leak / pool-baseline oracle --------------------------------

func TestOracle_ConnLeak_FiresOnLeakedConn(t *testing.T) {
	db := openSQLitePool(t)
	defer func() { _ = db.Close() }()
	// GREEN: a normal query returns its connection; InUse drains to 0.
	if _, err := db.Exec(`INSERT INTO kv(k,v) VALUES('x','1') ON CONFLICT(k) DO UPDATE SET v='1'`); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !sqlPoolDrains(db) {
		t.Fatalf("pool-baseline oracle FALSE POSITIVE: pool did not drain after a normal query")
	}
	// RED: a connection checked out and never returned keeps InUse > 0.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("checkout conn: %v", err)
	}
	if sqlPoolDrains(db) {
		t.Fatalf("connection-leak oracle FAILED TO FIRE: InUse drained to 0 with a conn still checked out")
	}
	_ = conn.Close() // release the plant; never leaked past the test
	if !sqlPoolDrains(db) {
		t.Fatalf("pool did not drain after releasing the leaked conn")
	}
}

// --- Deadlock oracle --------------------------------------------------------

func TestOracle_Deadlock_FiresOnBlockedGoroutine(t *testing.T) {
	// GREEN: all goroutines finish within the timeout.
	if !schedfuzz.RunBounded(t, 3, 2*time.Second, func(gi int) {}) {
		t.Fatalf("deadlock oracle FALSE POSITIVE: fast goroutines reported as a deadlock")
	}
	// RED: one goroutine blocks forever -> RunBounded times out (false).
	release := make(chan struct{})
	defer close(release)
	completed := schedfuzz.RunBounded(t, 2, 300*time.Millisecond, func(gi int) {
		if gi == 0 {
			<-release
		}
	})
	if completed {
		t.Fatalf("deadlock oracle FAILED TO FIRE: a permanently-blocked goroutine reported as completed")
	}
}

// --- Goroutine-leak oracle --------------------------------------------------

func TestOracle_GoroutineLeak_FiresOnLeakedGoroutine(t *testing.T) {
	base := schedfuzz.GoroutineBaseline()
	// GREEN: no leak -> settles at baseline.
	if _, ok := schedfuzz.SettleGoroutines(base, 0); !ok {
		t.Fatalf("goroutine-leak oracle FALSE POSITIVE: settled baseline reported as a leak")
	}
	// RED: a blocked goroutine keeps the count above baseline.
	release := make(chan struct{})
	started := make(chan struct{})
	go func() { close(started); <-release }()
	<-started
	if _, ok := schedfuzz.SettleGoroutines(base, 0); ok {
		close(release)
		t.Fatalf("goroutine-leak oracle FAILED TO FIRE: a blocked goroutine did not register as a leak")
	}
	close(release)
}
