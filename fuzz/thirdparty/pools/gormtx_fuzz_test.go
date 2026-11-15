// FuzzGormTxnLinearizable — concurrency fuzzer for gorm.io/gorm transactions,
// the read-modify-write path Keyorix relies on for its locking writes:
// TryAcquireSchedulerLock (internal/storage/store/local_scheduler_lock_lease.go)
// and storeNextSecretVersion both do a transactional SELECT ... (FOR UPDATE on
// Postgres) then an UPDATE, exactly the shape modeled here. Live caller: every
// scheduler tick and every secret-version write on a shared *gorm.DB.
//
// Model: counterModel (see kvmodel_test.go). Each op is an atomic increment —
// a transactional read-modify-write of a row's counter that returns the new
// value. Linearizability of this history is precisely the lost-update /
// transaction-isolation oracle: if two increments both read n and both return
// n+1, no sequential order explains the history and porcupine reports Illegal.
// The production path (a gorm Transaction, with clause.Locking{Strength:"UPDATE"}
// on Postgres and BEGIN IMMEDIATE write-serialization on SQLite — mirroring
// TryAcquireSchedulerLock's own dialect-conditional FOR UPDATE) must stay
// linearizable; the oracle's red proof (TestOracle_Isolation_*) runs the
// non-transactional variant and shows the SAME oracle firing.
//
// SQLite always; Postgres too when KEYORIX_TEST_PG_DSN is set. Postgres state
// lives in a per-run schema dropped on cleanup (fuzzworld.OpenPostgres).
//
// What the isolation oracle does NOT verify: anything about aborted/retried
// transactions' liveness, deadlock-retry behaviour, or isolation anomalies
// other than lost update (no write-skew / phantom model here — the counter is a
// single-row RMW by construction).
package pools

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/schedfuzz"
)

// gormKV is the single-row-per-key counter table. Named kv to match the other
// targets; only the n column is used by this target.
type gormKV struct {
	K string `gorm:"column:k;primaryKey"`
	V string `gorm:"column:v;default:''"`
	N int64  `gorm:"column:n;default:0"`
}

func (gormKV) TableName() string { return "kv" }

// gormIncrement does a transactional read-modify-write of key k's counter and
// returns the new value. This is the PRODUCTION-faithful path: a gorm
// Transaction with a dialect-conditional FOR UPDATE on Postgres, exactly like
// TryAcquireSchedulerLock. On SQLite the _txlock=immediate DSN makes the
// Transaction take a write lock at BEGIN, serializing concurrent increments.
func gormIncrement(ctx context.Context, db *gorm.DB, k string) (int64, error) {
	var newN int64
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var row gormKV
		if err := q.Where("k = ?", k).Take(&row).Error; err != nil {
			return err
		}
		row.N++
		if err := tx.Model(&gormKV{}).Where("k = ?", k).Update("n", row.N).Error; err != nil {
			return err
		}
		newN = row.N
		return nil
	})
	return newN, err
}

// gormIncrementUnsafe is the DEFECT variant used only by the isolation oracle's
// red proof: read and write are two separate autocommit statements with no
// transaction and no lock, so concurrent callers that both read n both write
// n+1 — a lost update. Never used by the fuzz target itself.
func gormIncrementUnsafe(ctx context.Context, db *gorm.DB, k string, beforeWrite func()) (int64, error) {
	var row gormKV
	if err := db.WithContext(ctx).Where("k = ?", k).Take(&row).Error; err != nil {
		return 0, err
	}
	if beforeWrite != nil {
		beforeWrite()
	}
	row.N++
	if err := db.WithContext(ctx).Model(&gormKV{}).Where("k = ?", k).Update("n", row.N).Error; err != nil {
		return 0, err
	}
	return row.N, nil
}

// gormCancelProbe runs a two-statement transaction on a disjoint probe key
// under a context cancelled mid-flight — the mid-TRANSACTION cancellation leak
// probe. Its only assertion is indirect: the pool must still drain to baseline
// afterwards (checked once per iteration). It never touches a counter key, so
// it cannot perturb the isolation oracle, and whatever it commits or rolls back
// is irrelevant.
func gormCancelProbe(db *gorm.DB, probeKey string, val byte) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(time.Duration(1+int(val)%20) * time.Microsecond); cancel() }()
	_ = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&gormKV{K: probeKey, N: 0}).Error; err != nil {
			return err
		}
		return tx.Model(&gormKV{}).Where("k = ?", probeKey).Update("n", gorm.Expr("n + 1")).Error
	})
	cancel()
}

func gormWorlds(t testing.TB) []*fuzzworld.World {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gormtx.db")
	dsn := fmt.Sprintf("%s?_foreign_keys=1&_busy_timeout=%d&_journal_mode=WAL&_txlock=immediate", dbPath, sqliteBusyTimeoutMillis)
	sq := &fuzzworld.World{Backend: fuzzworld.BackendSQLite, DB: fuzzworld.OpenSQLite(t, dsn, sqliteMaxOpenConns)}
	worlds := []*fuzzworld.World{sq}
	if pg := fuzzworld.OpenPostgres(t, "sc1_gormtx"); pg != nil {
		worlds = append(worlds, &fuzzworld.World{Backend: fuzzworld.BackendPostgres, DB: pg})
	}
	for _, w := range worlds {
		if err := w.DB.AutoMigrate(&gormKV{}); err != nil {
			t.Fatalf("[%s] migrate kv: %v", w.Backend, err)
		}
	}
	return worlds
}

// resetCounters sets every key's counter back to 0 and ensures the row exists,
// so each iteration starts from counterModel's Init state.
func resetCounters(t *testing.T, w *fuzzworld.World) {
	t.Helper()
	for k := range poolNumKeys {
		kStr := fmt.Sprintf("k%d", k)
		if err := w.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "k"}},
			DoUpdates: clause.Assignments(map[string]any{"n": 0}),
		}).Create(&gormKV{K: kStr, N: 0}).Error; err != nil {
			t.Fatalf("[%s] reset counter %s: %v", w.Backend, kStr, err)
		}
	}
}

func FuzzGormTxnLinearizable(f *testing.F) {
	worlds := gormWorlds(f)
	baseGoroutines := schedfuzz.GoroutineBaseline()

	f.Add([]byte{3, 2, 0, 0, 1, 0, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 1, 1})
	f.Add([]byte{7, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		prog := schedfuzz.Decode(program, poolMaxGoroutines, poolMaxOpsPerGoroutine, poolNumKeys)
		if len(prog.Goroutines) == 0 {
			return
		}
		prev := runtime.GOMAXPROCS(prog.GOMAXPROCS)
		defer runtime.GOMAXPROCS(prev)

		for _, w := range worlds {
			resetCounters(t, w)
			hist := newHistory()
			start := time.Now()
			completed := schedfuzz.RunBounded(t, len(prog.Goroutines), deadlockTimeout, func(gi int) {
				for _, op := range prog.Goroutines[gi] {
					schedfuzz.Pace(op)
					kStr := fmt.Sprintf("k%d", op.Key)
					if op.Kind%4 == 3 { // mid-transaction cancellation leak probe (not recorded)
						gormCancelProbe(w.DB, "probe"+kStr, op.Val)
						continue
					}
					call := time.Since(start).Nanoseconds()
					n, err := gormIncrement(context.Background(), w.DB, kStr)
					ret := time.Since(start).Nanoseconds()
					if err != nil {
						// A serialization failure / busy timeout is an accepted
						// non-liveness outcome; skip it from the history (its
						// effect did not apply), matching the in-tree harness.
						continue
					}
					hist.add(op.Key, porcupine.Operation{ClientId: gi, Input: counterOp{}, Call: call, Output: n, Return: ret})
				}
			})
			if !completed {
				t.Fatalf("[%s] DEADLOCK: goroutines did not finish within %s (gorm tx)", w.Backend, deadlockTimeout)
			}

			checkAll(t, "gorm counter "+w.Backend, counterModel, hist)
			if sqlDB, err := w.DB.DB(); err == nil {
				assertSQLPoolDrained(t, sqlDB, "gorm "+w.Backend)
			}
		}
		if n, ok := schedfuzz.SettleGoroutines(baseGoroutines, goroutineSlack); !ok {
			t.Fatalf("GOROUTINE LEAK (gorm): %d goroutines, baseline %d (+%d slack)", n, baseGoroutines, goroutineSlack)
		}
	})
}
