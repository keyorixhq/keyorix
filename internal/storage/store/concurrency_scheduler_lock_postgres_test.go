package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises WithSchedulerLock's pg_try_advisory_lock (local_scheduler_lock.go)
// across genuinely independent connections — a single-connection test cannot
// say anything about it: pg_try_advisory_lock is scoped to the SESSION taking
// it, so one connection calling it twice would just re-acquire its own lock.
// This drives many independent LocalStorage instances (own *gorm.DB, own
// Postgres backend connection) at the SAME advisory-lock key concurrently:
// exactly one may run its job at a time, every other concurrent attempt must
// see the lock held and skip the tick (acquired=false) rather than running
// alongside the winner — the "only one replica runs this periodic job" ADR-039
// guarantee this function exists to provide.
func TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 8
	const key = 0x5343484544 // arbitrary, namespaced to this test

	stores := make([]*LocalStorage, instances)
	for i := 0; i < instances; i++ {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	var running int32
	var maxConcurrent int32
	var acquiredCount int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < instances; i++ {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			acquired, err := ls.WithSchedulerLock(context.Background(), key, func() error {
				n := atomic.AddInt32(&running, 1)
				for {
					m := atomic.LoadInt32(&maxConcurrent)
					if n <= m || atomic.CompareAndSwapInt32(&maxConcurrent, m, n) {
						break
					}
				}
				time.Sleep(150 * time.Millisecond) // hold the lock long enough for every racer to attempt while it's held
				atomic.AddInt32(&running, -1)
				return nil
			})
			require.NoError(t, err)
			if acquired {
				atomic.AddInt32(&acquiredCount, 1)
			}
		}(stores[i])
	}
	close(start) // release every instance's attempt at once
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&maxConcurrent), "at most one replica's job may run at a time")
	assert.Equal(t, int32(1), atomic.LoadInt32(&acquiredCount), "exactly one replica may win the advisory lock for this tick")
}

// TestConcurrency_SchedulerLockLease_MultiInstancePostgres exercises the
// row-based lease (local_scheduler_lock_lease.go) used by RemoteStorage's
// WithSchedulerLock, which is deliberately independent of the advisory-lock
// mechanism above — its own FOR UPDATE row lock, tested here the same way:
// genuinely independent connections, not one connection racing itself.
//
// Two properties, matching the task: (a) under concurrent contention on a
// BRAND-NEW key (never acquired before — the race that matters, and the one
// this test used to avoid), exactly one holder wins; (b) after the winner's
// lease TTL expires without renewal, a DIFFERENT holder can reclaim the SAME
// key — and at every point in between there is at most one lease row for
// that key, so no two holders are ever simultaneously valid.
//
// (a) used to seed the row with one uncontended acquire before racing
// contenders against it, deliberately avoiding a brand-new-key race: prior to
// the ON CONFLICT DO NOTHING fix (local_scheduler_lock_lease.go), a
// concurrent first-time INSERT's unique-constraint violation aborted the
// whole enclosing Postgres transaction, and the Go recovery code
// (`if isUniqueViolation(createErr) { return nil }`) never got a chance to
// run — GORM's COMMIT on the already-aborted transaction was silently
// downgraded to a ROLLBACK, surfacing as a caller-facing error instead of
// (false, nil). See this campaign's report for the original repro. Now that
// the conflict is prevented rather than caught, this races the brand-new key
// directly — that race is the acceptance criterion.
func TestConcurrency_SchedulerLockLease_MultiInstancePostgres(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.SchedulerLockLease{}))

	const instances = 8
	const key = 0x4C454153450 // arbitrary, namespaced to this test; never acquired before this race

	stores := make([]*LocalStorage, instances)
	for i := 0; i < instances; i++ {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	// (a) contention: every instance races to be the FIRST-EVER acquirer of
	// this key, with a distinct holder id. Exactly one may win; every other
	// attempt must return cleanly (false, nil) — none may error.
	var wonCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	winners := make(chan string, instances)
	for i := 0; i < instances; i++ {
		wg.Add(1)
		go func(idx int, ls *LocalStorage) {
			defer wg.Done()
			holder := "replica-" + string(rune('A'+idx))
			<-start
			acquired, err := ls.TryAcquireSchedulerLock(context.Background(), key, holder, 5*time.Second)
			require.NoError(t, err, "a losing racer on a brand-new key must return (false, nil), never an error")
			if acquired {
				atomic.AddInt32(&wonCount, 1)
				winners <- holder
			}
		}(i, stores[i])
	}
	close(start)
	wg.Wait()
	close(winners)

	assert.Equal(t, int32(1), atomic.LoadInt32(&wonCount), "exactly one of the eight racing first-time acquirers may win")
	require.Len(t, winners, 1)
	winner := <-winners

	verifier := NewLocalStorage(pgOpen(t, dsn))
	assertExactlyOneLease(t, verifier, key, winner)

	// (b) expiry handover: a SHORT-TTL lease from a fresh holder, left
	// unrenewed past expiry, must become reclaimable by a different holder —
	// and only by one at a time, same as above.
	const handoverKey = key + 1
	holderA := NewLocalStorage(pgOpen(t, dsn))
	acquiredA, err := holderA.TryAcquireSchedulerLock(context.Background(), handoverKey, "holder-A", 100*time.Millisecond)
	require.NoError(t, err)
	require.True(t, acquiredA)

	// While still valid, a different holder must be refused.
	holderB := NewLocalStorage(pgOpen(t, dsn))
	acquiredB, err := holderB.TryAcquireSchedulerLock(context.Background(), handoverKey, "holder-B", 5*time.Second)
	require.NoError(t, err)
	assert.False(t, acquiredB, "holder-B must not acquire while holder-A's lease is still valid")

	time.Sleep(200 * time.Millisecond) // past holder-A's 100ms TTL, never renewed (simulates a crashed replica)

	// Multiple late claimants race the now-expired lease; exactly one may
	// reclaim it.
	var reclaimWon int32
	var wg2 sync.WaitGroup
	claimants := []*LocalStorage{holderB, NewLocalStorage(pgOpen(t, dsn)), NewLocalStorage(pgOpen(t, dsn))}
	names := []string{"holder-B", "holder-C", "holder-D"}
	start2 := make(chan struct{})
	reclaimWinner := make(chan string, len(claimants))
	for i, ls := range claimants {
		wg2.Add(1)
		go func(idx int, ls *LocalStorage) {
			defer wg2.Done()
			<-start2
			ok, err := ls.TryAcquireSchedulerLock(context.Background(), handoverKey, names[idx], 5*time.Second)
			require.NoError(t, err)
			if ok {
				atomic.AddInt32(&reclaimWon, 1)
				reclaimWinner <- names[idx]
			}
		}(i, ls)
	}
	close(start2)
	wg2.Wait()
	close(reclaimWinner)

	assert.Equal(t, int32(1), atomic.LoadInt32(&reclaimWon), "exactly one late claimant may reclaim an expired lease")
	newHolder := <-reclaimWinner
	assertExactlyOneLease(t, verifier, handoverKey, newHolder)
}

// assertExactlyOneLease checks there is exactly one lease row for key and
// that its holder is exactly want — the structural check that no two
// holders are ever simultaneously valid for the same key.
func assertExactlyOneLease(t *testing.T, verifier *LocalStorage, key int64, want string) {
	t.Helper()
	var leases []models.SchedulerLockLease
	require.NoError(t, verifier.DB().Where("key = ?", key).Find(&leases).Error)
	require.Len(t, leases, 1, "exactly one lease row must exist for this key")
	assert.Equal(t, want, leases[0].Holder)
}
