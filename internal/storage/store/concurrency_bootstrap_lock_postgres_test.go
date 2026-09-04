package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_WithBootstrapLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises local_bootstrap_lock.go's pg_advisory_lock across genuinely
// independent connections, the same way
// TestConcurrency_WithAuditCheckpointLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises its sibling lock: many independent LocalStorage instances (own
// *gorm.DB, own Postgres backend connection) racing BootstrapSystem's
// check-then-create sequence. A single-connection test (see
// TestWithBootstrapLock_SerializesConcurrentCallers in local_bootstrap_lock_test.go)
// only proves the process-local ls.bootstrapMu works — it can't say anything
// about the pg_advisory_lock branch, which is the ONLY thing serializing two
// different replica PROCESSES (two independent *gorm.DB connections) racing
// POST /system/init against the same shared database (#core-auth-03). Like
// WithAuditCheckpointLock (and unlike WithSchedulerLock), WithBootstrapLock
// BLOCKS until it acquires the lock rather than skipping on contention, so
// every racer here is expected to eventually run fn — the assertion is that
// none of them ever run it concurrently with another.
func TestConcurrency_WithBootstrapLock_MultiInstancePostgres_ExactlyOneRunsAtOnce(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 8

	stores := make([]*LocalStorage, instances)
	for i := 0; i < instances; i++ {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	var running int32
	var maxConcurrent int32
	var completed int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < instances; i++ {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			err := ls.WithBootstrapLock(context.Background(), func() error {
				n := atomic.AddInt32(&running, 1)
				for {
					m := atomic.LoadInt32(&maxConcurrent)
					if n <= m || atomic.CompareAndSwapInt32(&maxConcurrent, m, n) {
						break
					}
				}
				time.Sleep(75 * time.Millisecond) // hold the lock long enough for every racer to attempt while it's held
				atomic.AddInt32(&running, -1)
				return nil
			})
			require.NoError(t, err)
			atomic.AddInt32(&completed, 1)
		}(stores[i])
	}
	close(start) // release every instance's attempt at once
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&maxConcurrent),
		"at most one replica's bootstrap check-then-create critical section may run at a time")
	assert.Equal(t, int32(instances), atomic.LoadInt32(&completed),
		"WithBootstrapLock blocks rather than skips, so every racer must eventually run fn")
}

// TestConcurrency_WithBootstrapLock_MultiInstancePostgres_ErrorStillReleases
// confirms a losing racer isn't permanently blocked behind a winner whose fn
// returned an error: the advisory lock (and the pooled connection carrying
// it) must still be released via the deferred pg_advisory_unlock/Close even
// on the error path, or every subsequent replica attempting to bootstrap
// would hang forever after the first bootstrap attempt fails.
func TestConcurrency_WithBootstrapLock_MultiInstancePostgres_ErrorStillReleases(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	first := NewLocalStorage(pgOpen(t, dsn))
	sentinel := assert.AnError
	err := first.WithBootstrapLock(context.Background(), func() error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	second := NewLocalStorage(pgOpen(t, dsn))
	ran := false
	done := make(chan error, 1)
	go func() {
		done <- second.WithBootstrapLock(context.Background(), func() error {
			ran = true
			return nil
		})
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("second replica's WithBootstrapLock never returned — the first racer's error left the advisory lock held")
	}
	assert.True(t, ran, "the second replica must be able to acquire and run after the first racer's fn errored")
}
