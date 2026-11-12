package core

import (
	"time"
)

// beforeAMayBlock is beforeA for a race whose fix is a lock that replica B's
// operation shares with A's: run synchronously inside A's hook, B would wait
// on the lock A holds while A waits on the hook, and the test would hang. So
// B starts in a goroutine and the hook returns as soon as B either finishes
// (no shared lock: B commits inside A's window, the unfixed interleaving) or
// Postgres reports a backend waiting on a lock (B is blocked behind A and
// will run once A releases). The caller must call waitB after A's operation
// returns, before reading B's result.
//
// The lock-wait probe counts only the fixture's own backends (application_name),
// so a parallel test's or another package's waiter cannot make the hook return
// before B has reached the lock and hide a red run.
func (f *ctaReview) beforeAMayBlock(kind, table string, concurrent func()) (fired func() bool, waitB func()) {
	f.t.Helper()
	done := make(chan struct{})
	started := false
	fired = f.beforeA(kind, table, func() {
		started = true
		go func() {
			defer close(done)
			concurrent()
		}()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				return
			default:
			}
			if f.lockWaiters() > 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return fired, func() {
		if started {
			<-done
		}
	}
}
