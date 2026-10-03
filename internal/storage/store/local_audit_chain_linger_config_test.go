// local_audit_chain_linger_config_test.go — coordinator review on #2420:
// linger defaults to 0 but stays configurable via
// LocalStorage.SetAuditFlusherLingerWindow (wired from
// config.DatabaseConfig.GetAuditFlusherLingerWindow in production). These
// tests exercise the REAL flusher goroutine end-to-end (unlike
// local_audit_chain_batch_isolation_test.go's direct commitAuditBatch
// calls, which bypass the queue/timer entirely) to prove the configured
// value actually changes its behavior.
package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestAuditFlusher_DefaultLingerIsZero_NoDeliberateWait confirms a
// freshly-constructed LocalStorage (no SetAuditFlusherLingerWindow call)
// lingers for zero time: two SEQUENTIAL submissions, the second one not
// started until the first has fully returned, must land in two separate
// flushes (there is nothing to batch sequentially-arriving items into
// without a deliberate wait).
func TestAuditFlusher_DefaultLingerIsZero_NoDeliberateWait(t *testing.T) {
	ls := newAuditChainTestStore(t)
	before := testutil.ToFloat64(auditFlushesTotal)

	appendEvent(t, ls, "secret.read", "first", time.Now().UTC())
	appendEvent(t, ls, "secret.read", "second", time.Now().UTC())

	flushes := testutil.ToFloat64(auditFlushesTotal) - before
	assert.Equal(t, float64(2), flushes, "with no configured linger, two sequential submissions must NOT be coalesced into one flush")
}

// TestAuditFlusher_ConfiguredLingerCoalescesConcurrentSubmissions confirms
// that SetAuditFlusherLingerWindow with a generous window lets two
// CONCURRENT submissions (the second arriving while the flusher is already
// waiting on the first) land in the SAME flush — the behavior the
// coordinator asked to keep available, just opt-in rather than default.
func TestAuditFlusher_ConfiguredLingerCoalescesConcurrentSubmissions(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ls.SetAuditFlusherLingerWindow(200 * time.Millisecond)
	ctx := context.Background()
	before := testutil.ToFloat64(auditFlushesTotal)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Description: "concurrent-1", EventTime: time.Now().UTC(), ActorType: "user",
		}))
	}()
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond) // start well inside the 200ms linger window
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Description: "concurrent-2", EventTime: time.Now().UTC(), ActorType: "user",
		}))
	}()
	wg.Wait()

	flushes := testutil.ToFloat64(auditFlushesTotal) - before
	assert.Equal(t, float64(1), flushes, "with a configured linger window, two concurrent submissions must be coalesced into ONE flush")

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid)
	assert.Equal(t, int64(2), v.ChainedEvents)
}
