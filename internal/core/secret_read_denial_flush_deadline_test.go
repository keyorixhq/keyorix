package core

// secret_read_denial_flush_deadline_test.go — #3602: flushing the open
// aggregation windows stops at the caller's deadline, even when a write is
// stuck, and reports how many summary rows were not written.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretReadDenialFlushAll_StuckWriteStopsAtDeadlineAndCountsUnwritten(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	agg := newDenialAggregator(time.Hour, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, func(denialRow) { <-stuck })
	const keys = 3
	for target := range uint(keys) {
		d := testDenial(1, SecretReadDeniedForbidden, 100+target)
		// The first of each key is due at once (written by the caller); the
		// second opens the summary that flushAll owes.
		agg.admit(d, time.Now())
		agg.admit(d, time.Now())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	unwritten := agg.flushAll(ctx)
	assert.Less(t, time.Since(start), 5*time.Second, "a stuck write must not hold the caller past its deadline")
	assert.Equal(t, keys, unwritten, "the in-flight row and the ones never started are all unwritten")
}

func TestSecretReadDenialFlushAll_AllWrittenReportsZero(t *testing.T) {
	var written int
	agg := newDenialAggregator(time.Hour, secretReadDenialPrincipalKeys, secretReadDenialMaxKeys, func(denialRow) { written++ })
	for range 4 {
		agg.admit(testDenial(1, SecretReadDeniedForbidden, 7), time.Now())
	}
	require.Equal(t, 0, written)
	assert.Equal(t, 0, agg.flushAll(context.Background()))
	assert.Equal(t, 1, written, "one summary row for the open window")
}
