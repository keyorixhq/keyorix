// consume_clock_monotonic_strip_test.go — Part 2 regression audit
// continuation (2026-09-04): consumeClockLooksRegressed (entry.go, #1638)
// compared its `now` argument directly against consumeClockWatermark, with
// no monotonic-clock-reading strip. See internal/core's
// clock_watermark_monotonic_strip_test.go for the full explanation of why
// this defeats the regression check entirely in production (both operands
// carry a monotonic reading from real time.Now() calls, so Before/After use
// ONLY the monotonic delta -- which never regresses even when the OS wall
// clock is stepped backward) and why the existing time.Date(...)-based
// tests in this package could never have caught it (time.Date never
// attaches a monotonic reading, so those tests always exercised a
// wall-clock-only comparison regardless of what the production code did).
package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hasMonotonicReading(t time.Time) bool {
	return strings.Contains(t.String(), " m=")
}

// TestConsumeClockLooksRegressed_StripsMonotonicReading proves the fix: a
// real, monotonic-carrying time.Now() reading, once processed by
// consumeClockLooksRegressed, is stored into consumeClockWatermark without
// a monotonic reading -- so the NEXT call's regression check is a genuine
// wall-clock comparison.
func TestConsumeClockLooksRegressed_StripsMonotonicReading(t *testing.T) {
	real := time.Now()
	require.True(t, hasMonotonicReading(real), "sanity: the input this test feeds through consumeClockLooksRegressed must itself carry a monotonic reading")

	ls := &LocalStorage{consumeClockWatermark: &clockWatermark{}}
	regressed := ls.consumeClockLooksRegressed(real)
	require.False(t, regressed, "a fresh watermark (zero value) must never itself report a regression")
	assert.False(t, hasMonotonicReading(ls.consumeClockWatermark.time), "consumeClockWatermark's stored value must not carry a monotonic reading")
}
