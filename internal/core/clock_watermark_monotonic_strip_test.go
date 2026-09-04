// clock_watermark_monotonic_strip_test.go — Part 2 regression audit
// continuation (2026-09-04): every clock-regression watermark in this
// package (and its internal/storage/store sibling) compared its `now`
// argument directly, without stripping a monotonic clock reading first.
//
// This matters because Go's time.Time carries an OPTIONAL monotonic reading
// alongside its wall-clock reading whenever it comes from a real time.Now()
// call (never from time.Date(...), time.Parse, or a DB round-trip). When
// BOTH operands of a Before/After/Sub comparison carry a monotonic reading,
// Go uses ONLY the monotonic delta — which tracks elapsed real time since an
// arbitrary reference point and is, by construction, immune to the OS wall
// clock being stepped backward (an NTP correction, or an operator running
// `date -s`). So a watermark comparison built from two real time.Now()
// values NEVER detects the exact "host clock stepped backward" condition
// every one of these mechanisms exists to catch — it silently degrades to
// "did more real time elapse," which is always true.
//
// This is NOT reproducible with the existing time.Date(...)-based tests
// throughout this package (TestGetSecretValue_ClockSteppedBackward*, etc.):
// time.Date never attaches a monotonic reading in the first place (the
// stdlib docs guarantee it), so those tests exercise wall-clock-only
// comparisons regardless of whether the production code strips monotonic —
// passing either way, which is exactly how this bug shipped undetected
// across #1632/#1638/#1651/#1653's entire wave. Actually reproducing a live
// OS clock step is neither safe nor appropriate for a unit test, so this
// file instead directly verifies the documented, testable contract the fix
// relies on: time.Time.String() includes a "m=" monotonic-reading suffix
// if and only if the value still carries one (see time.Time's package doc,
// "Note that the Go == operator compares... consider t.Format(RFC3339Nano)"
// section). A real time.Now() value must show it; a value threaded through
// any of the fixed effectiveNow-style helpers below must not.
package core

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hasMonotonicReading reports whether t carries a monotonic clock reading,
// via the documented String() contract (time.Time package doc).
func hasMonotonicReading(t time.Time) bool {
	return strings.Contains(t.String(), " m=")
}

// TestRealTimeNow_CarriesMonotonicReading is the calibration check: confirms
// this Go runtime's time.Now() actually attaches a monotonic reading, so the
// tests below are exercising the real hazard, not a no-op on a platform
// where it never applied.
func TestRealTimeNow_CarriesMonotonicReading(t *testing.T) {
	require.True(t, hasMonotonicReading(time.Now()), "calibration: time.Now() must carry a monotonic reading for these tests to mean anything")
}

// TestDateConstructedTime_NeverCarriesMonotonicReading is the other half of
// the calibration: confirms time.Date(...) (what every existing
// ClockSteppedBackward-style test in this package injects via c.now)
// structurally CANNOT reproduce this bug class, explaining why those tests
// passed throughout even while the production code was broken.
func TestDateConstructedTime_NeverCarriesMonotonicReading(t *testing.T) {
	require.False(t, hasMonotonicReading(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
}

// TestAuthEffectiveNow_StripsMonotonicReading proves the actual fix: a real,
// monotonic-carrying time.Now() reading, once round-tripped through
// authEffectiveNow, no longer carries one -- so a LATER comparison against
// this same returned value (by any caller, including a second call to
// authEffectiveNow itself) is a genuine wall-clock comparison, capable of
// observing a backward OS clock step.
func TestAuthEffectiveNow_StripsMonotonicReading(t *testing.T) {
	c := &KeyorixCore{now: time.Now}
	real := time.Now()
	require.True(t, hasMonotonicReading(real), "sanity: the input this test feeds through c.now must itself carry a monotonic reading")

	got := c.authEffectiveNow()
	assert.False(t, hasMonotonicReading(got), "authEffectiveNow's returned/stored watermark value must not carry a monotonic reading -- an unstripped one would make the NEXT call's regression check compare monotonic deltas instead of wall-clock time, silently never detecting a backward OS clock step")
}

// TestCheckSecretExpiryClockNotRegressed_StripsMonotonicReading is the same
// proof for #1635's actual named target.
func TestCheckSecretExpiryClockNotRegressed_StripsMonotonicReading(t *testing.T) {
	c := &KeyorixCore{}
	require.NoError(t, c.checkSecretExpiryClockNotRegressed(time.Now()))
	assert.False(t, hasMonotonicReading(c.secretExpiryWatermark), "secretExpiryWatermark must be stored without a monotonic reading")
}

// #1638's actual named target (consumeClockLooksRegressed) is unexported on
// LocalStorage in internal/storage/store -- see
// internal/storage/store/consume_clock_monotonic_strip_test.go for its
// equivalent proof, same technique, different package.

// TestConnectShareOIDCEffectiveNow_StripMonotonicReading covers the
// remaining #1653-wave clamp mechanisms (connectEffectiveNow,
// shareEffectiveNow, OIDCVerifier.effectiveNow) in one pass -- same proof,
// same reason, applied to each.
func TestConnectShareOIDCEffectiveNow_StripMonotonicReading(t *testing.T) {
	t.Run("connectEffectiveNow", func(t *testing.T) {
		c := &KeyorixCore{now: time.Now}
		got := c.connectEffectiveNow()
		assert.False(t, hasMonotonicReading(got))
	})
	t.Run("shareEffectiveNow", func(t *testing.T) {
		c := &KeyorixCore{now: time.Now}
		got := c.shareEffectiveNow()
		assert.False(t, hasMonotonicReading(got))
	})
	t.Run("OIDCVerifier.effectiveNow", func(t *testing.T) {
		v := &OIDCVerifier{now: time.Now}
		got := v.effectiveNow()
		assert.False(t, hasMonotonicReading(got))
	})
}

// TestSessionRefreshAndAccessRequestApprovalClockChecks_StripMonotonicReading
// covers the two REFUSE-shaped (#1653) mechanisms.
func TestSessionRefreshAndAccessRequestApprovalClockChecks_StripMonotonicReading(t *testing.T) {
	// Neither function under test calls i18n.T (both return a plain
	// fmt.Errorf), so no i18n init/reset is needed here -- deliberately
	// avoided to not add another instance of the pre-existing i18n global-
	// singleton test-isolation gap other tests in this package already
	// document (secret_value_clock_regression_test.go's newClockRegressionCore).
	t.Run("checkSessionRefreshClockNotRegressed", func(t *testing.T) {
		c := &KeyorixCore{}
		require.NoError(t, c.checkSessionRefreshClockNotRegressed(time.Now()))
		assert.False(t, hasMonotonicReading(c.sessionRefreshWatermark))
	})
	t.Run("checkAccessRequestApprovalClockNotRegressed", func(t *testing.T) {
		c := &KeyorixCore{}
		require.NoError(t, c.checkAccessRequestApprovalClockNotRegressed(time.Now()))
		assert.False(t, hasMonotonicReading(c.accessRequestApprovalWatermark))
	})
}
