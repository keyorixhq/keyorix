// connect_clock_regression_test.go — #1653 (follow-up to #1632): exploit-shaped
// tests for Connect ref-grant resolution's defense against a backward-stepped
// host clock. connectRefAllowed/connectRefGrantDelegates/
// connectorHasAnyDelegationForActor read time.Now() internally (via
// connectEffectiveNow) rather than accepting it as a parameter, so — same
// technique as the RBAC cluster's own regression test (#1651) — this seeds
// connectClockWatermark directly (an unexported field, accessible from this
// package) to simulate "this process has already observed a later real
// time," then calls the real, unmodified connectRefAllowed.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectRefAllowed_ClockSteppedBackward_ExpiredGrantStaysDenied is the
// exploit-shaped test: a ConnectRefGrant whose ExpiresAt already elapsed
// relative to a time this process has previously observed must not be
// resurrected merely because the real time.Now() reading right now looks
// earlier than that watermark.
func TestConnectRefAllowed_ClockSteppedBackward_ExpiredGrantStaysDenied(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "temp-reader")
	seedConnectPlatformUsePermission(t, db, 5)

	future := time.Now().Add(24 * time.Hour)
	c.connectClockWatermark = future

	// Genuinely expired relative to the watermark, but NOT expired relative
	// to the real, un-mocked time.Now() this test actually runs at.
	expiry := time.Now().Add(time.Hour)
	seedGrantExpiring(t, c, 5, "aws", "metrics/", expiry)

	ok, err := c.connectRefAllowed(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.False(t, ok, "a grant already expired relative to a time this process has previously observed must not be resurrected by a real clock reading that looks earlier")
}

// TestConnectRefAllowed_ClockSteppedBackward_LegitimatelyLiveGrantStillAllowed
// is the positive control: a grant genuinely still live even past the
// watermark must still authorize normally.
func TestConnectRefAllowed_ClockSteppedBackward_LegitimatelyLiveGrantStillAllowed(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "temp-reader")
	seedConnectPlatformUsePermission(t, db, 5)

	future := time.Now().Add(24 * time.Hour)
	c.connectClockWatermark = future

	stillLive := future.Add(24 * time.Hour)
	seedGrantExpiring(t, c, 5, "aws", "metrics/", stillLive)

	ok, err := c.connectRefAllowed(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.True(t, ok, "a grant genuinely live past the watermark must still authorize")
}

// TestConnectEffectiveNow_ClampsBackwardReadingToWatermark is a direct unit
// test of the clamp itself.
func TestConnectEffectiveNow_ClampsBackwardReadingToWatermark(t *testing.T) {
	c := &KeyorixCore{now: time.Now}
	watermark := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c.connectClockWatermark = watermark

	c.now = func() time.Time { return watermark.Add(-time.Hour) }
	assert.Equal(t, watermark, c.connectEffectiveNow(), "a backward-looking reading must clamp up to the watermark")

	forward := watermark.Add(time.Hour)
	c.now = func() time.Time { return forward }
	assert.Equal(t, forward, c.connectEffectiveNow(), "a forward reading must pass through unchanged and advance the watermark")
	assert.Equal(t, forward, c.connectClockWatermark)
}
