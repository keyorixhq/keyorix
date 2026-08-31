// rbac_clock_regression_test.go — #1632: exploit-shaped tests for the RBAC
// permission-resolution cluster's defense against a backward-stepped host
// clock. Unlike ConsumeMFAChallenge/ConsumeWebAuthnSession, the functions in
// local_rbac.go do not take `now` as a parameter — they read the OS clock
// directly via time.Now(), which a test cannot move backward. Instead, these
// tests seed rbacClockWatermark directly (an unexported field, accessible
// from this package) to simulate "this process has already legitimately
// observed a later real time" — exactly the state a genuinely-running
// process would be in right before an operator or NTP correction steps its
// OS clock backward — then call the real, unmodified function (which still
// reads the real, un-mocked time.Now()) and assert the clamp still refuses
// to treat an already-expired-relative-to-that-later-time grant as live.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestGetUserRoles_ClockSteppedBackward_ExpiredGrantStaysExpired is the
// exploit-shaped test: a UserRole grant whose ExpiresAt already elapsed
// relative to a time this process has previously observed (the watermark)
// must not be resurrected merely because the real time.Now() reading right
// now looks earlier than that watermark — the actual backward-clock shape a
// host clock rollback produces.
//
// Before the fix (bare time.Now(), no clamp): GetUserRoles would evaluate
// expires_at > real-now, which is TRUE for a grant expiring between real-now
// and the watermark — the role wrongly still resolves. After the fix:
// rbacEffectiveNow clamps the comparison up to the watermark, correctly
// excluding it.
func TestGetUserRoles_ClockSteppedBackward_ExpiredGrantStaysExpired(t *testing.T) {
	ls := newS27bStore(t, &models.Role{}, &models.UserRole{})
	ctx := context.Background()

	// Simulate this process having already legitimately observed a later
	// real time (as it would have, running continuously, right before an
	// operator/NTP correction stepped the host clock backward).
	future := time.Now().UTC().Add(24 * time.Hour)
	ls.rbacClockWatermark.time = future

	// Genuinely expired relative to the watermark (future), but NOT expired
	// relative to the real, un-mocked time.Now() this test actually runs at.
	expiry := time.Now().UTC().Add(time.Hour)
	require.NoError(t, ls.db.Create(&models.Role{ID: 1, Name: "rbac-clock-regression-role"}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 42, RoleID: 1, ExpiresAt: &expiry}).Error)

	roles, err := ls.GetUserRoles(ctx, 42)
	require.NoError(t, err)
	assert.Empty(t, roles, "a grant already expired relative to a time this process has previously observed must not be resurrected by a real clock reading that looks earlier")
}

// TestGetUserRoles_ClockSteppedBackward_LegitimatelyLiveGrantStillResolves is
// the positive control: a grant that is genuinely still live even relative
// to the watermark (i.e., not exploiting anything) must still resolve
// normally — the clamp must not become a blanket denial.
func TestGetUserRoles_ClockSteppedBackward_LegitimatelyLiveGrantStillResolves(t *testing.T) {
	ls := newS27bStore(t, &models.Role{}, &models.UserRole{})
	ctx := context.Background()

	future := time.Now().UTC().Add(24 * time.Hour)
	ls.rbacClockWatermark.time = future

	stillLive := future.Add(24 * time.Hour) // live even past the watermark
	require.NoError(t, ls.db.Create(&models.Role{ID: 1, Name: "rbac-clock-regression-control"}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 43, RoleID: 1, ExpiresAt: &stillLive}).Error)

	roles, err := ls.GetUserRoles(ctx, 43)
	require.NoError(t, err)
	require.Len(t, roles, 1, "a grant genuinely live past the watermark must still resolve")
	assert.Equal(t, uint(1), roles[0].ID)
}

// TestRbacEffectiveNow_ClampsBackwardReadingToWatermark is a direct unit
// test of the clamp itself: a now earlier than the watermark returns the
// watermark, unchanged; a now at or after the watermark returns now and
// advances the watermark.
func TestRbacEffectiveNow_ClampsBackwardReadingToWatermark(t *testing.T) {
	ls := newS27bStore(t)

	watermark := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	ls.rbacClockWatermark.time = watermark

	backward := watermark.Add(-time.Hour)
	assert.Equal(t, watermark, ls.rbacEffectiveNow(backward), "a backward-looking reading must clamp up to the watermark, not pass through unchanged")

	forward := watermark.Add(time.Hour)
	assert.Equal(t, forward, ls.rbacEffectiveNow(forward), "a forward reading must pass through unchanged")
	assert.Equal(t, forward, ls.rbacClockWatermark.time, "a forward reading must advance the watermark")
}

// TestRbacEffectiveNow_FreshWatermarkNeverClampsForward covers the
// zero-value watermark case: a fresh LocalStorage (no prior RBAC query has
// ever run) must let the very first real time.Now() reading through
// unclamped.
func TestRbacEffectiveNow_FreshWatermarkNeverClampsForward(t *testing.T) {
	ls := newS27bStore(t)
	now := time.Now().UTC()
	assert.Equal(t, now, ls.rbacEffectiveNow(now), "an unset watermark must never clamp the first real reading")
}
