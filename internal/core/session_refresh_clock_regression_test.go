// session_refresh_clock_regression_test.go — #1653 (follow-up to #1632):
// exploit-shaped test for RefreshSession's absolute-ceiling recheck.
// `!now.Before(*old.AbsoluteExpiresAt)` binds a fresh c.now() directly
// against a DB-loaded, non-renewable ceiling with no defense against a
// backward-stepped host clock — this reuses session_ttl_test.go's
// newSessionCore fixed-clock pattern, swapping c.now between calls to
// simulate the clock stepping backward mid-process.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestRefreshSession_ClockSteppedBackward_PastCeilingStaysRefused is the
// exploit-shaped test. Sequence:
//
//  1. At a baseline c.now() two hours past the session's absolute ceiling,
//     RefreshSession correctly refuses (the pre-existing ceiling check
//     fires) — and this warms checkSessionRefreshClockNotRegressed's
//     watermark to that baseline.
//  2. Step c.now() BACKWARD to 10 minutes BEFORE the ceiling (i.e., if
//     trusted naively, the pre-existing check `!now.Before(ceiling)` would
//     evaluate false and ALLOW the refresh) and call RefreshSession again
//     with the same session. Before this fix, the session refreshes past
//     its real absolute lifetime. After the fix, the regression guard
//     refuses before the ceiling check is ever reached.
func TestRefreshSession_ClockSteppedBackward_PastCeilingStaysRefused(t *testing.T) {
	store := new(MockStorage)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(time.Hour)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", AbsoluteExpiresAt: &ceiling}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("DeleteSession", mock.Anything, uint(7)).Return(nil)

	// Step 1: baseline, clearly past the ceiling — correctly refused, warms
	// the watermark.
	c.now = func() time.Time { return ceiling.Add(2 * time.Hour) }
	_, err := c.RefreshSession(context.Background(), "old")
	require.Error(t, err, "sanity: refresh must be refused at the baseline time before the clock ever moves")
	require.Contains(t, err.Error(), "re-authentication required")

	// Step 2: the exploit. Step c.now() BACKWARD to before the ceiling.
	c.now = func() time.Time { return ceiling.Add(-10 * time.Minute) }
	_, err = c.RefreshSession(context.Background(), "old")
	require.Error(t, err, "refresh must still be refused after the clock steps backward to before the ceiling")
	require.Contains(t, err.Error(), "re-authentication required")
}

// TestRefreshSession_ClockSteppedBackward_LegitimatelyWithinCeilingStillRefreshes
// is the positive control: a session well within its ceiling, refreshed
// after a SMALL in-tolerance backward step, must still succeed.
func TestRefreshSession_ClockSteppedBackward_LegitimatelyWithinCeilingStillRefreshes(t *testing.T) {
	store := new(MockStorage)
	captured := captureRotatedSession(store, 7)
	c := newSessionCore(store, 30*time.Minute, 12*time.Hour)

	ceiling := sessionTestNow.Add(8 * time.Hour)
	old := &models.Session{ID: 7, UserID: 1, SessionToken: "old", FamilyID: "fam-1", AbsoluteExpiresAt: &ceiling}
	store.On("GetSessionAny", mock.Anything, "old").Return(old, nil)
	store.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)

	c.now = func() time.Time { return sessionTestNow.Add(-1 * time.Second) }
	_, err := c.RefreshSession(context.Background(), "old")
	require.NoError(t, err, "a small in-tolerance backward step must not refuse a session well within its ceiling")
	require.NotNil(t, captured.AbsoluteExpiresAt)
}

// TestCheckSessionRefreshClockNotRegressed_FreshWatermarkNeverRefuses covers
// the zero-value watermark case directly.
func TestCheckSessionRefreshClockNotRegressed_FreshWatermarkNeverRefuses(t *testing.T) {
	c := &KeyorixCore{}
	err := c.checkSessionRefreshClockNotRegressed(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err, "an unset watermark must never itself cause a refusal")
}
