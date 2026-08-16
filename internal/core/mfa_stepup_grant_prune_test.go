package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// store-mfa-002: CreateMFAStepUpGrant inserts a brand-new row on every
// successful VerifyMFAStepUp, and (before this fix) nothing ever pruned them —
// DeleteMFAStepUpGrantsFor existed but was only reachable via the
// RemoteStorage HTTP proxy, never called from a local maintenance path. These
// tests cover the new PruneMFAStepUpGrants sweep, mirroring rate_limit_test.go's
// TestPruneLoginAttempts_* coverage for the analogous LoginAttempt prune.

// TestPruneMFAStepUpGrants_RemovesOldRowsKeepsRecent exercises the real
// SQLite path (LocalStorage): a grant expired well past the retention window
// is removed; a grant that is still within the retention window (even though
// already expired — it's the retention window, not the active-grant window,
// that matters here) survives.
func TestPruneMFAStepUpGrants_RemovesOldRowsKeepsRecent(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	retention := 30 * 24 * time.Hour

	// Expired 40 days ago — older than the 30-day retention window, must be pruned.
	oldGrant := &models.MFAStepUpGrant{UserID: 1, ExpiresAt: fixed.Add(-40 * 24 * time.Hour)}
	require.NoError(t, db.Create(oldGrant).Error)

	// Expired 5 days ago — within the 30-day retention window, must survive.
	recentGrant := &models.MFAStepUpGrant{UserID: 1, ExpiresAt: fixed.Add(-5 * 24 * time.Hour)}
	require.NoError(t, db.Create(recentGrant).Error)

	removed, err := c.PruneMFAStepUpGrants(ctx, retention, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed, "only the row past the retention window is removed")

	var remaining []models.MFAStepUpGrant
	require.NoError(t, db.Find(&remaining).Error)
	require.Len(t, remaining, 1, "the within-window row must survive")
	assert.Equal(t, recentGrant.ID, remaining[0].ID)
}

// TestPruneMFAStepUpGrants_ZeroRetentionUsesDefault confirms retention<=0
// falls back to DefaultMFAStepUpGrantRetention (30 days) rather than pruning
// everything (e.g. a zero time.Duration must not mean "prune anything expired
// at all", which would defeat the "kept for audit purposes" design).
func TestPruneMFAStepUpGrants_ZeroRetentionUsesDefault(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	// Expired 1 day ago — well within even the shortest sane retention window.
	grant := &models.MFAStepUpGrant{UserID: 1, ExpiresAt: fixed.Add(-24 * time.Hour)}
	require.NoError(t, db.Create(grant).Error)

	removed, err := c.PruneMFAStepUpGrants(ctx, 0, time.Time{})
	require.NoError(t, err)
	assert.Zero(t, removed, "a recently-expired row must survive the default 30-day retention")

	var count int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// TestPruneMFAStepUpGrants_ClampsFutureBeforeToRetention is the
// store-mfa-002/CORE-RATE-003-shaped regression: a caller-supplied `before`
// LATER than now-retention (e.g. an attacker-influenced request body via the
// RemoteStorage proxy) must never widen the deletion window — the storage
// call underneath must always receive the clamped cutoff.
func TestPruneMFAStepUpGrants_ClampsFutureBeforeToRetention(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	retention := 30 * 24 * time.Hour
	maxCutoff := now.Add(-retention)
	attackerBefore := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	mockStore := new(MockStorage)
	mockStore.On("PruneMFAStepUpGrants", mock.Anything, maxCutoff).Return(int64(3), nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneMFAStepUpGrants(context.Background(), retention, attackerBefore)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneMFAStepUpGrants_NarrowerBeforeIsHonored confirms a caller CAN
// still narrow the deletion window below the retention-derived cutoff — only
// widening past it is blocked.
func TestPruneMFAStepUpGrants_NarrowerBeforeIsHonored(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	retention := 30 * 24 * time.Hour
	narrowerBefore := now.Add(-60 * 24 * time.Hour)

	mockStore := new(MockStorage)
	mockStore.On("PruneMFAStepUpGrants", mock.Anything, narrowerBefore).Return(int64(1), nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneMFAStepUpGrants(context.Background(), retention, narrowerBefore)
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneMFAStepUpGrants_NoAuditEventEmitted pins the deliberate design
// decision (see PruneMFAStepUpGrants's doc comment): unlike PruneLoginAttempts,
// a successful prune here does NOT write an audit event, because a grant
// row's CREATION is already permanently audited (mfa.stepup_verified) — the
// row itself is a redundant operational copy, not the sole evidentiary
// record. This guards against a future change reflexively bolting on an
// audit event without revisiting that reasoning.
func TestPruneMFAStepUpGrants_NoAuditEventEmitted(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	mockStore := new(MockStorage)
	mockStore.On("PruneMFAStepUpGrants", mock.Anything, mock.Anything).Return(int64(5), nil)
	// Deliberately no .On("LogAuditEvent", ...) expectation — AssertNotCalled below
	// enforces that it's never invoked.

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneMFAStepUpGrants(context.Background(), 0, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), removed)
	mockStore.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}
