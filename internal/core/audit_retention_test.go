package core

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuditRetentionCoverage_MeetsNIS2(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	oldest := fixed.AddDate(0, 0, -400) // 400d back → > 365
	newest := fixed.AddDate(0, 0, -1)

	store := new(MockStorage)
	store.On("AuditRetentionStats", mock.Anything).Return(&storage.AuditRetentionStats{
		TotalEvents: 12345, Oldest: &oldest, Newest: &newest,
	}, nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	cov, err := c.AuditRetentionCoverage(context.Background())
	require.NoError(t, err)
	require.Equal(t, RetentionPolicyUnlimited, cov.RetentionPolicy)
	require.Equal(t, int64(12345), cov.TotalEvents)
	require.Equal(t, 400, cov.CoverageDays)
	require.True(t, cov.MeetsNIS2TwelveMonth, "400 days of history covers the 12-month window")
	require.Equal(t, &oldest, cov.OldestEvent)
	require.Equal(t, &newest, cov.NewestEvent)
}

func TestAuditRetentionCoverage_YoungDeployment(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	oldest := fixed.AddDate(0, 0, -100) // only 100d of history

	store := new(MockStorage)
	store.On("AuditRetentionStats", mock.Anything).Return(&storage.AuditRetentionStats{
		TotalEvents: 50, Oldest: &oldest, Newest: &fixed,
	}, nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	cov, err := c.AuditRetentionCoverage(context.Background())
	require.NoError(t, err)
	require.Equal(t, 100, cov.CoverageDays)
	require.False(t, cov.MeetsNIS2TwelveMonth, "< 365 days of history yet")
	// Policy is still unlimited regardless of how young the deployment is.
	require.Equal(t, RetentionPolicyUnlimited, cov.RetentionPolicy)
}

func TestVerifyAuditChain_PassesThrough(t *testing.T) {
	brokenID := uint(42)
	store := new(MockStorage)
	store.On("VerifyAuditChain", mock.Anything).Return(&storage.AuditChainVerification{
		Valid: false, ChainedEvents: 41, FirstBrokenID: &brokenID, Reason: "event modified",
	}, nil)

	c := NewKeyorixCore(store)
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	require.False(t, v.Valid)
	require.Equal(t, &brokenID, v.FirstBrokenID)
	require.Equal(t, "event modified", v.Reason)
}

func TestAuditRetentionCoverage_Empty(t *testing.T) {
	store := new(MockStorage)
	store.On("AuditRetentionStats", mock.Anything).Return(&storage.AuditRetentionStats{
		TotalEvents: 0, Oldest: nil, Newest: nil,
	}, nil)

	c := NewKeyorixCore(store)

	cov, err := c.AuditRetentionCoverage(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(0), cov.TotalEvents)
	require.Equal(t, 0, cov.CoverageDays)
	require.False(t, cov.MeetsNIS2TwelveMonth)
	require.Nil(t, cov.OldestEvent)
	require.Equal(t, RetentionPolicyUnlimited, cov.RetentionPolicy)
}

// TestAuditRetentionCoverage_FutureOldest covers the defensive `days < 0 → 0`
// clamp in AuditRetentionCoverage when the oldest recorded event has a timestamp
// in the future relative to `now` (clock skew / test-clock edge case).
func TestAuditRetentionCoverage_FutureOldest(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// oldest is 1 day in the future relative to the fixed clock.
	oldest := fixed.Add(24 * time.Hour)

	ms := new(MockStorage)
	ms.On("AuditRetentionStats", mock.Anything).Return(&storage.AuditRetentionStats{
		TotalEvents: 1, Oldest: &oldest, Newest: &oldest,
	}, nil)

	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return fixed }

	cov, err := c.AuditRetentionCoverage(context.Background())
	require.NoError(t, err)
	// days would be negative without the clamp; it must be floored to 0.
	require.Equal(t, 0, cov.CoverageDays, "negative coverage days must be clamped to zero")
	require.False(t, cov.MeetsNIS2TwelveMonth)
	require.Equal(t, RetentionPolicyUnlimited, cov.RetentionPolicy)
}

// TestVerifyAuditChain_CheckpointEnforceError covers the error path inside
// VerifyAuditChain when enforceAuditCheckpoint returns an error. This requires a
// configured checkpoint key (so AuditCheckpointsAvailable() is true) and a
// storage failure in GetSystemMetadata (the high-water read inside
// enforceAuditHighWater).
func TestVerifyAuditChain_CheckpointEnforceError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("VerifyAuditChain", mock.Anything).Return(&storage.AuditChainVerification{
		Valid: true, ChainedEvents: 5,
	}, nil)
	// GetSystemMetadata is called by auditHighWaterFloor inside enforceAuditHighWater.
	ms.On("GetSystemMetadata", mock.Anything, mock.Anything).
		Return("", false, errors.New("metadata store unavailable"))

	c := NewKeyorixCore(ms)
	// Wire a non-empty key so AuditCheckpointsAvailable() returns true.
	c.SetAuditCheckpointKey(bytes.Repeat([]byte{0xAB}, 32), "v1")

	_, err := c.VerifyAuditChain(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify audit checkpoint")
}
