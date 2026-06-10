package core

import (
	"context"
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
