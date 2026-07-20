package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var quotaFixed = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func newQuotaCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return quotaFixed }}
}

func maxReadsPtr(n int) *int { return &n }

// TestQuotaUsagePct verifies the percentage helper across boundary values.
func TestQuotaUsagePct_ZeroMaxReads(t *testing.T) {
	assert.Equal(t, 0, QuotaUsagePct(50, 0))
}

func TestQuotaUsagePct_NegativeMaxReads(t *testing.T) {
	assert.Equal(t, 0, QuotaUsagePct(50, -1))
}

func TestQuotaUsagePct_Half(t *testing.T) {
	assert.Equal(t, 50, QuotaUsagePct(50, 100))
}

func TestQuotaUsagePct_NinetyFive(t *testing.T) {
	assert.Equal(t, 95, QuotaUsagePct(95, 100))
}

func TestQuotaUsagePct_Full(t *testing.T) {
	assert.Equal(t, 100, QuotaUsagePct(100, 100))
}

func TestQuotaUsagePct_Exceeds(t *testing.T) {
	// Capped at 100 even when readCount > maxReads.
	assert.Equal(t, 100, QuotaUsagePct(110, 100))
}

// TestCheckReadQuotas_NoSecretsWithQuota — empty result when storage returns none.
func TestCheckReadQuotas_NoSecretsWithQuota(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Checked)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
	assert.Equal(t, 0, result.Exhausted)
}

// TestCheckReadQuotas_BelowThreshold — 50% usage, no notification.
func TestCheckReadQuotas_BelowThreshold(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 1, Name: "low-usage", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 50, OwnerID: 10}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
	store.AssertNotCalled(t, "CreateNotification")
}

// TestCheckReadQuotas_AtWarningThreshold — 80% usage → Warning notification.
func TestCheckReadQuotas_AtWarningThreshold(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 2, Name: "warn-secret", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 80, OwnerID: 11}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(11), true, 200).Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 1, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
	assert.Equal(t, 0, result.Exhausted)
}

// TestCheckReadQuotas_AtCriticalThreshold — 95% usage → Critical notification.
func TestCheckReadQuotas_AtCriticalThreshold(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 3, Name: "crit-secret", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 95, OwnerID: 12}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(12), true, 200).Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 1, result.Criticals)
	assert.Equal(t, 0, result.Exhausted)
}

// TestCheckReadQuotas_Exhausted — 100% usage → Critical + Exhausted count.
func TestCheckReadQuotas_Exhausted(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 4, Name: "exhaust-secret", IsSecret: true,
		MaxReads: maxReadsPtr(10), ReadCount: 10, OwnerID: 13}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(13), true, 200).Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Checked)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 1, result.Criticals)
	assert.Equal(t, 1, result.Exhausted)
}

// TestCheckReadQuotas_DeduplicateSameSeverity — existing warning → skip.
func TestCheckReadQuotas_DeduplicateSameSeverity(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 5, Name: "dedup-secret", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 80, OwnerID: 14}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	existing := &models.Notification{
		ID:       99,
		Type:     NotificationReadQuotaWarning,
		Link:     "/secrets/5",
		Severity: models.NotificationSeverityWarning,
	}
	store.On("ListNotifications", ctx, uint(14), true, 200).
		Return([]*models.Notification{existing}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
	store.AssertNotCalled(t, "CreateNotification")
}

// TestCheckReadQuotas_EscalateWarningToCritical — existing warning, now 95% → upgrade.
func TestCheckReadQuotas_EscalateWarningToCritical(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 6, Name: "escalate-secret", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 95, OwnerID: 15}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	existing := &models.Notification{
		ID:       88,
		Type:     NotificationReadQuotaWarning,
		Link:     "/secrets/6",
		Severity: models.NotificationSeverityWarning,
	}
	store.On("ListNotifications", ctx, uint(15), true, 200).
		Return([]*models.Notification{existing}, nil)
	store.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 1, result.Criticals)
	store.AssertCalled(t, "UpdateNotification", ctx, mock.AnythingOfType("*models.Notification"))
}

// TestCheckReadQuotas_StorageError — propagates ListSecretsWithQuota error.
func TestCheckReadQuotas_StorageError(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	store.On("ListSecretsWithQuota", ctx).Return(nil, errors.New("db down"))

	_, err := c.CheckReadQuotas(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db down")
}

// TestCheckReadQuotas_ListNotificationsError — gracefully handles read error
// on dedup check by notifying (fail-open for notifications).
func TestCheckReadQuotas_ListNotificationsError(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 7, Name: "notif-err", IsSecret: true,
		MaxReads: maxReadsPtr(100), ReadCount: 80, OwnerID: 16}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(16), true, 200).
		Return(nil, errors.New("read error"))
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Warnings)
}

// TestCheckReadQuotas_ZeroOwnerSkipsNotification — ownerID=0 must not notify.
func TestCheckReadQuotas_ZeroOwnerSkipsNotification(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 8, Name: "no-owner", IsSecret: true,
		MaxReads: maxReadsPtr(10), ReadCount: 9, OwnerID: 0}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(0), true, 200).Return([]*models.Notification{}, nil)
	// notifyWithSeverity short-circuits on userID=0, so no CreateNotification is expected.

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	// Checked incremented, but no notification created (OwnerID=0).
	assert.Equal(t, 1, result.Checked)
	store.AssertNotCalled(t, "CreateNotification")
}

// TestCheckReadQuotas_NilMaxReadsSkipped — a secret returned by storage with nil
// MaxReads (defensive guard) must be skipped without panicking.
func TestCheckReadQuotas_NilMaxReadsSkipped(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	// MaxReads is nil — should be skipped (defensive path, storage shouldn't return this).
	secret := models.SecretNode{ID: 10, Name: "nil-max", IsSecret: true, ReadCount: 5, OwnerID: 18}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	// Nil MaxReads is skipped — checked stays 0.
	assert.Equal(t, 0, result.Checked)
	store.AssertNotCalled(t, "CreateNotification")
}

// TestListSecretsWithQuota_CorePassThrough — exercises the core method.
func TestListSecretsWithQuota_CorePassThrough(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	maxR := 5
	expected := []models.SecretNode{{ID: 1, MaxReads: &maxR, ReadCount: 3}}
	store.On("ListSecretsWithQuota", ctx).Return(expected, nil)

	got, err := c.ListSecretsWithQuota(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, uint(1), got[0].ID)
}

// TestCheckReadQuotas_ExhaustedOverMaxReads — ReadCount > MaxReads still caps at 100%.
func TestCheckReadQuotas_ExhaustedOverMaxReads(t *testing.T) {
	store := new(MockStorage)
	c := newQuotaCore(store)
	ctx := context.Background()

	secret := models.SecretNode{ID: 9, Name: "over-secret", IsSecret: true,
		MaxReads: maxReadsPtr(5), ReadCount: 7, OwnerID: 17}
	store.On("ListSecretsWithQuota", ctx).Return([]models.SecretNode{secret}, nil)
	store.On("ListNotifications", ctx, uint(17), true, 200).Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckReadQuotas(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Criticals)
	assert.Equal(t, 1, result.Exhausted)
}
