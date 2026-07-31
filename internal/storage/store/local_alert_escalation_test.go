package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newAlertEscalationTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AlertEscalationPolicy{}, &models.AnomalyAlert{}))
	return NewLocalStorage(db)
}

func TestAlertEscalationPolicy_CRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	p := &models.AlertEscalationPolicy{
		Name:                 "test-policy",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 30,
		ChannelIDs:           "1,2",
		Enabled:              true,
		CreatedBy:            1,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
	}

	// Create
	require.NoError(t, ls.CreateAlertEscalationPolicy(ctx, p))
	assert.NotZero(t, p.ID)

	// Get
	got, err := ls.GetAlertEscalationPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-policy", got.Name)
	assert.Equal(t, "medium", got.MinSeverity)
	assert.Equal(t, 30, got.EscalateAfterMinutes)
	assert.Equal(t, "1,2", got.ChannelIDs)
	assert.True(t, got.Enabled)

	// List
	policies, err := ls.ListAlertEscalationPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, policies, 1)

	// Update
	got.Name = "updated-policy"
	got.MinSeverity = "high"
	got.EscalateAfterMinutes = 60
	got.ChannelIDs = "3"
	got.Enabled = false
	got.UpdatedAt = time.Now().UTC()
	require.NoError(t, ls.UpdateAlertEscalationPolicy(ctx, got))

	updated, err := ls.GetAlertEscalationPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-policy", updated.Name)
	assert.Equal(t, "high", updated.MinSeverity)
	assert.Equal(t, 60, updated.EscalateAfterMinutes)
	assert.Equal(t, "3", updated.ChannelIDs)
	assert.False(t, updated.Enabled)

	// Delete
	require.NoError(t, ls.DeleteAlertEscalationPolicy(ctx, p.ID))
	_, err = ls.GetAlertEscalationPolicy(ctx, p.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// List returns empty after delete
	policies, err = ls.ListAlertEscalationPolicies(ctx)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestAlertEscalationPolicy_UniqueNameConstraint(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	p1 := &models.AlertEscalationPolicy{
		Name:                 "dup-name",
		MinSeverity:          "low",
		EscalateAfterMinutes: 15,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
	}
	require.NoError(t, ls.CreateAlertEscalationPolicy(ctx, p1))

	p2 := &models.AlertEscalationPolicy{
		Name:                 "dup-name",
		MinSeverity:          "medium",
		EscalateAfterMinutes: 30,
		CreatedAt:            time.Now().UTC(),
		UpdatedAt:            time.Now().UTC(),
	}
	err := ls.CreateAlertEscalationPolicy(ctx, p2)
	require.Error(t, err)
}

func TestAlertEscalationPolicy_GetNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	_, err := ls.GetAlertEscalationPolicy(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAlertEscalationPolicy_UpdateNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	p := &models.AlertEscalationPolicy{
		ID:          9999,
		Name:        "ghost",
		MinSeverity: "low",
		UpdatedAt:   time.Now().UTC(),
	}
	err := ls.UpdateAlertEscalationPolicy(ctx, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAlertEscalationPolicy_DeleteNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	err := ls.DeleteAlertEscalationPolicy(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListUnacknowledgedAnomalyAlertsBefore(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	recent := now.Add(-5 * time.Minute)

	// Old unacknowledged — should be returned
	alert1 := &models.AnomalyAlert{
		AlertType:    "off_hours",
		Severity:     "high",
		DetectedAt:   old,
		Acknowledged: false,
	}
	// Recent unacknowledged — should NOT be returned (too new)
	alert2 := &models.AnomalyAlert{
		AlertType:    "new_ip",
		Severity:     "medium",
		DetectedAt:   recent,
		Acknowledged: false,
	}
	// Old but acknowledged — should NOT be returned
	alert3 := &models.AnomalyAlert{
		AlertType:    "frequency_spike",
		Severity:     "critical",
		DetectedAt:   old,
		Acknowledged: true,
	}

	require.NoError(t, ls.db.Create(alert1).Error)
	require.NoError(t, ls.db.Create(alert2).Error)
	require.NoError(t, ls.db.Create(alert3).Error)

	threshold := now.Add(-30 * time.Minute)
	results, err := ls.ListUnacknowledgedAnomalyAlertsBefore(ctx, threshold)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, alert1.ID, results[0].ID)
	assert.False(t, results[0].Acknowledged)
	assert.True(t, strings.EqualFold("high", results[0].Severity))
}

func TestListUnacknowledgedAnomalyAlertsBefore_Empty(t *testing.T) {
	ctx := context.Background()
	ls := newAlertEscalationTestStore(t)

	threshold := time.Now().UTC()
	results, err := ls.ListUnacknowledgedAnomalyAlertsBefore(ctx, threshold)
	require.NoError(t, err)
	assert.Empty(t, results)
}
