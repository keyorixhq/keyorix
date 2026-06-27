package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// GetRotationStatus classifies every policy-covered secret as overdue / due_soon
// / ok against the policy interval + alert window, including healthy secrets
// (which EvaluateRotationPolicies omits).
func TestGetRotationStatus_Classification(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	daysAgo := func(d int) *time.Time {
		t := fixed.Add(-time.Duration(d) * 24 * time.Hour)
		return &t
	}

	store := new(MockStorage)
	projectID := uint(1)

	policy := &models.RotationPolicy{
		ID:              7,
		Name:            "90-day prod",
		Scope:           "project",
		ProjectID:       &projectID,
		IntervalDays:    90,
		AlertDaysBefore: 14,
		IsActive:        true,
	}
	// An inactive policy must be ignored entirely.
	inactive := &models.RotationPolicy{ID: 8, Name: "off", Scope: "project", ProjectID: &projectID, IntervalDays: 30, IsActive: false}

	secrets := []*models.SecretNode{
		{ID: 1, Name: "overdue-key", EnvironmentID: 2, LastRotatedAt: daysAgo(120)},                                               // 120 > 90 → overdue
		{ID: 2, Name: "due-soon-key", EnvironmentID: 2, LastRotatedAt: daysAgo(80), AutoRotate: true, RotationBackend: "prod-pg"}, // 90-80=10 <= 14 → due_soon
		{ID: 3, Name: "healthy-key", EnvironmentID: 2, LastRotatedAt: daysAgo(10)},                                                // 90-10=80 > 14 → ok
		{ID: 4, Name: "never-rotated", EnvironmentID: 2, CreatedAt: *daysAgo(200)},                                                // falls back to CreatedAt → overdue
	}

	store.On("ListRotationPolicies", mock.Anything, &projectID, (*uint)(nil)).Return([]*models.RotationPolicy{policy, inactive}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).Return(secrets, int64(len(secrets)), nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	entries, err := c.GetRotationStatus(context.Background(), &projectID, nil)
	require.NoError(t, err)
	require.Len(t, entries, 4, "all covered secrets returned, inactive policy skipped")

	byID := map[uint]*RotationStatusEntry{}
	for _, e := range entries {
		byID[e.SecretID] = e
	}

	require.Equal(t, RotationStatusOverdue, byID[1].Status)
	require.Equal(t, 30, byID[1].DaysOverdue) // 120 - 90
	require.Equal(t, RotationStatusDueSoon, byID[2].Status)
	require.Equal(t, RotationStatusOK, byID[3].Status)
	require.Equal(t, RotationStatusOverdue, byID[4].Status, "never-rotated falls back to CreatedAt")
	require.Equal(t, uint(7), byID[1].PolicyID)
	require.Equal(t, 90, byID[1].IntervalDays)
	// Auto-rotation visibility flows through: a self-rotating secret reports its backend.
	require.True(t, byID[2].AutoRotate)
	require.Equal(t, "prod-pg", byID[2].RotationBackend)
	require.False(t, byID[1].AutoRotate, "reminder-only secret is not auto-rotate")
}

// When the caller restricts to a specific environment, a project-scoped policy's
// secret enumeration is confined to that environment, and an environment-scoped policy
// for a DIFFERENT environment is skipped entirely — so an environment-scoped reader
// can't see another environment's rotation posture.
func TestGetRotationStatus_ConfinedToEnvironment(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	projectID := uint(1)
	envID := uint(2)
	otherEnv := uint(9)

	projPolicy := &models.RotationPolicy{ID: 1, Name: "proj", Scope: "project", ProjectID: &projectID, IntervalDays: 90, IsActive: true}
	otherEnvPolicy := &models.RotationPolicy{ID: 2, Name: "env9", Scope: "environment", EnvironmentID: &otherEnv, IntervalDays: 90, IsActive: true}

	store.On("ListRotationPolicies", mock.Anything, &projectID, (*uint)(nil)).
		Return([]*models.RotationPolicy{projPolicy, otherEnvPolicy}, nil)
	// The project-scoped policy's secret listing must be confined to env 2; the env-9
	// policy must never reach ListSecrets (it's skipped before enumeration).
	store.On("ListSecrets", mock.Anything, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.EnvironmentID != nil && *f.EnvironmentID == envID
	})).Return([]*models.SecretNode{{ID: 1, Name: "k", EnvironmentID: envID, LastRotatedAt: &fixed}}, int64(1), nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }

	entries, err := c.GetRotationStatus(context.Background(), &projectID, &envID)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the project policy's env-2 secret; the env-9 policy is skipped")
	require.Equal(t, uint(1), entries[0].SecretID)
	store.AssertExpectations(t)
}
