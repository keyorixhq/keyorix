package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	calNow  = time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	calFrom = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	calTo   = time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC)
)

func calCore(ms *MockStorage) *KeyorixCore {
	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return calNow }
	return c
}

func calPolicy(id uint, active bool, intervalDays int) *models.RotationPolicy {
	return &models.RotationPolicy{
		ID:           id,
		Name:         "pol",
		Scope:        "project",
		ProjectID:    ptr(uint(1)),
		IntervalDays: intervalDays,
		IsActive:     active,
	}
}

func ptr[T any](v T) *T { return &v }

// GetRotationCalendar returns an error when from is after to.
func TestGetRotationCalendar_InvalidRange(t *testing.T) {
	ms := new(MockStorage)
	c := calCore(ms)

	_, err := c.GetRotationCalendar(context.Background(), calTo, calFrom, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "from must not be after to")
}

// GetRotationCalendar surfaces a storage error from ListRotationPolicies.
func TestGetRotationCalendar_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return(nil, errors.New("db down"))

	c := calCore(ms)
	_, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "db down")
}

// Inactive policies are skipped; the result is empty.
func TestGetRotationCalendar_InactivePolicy(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{calPolicy(1, false, 30)}, nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// scopedPolicySecrets failure is propagated as an error.
func TestGetRotationCalendar_SecretListError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{calPolicy(1, true, 30)}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(nil, int64(0), errors.New("secrets unavailable"))

	c := calCore(ms)
	_, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secrets unavailable")
}

// A secret whose NextRotationAt falls within [from, to] is included, using
// LastRotatedAt as the baseline.
func TestGetRotationCalendar_SecretInWindowUsesLastRotatedAt(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(5, true, 30)
	// LastRotatedAt = 2026-07-10 → next = 2026-08-09 (within window)
	lastRotated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	secrets := []*models.SecretNode{
		{ID: 11, Name: "api-key", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &lastRotated, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	require.Equal(t, uint(11), e.SecretID)
	require.Equal(t, "api-key", e.SecretName)
	require.Equal(t, uint(5), e.PolicyID)
	require.Equal(t, 30, e.IntervalDays)
	require.NotNil(t, e.LastRotatedAt)
	expected := lastRotated.AddDate(0, 0, 30)
	require.Equal(t, expected, e.NextRotationAt)
	require.False(t, e.IsOverdue)
}

// A secret with no LastRotatedAt falls back to CreatedAt as the baseline.
func TestGetRotationCalendar_FallsBackToCreatedAt(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(6, true, 30)
	created := time.Date(2026, 7, 5, 0, 0, 0, 0, time.UTC)
	// no LastRotatedAt → next = 2026-08-04 (within window)
	secrets := []*models.SecretNode{
		{ID: 12, Name: "db-pass", ProjectID: 1, EnvironmentID: 2, CreatedAt: created},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	require.Nil(t, e.LastRotatedAt)
	require.Equal(t, created.AddDate(0, 0, 30), e.NextRotationAt)
}

// A secret whose NextRotationAt is before from is filtered out.
func TestGetRotationCalendar_BeforeWindowFiltered(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(7, true, 30)
	// LastRotatedAt 2026-05-01 → next = 2026-05-31 (before calFrom=2026-07-01)
	lastRotated := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	secrets := []*models.SecretNode{
		{ID: 13, Name: "old-key", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &lastRotated},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// A secret whose NextRotationAt is after to is filtered out.
func TestGetRotationCalendar_AfterWindowFiltered(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(8, true, 90)
	// LastRotatedAt 2026-07-01 → next = 2026-09-29 (after calTo=2026-08-31)
	lastRotated := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	secrets := []*models.SecretNode{
		{ID: 14, Name: "long-interval", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &lastRotated},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// An overdue secret (next < now) within the window is marked IsOverdue=true
// with a negative DaysUntilDue.
func TestGetRotationCalendar_OverdueSecret(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(9, true, 30)
	// LastRotatedAt = 2026-06-10 → next = 2026-07-10 (< calNow=2026-07-21, in window)
	lastRotated := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	secrets := []*models.SecretNode{
		{ID: 15, Name: "overdue-key", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &lastRotated},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	require.True(t, e.IsOverdue)
	require.Negative(t, e.DaysUntilDue)
}

// Results are sorted by NextRotationAt ascending.
func TestGetRotationCalendar_SortedByNextRotation(t *testing.T) {
	ms := new(MockStorage)
	pol := calPolicy(10, true, 30)
	// Three secrets due in different order
	r1 := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC) // next = 2026-08-19
	r2 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)  // next = 2026-07-31 (earliest)
	r3 := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) // next = 2026-08-14
	secrets := []*models.SecretNode{
		{ID: 20, Name: "c", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &r1},
		{ID: 21, Name: "a", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &r2},
		{ID: 22, Name: "b", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &r3},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{pol}, nil)
	ms.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(3), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	require.True(t, entries[0].NextRotationAt.Before(entries[1].NextRotationAt))
	require.True(t, entries[1].NextRotationAt.Before(entries[2].NextRotationAt))
	// earliest is secret 21 (r2)
	require.Equal(t, uint(21), entries[0].SecretID)
}

// No policies → empty result (not an error).
func TestGetRotationCalendar_NoPolicies(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{}, nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// Multiple policies across scopes are all evaluated.
func TestGetRotationCalendar_MultiplePolicies(t *testing.T) {
	ms := new(MockStorage)
	p1 := calPolicy(11, true, 30)
	p2 := &models.RotationPolicy{
		ID:            12,
		Name:          "env-pol",
		Scope:         "environment",
		EnvironmentID: ptr(uint(3)),
		IntervalDays:  14,
		IsActive:      true,
	}
	// policy 1 (project-scoped) secret
	r1 := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) // next=2026-08-09
	p1Secrets := []*models.SecretNode{
		{ID: 30, Name: "p1-key", ProjectID: 1, EnvironmentID: 2, LastRotatedAt: &r1},
	}
	// policy 2 (env-scoped) secret
	r2 := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) // next=2026-07-29
	p2Secrets := []*models.SecretNode{
		{ID: 31, Name: "p2-key", ProjectID: 1, EnvironmentID: 3, LastRotatedAt: &r2},
	}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{p1, p2}, nil)

	// Use filter matching to return the right secret set per policy.
	ms.On("ListSecrets", mock.Anything, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.ProjectID != nil && *f.ProjectID == 1
	})).Return(p1Secrets, int64(1), nil)
	ms.On("ListSecrets", mock.Anything, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.EnvironmentID != nil && *f.EnvironmentID == 3
	})).Return(p2Secrets, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, nil, nil)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	// sorted: p2-key next=07-29, p1-key next=08-09
	require.Equal(t, uint(31), entries[0].SecretID)
	require.Equal(t, uint(30), entries[1].SecretID)
}

// core-rotation-2026-08-08-003: GetRotationCalendar previously had no way to scope
// down from the full deployment-wide aggregate, so any caller who cleared the
// (broad, global-scope) secrets.read bar saw every project's secret names/rotation
// detail. A non-nil projectID now confines the calendar to that project: it's
// passed straight through to ListRotationPolicies (the storage layer's own project
// filter), so a policy belonging to a different project is never even fetched —
// mirroring GetRotationStatus/EvaluateRotationPolicies' existing scoping. Since the
// mock only has an expectation for ListRotationPolicies(&projectA, nil), a
// regression back to the unscoped ListRotationPolicies(nil, nil) call would panic
// here on an unmatched call rather than silently leaking project B's data.
func TestGetRotationCalendar_ScopedToProject(t *testing.T) {
	ms := new(MockStorage)
	projectA := uint(1)
	polA := calPolicy(20, true, 30)
	polA.ProjectID = &projectA

	rA := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) // next=2026-08-09
	secretsA := []*models.SecretNode{
		{ID: 40, Name: "project-a-key", ProjectID: projectA, EnvironmentID: 2, LastRotatedAt: &rA},
	}

	ms.On("ListRotationPolicies", mock.Anything, &projectA, (*uint)(nil)).
		Return([]*models.RotationPolicy{polA}, nil)
	ms.On("ListSecrets", mock.Anything, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.ProjectID != nil && *f.ProjectID == projectA
	})).Return(secretsA, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, &projectA, nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, uint(40), entries[0].SecretID)
	require.Equal(t, "project-a-key", entries[0].SecretName)
	require.Equal(t, projectA, entries[0].ProjectID)
	ms.AssertExpectations(t)
}

// When the caller further restricts to a specific environment, a project-scoped
// policy's secret enumeration is confined to that environment, and any
// environment-scoped policy targeting a DIFFERENT environment is skipped
// entirely (never even reaches scopedPolicySecrets) — mirrors
// TestGetRotationStatus_ConfinedToEnvironment via the same
// policyAppliesToEnv + scopedPolicySecrets(reqEnvID) machinery.
func TestGetRotationCalendar_ScopedToEnvironment(t *testing.T) {
	ms := new(MockStorage)
	projectID := uint(1)
	envID := uint(2)
	otherEnv := uint(9)

	projPolicy := calPolicy(21, true, 30)
	projPolicy.ProjectID = &projectID
	otherEnvPolicy := &models.RotationPolicy{ID: 22, Name: "env9", Scope: "environment", EnvironmentID: &otherEnv, IntervalDays: 30, IsActive: true}

	r := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) // next=2026-08-09
	ms.On("ListRotationPolicies", mock.Anything, &projectID, (*uint)(nil)).
		Return([]*models.RotationPolicy{projPolicy, otherEnvPolicy}, nil)
	ms.On("ListSecrets", mock.Anything, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.EnvironmentID != nil && *f.EnvironmentID == envID
	})).Return([]*models.SecretNode{
		{ID: 41, Name: "env2-key", ProjectID: projectID, EnvironmentID: envID, LastRotatedAt: &r},
	}, int64(1), nil)

	c := calCore(ms)
	entries, err := c.GetRotationCalendar(context.Background(), calFrom, calTo, &projectID, &envID)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the project policy's env-2 secret; the env-9 policy is skipped")
	require.Equal(t, uint(41), entries[0].SecretID)
	ms.AssertExpectations(t)
}
