package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixed clock for all sub-tests.
var rbFixed = time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

func rbDaysAgo(d int) *time.Time {
	t := rbFixed.Add(-time.Duration(d) * 24 * time.Hour)
	return &t
}

// newRBCore returns a core with the mock store and a frozen clock.
func newRBCore(store *MockStorage) *KeyorixCore {
	c := NewKeyorixCore(store)
	c.now = func() time.Time { return rbFixed }
	return c
}

// policyForBackend is a helper that creates a minimal, active project-scoped policy
// (project 1, no environment scope) with the given ID, interval and — importantly —
// no EnvironmentID so scopedPolicySecrets uses a nil envID (lists all secrets in the
// project).
func policyForBackend(id uint, intervalDays int) *models.RotationPolicy {
	pid := uint(1)
	return &models.RotationPolicy{
		ID:           id,
		Name:         "test-policy",
		Scope:        "project",
		ProjectID:    &pid,
		IntervalDays: intervalDays,
		IsActive:     true,
	}
}

// TestGetRotationBackendReport_NoPolicies — no rotation policies → empty backends
// slice and TotalOverdue == 0.
func TestGetRotationBackendReport_NoPolicies(t *testing.T) {
	store := new(MockStorage)
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{}, nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	assert.Empty(t, report.Backends)
	assert.Equal(t, 0, report.TotalOverdue)
	assert.False(t, report.GeneratedAt.IsZero())
	store.AssertExpectations(t)
}

// TestGetRotationBackendReport_SinglePolicyUpToDate — one secret, rotated recently
// → up_to_date=1, overdue=0.
func TestGetRotationBackendReport_SinglePolicyUpToDate(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 90)

	secrets := []*models.SecretNode{
		{ID: 1, Name: "fresh-key", RotationBackend: "vault", LastRotatedAt: rbDaysAgo(10)},
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 1)
	b := report.Backends[0]
	assert.Equal(t, "vault", b.Backend)
	assert.Equal(t, 1, b.Total)
	assert.Equal(t, 0, b.Overdue)
	assert.Equal(t, 1, b.UpToDate)
	assert.Equal(t, 0, b.NeverRotated)
	assert.Equal(t, 0, report.TotalOverdue)
	store.AssertExpectations(t)
}

// TestGetRotationBackendReport_SinglePolicyOverdue — one secret past its interval
// → overdue=1.
func TestGetRotationBackendReport_SinglePolicyOverdue(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	secrets := []*models.SecretNode{
		{ID: 2, Name: "stale-key", RotationBackend: "aws_sm", LastRotatedAt: rbDaysAgo(120)},
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 1)
	b := report.Backends[0]
	assert.Equal(t, "aws_sm", b.Backend)
	assert.Equal(t, 1, b.Overdue)
	assert.Equal(t, 0, b.UpToDate)
	assert.Equal(t, 1, report.TotalOverdue)
}

// TestGetRotationBackendReport_NeverRotated — policy set but LastRotatedAt is nil
// (secret was never rotated). Falls back to CreatedAt → likely overdue. Also counts
// in never_rotated.
func TestGetRotationBackendReport_NeverRotated(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	secrets := []*models.SecretNode{
		// CreatedAt is 200 days ago → overdue under 30-day policy; LastRotatedAt nil.
		{ID: 3, Name: "never-rotated", RotationBackend: "generic", CreatedAt: *rbDaysAgo(200)},
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(1), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 1)
	b := report.Backends[0]
	assert.Equal(t, "generic", b.Backend)
	assert.Equal(t, 1, b.NeverRotated, "never_rotated counter must fire when LastRotatedAt is nil")
	assert.Equal(t, 1, b.Overdue, "overdue counter: falls back to CreatedAt (200 days > 30)")
	assert.Equal(t, 0, b.UpToDate)
}

// TestGetRotationBackendReport_MultipleBackends — secrets across aws_sm, vault,
// and (empty = keyorix-internal). Report must group correctly.
func TestGetRotationBackendReport_MultipleBackends(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	secrets := []*models.SecretNode{
		{ID: 1, RotationBackend: "aws_sm", LastRotatedAt: rbDaysAgo(100)},  // overdue
		{ID: 2, RotationBackend: "aws_sm", LastRotatedAt: rbDaysAgo(5)},    // up-to-date
		{ID: 3, RotationBackend: "vault", LastRotatedAt: rbDaysAgo(200)},   // overdue
		{ID: 4, RotationBackend: "vault", LastRotatedAt: rbDaysAgo(200)},   // overdue
		{ID: 5, RotationBackend: "", LastRotatedAt: rbDaysAgo(10)},         // up-to-date, no backend
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(5), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 3, "three distinct backends")

	byBackend := make(map[string]BackendRotationStat)
	for _, b := range report.Backends {
		byBackend[b.Backend] = b
	}

	aws := byBackend["aws_sm"]
	assert.Equal(t, 2, aws.Total)
	assert.Equal(t, 1, aws.Overdue)
	assert.Equal(t, 1, aws.UpToDate)

	vault := byBackend["vault"]
	assert.Equal(t, 2, vault.Total)
	assert.Equal(t, 2, vault.Overdue)
	assert.Equal(t, 0, vault.UpToDate)

	internal := byBackend[""]
	assert.Equal(t, 1, internal.Total)
	assert.Equal(t, 0, internal.Overdue)
	assert.Equal(t, 1, internal.UpToDate)

	assert.Equal(t, 3, report.TotalOverdue)
}

// TestGetRotationBackendReport_SortedByOverdueDescending — the backend with the
// most overdue secrets must appear first; ties broken by backend name.
func TestGetRotationBackendReport_SortedByOverdueDescending(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	// vault: 3 overdue, aws_sm: 1 overdue, generic: 0 overdue
	secrets := []*models.SecretNode{
		{ID: 1, RotationBackend: "aws_sm", LastRotatedAt: rbDaysAgo(200)}, // overdue
		{ID: 2, RotationBackend: "vault", LastRotatedAt: rbDaysAgo(200)},  // overdue
		{ID: 3, RotationBackend: "vault", LastRotatedAt: rbDaysAgo(200)},  // overdue
		{ID: 4, RotationBackend: "vault", LastRotatedAt: rbDaysAgo(200)},  // overdue
		{ID: 5, RotationBackend: "generic", LastRotatedAt: rbDaysAgo(5)},  // up-to-date
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(5), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 3)
	assert.Equal(t, "vault", report.Backends[0].Backend, "vault has most overdue")
	assert.Equal(t, "aws_sm", report.Backends[1].Backend, "aws_sm second")
	assert.Equal(t, "generic", report.Backends[2].Backend, "generic last (0 overdue)")
}

// TestGetRotationBackendReport_TieBreakByName — two backends with the same overdue
// count must be ordered alphabetically.
func TestGetRotationBackendReport_TieBreakByName(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	secrets := []*models.SecretNode{
		{ID: 1, RotationBackend: "zebra", LastRotatedAt: rbDaysAgo(200)}, // overdue
		{ID: 2, RotationBackend: "alpha", LastRotatedAt: rbDaysAgo(200)}, // overdue
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(2), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	require.Len(t, report.Backends, 2)
	assert.Equal(t, "alpha", report.Backends[0].Backend, "alpha comes before zebra on tie")
}

// TestGetRotationBackendReport_TotalOverdueSumsAllBackends — TotalOverdue must equal
// the sum of all per-backend Overdue counts.
func TestGetRotationBackendReport_TotalOverdueSumsAllBackends(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)

	secrets := []*models.SecretNode{
		{ID: 1, RotationBackend: "a", LastRotatedAt: rbDaysAgo(200)}, // overdue
		{ID: 2, RotationBackend: "a", LastRotatedAt: rbDaysAgo(200)}, // overdue
		{ID: 3, RotationBackend: "b", LastRotatedAt: rbDaysAgo(200)}, // overdue
		{ID: 4, RotationBackend: "b", LastRotatedAt: rbDaysAgo(5)},   // up-to-date
	}
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(secrets, int64(4), nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, report.TotalOverdue)
}

// TestGetRotationBackendReport_StorageError — a storage error from GetRotationStatus
// must propagate to the caller.
func TestGetRotationBackendReport_StorageError(t *testing.T) {
	store := new(MockStorage)
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return(nil, errors.New("db is down"))

	c := newRBCore(store)
	_, err := c.GetRotationBackendReport(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db is down")
}

// TestGetRotationBackendReport_GeneratedAtSet — GeneratedAt is set to the core's
// current time.
func TestGetRotationBackendReport_GeneratedAtSet(t *testing.T) {
	store := new(MockStorage)
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{}, nil)

	c := newRBCore(store)
	report, err := c.GetRotationBackendReport(context.Background())
	require.NoError(t, err)
	assert.Equal(t, rbFixed, report.GeneratedAt)
}

// TestGetRotationBackendReport_ListSecretsError — if listing secrets for a policy
// fails, GetRotationStatus returns an error that GetRotationBackendReport propagates.
func TestGetRotationBackendReport_ListSecretsError(t *testing.T) {
	store := new(MockStorage)
	policy := policyForBackend(1, 30)
	store.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).
		Return([]*models.RotationPolicy{policy}, nil)
	store.On("ListSecrets", mock.Anything, mock.AnythingOfType("*storage.SecretFilter")).
		Return(nil, int64(0), errors.New("secrets table missing"))

	c := newRBCore(store)
	_, err := c.GetRotationBackendReport(context.Background())
	require.Error(t, err, "storage error from ListSecrets must propagate")
}

// Ensure the storage package import is used (SecretFilter comes from there).
var _ = storage.SecretFilter{}
