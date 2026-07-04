package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingDashboardAuditStore wraps LocalStorage and fails every GetAuditLogs
// call, simulating an audit-log query outage while every other dashboard
// sub-check still runs for real.
type failingDashboardAuditStore struct {
	*store.LocalStorage
}

func (s *failingDashboardAuditStore) GetAuditLogs(_ context.Context, _ *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	return nil, 0, errors.New("simulated audit log outage")
}

// failingDashboardStatsStore wraps LocalStorage and fails GetStats, simulating
// a DB error on the active-users rollup.
type failingDashboardStatsStore struct {
	*store.LocalStorage
}

func (s *failingDashboardStatsStore) GetStats(_ context.Context) (*storage.StorageStats, error) {
	return nil, errors.New("simulated stats query failure")
}

// failingDashboardUsersStore wraps LocalStorage and fails ListUsers, simulating
// a DB error on the inactive-users rollup.
type failingDashboardUsersStore struct {
	*store.LocalStorage
}

func (s *failingDashboardUsersStore) ListUsers(_ context.Context, _ *storage.UserFilter) ([]*models.User, int64, error) {
	return nil, 0, errors.New("simulated users query failure")
}

// failingExpiringSecretsStore wraps LocalStorage and fails ListSecrets only
// when called with the ExpiresBefore filter getExpiringSecrets uses, leaving
// the unrelated TotalSecrets ListSecrets call (no ExpiresBefore) untouched.
type failingExpiringSecretsStore struct {
	*store.LocalStorage
}

func (s *failingExpiringSecretsStore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if filter != nil && filter.ExpiresBefore != nil {
		return nil, 0, errors.New("simulated expiring-secrets query failure")
	}
	return s.LocalStorage.ListSecrets(ctx, filter)
}

// #394: on a real deployment, a failed audit-log/user-count query left every
// deployment-wide dashboard stat at its zero value — byte-identical to
// "queried, genuinely zero" (e.g. FailedAuthAttempts24h=0 reads as a clean
// window even when the query that would report failed logins errored out).
// These tests prove the sub-checks now surface as Degraded instead.
func TestGetDashboardStats_DegradedOnAuditLogsQueryError(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor1", "system_auditor", storage.Scope{})
	c.storage = &failingDashboardAuditStore{LocalStorage: st}

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor1")
	require.NoError(t, err, "a single failed sub-check must not abort the whole dashboard")

	assert.Zero(t, stats.AuditEvents30d, "the field itself still reads as its safe-default zero value")
	assert.Zero(t, stats.AuditLogins30d)
	assert.Zero(t, stats.AuditSecretReads30d)
	assert.Zero(t, stats.FailedAuthAttempts24h)
	assert.True(t, stats.Degraded, "a failed audit-log query must flip Degraded — the zero values above are UNKNOWN, not verified-clean")
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_count"), "expected an audit_count entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_logins"), "expected an audit_logins entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "audit_secret_reads"), "expected an audit_secret_reads entry, got %v", stats.DegradedReasons)
	assert.True(t, containsSubstring(stats.DegradedReasons, "failed_auth_24h"), "expected a failed_auth_24h entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnActiveUsersQueryError(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor2", "system_auditor", storage.Scope{})
	c.storage = &failingDashboardStatsStore{LocalStorage: st}

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor2")
	require.NoError(t, err)

	assert.Zero(t, stats.ActiveUsers, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed active-users query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "active_users"), "expected an active_users entry, got %v", stats.DegradedReasons)
}

func TestGetDashboardStats_DegradedOnInactiveUsersQueryError(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor3", "system_auditor", storage.Scope{})
	c.storage = &failingDashboardUsersStore{LocalStorage: st}

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor3")
	require.NoError(t, err)

	assert.Zero(t, stats.InactiveUsers, "the field itself still reads as its safe-default zero value")
	assert.True(t, stats.Degraded, "a failed inactive-users query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "inactive_users"), "expected an inactive_users entry, got %v", stats.DegradedReasons)
}

// #394: getExpiringSecrets paged through ListSecrets and silently discarded
// whatever it had accumulated so far on a page-load error — this proves the
// truncation is now surfaced via Degraded even for a baseline caller without
// audit.read (the expiring-secrets rollup is not gated by hasAuditRead).
func TestGetDashboardStats_DegradedOnExpiringSecretsQueryError(t *testing.T) {
	c, st := newBootstrappedCore(t)
	viewerID := seedUserWithRole(t, st, "viewer1", "system_viewer", storage.Scope{})
	c.storage = &failingExpiringSecretsStore{LocalStorage: st}

	stats, err := c.GetDashboardStats(context.Background(), viewerID, "viewer1")
	require.NoError(t, err)

	assert.Empty(t, stats.ExpiringSecrets, "the field itself still reads as its safe-default empty value")
	assert.True(t, stats.Degraded, "a failed expiring-secrets query must flip Degraded")
	assert.True(t, containsSubstring(stats.DegradedReasons, "expiring_secrets"), "expected an expiring_secrets entry, got %v", stats.DegradedReasons)
	// A baseline caller (no audit.read) must not see the deployment-wide
	// aggregates degrade too — expiring_secrets is the only failure injected.
	assert.False(t, containsSubstring(stats.DegradedReasons, "active_users"))
}

// A fully-healthy storage must never report Degraded.
func TestGetDashboardStats_NotDegradedOnSuccess(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "auditor4", "system_auditor", storage.Scope{})

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "auditor4")
	require.NoError(t, err)

	assert.False(t, stats.Degraded)
	assert.Empty(t, stats.DegradedReasons)
}
