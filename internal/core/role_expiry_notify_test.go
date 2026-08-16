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

var roleExpiryFixed = time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

func newRoleExpiryCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return roleExpiryFixed }}
}

// expiresAt returns a pointer to a time offset from roleExpiryFixed.
func expiresAt(d time.Duration) *time.Time {
	t := roleExpiryFixed.Add(d)
	return &t
}

func TestCheckRoleExpiry_NoGrants(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
}

func TestCheckRoleExpiry_WarningForFiveDayExpiry(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	// Expires in 5 days → Warning (within 7-day window, outside 1-day window)
	grant := models.UserRole{UserID: 10, RoleID: 3, ExpiresAt: expiresAt(5 * 24 * time.Hour)}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)
	store.On("GetRole", ctx, uint(3)).Return(&models.Role{ID: 3, Name: "Operator"}, nil)
	store.On("ListNotifications", ctx, uint(10), true, 200).
		Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
}

func TestCheckRoleExpiry_CriticalForTwentyHourExpiry(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	// Expires in 20 hours → Critical (within 1-day window)
	grant := models.UserRole{UserID: 11, RoleID: 4, ExpiresAt: expiresAt(20 * time.Hour)}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)
	store.On("GetRole", ctx, uint(4)).Return(&models.Role{ID: 4, Name: "Admin"}, nil)
	store.On("ListNotifications", ctx, uint(11), true, 200).
		Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 1, result.Criticals)
}

func TestCheckRoleExpiry_SkipsAlreadyExpiredGrants(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	// ExpiresAt is in the past — already expired, must be skipped.
	past := roleExpiryFixed.Add(-1 * time.Hour)
	grant := models.UserRole{UserID: 12, RoleID: 5, ExpiresAt: &past}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
}

func TestCheckRoleExpiry_SkipsDedupSameSeverity(t *testing.T) {
	// Existing warning notification for same role → skip (no new notification)
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	grant := models.UserRole{UserID: 13, RoleID: 6, ExpiresAt: expiresAt(5 * 24 * time.Hour)}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)
	store.On("GetRole", ctx, uint(6)).Return(&models.Role{ID: 6, Name: "Viewer"}, nil)
	// Existing unread warning for this exact (role, project, environment) grant.
	existingMsg := `Your "Viewer" role grant expires on`
	store.On("ListNotifications", ctx, uint(13), true, 200).
		Return([]*models.Notification{
			{
				Type:     NotificationRoleExpiryReminder,
				Message:  existingMsg,
				Link:     roleExpiryLink(6, 0, 0),
				Severity: models.NotificationSeverityWarning,
			},
		}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	// Same severity — should be skipped entirely
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 0, result.Criticals)
	store.AssertNotCalled(t, "CreateNotification")
}

func TestCheckRoleExpiry_UpgradeWarningToCritical(t *testing.T) {
	// Existing warning for a role now expiring in <1 day → escalate to critical
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	grant := models.UserRole{UserID: 14, RoleID: 7, ExpiresAt: expiresAt(20 * time.Hour)}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)
	store.On("GetRole", ctx, uint(7)).Return(&models.Role{ID: 7, Name: "Manager"}, nil)

	existingMsg := `Your "Manager" role grant expires on`
	existing := &models.Notification{
		ID:       99,
		Type:     NotificationRoleExpiryReminder,
		Message:  existingMsg,
		Link:     roleExpiryLink(7, 0, 0),
		Severity: models.NotificationSeverityWarning,
	}
	store.On("ListNotifications", ctx, uint(14), true, 200).
		Return([]*models.Notification{existing}, nil)
	store.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Warnings)
	assert.Equal(t, 1, result.Criticals)
	store.AssertCalled(t, "UpdateNotification", ctx, mock.AnythingOfType("*models.Notification"))
}

func TestCheckRoleExpiry_ListExpiringError(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return(nil, errors.New("db error"))

	_, err := c.CheckRoleExpiry(ctx)
	require.Error(t, err)
}

func TestCheckRoleExpiry_RoleNameFallback(t *testing.T) {
	// When GetRole fails, roleName should fall back to "#<id>".
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	grant := models.UserRole{UserID: 15, RoleID: 999, ExpiresAt: expiresAt(5 * 24 * time.Hour)}
	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grant}, nil)
	store.On("GetRole", ctx, uint(999)).Return(nil, errors.New("not found"))
	store.On("ListNotifications", ctx, uint(15), true, 200).Return([]*models.Notification{}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Warnings)
}

// TestCheckRoleExpiry_DedupKeyedOnGrantTuple_NotRoleName is the G22
// regression test: two DISTINCT role grants for the same user that happen to
// resolve to the same display Name ("Viewer") — RoleID 6 scoped to Project
// 100, and RoleID 9 (a different role, same Name) scoped to Project 200 —
// must get independent reminders. Before the fix, unreadRoleExpiryReminder
// matched on a `"<name>" role grant` substring in the notification Message
// and never considered ProjectID/EnvironmentID at all, so an existing unread
// reminder for grant A would spuriously match grant B (different role,
// different project, same resolved name) and silently suppress B's reminder.
// The fix keys the dedup check on the full (role, project, environment) grant
// tuple (encoded in Link via roleExpiryLink), so A's standing reminder no
// longer masks B's.
func TestCheckRoleExpiry_DedupKeyedOnGrantTuple_NotRoleName(t *testing.T) {
	store := new(MockStorage)
	c := newRoleExpiryCore(store)
	ctx := context.Background()

	grantA := models.UserRole{UserID: 20, RoleID: 6, ProjectID: 100, ExpiresAt: expiresAt(6 * 24 * time.Hour)}
	grantB := models.UserRole{UserID: 20, RoleID: 9, ProjectID: 200, ExpiresAt: expiresAt(3 * 24 * time.Hour)}

	store.On("ListExpiringUserRoles", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.UserRole{grantA, grantB}, nil)
	store.On("GetRole", ctx, uint(6)).Return(&models.Role{ID: 6, Name: "Viewer"}, nil)
	store.On("GetRole", ctx, uint(9)).Return(&models.Role{ID: 9, Name: "Viewer"}, nil)

	// Grant A already has a standing unread reminder from an earlier tick.
	existingForA := &models.Notification{
		ID:       9700,
		Type:     NotificationRoleExpiryReminder,
		Message:  `Your "Viewer" role grant expires on 2026-06-11 12:00 UTC.`,
		Link:     roleExpiryLink(6, 100, 0),
		Severity: models.NotificationSeverityWarning,
	}
	store.On("ListNotifications", ctx, uint(20), true, 200).
		Return([]*models.Notification{existingForA}, nil)
	store.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckRoleExpiry(ctx)
	require.NoError(t, err)
	// Grant A: existing same-severity reminder → skipped (not re-counted).
	// Grant B: distinct (role, project, environment) tuple → NOT suppressed by
	// A's reminder, even though both roles resolve to the same display Name →
	// must still be counted and notified.
	assert.Equal(t, 1, result.Warnings, "grant B (same role name, different role/project) must still get its own reminder")
	store.AssertNumberOfCalls(t, "CreateNotification", 1)
}
