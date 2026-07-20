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
	// Existing unread warning for this role
	existingMsg := `Your "Viewer" role grant expires on`
	store.On("ListNotifications", ctx, uint(13), true, 200).
		Return([]*models.Notification{
			{
				Type:     NotificationRoleExpiryReminder,
				Message:  existingMsg,
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
