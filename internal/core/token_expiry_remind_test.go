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

// fixed clock for token-expiry tests.
var tokenExpiryFixed = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

// newTokenExpiryCore builds a KeyorixCore pinned to tokenExpiryFixed.
func newTokenExpiryCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return tokenExpiryFixed }}
}

// tokenExpiresAt returns a pointer to tokenExpiryFixed offset by d.
func tokenExpiresAt(d time.Duration) *time.Time {
	t := tokenExpiryFixed.Add(d)
	return &t
}

// ── PAT tests ────────────────────────────────────────────────────────────────

func TestCheckTokenExpiry_NoExpiringTokens(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.PATWarnings)
	assert.Equal(t, 0, result.PATCriticals)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
}

func TestCheckTokenExpiry_PATExpiringIn3Days_Warning(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{
		ID:        1,
		UserID:    10,
		Name:      "my-ci-token",
		ExpiresAt: tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)
	ms.On("ListNotifications", ctx, uint(10), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.PATWarnings)
	assert.Equal(t, 0, result.PATCriticals)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
}

func TestCheckTokenExpiry_PATExpiringIn12Hours_Critical(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{
		ID:        2,
		UserID:    11,
		Name:      "deploy-key",
		ExpiresAt: tokenExpiresAt(12 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)
	ms.On("ListNotifications", ctx, uint(11), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.PATWarnings)
	assert.Equal(t, 1, result.PATCriticals)
}

func TestCheckTokenExpiry_AlreadyExpiredPAT_NotCounted(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	// expired 1 hour ago
	past := tokenExpiryFixed.Add(-time.Hour)
	pat := models.PersonalAccessToken{
		ID:        3,
		UserID:    12,
		Name:      "old-token",
		ExpiresAt: &past,
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.PATWarnings)
	assert.Equal(t, 0, result.PATCriticals)
	ms.AssertNotCalled(t, "CreateNotification")
}

func TestCheckTokenExpiry_PATDeduplication_SecondCallZero(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{
		ID:        4,
		UserID:    13,
		Name:      "staging-pat",
		ExpiresAt: tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	// First call: no existing notification → create one.
	ms.On("ListNotifications", ctx, uint(13), true, 200).
		Return([]*models.Notification{}, nil).Once()
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{ID: 1}, nil).Once()

	r1, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, r1.PATWarnings)

	// Second call: same-severity unread notification exists → skip.
	ms.On("ListNotifications", ctx, uint(13), true, 200).
		Return([]*models.Notification{{
			ID:       1,
			Type:     NotificationPATExpiry,
			Message:  `Your personal access token "staging-pat" expires on 2026-06-13 12:00 UTC.`,
			Link:     patExpiryLink(4),
			Severity: models.NotificationSeverityWarning,
		}}, nil).Once()

	r2, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, r2.PATWarnings)
	assert.Equal(t, 0, r2.PATCriticals)
}

func TestCheckTokenExpiry_PATUpgradeWarningToCritical(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{
		ID:        5,
		UserID:    14,
		Name:      "expiring-fast",
		ExpiresAt: tokenExpiresAt(20 * time.Hour), // within 1-day critical window
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	existing := &models.Notification{
		ID:       99,
		Type:     NotificationPATExpiry,
		Message:  `Your personal access token "expiring-fast" expires on 2026-06-11 08:00 UTC.`,
		Link:     patExpiryLink(5),
		Severity: models.NotificationSeverityWarning,
	}
	ms.On("ListNotifications", ctx, uint(14), true, 200).
		Return([]*models.Notification{existing}, nil)
	ms.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.PATWarnings)
	assert.Equal(t, 1, result.PATCriticals)
	ms.AssertCalled(t, "UpdateNotification", ctx, mock.AnythingOfType("*models.Notification"))
}

func TestCheckTokenExpiry_ListExpiringPATsError(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return(nil, errors.New("db error"))

	_, err := c.CheckTokenExpiry(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list expiring PATs")
}

// ── Machine credential tests ──────────────────────────────────────────────────

func TestCheckTokenExpiry_MachineCredExpiringIn3Days_Warning(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                1,
		MachineIdentityID: 100,
		Name:              "k8s-runner-cred",
		ExpiresAt:         tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 5}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(5), storage.Scope{}).Return([]uint{51}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(5), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(51)).Return(&models.Role{ID: 51, Name: "admin"}, nil)
	ms.On("ListNotifications", ctx, uint(5), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
	assert.Equal(t, 0, result.PATWarnings)
}

func TestCheckTokenExpiry_MachineCredExpiringIn12Hours_Critical(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                2,
		MachineIdentityID: 101,
		Name:              "ci-deploy-cred",
		ExpiresAt:         tokenExpiresAt(12 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 6}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(6), storage.Scope{}).Return([]uint{61}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(6), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(61)).Return(&models.Role{ID: 61, Name: "super_admin"}, nil)
	ms.On("ListNotifications", ctx, uint(6), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 1, result.MachineCriticals)
}

func TestCheckTokenExpiry_AlreadyExpiredMachineCred_NotCounted(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	past := tokenExpiryFixed.Add(-time.Hour)
	cred := models.MachineIdentityCredential{
		ID:                3,
		MachineIdentityID: 102,
		Name:              "expired-cred",
		ExpiresAt:         &past,
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	// globalAdminIDs still gets called after len(creds) > 0
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{}, int64(0), nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
	ms.AssertNotCalled(t, "CreateNotification")
}

func TestCheckTokenExpiry_ListExpiringMachineCredsError(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return(nil, errors.New("db error"))

	_, err := c.CheckTokenExpiry(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list expiring machine credentials")
}

func TestCheckTokenExpiry_MachineCredDeduplication(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                4,
		MachineIdentityID: 103,
		Name:              "runner-cred",
		ExpiresAt:         tokenExpiresAt(4 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 7}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(7), storage.Scope{}).Return([]uint{71}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(7), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(71)).Return(&models.Role{ID: 71, Name: "admin"}, nil)

	existingMsg := `Machine credential "runner-cred" expires on 2026-06-14 12:00 UTC.`
	ms.On("ListNotifications", ctx, uint(7), true, 200).
		Return([]*models.Notification{{
			ID:       55,
			Type:     NotificationMachineCredExpiry,
			Message:  existingMsg,
			Link:     machineCredExpiryLink(4),
			Severity: models.NotificationSeverityWarning,
		}}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
	ms.AssertNotCalled(t, "CreateNotification")
}

func TestCheckTokenExpiry_MachineCredUpgradeWarningToCritical(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                5,
		MachineIdentityID: 104,
		Name:              "soon-cred",
		ExpiresAt:         tokenExpiresAt(20 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 8}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(8), storage.Scope{}).Return([]uint{81}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(8), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(81)).Return(&models.Role{ID: 81, Name: "admin"}, nil)

	existing := &models.Notification{
		ID:       88,
		Type:     NotificationMachineCredExpiry,
		Message:  `Machine credential "soon-cred" expires on 2026-06-11 08:00 UTC.`,
		Link:     machineCredExpiryLink(5),
		Severity: models.NotificationSeverityWarning,
	}
	ms.On("ListNotifications", ctx, uint(8), true, 200).
		Return([]*models.Notification{existing}, nil)
	ms.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 1, result.MachineCriticals)
	ms.AssertCalled(t, "UpdateNotification", ctx, mock.AnythingOfType("*models.Notification"))
}

// ── Combined PAT + machine in same call ───────────────────────────────────────

func TestCheckTokenExpiry_BothPATAndMachineCred(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{
		ID:        10,
		UserID:    20,
		Name:      "combo-pat",
		ExpiresAt: tokenExpiresAt(3 * 24 * time.Hour),
	}
	cred := models.MachineIdentityCredential{
		ID:                10,
		MachineIdentityID: 200,
		Name:              "combo-cred",
		ExpiresAt:         tokenExpiresAt(5 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	// PAT owner
	ms.On("ListNotifications", ctx, uint(20), true, 200).
		Return([]*models.Notification{}, nil)
	// Admin for machine cred
	admin := &models.User{ID: 30}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(30), storage.Scope{}).Return([]uint{301}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(30), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(301)).Return(&models.Role{ID: 301, Name: "admin"}, nil)
	ms.On("ListNotifications", ctx, uint(30), true, 200).
		Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, result.PATWarnings)
	assert.Equal(t, 0, result.PATCriticals)
	assert.Equal(t, 1, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
}

// ── globalAdminIDs error path for machine creds ───────────────────────────────

func TestCheckTokenExpiry_AdminIDsError(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                20,
		MachineIdentityID: 300,
		Name:              "err-cred",
		ExpiresAt:         tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)
	ms.On("ListUsers", ctx, mock.Anything).Return(nil, int64(0), errors.New("db error"))

	_, err := c.CheckTokenExpiry(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list admin IDs")
}

// ── helper coverage ───────────────────────────────────────────────────────────

// TestUnreadPATExpiryReminder_ListNotificationsError verifies that when
// ListNotifications returns an error, the helper returns nil (prefer to notify).
func TestUnreadPATExpiryReminder_ListNotificationsError(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	ms.On("ListNotifications", ctx, uint(99), true, 200).
		Return(nil, errors.New("db error"))

	n := c.unreadPATExpiryReminder(ctx, 99, "some-token")
	assert.Nil(t, n)
}

// TestUnreadMachineCredExpiryReminder_ListNotificationsError mirrors the above for machine creds.
func TestUnreadMachineCredExpiryReminder_ListNotificationsError(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	ms.On("ListNotifications", ctx, uint(99), true, 200).
		Return(nil, errors.New("db error"))

	n := c.unreadMachineCredExpiryReminder(ctx, 99, "some-cred")
	assert.Nil(t, n)
}

// TestBumpTokenExpiryCount_AllBranches exercises every counter branch.
func TestBumpTokenExpiryCount_AllBranches(t *testing.T) {
	r := &TokenExpiryCheckResult{}
	bumpTokenExpiryCount(r, models.NotificationSeverityWarning, true)
	assert.Equal(t, 1, r.PATWarnings)
	bumpTokenExpiryCount(r, models.NotificationSeverityCritical, true)
	assert.Equal(t, 1, r.PATCriticals)
	bumpTokenExpiryCount(r, models.NotificationSeverityWarning, false)
	assert.Equal(t, 1, r.MachineWarnings)
	bumpTokenExpiryCount(r, models.NotificationSeverityCritical, false)
	assert.Equal(t, 1, r.MachineCriticals)
}

// TestTokenExpirySeverity_Boundary verifies the threshold boundary.
func TestTokenExpirySeverity_Boundary(t *testing.T) {
	now := tokenExpiryFixed
	// Exactly 1 day away → critical (Before check: expiresAt < now+1d is false at == boundary;
	// need to check one second before to be strictly before.)
	atBoundary := now.Add(tokenExpiryCriticalWindow)
	assert.Equal(t, models.NotificationSeverityWarning, tokenExpirySeverity(&atBoundary, now))

	justBefore := now.Add(tokenExpiryCriticalWindow - time.Second)
	assert.Equal(t, models.NotificationSeverityCritical, tokenExpirySeverity(&justBefore, now))
}

// TestPATExpiryMessage checks message formatting.
func TestPATExpiryMessage(t *testing.T) {
	exp := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	title, msg := patExpiryMessage("my-token", &exp)
	assert.Equal(t, "Personal access token expiring", title)
	assert.Contains(t, msg, `"my-token"`)
	assert.Contains(t, msg, "2026-06-17 12:00 UTC")
}

// TestMachineCredExpiryMessage checks message formatting.
func TestMachineCredExpiryMessage(t *testing.T) {
	exp := time.Date(2026, 6, 17, 8, 0, 0, 0, time.UTC)
	title, msg := machineCredExpiryMessage("runner-cred", &exp)
	assert.Equal(t, "Machine credential expiring", title)
	assert.Contains(t, msg, `"runner-cred"`)
	assert.Contains(t, msg, "2026-06-17 08:00 UTC")
}

// TestCheckTokenExpiry_MachineCredNoAdmins verifies that with zero global admins
// no notifications are emitted but result is all zeros (not an error).
func TestCheckTokenExpiry_MachineCredNoAdmins(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                30,
		MachineIdentityID: 400,
		Name:              "orphan-cred",
		ExpiresAt:         tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)
	// No admins returned.
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{}, int64(0), nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
}

// TestCheckTokenExpiry_PATNilExpiresAt ensures a PAT with nil ExpiresAt is skipped
// even if the storage layer erroneously returns it.
func TestCheckTokenExpiry_PATNilExpiresAt(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	pat := models.PersonalAccessToken{ID: 50, UserID: 50, Name: "nil-exp", ExpiresAt: nil}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{pat}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.PATWarnings)
	assert.Equal(t, 0, result.PATCriticals)
	ms.AssertNotCalled(t, "CreateNotification")
}

// TestCheckTokenExpiry_MachineCredNilExpiresAt mirrors the above for machine creds.
func TestCheckTokenExpiry_MachineCredNilExpiresAt(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{ID: 60, MachineIdentityID: 60, Name: "nil-exp-cred", ExpiresAt: nil}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 70}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(70), storage.Scope{}).Return([]uint{701}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(70), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(701)).Return(&models.Role{ID: 701, Name: "admin"}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
	ms.AssertNotCalled(t, "CreateNotification")
}

// TestCheckTokenExpiry_MachineCredMultipleAdmins_OnlyCountsOnce verifies that
// when multiple admins exist, the machine-cred counter increments only once
// per credential (not once per admin).
func TestCheckTokenExpiry_MachineCredMultipleAdmins_OnlyCountsOnce(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                70,
		MachineIdentityID: 500,
		Name:              "shared-cred",
		ExpiresAt:         tokenExpiresAt(3 * 24 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin1 := &models.User{ID: 80}
	admin2 := &models.User{ID: 81}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin1, admin2}, int64(2), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(80), storage.Scope{}).Return([]uint{801}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(80), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(801)).Return(&models.Role{ID: 801, Name: "admin"}, nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(81), storage.Scope{}).Return([]uint{811}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(81), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(811)).Return(&models.Role{ID: 811, Name: "super_admin"}, nil)
	ms.On("ListNotifications", ctx, uint(80), true, 200).Return([]*models.Notification{}, nil)
	ms.On("ListNotifications", ctx, uint(81), true, 200).Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	// Two admins both get notified, but the counter only goes up once per cred.
	assert.Equal(t, 1, result.MachineWarnings)
	assert.Equal(t, 0, result.MachineCriticals)
	// Both admins received a CreateNotification call.
	ms.AssertNumberOfCalls(t, "CreateNotification", 2)
}

// TestCheckTokenExpiry_MachineCredUpgradeCountsOnceAcrossAdmins verifies
// that escalation across multiple admins only increments the counter once.
func TestCheckTokenExpiry_MachineCredUpgradeCountsOnceAcrossAdmins(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                71,
		MachineIdentityID: 501,
		Name:              "escalating-cred",
		ExpiresAt:         tokenExpiresAt(20 * time.Hour), // critical window
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin1 := &models.User{ID: 90}
	admin2 := &models.User{ID: 91}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin1, admin2}, int64(2), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(90), storage.Scope{}).Return([]uint{901}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(90), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(901)).Return(&models.Role{ID: 901, Name: "admin"}, nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(91), storage.Scope{}).Return([]uint{911}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(91), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(911)).Return(&models.Role{ID: 911, Name: "admin"}, nil)

	existMsg := `Machine credential "escalating-cred" expires on 2026-06-11 08:00 UTC.`
	existLink := machineCredExpiryLink(71)
	existing90 := &models.Notification{ID: 90, Type: NotificationMachineCredExpiry, Message: existMsg, Link: existLink, Severity: models.NotificationSeverityWarning}
	existing91 := &models.Notification{ID: 91, Type: NotificationMachineCredExpiry, Message: existMsg, Link: existLink, Severity: models.NotificationSeverityWarning}
	ms.On("ListNotifications", ctx, uint(90), true, 200).Return([]*models.Notification{existing90}, nil)
	ms.On("ListNotifications", ctx, uint(91), true, 200).Return([]*models.Notification{existing91}, nil)
	ms.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).Return(nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	// Counter should only be incremented once (on the first successful upgrade).
	assert.Equal(t, 1, result.MachineCriticals)
	ms.AssertNumberOfCalls(t, "UpdateNotification", 2)
}

// TestCheckTokenExpiry_MachineCredUpgradeFailNotCounted verifies that a failed
// upgradeReminder (UpdateNotification error) does not increment the counter.
func TestCheckTokenExpiry_MachineCredUpgradeFailNotCounted(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	cred := models.MachineIdentityCredential{
		ID:                72,
		MachineIdentityID: 502,
		Name:              "fail-upgrade-cred",
		ExpiresAt:         tokenExpiresAt(20 * time.Hour),
	}
	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{cred}, nil)

	admin := &models.User{ID: 95}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(95), storage.Scope{}).Return([]uint{951}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(95), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(951)).Return(&models.Role{ID: 951, Name: "admin"}, nil)

	existMsg := `Machine credential "fail-upgrade-cred" expires on 2026-06-11 08:00 UTC.`
	existing := &models.Notification{ID: 95, Type: NotificationMachineCredExpiry, Message: existMsg, Link: machineCredExpiryLink(72), Severity: models.NotificationSeverityWarning}
	ms.On("ListNotifications", ctx, uint(95), true, 200).Return([]*models.Notification{existing}, nil)
	// UpdateNotification returns an error → upgradeReminder returns false.
	ms.On("UpdateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(errors.New("db error"))

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	// Failed upgrade should not count.
	assert.Equal(t, 0, result.MachineCriticals)
}

// ── G22 regression: dedup must key on token ID, not display Name ─────────────

// TestCheckTokenExpiry_PATDedupKeyedOnID_NotName is the G22 regression test:
// two different PATs owned by the SAME user that happen to share a display
// Name must still get independent reminders. Before the fix,
// unreadPATExpiryReminder matched on a quoted-name substring in the
// notification Message, so an existing unread reminder for token A (ID 200)
// would spuriously match token B (ID 201 — same Name, different ID) and
// silently suppress B's reminder. The fix keys the dedup check on the token's
// stable ID (encoded in Link via patExpiryLink), so A's standing reminder no
// longer masks B's.
func TestCheckTokenExpiry_PATDedupKeyedOnID_NotName(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	const sharedName = "shared-name-token"
	tokenA := models.PersonalAccessToken{ID: 200, UserID: 500, Name: sharedName, ExpiresAt: tokenExpiresAt(6 * 24 * time.Hour)}
	tokenB := models.PersonalAccessToken{ID: 201, UserID: 500, Name: sharedName, ExpiresAt: tokenExpiresAt(3 * 24 * time.Hour)}

	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{tokenA, tokenB}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{}, nil)

	// Token A already has a standing unread reminder from an earlier tick.
	existingForA := &models.Notification{
		ID:       9500,
		Type:     NotificationPATExpiry,
		Message:  `Your personal access token "shared-name-token" expires on 2026-06-16 12:00 UTC.`,
		Link:     patExpiryLink(200),
		Severity: models.NotificationSeverityWarning,
	}
	ms.On("ListNotifications", ctx, uint(500), true, 200).
		Return([]*models.Notification{existingForA}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	// Token A: existing same-severity reminder → skipped (not re-counted).
	// Token B: distinct token ID → NOT suppressed by A's reminder, even though
	// both tokens share a Name → must still be counted and notified.
	assert.Equal(t, 1, result.PATWarnings, "token B (same name, different ID) must still get its own reminder")
	ms.AssertNumberOfCalls(t, "CreateNotification", 1)
}

// TestCheckTokenExpiry_MachineCredDedupKeyedOnID_NotName mirrors the PAT case
// above for machine credentials: two credentials with the same Name but
// different IDs, notified to the same admin, must each get their own reminder.
func TestCheckTokenExpiry_MachineCredDedupKeyedOnID_NotName(t *testing.T) {
	ms := new(MockStorage)
	c := newTokenExpiryCore(ms)
	ctx := context.Background()

	const sharedName = "shared-name-cred"
	credA := models.MachineIdentityCredential{ID: 300, MachineIdentityID: 900, Name: sharedName, ExpiresAt: tokenExpiresAt(6 * 24 * time.Hour)}
	credB := models.MachineIdentityCredential{ID: 301, MachineIdentityID: 901, Name: sharedName, ExpiresAt: tokenExpiresAt(3 * 24 * time.Hour)}

	ms.On("ListExpiringPATs", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.PersonalAccessToken{}, nil)
	ms.On("ListExpiringMachineCredentials", ctx, mock.AnythingOfType("time.Time")).
		Return([]models.MachineIdentityCredential{credA, credB}, nil)

	admin := &models.User{ID: 600}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoleIDsAt", ctx, uint(600), storage.Scope{}).Return([]uint{6001}, nil)
	ms.On("GetUserGroupRoleIDsAt", ctx, uint(600), storage.Scope{}).Return([]uint{}, nil)
	ms.On("GetRole", ctx, uint(6001)).Return(&models.Role{ID: 6001, Name: "admin"}, nil)

	// Credential A already has a standing unread reminder for this admin.
	existingForA := &models.Notification{
		ID:       9600,
		Type:     NotificationMachineCredExpiry,
		Message:  `Machine credential "shared-name-cred" expires on 2026-06-16 12:00 UTC.`,
		Link:     machineCredExpiryLink(300),
		Severity: models.NotificationSeverityWarning,
	}
	ms.On("ListNotifications", ctx, uint(600), true, 200).
		Return([]*models.Notification{existingForA}, nil)
	ms.On("CreateNotification", ctx, mock.AnythingOfType("*models.Notification")).
		Return(&models.Notification{}, nil)

	result, err := c.CheckTokenExpiry(ctx)
	require.NoError(t, err)
	// Credential B: distinct credential ID → NOT suppressed by A's reminder,
	// even though both credentials share a Name → must still be counted.
	assert.Equal(t, 1, result.MachineWarnings, "credential B (same name, different ID) must still get its own reminder")
	ms.AssertNumberOfCalls(t, "CreateNotification", 1)
}

// ── UserFilter import usage ───────────────────────────────────────────────────

// Ensure storage.UserFilter is imported/used. globalAdminIDs uses it.
var _ = (*storage.UserFilter)(nil)
