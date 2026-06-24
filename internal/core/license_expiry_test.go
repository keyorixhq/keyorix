package core

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// gateWithExpiry builds a license gate whose license expires at notAfter.
func gateWithExpiry(t *testing.T, notAfter time.Time) *license.Gate {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	token, err := license.Issue(license.License{
		Licensee: "ACME GmbH", Plan: "enterprise-airgap", Features: []string{"airgap_updates"},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyID: "license-2026",
	}, priv)
	require.NoError(t, err)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-2026", pub))
	return license.NewGate(token, reg, "", time.Hour)
}

func TestScanLicenseExpiry_ActiveFarFromExpiry_NoNotify(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(gateWithExpiry(t, time.Now().Add(200*24*time.Hour)))

	n, err := c.ScanLicenseExpiry(context.Background(), 30)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	// A far-from-expiry license must not even query for admins.
	ms.AssertNotCalled(t, "ListUsers", mock.Anything, mock.Anything)
}

func TestScanLicenseExpiry_NoLicense_NoNotify(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms) // no gate set → nil gate → baseline
	n, err := c.ScanLicenseExpiry(context.Background(), 30)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	ms.AssertNotCalled(t, "ListUsers", mock.Anything, mock.Anything)
}

func TestScanLicenseExpiry_Expiring_NotifiesGlobalAdmins(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(gateWithExpiry(t, time.Now().Add(10*24*time.Hour))) // within 30d window

	admin := &models.User{ID: 2, Email: "admin@acme.test"}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{{Name: "system_admin"}}, nil)
	ms.On("ListNotifications", ctx, uint(2), true, 100).Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
		return n.Type == NotificationLicenseExpiry && n.UserID == 2 && n.ProjectID == nil
	})).Return(&models.Notification{ID: 1}, nil)

	n, err := c.ScanLicenseExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ms.AssertExpectations(t)
}

func TestScanLicenseExpiry_Dedup_NoResend(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(gateWithExpiry(t, time.Now().Add(5*24*time.Hour)))

	admin := &models.User{ID: 2, Email: "admin@acme.test"}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{admin}, int64(1), nil)
	ms.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{{Name: "admin"}}, nil)
	// Already an unread license-expiry reminder → must not re-create.
	ms.On("ListNotifications", ctx, uint(2), true, 100).
		Return([]*models.Notification{{ID: 9, Type: NotificationLicenseExpiry}}, nil)

	n, err := c.ScanLicenseExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	ms.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}

func TestScanLicenseExpiry_SkipsProjectScopedAdmin(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(gateWithExpiry(t, time.Now().Add(5*24*time.Hour)))

	// project_admin is project-scoped, not an install-wide admin → not a license recipient.
	user := &models.User{ID: 3, Email: "padmin@acme.test"}
	ms.On("ListUsers", ctx, mock.Anything).Return([]*models.User{user}, int64(1), nil)
	ms.On("GetUserRoles", ctx, uint(3)).Return([]*models.Role{{Name: "project_admin"}}, nil)

	n, err := c.ScanLicenseExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	ms.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}
