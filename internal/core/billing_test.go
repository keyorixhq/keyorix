package core

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// billingLicensedGate builds a license gate that grants license.FeatureBilling,
// mirroring gateWithExpiry (license_expiry_test.go) but for the billing feature
// specifically rather than an expiry scenario.
func billingLicensedGate(t *testing.T) *license.Gate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	token, err := license.Issue(license.License{
		Licensee: "ACME GmbH", Plan: "enterprise", Features: []string{license.FeatureBilling},
		IssuedAt: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyID: "license-billing",
	}, priv)
	require.NoError(t, err)
	reg := trust.NewRegistry()
	require.NoError(t, reg.Add(trust.PurposeLicense, "license-billing", pub))
	return license.NewGate(token, reg, "", time.Hour)
}

func TestGenerateBillingReport_Unlicensed_ReturnsError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms) // no gate set → nil gate → community baseline, no features

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	report, err := c.GenerateBillingReport(ctx, from, to, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "commercial license")
	ms.AssertNotCalled(t, "GetBillingReport", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestGenerateBillingReport_FromEqualsTo_ReturnsError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	same := time.Now()

	report, err := c.GenerateBillingReport(ctx, same, same, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "must be before")
	ms.AssertNotCalled(t, "GetBillingReport", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestGenerateBillingReport_FromAfterTo_ReturnsError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	from := time.Now()
	to := from.Add(-time.Hour) // inverted

	report, err := c.GenerateBillingReport(ctx, from, to, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "must be before")
	ms.AssertNotCalled(t, "GetBillingReport", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestGenerateBillingReport_WindowExceedsMax_ReturnsError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(366*24*time.Hour + time.Nanosecond) // just over the max

	report, err := c.GenerateBillingReport(ctx, from, to, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "exceeds the maximum")
	ms.AssertNotCalled(t, "GetBillingReport", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestGenerateBillingReport_WindowExactly366Days_Allowed(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(366 * 24 * time.Hour) // exactly the boundary, not over

	want := &storage.BillingReport{From: from, To: to}
	ms.On("GetBillingReport", ctx, from, to, []uint(nil)).Return(want, nil)

	got, err := c.GenerateBillingReport(ctx, from, to, nil)
	require.NoError(t, err)
	assert.Same(t, want, got)
	ms.AssertExpectations(t)
}

func TestGenerateBillingReport_Delegates_HappyPath(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	// Deliberately use a non-UTC location to confirm the core layer normalizes
	// to UTC before delegating to storage, per the function's doc comment.
	loc := time.FixedZone("UTC-5", -5*60*60)
	from := time.Date(2025, 6, 1, 10, 0, 0, 0, loc)
	to := time.Date(2025, 6, 8, 10, 0, 0, 0, loc)
	projectIDs := []uint{1, 2, 3}

	want := &storage.BillingReport{
		From:     from.UTC(),
		To:       to.UTC(),
		Projects: []storage.BillingProjectStat{{ProjectID: 1}},
	}
	ms.On("GetBillingReport", ctx, from.UTC(), to.UTC(), projectIDs).Return(want, nil)

	got, err := c.GenerateBillingReport(ctx, from, to, projectIDs)
	require.NoError(t, err)
	assert.Same(t, want, got)
	ms.AssertExpectations(t)

	// The call the mock recorded must have received UTC-normalized times, not
	// the original non-UTC location.
	call := ms.Calls[0]
	assert.Equal(t, time.UTC, call.Arguments.Get(1).(time.Time).Location())
	assert.Equal(t, time.UTC, call.Arguments.Get(2).(time.Time).Location())
}

func TestGenerateBillingReport_PropagatesStorageError(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetLicenseGate(billingLicensedGate(t))

	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	storageErr := assert.AnError
	ms.On("GetBillingReport", ctx, from.UTC(), to.UTC(), []uint(nil)).Return(nil, storageErr)

	got, err := c.GenerateBillingReport(ctx, from, to, nil)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, storageErr)
}
