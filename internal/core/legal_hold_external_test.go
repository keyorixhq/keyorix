package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal hold can be placed once and lifted once; while active IsLegalHoldActive
// reports true (the purge jobs gate on it).
func TestLegalHold_PlaceAndLift(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.LegalHold{}, &models.AuditEvent{}))
	ctx := context.Background()

	// No hold initially.
	active, err := h.CoreService.IsLegalHoldActive(ctx)
	require.NoError(t, err)
	assert.False(t, active)

	// A reason is required.
	_, err = h.CoreService.PlaceLegalHold(ctx, 1, "")
	require.Error(t, err)

	// Place a hold.
	hold, err := h.CoreService.PlaceLegalHold(ctx, 1, "litigation INC-7")
	require.NoError(t, err)
	assert.False(t, hold.Released)

	active, err = h.CoreService.IsLegalHoldActive(ctx)
	require.NoError(t, err)
	assert.True(t, active, "purges are now blocked")

	// A second hold is refused while one is active.
	_, err = h.CoreService.PlaceLegalHold(ctx, 1, "another")
	require.Error(t, err)

	// Lift it.
	require.NoError(t, h.CoreService.LiftLegalHold(ctx, 1))
	active, err = h.CoreService.IsLegalHoldActive(ctx)
	require.NoError(t, err)
	assert.False(t, active)

	// Lifting again (none active) is refused.
	require.Error(t, h.CoreService.LiftLegalHold(ctx, 1))
}

// The compliance posture reflects an active legal hold.
func TestLegalHold_SurfacesInPosture(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.LegalHold{}, &models.AuditEvent{}, &models.SecretNode{}, &models.AnomalyAlert{},
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{},
		&models.RotationPolicy{}, &models.SoDPolicy{},
	))
	ctx := context.Background()

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.False(t, p.LegalHold.Active)

	_, err = h.CoreService.PlaceLegalHold(ctx, 1, "investigation")
	require.NoError(t, err)

	p, err = h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.True(t, p.LegalHold.Active)
	assert.Equal(t, "investigation", p.LegalHold.Reason)
}
