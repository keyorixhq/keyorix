package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
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

// #157: a third-party system.write holder who neither placed the hold nor holds an
// admin-tier role must not be able to lift it — only the placer or an admin-tier
// principal may. The denial is itself audited, and the hold stays active.
func TestLegalHold_LiftDeniedForThirdParty(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.LegalHold{}, &models.AuditEvent{}, &models.User{}, &models.UserRole{}))
	ctx := context.Background()

	_, err := h.CoreService.PlaceLegalHold(ctx, 1, "litigation INC-9")
	require.NoError(t, err)

	// Actor 9 holds no role at all — neither the placer nor admin-tier.
	err = h.CoreService.LiftLegalHold(ctx, 9)
	require.Error(t, err, "a non-placer, non-admin actor must not be able to lift the hold")

	active, aerr := h.CoreService.IsLegalHoldActive(ctx)
	require.NoError(t, aerr)
	assert.True(t, active, "the hold must remain active after a denied lift attempt")

	// The denial is audited distinctly (event still EventLegalHoldLifted per the
	// implementation, but with Success=false — verify a failed attempt was recorded).
	var failed int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ? AND success = ?", core.EventLegalHoldLifted, false).Count(&failed).Error)
	assert.Equal(t, int64(1), failed, "the denied lift attempt must be audited")

	// A DIFFERENT admin-tier principal (not the placer) may still lift it.
	h.AssignUserRole(t, 20, 2, nil) // role 2 = admin (global)
	require.NoError(t, h.CoreService.LiftLegalHold(ctx, 20))
	active, aerr = h.CoreService.IsLegalHoldActive(ctx)
	require.NoError(t, aerr)
	assert.False(t, active, "an admin-tier non-placer must be able to lift the hold")
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
