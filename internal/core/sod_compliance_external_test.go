package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SoD violations surface in both the compliance posture (as a count) and the
// evidence pack (as the toxic-combination register).
func TestSoD_SurfacesInPostureAndEvidence(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.SoDPolicy{}, &models.AuditEvent{}, &models.AccessReviewCampaign{},
		&models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil) // editor → secrets.write + users.read
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, p.AccessGovernance.SoDViolations, 1, "alice's editor role violates the policy")

	ev, err := h.CoreService.GenerateComplianceEvidence(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, ev.SoDViolations)
	assert.Equal(t, "write-vs-useradmin", ev.SoDViolations[0].PolicyName)
	assert.Equal(t, "alice", ev.SoDViolations[0].Username)
}
