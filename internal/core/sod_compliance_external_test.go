package core_test

import (
	"context"
	"testing"
	"time"

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

// #170: an approved, active risk exception matching the violation's Reference
// suppresses it from the posture's SoDViolations count; before approval (or with a
// non-matching reference) the violation still counts — a governed exception must
// actually be granted before it does anything.
func TestSoD_SuppressedByApprovedRiskException(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.SoDPolicy{}, &models.AuditEvent{}, &models.AccessReviewCampaign{},
		&models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
		&models.RiskException{},
	))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, nil) // editor → secrets.write + users.read
	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "write-vs-useradmin", "", "secrets.write", "users.read")
	require.NoError(t, err)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, p.AccessGovernance.SoDViolations, 1, "unaccepted, the violation counts")

	violations, err := h.CoreService.DetectSoDViolations(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, violations)
	ref := violations[0].Reference
	require.NotEmpty(t, ref, "every violation must carry a stable reference to except against")

	// Create the exception — NOT yet approved. Still counts.
	exc, err := h.CoreService.CreateRiskException(ctx, 1, "accept for Q3 migration", "sod", ref, "temporary", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)
	p, err = h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, p.AccessGovernance.SoDViolations, 1, "an unapproved exception must not suppress anything yet")

	// A different actor approves it — now suppressed.
	require.NoError(t, h.CoreService.ApproveRiskException(ctx, 2, exc.ID))
	p, err = h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, p.AccessGovernance.SoDViolations, "an approved, matching-reference exception suppresses the violation")
}
