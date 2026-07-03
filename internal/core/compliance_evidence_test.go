// compliance_evidence_test.go — #362: GenerateComplianceEvidence independently
// re-queries several of the same signals GetCompliancePosture already rolled up
// (risk exceptions, SoD violations, rotation status, per-project campaigns/
// break-glass) rather than reusing the posture's result — so each of those had its
// OWN copy of the #136 fail-open bug shape. These tests pin that a query failure on
// the EVIDENCE PACK'S OWN copy of each query now flips ev.Posture.Degraded (via the
// shared posture.degrade helper) instead of silently leaving the archivable,
// timestamped evidence pack's slice at its pre-initialized empty value —
// indistinguishable from "queried, found genuinely none".
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #362: risk_exceptions — models.RiskException deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnRiskExceptionsQueryError(t *testing.T) {
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err, "a single failed evidence sub-query must not abort the whole pack")

	assert.Empty(t, ev.RiskExceptions, "the field itself still reads as its pre-initialized empty value")
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded, "a failed risk-exceptions query must flip the shared Degraded signal")
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:risk_exceptions"), "got %v", ev.Posture.DegradedReasons)
}

// #362: sod_violations — models.SoDPolicy deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnSoDViolationsQueryError(t *testing.T) {
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.SoDViolations)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:sod_violations"), "got %v", ev.Posture.DegradedReasons)
}

// #362: rotation_overdue — models.RotationPolicy deliberately not migrated. Before the
// fix this was the permanently-archivable evidence pack's own copy of #358.
func TestGenerateComplianceEvidence_DegradesOnRotationOverdueQueryError(t *testing.T) {
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.RotationOverdue)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:rotation_overdue"), "got %v", ev.Posture.DegradedReasons)
}

// #362: campaigns, per project — models.AccessReviewCampaign deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnCampaignsQueryError(t *testing.T) {
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}, &models.UserRole{}, &models.GroupRole{}, &models.AuditEvent{}))

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.Campaigns)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:campaigns:project=1"), "got %v", ev.Posture.DegradedReasons)
}

// #362: break-glass register, per project — models.BreakGlassActivation deliberately
// not migrated. The evidence pack's break-glass register hiding an active emergency
// activation is the most severe of this family.
func TestGenerateComplianceEvidence_DegradesOnBreakGlassQueryError(t *testing.T) {
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.UserRole{}, &models.GroupRole{}, &models.AuditEvent{}))

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.BreakGlass, "the register must not silently read as empty (= no emergency access) on a query error")
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:break_glass:project=1"), "got %v", ev.Posture.DegradedReasons)
}
