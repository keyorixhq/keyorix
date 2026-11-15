package handlers

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #4230 part 1, server half: GET /audit/verify for a sealed chain carries the
// seal text in state_reason AND a non-empty reason, so a client that renders
// `reason` (the CLI prints "FAILED ...: <reason>") never shows an empty one.
// Sealed is not valid, but the walk did not fail: first_broken_id stays absent.
func TestAuditVerifyResponse_SealedCarriesStateReasonAndReason(t *testing.T) {
	const seal = "the chain was sealed at event 41 (key change); rows since the seal verify"
	resp := auditVerifyResponse(&core.AuditVerifyReport{
		Status:      core.AuditVerifyStatusSealed,
		Mode:        core.AuditVerifyModeFull,
		StateReason: seal,
	})
	assert.Equal(t, "sealed", resp["status"])
	assert.Equal(t, false, resp["valid"])
	assert.Equal(t, seal, resp["state_reason"])
	assert.Equal(t, seal, resp["reason"])
	assert.NotContains(t, resp, "first_broken_id", "a sealed chain has no broken row")
}

// A sealed report whose state text is empty still gets a non-empty reason.
func TestAuditVerifyResponse_SealedWithoutStateTextStillHasReason(t *testing.T) {
	resp := auditVerifyResponse(&core.AuditVerifyReport{Status: core.AuditVerifyStatusSealed, Mode: core.AuditVerifyModeFull})
	reason, ok := resp["reason"].(string)
	require.True(t, ok, "reason must be present for status sealed")
	assert.NotEmpty(t, reason)
}

// Calibration (green side): valid and not_proven keep their shape: no reason.
func TestAuditVerifyResponse_ValidHasNoReason(t *testing.T) {
	resp := auditVerifyResponse(&core.AuditVerifyReport{Status: core.AuditVerifyStatusValid, Valid: true, Mode: core.AuditVerifyModeFull})
	assert.NotContains(t, resp, "reason")
}
