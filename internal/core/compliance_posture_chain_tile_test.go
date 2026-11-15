// compliance_posture_chain_tile_test.go — #4186: the audit-integrity tile reported
// the count verified at the last check (13) while `audit verify` walked 259. The
// posture now carries the check's head id, and, once the check is stale, the
// newest event id from the cheap head lookup, so the tile can say how many
// events are newer than what was verified.
package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuditCheckStale(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Second)
	old := now.Add(-time.Hour)
	assert.False(t, auditCheckStale(&AuditVerifyReport{Mode: AuditVerifyModeIncremental, LastCheckedAt: &fresh}, now))
	assert.True(t, auditCheckStale(&AuditVerifyReport{Mode: AuditVerifyModeIncremental, LastCheckedAt: &old}, now))
	assert.True(t, auditCheckStale(&AuditVerifyReport{Mode: AuditVerifyModeIncremental}, now), "no recorded check is stale")
	assert.False(t, auditCheckStale(&AuditVerifyReport{Mode: AuditVerifyModeFull}, now), "a full walk made for this request is current")
}

func TestApplyAuditIntegrityPosture_StaleCheckShowsHeadAndNewerEvents(t *testing.T) {
	checked := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	report := &AuditVerifyReport{
		Status: AuditVerifyStatusValid, Valid: true, Mode: AuditVerifyModeIncremental,
		ChainedEvents: 13, HeadID: 13, Checkpointed: true, LastCheckedAt: &checked,
	}

	t.Run("stale with newer events", func(t *testing.T) {
		p := &CompliancePosture{}
		applyAuditIntegrityPosture(p, &complianceSnapshot{auditChain: report, auditStale: true, auditLatestID: 259})
		ai := p.AuditIntegrity
		assert.EqualValues(t, 13, ai.ChainedEvents, "the verified count is not rewritten")
		assert.EqualValues(t, 13, ai.HeadID)
		assert.True(t, ai.Stale)
		assert.EqualValues(t, 259, ai.LatestEventID)
		assert.EqualValues(t, 246, ai.EventsSinceCheck)
		assert.Equal(t, &checked, ai.LastCheckedAt)
	})

	t.Run("fresh check reads nothing extra", func(t *testing.T) {
		p := &CompliancePosture{}
		applyAuditIntegrityPosture(p, &complianceSnapshot{auditChain: report})
		ai := p.AuditIntegrity
		assert.False(t, ai.Stale)
		assert.Zero(t, ai.LatestEventID)
		assert.Zero(t, ai.EventsSinceCheck)
		assert.EqualValues(t, 13, ai.HeadID)
	})
}
