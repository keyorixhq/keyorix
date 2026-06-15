package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatComplianceDigest(t *testing.T) {
	p := &CompliancePosture{
		AccessGovernance: AccessGovernancePosture{ProjectsOverdue: 2, SoDViolations: 1, DormantRoleGrants: 3},
		Rotation:         RotationPosture{Overdue: 1, DueSoon: 2},
		Identity:         IdentityPosture{SecondFactorPercent: 80},
		Classification:   ClassificationPosture{TotalSecrets: 10, Unclassified: 4},
		Anomalies:        AnomaliesPosture{Unacknowledged: 3, HighSeverityOpen: 1},
		Risk:             RiskPosture{ActiveExceptions: 2, ExpiringSoon: 1},
		LegalHold:        LegalHoldPosture{Active: true, Reason: "INC-7"},
	}
	controls := []ControlState{
		{Name: "Tamper-evident audit trail", Status: ControlStatusPass},
		{Name: "Access recertification", Status: ControlStatusGap},
		{Name: "Secret rotation", Status: ControlStatusGap},
	}
	title, body := formatComplianceDigest(p, controls)
	assert.Contains(t, title, "2 gaps across 3 controls")
	assert.Contains(t, body, "1 pass, 2 gap")
	assert.Contains(t, body, "Access recertification, Secret rotation")
	assert.Contains(t, body, "2 project(s) overdue")
	assert.Contains(t, body, "4 of 10 secrets unclassified")
	assert.Contains(t, body, "2 active exception(s)")
	assert.Contains(t, body, "legal hold is ACTIVE")
}

func TestFormatComplianceDigest_AllPass(t *testing.T) {
	p := &CompliancePosture{Identity: IdentityPosture{SecondFactorPercent: 100}}
	controls := []ControlState{{Name: "X", Status: ControlStatusPass}, {Name: "Y", Status: ControlStatusPass}}
	title, _ := formatComplianceDigest(p, controls)
	assert.Contains(t, title, "2/2 controls pass")
}

func TestSendComplianceDigest_NoSinkNoOp(t *testing.T) {
	c := &KeyorixCore{storage: new(MockStorage), now: time.Now}
	sent, err := c.SendComplianceDigest(context.Background())
	require.NoError(t, err)
	assert.False(t, sent, "no notification channel → nothing delivered")
}

func TestSendComplianceDigest_Broadcasts(t *testing.T) {
	c, db, _ := newEvidenceExportCore(t) // real store, empty deployment
	sink := &fakeSink{}
	c.SetNotificationSink(sink)
	sent, err := c.SendComplianceDigest(context.Background())
	require.NoError(t, err)
	assert.True(t, sent)
	require.Len(t, sink.events, 1)
	assert.Equal(t, "compliance.digest", sink.events[0].Type)
	assert.Contains(t, sink.events[0].Title, "compliance digest")

	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "compliance.digest_sent").Count(&n).Error)
	assert.Equal(t, int64(1), n)
}
