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

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "compliance.digest_sent").Find(&events).Error)
	require.Len(t, events, 1)
	require.NotNil(t, events[0].Success)
	assert.True(t, *events[0].Success, "the digest genuinely was delivered — the audit event must say so")
}

// TestSendComplianceDigest_NoChannelAcceptsIt is a regression test for #221: an
// email-only deployment with no configured broadcast destination used to have
// Deliver() silently drop the event AND still get an audit event claiming
// "compliance digest broadcast to notification channels" — a false positive an
// operator could never distinguish from an actual, successful send. The sink here
// stands in for exactly that case (fakeSink.refuse mirrors EmailSink.Deliver
// returning false with no recipient/no broadcast_to configured): the audit event
// must now say the broadcast was NOT delivered, and a log line must make the gap
// discoverable.
func TestSendComplianceDigest_NoChannelAcceptsIt(t *testing.T) {
	c, db, _ := newEvidenceExportCore(t) // real store, empty deployment
	sink := &fakeSink{refuse: true}
	c.SetNotificationSink(sink)

	var sent bool
	var err error
	logged := captureLog(t, func() {
		sent, err = c.SendComplianceDigest(context.Background())
	})
	require.NoError(t, err)
	assert.False(t, sent, "no channel accepted the broadcast — the caller must be told delivery did not happen")
	assert.Empty(t, sink.events, "the sink never actually accepted the event")
	assert.Contains(t, logged, "compliance digest", "a no-op broadcast must be logged, not silent")

	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "compliance.digest_sent").Find(&events).Error)
	require.Len(t, events, 1, "the attempt is still audited")
	require.NotNil(t, events[0].Success)
	assert.False(t, *events[0].Success, "delivery never happened — the audit event must not claim success (#221)")
}
