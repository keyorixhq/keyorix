package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findControl returns the control with the given id (or fails the test).
func findControl(t *testing.T, controls []ControlState, id string) ControlState {
	t.Helper()
	for _, c := range controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %q not found", id)
	return ControlState{}
}

// A fully-healthy posture yields all controls pass/not-configured, never a gap, and
// every control carries an ISO 27001 reference.
func TestEvaluateControls_HealthyPosture(t *testing.T) {
	p := &CompliancePosture{
		AuditIntegrity:   AuditIntegrityPosture{ChainVerified: true, Checkpointed: true, ChainedEvents: 100},
		AccessGovernance: AccessGovernancePosture{Projects: 3},
		Rotation:         RotationPosture{CoveredSecrets: 10},
		Identity:         IdentityPosture{ActiveUsers: 5, UsersWithSecondFactor: 5, SecondFactorPercent: 100},
		Classification:   ClassificationPosture{TotalSecrets: 10},
		Anomalies:        AnomaliesPosture{},
		Retention:        RetentionPosture{Enabled: true, AnomalyAlertsDays: 90},
	}
	controls := EvaluateControls(p)
	require.NotEmpty(t, controls)
	for _, c := range controls {
		assert.NotEqual(t, ControlStatusGap, c.Status, "healthy posture has no gaps: %s", c.ID)
		assert.NotEmpty(t, c.Frameworks.ISO27001, "control %s maps to an ISO 27001 clause", c.ID)
		assert.NotEmpty(t, c.Frameworks.ENS, "control %s maps to an ENS measure", c.ID)
		assert.NotEmpty(t, c.Name)
	}
	// Retention enabled → pass.
	assert.Equal(t, ControlStatusPass, findControl(t, controls, "data-retention").Status)
}

// Each unhealthy posture figure flips the matching control to a gap.
func TestEvaluateControls_GapsFromPosture(t *testing.T) {
	p := &CompliancePosture{
		AuditIntegrity: AuditIntegrityPosture{ChainVerified: false},
		AccessGovernance: AccessGovernancePosture{
			Projects: 4, ProjectsOverdue: 2, ProjectsNeverReviewed: 1, DormantRoleGrants: 3, SoDViolations: 1,
		},
		Rotation:       RotationPosture{Overdue: 2},
		Identity:       IdentityPosture{ActiveUsers: 5, UsersWithSecondFactor: 3, SecondFactorPercent: 60},
		Classification: ClassificationPosture{TotalSecrets: 10, Unclassified: 4},
		Anomalies:      AnomaliesPosture{Unacknowledged: 3, HighSeverityOpen: 1},
		Retention:      RetentionPosture{Enabled: false},
	}
	controls := EvaluateControls(p)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "audit-trail-integrity").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "access-recertification").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "dormant-access").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "separation-of-duties").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "second-factor").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "secret-rotation").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "data-classification").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "anomaly-detection").Status)
	// Retention unconfigured is "not configured", not a hard gap.
	assert.Equal(t, ControlStatusNotConfigured, findControl(t, controls, "data-retention").Status)
}

// Every ENS reference is a well-formed RD 311/2022 measure code: it names one of the
// three measure frameworks (org. / op. / mp.) so the matrix can't carry a typo'd or
// stray code that an auditor would reject.
func TestEvaluateControls_ENSMeasureCodesWellFormed(t *testing.T) {
	controls := EvaluateControls(&CompliancePosture{})
	validPrefix := func(code string) bool {
		for _, p := range []string{"org.", "op.", "mp."} {
			if strings.HasPrefix(code, p) {
				return true
			}
		}
		return false
	}
	for _, c := range controls {
		for _, code := range c.Frameworks.ENS {
			assert.True(t, validPrefix(code),
				"control %s has ENS code %q outside the org./op./mp. frameworks", c.ID, code)
		}
	}
}

func TestGetComplianceControls_SummaryTallies(t *testing.T) {
	c, _, _ := newEvidenceExportCore(t) // real in-memory store, empty deployment
	got, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(got.Controls), got.Summary.Total)
	assert.Equal(t, got.Summary.Total, got.Summary.Pass+got.Summary.Gap+got.Summary.NotConfigured)
	assert.False(t, got.GeneratedAt.IsZero())
}

// The supply-chain-integrity control reflects whether updates are verified against a
// pinned signing key: a signed release passes; an unsigned/source build is "not
// configured" (the control doesn't apply), never a gap.
func TestEvaluateControls_SupplyChainIntegrity(t *testing.T) {
	signed := EvaluateControls(&CompliancePosture{
		SupplyChain: SupplyChainPosture{UpdateSigningTrusted: true, TrustedUpdateKeys: 1, LicenseState: "active", LicenseValid: true},
	})
	sc := findControl(t, signed, "supply-chain-integrity")
	assert.Equal(t, ControlStatusPass, sc.Status)
	assert.Contains(t, sc.Detail, "1 pinned signing key")
	assert.Contains(t, sc.Frameworks.NIS2, "Art.21(2)(d)")

	unsigned := EvaluateControls(&CompliancePosture{SupplyChain: SupplyChainPosture{}})
	scu := findControl(t, unsigned, "supply-chain-integrity")
	assert.Equal(t, ControlStatusNotConfigured, scu.Status)
	assert.NotEqual(t, ControlStatusGap, scu.Status)
}
