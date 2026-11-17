package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

// POSTURE-CONSUMERS-NOV-1 item 1: the gRPC posture carries the degraded
// break-glass count the REST posture returns.
func TestCompliancePostureToProto_CarriesDegradedActivations(t *testing.T) {
	p := &core.CompliancePosture{GeneratedAt: time.Unix(1, 0)}
	p.EmergencyAccess.TotalActivations = 5
	p.EmergencyAccess.DegradedActivations = 3
	out := compliancePostureToProto(p)
	assert.Equal(t, int32(3), out.GetEmergencyAccess().GetDegradedActivations())
	assert.Equal(t, int32(5), out.GetEmergencyAccess().GetTotalActivations())
}
