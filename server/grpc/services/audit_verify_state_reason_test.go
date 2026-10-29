package services

// CORE-GRPC-TAILS-1 item 3: VerifyAuditChainResponse carries state_reason, so a
// gRPC client that sees status "sealed" is told which accepted audit loss it is.
// Before, the field did not exist: status sealed arrived with no explanation
// (AUDIT-ACCEPT-LOSS-1 report).

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestVerifyAuditChainResponse_CarriesStateReason(t *testing.T) {
	const sealReason = "audit chain sealed: 1 accepted loss (ids 3), accepted by ops-oncall"
	cases := []struct {
		name   string
		report core.AuditVerifyReport
	}{
		{"sealed names the accepted loss", core.AuditVerifyReport{
			Status: core.AuditVerifyStatusSealed, Mode: core.AuditVerifyModeIncremental,
			Valid: false, StateReason: sealReason,
		}},
		{"not proven keeps both reasons", core.AuditVerifyReport{
			Status: core.AuditVerifyStatusNotProven, Mode: core.AuditVerifyModeIncremental,
			NotProvenReason: "no completed full verification yet",
			StateReason:     "the persisted state is older than the signed checkpoint",
		}},
		{"valid has none", core.AuditVerifyReport{
			Status: core.AuditVerifyStatusValid, Mode: core.AuditVerifyModeIncremental, Valid: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyAuditChainResponse(&tc.report)
			assert.Equal(t, tc.report.Status, got.GetStatus())
			assert.Equal(t, tc.report.Valid, got.GetValid())
			assert.Equal(t, tc.report.StateReason, got.GetStateReason())
			assert.Equal(t, tc.report.NotProvenReason, got.GetNotProvenReason())
		})
	}
}
