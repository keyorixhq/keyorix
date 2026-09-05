// machine_credential_classify_audit_test.go — #1714 invariant guard.
//
// UpdateMachineIdentityCredentialProxy (server/http/handlers/machine_identities_proxy.go)
// used to call storage.UpdateMachineIdentityCredential directly after a raw
// fetch+patch-Classification-only: no authz-ceiling issue (already narrowed,
// G80 overnight campaign), but zero audit trail -- a system.write holder could
// silently reclassify a machine credential's data-sensitivity label with no
// record of the change. The fix routes the proxy through
// ClassifyMachineTokenByID, which performs the fetch, the mutation, and the
// machine_identity.token_classified audit write as one unit.
//
// This test asserts the invariant directly against ClassifyMachineTokenByID,
// the ONLY route into this mutation for a caller that has just a credential
// ID: a real classification change produces exactly one audit event, and a
// no-op (new value equals the current one) produces none, matching
// ClassifyMachineToken's own no-op short-circuit.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClassifyMachineTokenByID_RealChange_WritesOneAuditEvent(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	const machineID = uint(9)
	const projectID = uint(3)
	cred := &models.MachineIdentityCredential{ID: 55, MachineIdentityID: machineID, Classification: "internal"}
	machine := &models.MachineIdentity{ID: machineID, ProjectID: projectID}

	ms.On("GetMachineIdentityCredentialByID", ctx, cred.ID).Return(cred, nil)
	ms.On("GetMachineIdentity", ctx, machineID).Return(machine, nil)
	ms.On("UpdateMachineIdentityCredential", ctx, mock.MatchedBy(func(c *models.MachineIdentityCredential) bool {
		return c.Classification == "confidential"
	})).Return(nil)

	var captured *models.AuditEvent
	ms.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	require.NoError(t, c.ClassifyMachineTokenByID(ctx, cred.ID, "confidential"))

	ms.AssertNumberOfCalls(t, "UpdateMachineIdentityCredential", 1)
	ms.AssertNumberOfCalls(t, "LogAuditEvent", 1)
	require.NotNil(t, captured, "reclassifying a machine credential must write an audit event")
	assert.Equal(t, "machine_identity.token_classified", captured.EventType)
	require.NotNil(t, captured.ProjectID)
	assert.Equal(t, projectID, *captured.ProjectID)
}

func TestClassifyMachineTokenByID_NoOp_WritesNoAuditEvent(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	cred := &models.MachineIdentityCredential{ID: 56, MachineIdentityID: 9, Classification: "internal"}
	ms.On("GetMachineIdentityCredentialByID", ctx, cred.ID).Return(cred, nil)

	require.NoError(t, c.ClassifyMachineTokenByID(ctx, cred.ID, "internal"))

	ms.AssertNumberOfCalls(t, "UpdateMachineIdentityCredential", 0)
	ms.AssertNumberOfCalls(t, "LogAuditEvent", 0)
}

func TestClassifyMachineTokenByID_InvalidClassification_Rejected(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ctx := context.Background()

	err := c.ClassifyMachineTokenByID(ctx, 1, "super-secret")
	require.Error(t, err)
	ms.AssertNotCalled(t, "GetMachineIdentityCredentialByID", mock.Anything, mock.Anything)
}
