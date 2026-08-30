// audit_userid_machine_principal_test.go — guards #1626: emitAudit is the single
// choke point (#1530) every audit writer funnels through, and it must never let
// a machine principal's raw ID reach AuditEvent.UserID, a human-attribution
// column that collides with the same User.ID space #1623 fixed for persisted
// model columns. Eight callers (SetSecretAutoRotate, CreateConnectRefGrant/
// DeleteConnectRefGrant, AddSecretDependency/RemoveSecretDependency,
// transferOwnership, RevokeAllPersonalAccessTokensForUser/
// DeleteSessionsForUserExcept) built userID from a PrincipalID()-derived value
// and handed it to writeAuditEventFull/writeAuditEventDiff/writeAuditEventFailed
// -- all of which funnel through emitAudit already (TestDirectLogAuditEventCallersAreSafe,
// #1530's existing guard, confirms nothing else reaches storage.LogAuditEvent), so
// the fix and the guard both belong at that one point, not at eight call sites.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestEmitAudit_MachineActorNeverGetsUserID pins the choke-point invariant
// directly: any event already actor-typed "machine_identity" must have UserID
// cleared by emitAudit, regardless of what the caller set it to -- the same
// unconditional guarantee emitAudit already gives MachineIdentityID (#1530),
// now given to UserID in the opposite direction.
//
// Verified red per standing practice: temporarily removed the `event.UserID =
// nil` line from emitAudit (service.go), confirmed this test failed with
// UserID still holding the machine's raw ID, then restored it.
func TestEmitAudit_MachineActorNeverGetsUserID(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := WithMachineActor(context.Background(), 77)

	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.UserID == nil && e.MachineIdentityID != nil && *e.MachineIdentityID == 77
	})).Return(nil)

	staleUserID := uint(42) // a machine's raw PrincipalID(), the exact #1626 mistake
	c.emitAudit(ctx, &models.AuditEvent{
		EventType: "test.probe",
		ActorType: ActorTypeMachine,
		UserID:    &staleUserID,
	})

	store.AssertExpectations(t)
}

// Positive control: a genuine human-actored event is untouched by the #1626
// correction -- UserID survives exactly as the caller set it, and
// MachineIdentityID stays nil. The fix must not widen into "always clear
// UserID"; it is conditioned on ActorType == machine specifically.
func TestEmitAudit_HumanActorKeepsUserID(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.UserID != nil && *e.UserID == 9 && e.MachineIdentityID == nil
	})).Return(nil)

	humanID := uint(9)
	c.emitAudit(ctx, &models.AuditEvent{
		EventType: "test.probe",
		ActorType: ActorTypeUser,
		UserID:    &humanID,
	})

	store.AssertExpectations(t)
}

// TestAddSecretDependency_AuditEventUserIDNotMachinePrincipal reproduces #1626
// end-to-end against one of the eight real call sites (not just emitAudit in
// isolation): a machine identity's own AddSecretDependency audit write
// (EventSecretDependencyAdded, secret_dependencies.go) must not carry the
// machine's raw PrincipalID in AuditEvent.UserID, even though
// AddSecretDependency's OWN model-column attribution (CreatedBy/
// CreatedByMachineIdentityID, #1623/#1625) is already correct -- this is the
// audit trail for the same action, a separate write, previously not covered by
// that fix. ctx is tagged with WithActorType/WithMachineActor exactly as the
// real HTTP auth middleware tags a machine-authenticated request's context
// (buildRequestContext, server/middleware/auth.go) -- AddSecretDependency's own
// actorKind PARAMETER only drives AuthorizeSecretPrincipal, not the audit
// writer's context-derived ActorType/MachineIdentityID stamp, so a bare
// context.Background() here would not reproduce the real bug.
func TestAddSecretDependency_AuditEventUserIDNotMachinePrincipal(t *testing.T) {
	const machineID = uint(7)
	ctx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), machineID)
	c, db := newDepCore(t)

	perm := &models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
	require.NoError(t, db.Create(perm).Error)
	role := &models.Role{Name: "secret-writer-audit-probe"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.MachineIdentity{ID: machineID, ProjectID: 1, Name: "ci", State: "active"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: machineID, RoleID: role.ID, ProjectID: 1, EnvironmentID: 1}).Error)

	dependent := mkSecret(t, db, 1, "audit-probe-app")
	dependsOn := mkSecret(t, db, 1, "audit-probe-db")

	_, err := c.AddSecretDependency(ctx, ActorTypeMachine, machineID, dependent, dependsOn, "machine-created", machineID)
	require.NoError(t, err)

	var events []*models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventSecretDependencyAdded).Find(&events).Error)
	require.Len(t, events, 1, "AddSecretDependency must have produced exactly one audit event")
	event := events[0]

	assert.Equal(t, ActorTypeMachine, event.ActorType, "sanity: the event must be actor-typed as a machine")
	assert.Nil(t, event.UserID,
		"CEILING VIOLATED (#1626): a machine identity's AddSecretDependency produced an audit event "+
			"with the machine's raw ID sitting in UserID, a human-attribution column")
	require.NotNil(t, event.MachineIdentityID)
	assert.Equal(t, machineID, *event.MachineIdentityID, "the attributed machine identity must be the one that actually made the call")
}
