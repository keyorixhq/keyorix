// connect_delegation_test.go covers connectorHasAnyDelegationForActor
// (connect.go) -- used by ConnectReadableConnectorNames to decide whether a
// connector shows up in a listing. Previously untested: the storage-error
// branch, the no-grants-at-all short-circuit, actorRoleIDs' own error, an
// active grant matching the actor's roles, and an active grant NOT matching
// (wrong role) plus an expired grant that WOULD match by role alone.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConnectorHasAnyDelegationForActor_ListGrantsError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.Error(t, err)
	assert.False(t, ok)
}

func TestConnectorHasAnyDelegationForActor_NoGrants(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return([]*models.ConnectRefGrant{}, nil)
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.NoError(t, err)
	assert.False(t, ok)
	ms.AssertNotCalled(t, "GetMachineRoles", mock.Anything, mock.Anything)
}

func TestConnectorHasAnyDelegationForActor_ActorRoleIDsError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return(
		[]*models.ConnectRefGrant{{ID: 1, RoleID: 5, Connector: "db-prod"}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.Error(t, err)
	assert.False(t, ok)
}

func TestConnectorHasAnyDelegationForActor_MatchingActiveGrant_True(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return(
		[]*models.ConnectRefGrant{{ID: 1, RoleID: 5, Connector: "db-prod", RefPrefix: ""}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 5, Name: "db-reader"}}, nil)
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestConnectorHasAnyDelegationForActor_RoleMismatch_False(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return(
		[]*models.ConnectRefGrant{{ID: 1, RoleID: 5, Connector: "db-prod", RefPrefix: ""}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 6, Name: "unrelated"}}, nil)
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestConnectorHasAnyDelegationForActor_ExpiredGrant_False(t *testing.T) {
	ms := new(MockStorage)
	past := time.Now().Add(-time.Hour)
	ms.On("ListConnectRefGrantsByConnector", mock.Anything, "db-prod").Return(
		[]*models.ConnectRefGrant{{ID: 1, RoleID: 5, Connector: "db-prod", RefPrefix: "", ExpiresAt: &past}}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 5, Name: "db-reader"}}, nil)
	c := NewKeyorixCore(ms)
	ok, err := c.connectorHasAnyDelegationForActor(context.Background(), ActorTypeMachine, 1, "db-prod")
	require.NoError(t, err)
	assert.False(t, ok, "an expired grant must not authorize even though the role matches")
}
