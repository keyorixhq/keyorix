package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeConnector struct {
	name string
	val  string
	err  error
}

func (f fakeConnector) Name() string { return f.name }
func (f fakeConnector) Type() string { return "fake" }
func (f fakeConnector) GetSecret(_ context.Context, _ string) (string, error) {
	return f.val, f.err
}

func connectTestCore(t *testing.T, conns ...connect.Connector) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms}
	if len(conns) > 0 {
		c.SetConnectManager(connect.NewManager(conns))
	}
	return c, ms
}

func TestReadFederatedSecret_Success(t *testing.T) {
	c, ms := connectTestCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	require.True(t, c.ConnectEnabled())

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "prod/db")
	require.NoError(t, err)
	assert.Equal(t, "v3ry-secret", val)
	// The read is audited.
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestReadFederatedSecret_UnknownConnector(t *testing.T) {
	c, _ := connectTestCore(t, fakeConnector{name: "aws", val: "x"})
	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "nope", "ref")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown connector")
}

func TestReadFederatedSecret_DisabledWhenNoManager(t *testing.T) {
	c := &KeyorixCore{storage: new(MockStorage)}
	assert.False(t, c.ConnectEnabled())
	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestReadFederatedSecret_BackendErrorAudited(t *testing.T) {
	c, ms := connectTestCore(t, fakeConnector{name: "aws", err: errors.New("AccessDenied")})
	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.Error(t, err)
	// A failed read is still audited (with FAILED in the description).
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// TestReadFederatedSecret_MachineIdentityAuditedAsMachine proves a machine-identity
// connect-read is attributed on the audit event as ActorTypeMachine (ADR-023), not
// silently defaulted to "user" — even when the caller passes a bare, untagged
// context.Background() (i.e. WITHOUT the transport layer having already called
// core.WithActorType). ReadFederatedSecret must stamp actorType itself rather than
// trust that upstream middleware tagged the context.
func TestReadFederatedSecret_MachineIdentityAuditedAsMachine(t *testing.T) {
	ms := new(MockStorage)
	var got *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e
		return true
	})).Return(nil)
	c := &KeyorixCore{storage: ms}
	c.SetConnectManager(connect.NewManager([]connect.Connector{fakeConnector{name: "aws", val: "v"}}))

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeMachine, 42, "aws", "ref")
	require.NoError(t, err)
	assert.Equal(t, "v", val)
	require.NotNil(t, got)
	assert.Equal(t, ActorTypeMachine, got.ActorType, "machine-identity read must be actored as machine_identity, not default to user")
	require.NotNil(t, got.UserID)
	assert.EqualValues(t, 42, *got.UserID)
}

// TestReadFederatedSecret_UserAuditedAsUser is the counterpart: an ordinary user read
// is attributed as ActorTypeUser.
func TestReadFederatedSecret_UserAuditedAsUser(t *testing.T) {
	ms := new(MockStorage)
	var got *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e
		return true
	})).Return(nil)
	c := &KeyorixCore{storage: ms}
	c.SetConnectManager(connect.NewManager([]connect.Connector{fakeConnector{name: "aws", val: "v"}}))

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 7, "aws", "ref")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, ActorTypeUser, got.ActorType)
}
