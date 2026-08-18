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

// connectTestCore wires every connector as scope: platform by default (ADR-082) —
// a platform connector passes ownership for any caller in this branch, matching
// this suite's pre-ADR-082 assumption that any caller can reach a configured test
// connector. Tests that specifically exercise ownership/scope behavior use their
// own setup (see connect_ownership_test.go) instead of this helper.
func connectTestCore(t *testing.T, conns ...connect.Connector) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms}
	if len(conns) > 0 {
		c.SetConnectManager(connect.NewManager(conns))
		ownership := make(map[string]ConnectOwnership, len(conns))
		for _, conn := range conns {
			ownership[conn.Name()] = ConnectOwnership{Scope: "platform"}
		}
		c.SetConnectOwnership(ownership)
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
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms}
	assert.False(t, c.ConnectEnabled())
	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
	// ADR-082 branch 3: the disabled path is now audited too (previously silent).
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
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
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "platform"}})

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
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "platform"}})

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 7, "aws", "ref")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, ActorTypeUser, got.ActorType)
}

// TestConnectErrors_AreTypedSentinels proves the errors ReadFederatedSecret /
// CreateConnectRefGrant produce for their deliberately-crafted, safe outcomes are
// identifiable via errors.Is against the core package's sentinels (G50). This is
// what lets the HTTP layer's isSafeConnectError classify safe vs. unsafe errors by
// type instead of by substring-matching err.Error() against caller-influenced text.
func TestConnectErrors_AreTypedSentinels(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms}
	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectDisabled)

	c2, _ := connectTestCore(t, fakeConnector{name: "aws"})
	_, err = c2.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "nope", "ref")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectUnknownConnector)

	_, err = c2.CreateConnectRefGrant(context.Background(), 1, 0, "aws", "", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectRoleRequired)

	_, err = c2.CreateConnectRefGrant(context.Background(), 1, 5, "nope", "", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectUnknownConnector)
}

// TestReadFederatedSecret_AuditDescriptionRedactsRawUpstreamError is the G50
// regression test (detection_idea): a caller-influenced ref, echoed back by the
// upstream connector inside its own error text along with internal-looking detail
// (a fake internal hostname plus a "safe" marker phrase that isSafeConnectError
// would previously have substring-matched), must never be persisted verbatim into
// the audit_events.Description written for the failed read.
func TestReadFederatedSecret_AuditDescriptionRedactsRawUpstreamError(t *testing.T) {
	const ref = "prod/db"
	rawUpstreamErr := errors.New(
		"dial tcp 10.0.0.5:8200: connection refused (ref=" + ref +
			") — is not permitted for your roles on connector \"aws\"")

	ms := new(MockStorage)
	var got *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e
		return true
	})).Return(nil)
	c := &KeyorixCore{storage: ms}
	c.SetConnectManager(connect.NewManager([]connect.Connector{
		fakeConnector{name: "aws", err: rawUpstreamErr},
	}))
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "platform"}})

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", ref)
	require.Error(t, err)
	// The caller (HTTP layer) still gets the raw err back to classify/sanitize itself.
	assert.Equal(t, rawUpstreamErr, err)

	require.NotNil(t, got, "a failed federated read must still be audited")
	assert.NotContains(t, got.Description, "10.0.0.5", "raw upstream host detail must not reach the audit trail")
	assert.NotContains(t, got.Description, "connection refused", "raw upstream error text must not reach the audit trail")
	assert.Contains(t, got.Description, "FAILED")
	assert.Contains(t, got.Description, "an internal error occurred")
}
