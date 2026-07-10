// core_s2_test.go — sprint-2 coverage: account sessions, catalog, connect,
// dashboard helpers, group permission, and anomaly detector edge paths.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── account.go ────────────────────────────────────────────────────────────────

func TestCurrentSessionID_EmptyToken(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// An empty token must return 0 without any storage call.
	id := c.CurrentSessionID(context.Background(), "")
	assert.Equal(t, uint(0), id)
	ms.AssertNotCalled(t, "GetSession", mock.Anything, mock.Anything)
}

func TestCurrentSessionID_StorageError(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ms.On("GetSession", mock.Anything, "bad-token").Return(nil, errors.New("not found"))
	// Storage error → return 0.
	id := c.CurrentSessionID(context.Background(), "bad-token")
	assert.Equal(t, uint(0), id)
}

func TestCurrentSessionID_Valid(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	sess := &models.Session{ID: 42, SessionToken: "tok"}
	ms.On("GetSession", mock.Anything, "tok").Return(sess, nil)
	id := c.CurrentSessionID(context.Background(), "tok")
	assert.Equal(t, uint(42), id)
}

func TestListOwnSessions_ZeroUserID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListOwnSessions(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestRevokeOwnSession_WrongOwner(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// Session belongs to user 2, caller is user 1.
	sess := &models.Session{ID: 5, UserID: 2, SessionToken: "t"}
	ms.On("GetSessionByID", mock.Anything, uint(5)).Return(sess, nil)
	err := c.RevokeOwnSession(context.Background(), 1, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
	ms.AssertNotCalled(t, "DeleteSession", mock.Anything, mock.Anything)
}

func TestRevokeOwnSession_ZeroIDs(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RevokeOwnSession(context.Background(), 0, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// ── catalog.go ────────────────────────────────────────────────────────────────

func TestGetProject_Delegated(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetProject", mock.Anything, uint(7)).Return(&models.Project{ID: 7, Name: "web"}, nil)
	c := NewKeyorixCore(ms)
	p, err := c.GetProject(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), p.ID)
}

func TestGetProject_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetProject", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetProject(context.Background(), 99)
	require.Error(t, err)
}

func TestListProjectsWithCounts_Delegated(t *testing.T) {
	// MockStorage.ListProjectsWithCounts is a fixed stub returning (nil, nil).
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	result, err := c.ListProjectsWithCounts(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestDeleteEnvironment_Delegated(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// MockStorage.DeleteEnvironment returns nil.
	require.NoError(t, c.DeleteEnvironment(context.Background(), 1))
}

func TestGetEnvironment_Delegated(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// MockStorage.GetEnvironment returns &models.Environment{}.
	env, err := c.GetEnvironment(context.Background(), 1)
	require.NoError(t, err)
	assert.NotNil(t, env)
}

func TestListEnvironments_Delegated(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// MockStorage.ListEnvironments returns nil, nil.
	envs, err := c.ListEnvironments(context.Background())
	require.NoError(t, err)
	assert.Nil(t, envs)
}

func TestCreateEnvironment_EmptyName(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.CreateEnvironment(context.Background(), 1, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment name is required")
}

func TestCreateEnvironment_TooLongName(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'a'
	}
	_, err := c.CreateEnvironment(context.Background(), 1, string(long))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestCreateEnvironment_Success(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// MockStorage.CreateEnvironment returns the passed env back.
	env, err := c.CreateEnvironment(context.Background(), 1, "staging")
	require.NoError(t, err)
	assert.Equal(t, "staging", env.Name)
	assert.Equal(t, uint(1), env.ProjectID)
}

// ── connect.go ────────────────────────────────────────────────────────────────

func TestConnectConnectorNames_NoManager(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	names := c.ConnectConnectorNames()
	assert.Nil(t, names)
}

func TestConnectConnectorNames_WithManager(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := &KeyorixCore{storage: ms}
	c.SetConnectManager(connect.NewManager([]connect.Connector{fakeConnector{name: "aws"}}))
	names := c.ConnectConnectorNames()
	assert.Equal(t, []string{"aws"}, names)
}

func TestListConnectRefGrants_Delegated(t *testing.T) {
	ms := new(MockStorage)
	// MockStorage.ListConnectRefGrants is a fixed stub returning (nil, nil).
	c := NewKeyorixCore(ms)
	grants, err := c.ListConnectRefGrants(context.Background())
	require.NoError(t, err)
	assert.Nil(t, grants)
}

func TestDeleteConnectRefGrant_Success(t *testing.T) {
	// DeleteConnectRefGrant mock is a fixed stub (returns nil, no m.Called).
	// LogAuditEvent is called via writeAuditEvent — mock it to avoid panics.
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	// Fixed stub returns nil — success path.
	require.NoError(t, c.DeleteConnectRefGrant(context.Background(), 1, 3))
}

// ── catalog.go – extra helpers ────────────────────────────────────────────────

func TestListEnvironmentsByProjectIncludingDeleted(t *testing.T) {
	ms := new(MockStorage)
	// MockStorage.ListEnvironmentsByProjectIncludingDeleted is a fixed stub.
	c := NewKeyorixCore(ms)
	envs, err := c.ListEnvironmentsByProjectIncludingDeleted(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, envs)
}

func TestTranslateProjectNameError_DuplicateName(t *testing.T) {
	// Call CreateProject with a duplicate-name storage error so translateProjectNameError
	// is exercised on the non-duplicate path via the mock.
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// Use CreateProjectWithEnvs with an empty envNames to hit validateProjectName
	// then storage.CreateProject (which won't be called because mock returns nil
	// on fixed stub). Instead trigger it via CreateProject which goes through
	// validateProjectName then storage.CreateProject. Stub returns ErrDuplicateProjectName.
	_, err := c.CreateProject(context.Background(), "", "")
	// Empty name triggers validateProjectName error — translateProjectNameError is
	// exercised only when CreateProject succeeds validation but storage fails.
	require.Error(t, err)
	// Exercise translateProjectNameError directly via a non-duplicate error.
	nonDup := errors.New("some other error")
	out := translateProjectNameError(nonDup)
	assert.Equal(t, nonDup, out)
	// And with the actual duplicate sentinel.
	dup := translateProjectNameError(storage.ErrDuplicateProjectName)
	assert.Contains(t, dup.Error(), "already exists")
}

// ── dashboard.go helpers ──────────────────────────────────────────────────────

func TestComputeTrend_BothZero(t *testing.T) {
	assert.Nil(t, computeTrend(0, 0))
}

func TestComputeTrend_PrevZeroCurrentNonZero(t *testing.T) {
	trend := computeTrend(0, 10)
	require.NotNil(t, trend)
	assert.Equal(t, 100.0, trend.Value)
	assert.True(t, trend.IsPositive)
}

func TestComputeTrend_NoChange(t *testing.T) {
	assert.Nil(t, computeTrend(10, 10))
}

func TestComputeTrend_Increase(t *testing.T) {
	trend := computeTrend(100, 150)
	require.NotNil(t, trend)
	assert.Equal(t, 50.0, trend.Value)
	assert.True(t, trend.IsPositive)
}

func TestComputeTrend_Decrease(t *testing.T) {
	trend := computeTrend(100, 80)
	require.NotNil(t, trend)
	assert.Equal(t, 20.0, trend.Value)
	assert.False(t, trend.IsPositive)
}

func TestLastIndex_EmptySubstr(t *testing.T) {
	assert.Equal(t, 5, lastIndex("hello", ""))
}

func TestLastIndex_NotFound(t *testing.T) {
	assert.Equal(t, -1, lastIndex("hello", "xyz"))
}

func TestLastIndex_LastOccurrence(t *testing.T) {
	// "aXbXc" — second X is at index 3.
	assert.Equal(t, 3, lastIndex("aXbXc", "X"))
}

func TestExtractSecretName_Found(t *testing.T) {
	assert.Equal(t, "prod-db", extractSecretName("User admin deleted secret prod-db"))
}

func TestExtractSecretName_NotFound(t *testing.T) {
	assert.Equal(t, "", extractSecretName("User admin logged in"))
}

func TestMapAuditEventToActivity_SecretRead(t *testing.T) {
	e := &models.AuditEvent{ID: 1, EventType: "secret.read", Description: "User alice read secret api-key", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "alice")
	assert.Equal(t, "accessed", item.Type)
	assert.Equal(t, "api-key", item.SecretName)
}

func TestMapAuditEventToActivity_AuthLogin(t *testing.T) {
	e := &models.AuditEvent{ID: 2, EventType: "auth.login", Description: "User bob logged in"}
	item := mapAuditEventToActivity(e, "bob")
	assert.Equal(t, "login", item.Type)
	assert.Equal(t, "", item.SecretName)
}

func TestMapAuditEventToActivity_Fallback(t *testing.T) {
	e := &models.AuditEvent{ID: 3, EventType: "rbac.role_assigned", Description: "role assigned"}
	item := mapAuditEventToActivity(e, "admin")
	assert.Equal(t, "rbac.role_assigned", item.Type)
	assert.Equal(t, "", item.SecretName)
}

func TestGetActivityFeed_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return(nil, int64(0), errors.New("db down"))
	c := NewKeyorixCore(ms)
	feed, err := c.GetActivityFeed(context.Background(), 1, "alice", -1, 0)
	require.NoError(t, err) // storage error is swallowed; returns empty feed
	assert.Empty(t, feed.Items)
	assert.Equal(t, 1, feed.Page)
	assert.Equal(t, 10, feed.PageSize)
}

func TestGetActivityFeed_WithEvents(t *testing.T) {
	ms := new(MockStorage)
	events := []*models.AuditEvent{
		{ID: 1, EventType: "secret.read", Description: "User alice read secret db-pw", EventTime: time.Now()},
	}
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return(events, int64(1), nil)
	c := NewKeyorixCore(ms)
	feed, err := c.GetActivityFeed(context.Background(), 1, "alice", 1, 10)
	require.NoError(t, err)
	require.Len(t, feed.Items, 1)
	assert.Equal(t, "accessed", feed.Items[0].Type)
}

// ── group_sharing.go ──────────────────────────────────────────────────────────

func TestCheckUserGroupPermission_ZeroSecretID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, _, err := c.CheckUserGroupPermission(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestCheckUserGroupPermission_ZeroUserID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, _, err := c.CheckUserGroupPermission(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestCheckUserGroupPermission_Valid(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	ok, perm, err := c.CheckUserGroupPermission(context.Background(), 1, 1)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, "", perm)
}

// ── groups.go ────────────────────────────────────────────────────────────────

func TestListGroups_Success(t *testing.T) {
	ms := new(MockStorage)
	grps := []*models.Group{{ID: 1, Name: "admins"}}
	ms.On("ListGroups", mock.Anything).Return(grps, nil)
	c := NewKeyorixCore(ms)
	result, err := c.ListGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "admins", result[0].Name)
}

func TestListGroups_Error(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListGroups", mock.Anything).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ListGroups(context.Background())
	require.Error(t, err)
}

// ── anomaly.go ────────────────────────────────────────────────────────────────

func TestSetBaselineQuarantine(t *testing.T) {
	ms := new(MockStorage)
	d := NewAnomalyDetector(ms)
	d.SetBaselineQuarantine(48 * time.Hour)
	assert.Equal(t, 48*time.Hour, d.quarantine)
}

func TestSetMLConfig(t *testing.T) {
	ms := new(MockStorage)
	d := NewAnomalyDetector(ms)
	cfg := MLConfig{Enabled: true}
	d.SetMLConfig(cfg)
	assert.True(t, d.ml.Enabled)
}
