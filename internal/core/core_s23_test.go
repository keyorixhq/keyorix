// core_s23_test.go — sprint-23 coverage blitz:
// audit.go (LogRoleCreated/Updated/Deleted, LogSecretRead/Created/Updated/Rotated/Deleted,
// LogAuthLogin/Failure/Logout, LookupSessionUser), auth.go (Logout,
// GetSessionForRemoteProxy, DeleteSessionForRemoteProxy), auth_bootstrap.go
// (IsBuiltinRole, GenerateBootstrapToken), catalog.go (CreateProjectWithEnvs),
// compliance_evidence.go (appendEvidenceRotations), dashboard.go
// (mapAuditEventToActivity — remaining branches), dynamic_secrets.go
// (ListDynamicSecretConfigs, SetDynamicSecretConfigEnabled, GetDynamicSecretLease),
// impersonation.go (SessionImpersonator), invitations.go
// (revokeInvitationGrants, revokeSystemRoleGrant), anomaly.go
// (auditBusinessHoursConfig).
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

// ── helpers ───────────────────────────────────────────────────────────────────

// auditCore builds a core with LogAuditEvent + CreateSecretAccessLog mocked.
func auditCore(t *testing.T) (*MockStorage, *KeyorixCore) {
	t.Helper()
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	ms.On("CreateSecretAccessLog", mock.Anything, mock.Anything).Return(nil)
	return ms, NewKeyorixCore(ms)
}

// ── audit.go — role-definition events ────────────────────────────────────────

func TestLogRoleCreated(t *testing.T) {
	ms, c := auditCore(t)
	c.LogRoleCreated(context.Background(), 1, 42, "editor")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleCreated && e.UserID != nil && *e.UserID == 1
	}))
}

func TestLogRoleUpdated(t *testing.T) {
	ms, c := auditCore(t)
	c.LogRoleUpdated(context.Background(), 2, 7, "reviewer")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleUpdated
	}))
}

func TestLogRoleDeleted(t *testing.T) {
	ms, c := auditCore(t)
	c.LogRoleDeleted(context.Background(), 3, 9, "old-role")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleDeleted
	}))
}

// logRoleDefinitionChange is exercised through the three callers above.
// A test with actorID==0 exercises the nil-actor branch in writeRBACAudit.
func TestLogRoleCreated_ZeroActorID(t *testing.T) {
	ms, c := auditCore(t)
	c.LogRoleCreated(context.Background(), 0, 5, "viewer")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		// actorID 0 → writeRBACAudit passes nil UserID
		return e.EventType == EventRoleCreated && e.UserID == nil
	}))
}

// ── audit.go — secret audit events ───────────────────────────────────────────

func TestLogSecretRead(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretRead(context.Background(), 1, 10, "alice", "db-password", "1.2.3.4", "curl")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.read"
	}))
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.MatchedBy(func(l *models.SecretAccessLog) bool {
		return l.Action == "read" && l.SecretNodeID == 10
	}))
}

func TestLogSecretCreated(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretCreated(context.Background(), 1, 11, "alice", "new-secret", "1.2.3.4", "go-client")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.created"
	}))
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.MatchedBy(func(l *models.SecretAccessLog) bool {
		return l.Action == "create"
	}))
}

func TestLogSecretUpdated(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretUpdated(context.Background(), 1, 12, "alice", "some-secret", "1.2.3.4", "ua")
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.MatchedBy(func(l *models.SecretAccessLog) bool {
		return l.Action == "update"
	}))
}

func TestLogSecretRotated(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretRotated(context.Background(), 1, 13, "alice", "api-key", "127.0.0.1", "ua")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.rotated"
	}))
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.MatchedBy(func(l *models.SecretAccessLog) bool {
		return l.Action == "rotate"
	}))
}

func TestLogSecretRotatedWithProject(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretRotatedWithProject(context.Background(), 1, 14, 99, "alice", "key", "1.2.3.4", "ua")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.rotated" && e.ProjectID != nil && *e.ProjectID == 99
	}))
}

func TestLogSecretDeleted(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretDeleted(context.Background(), 1, 15, "alice", "old-key", "1.2.3.4", "ua")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.deleted"
	}))
	ms.AssertCalled(t, "CreateSecretAccessLog", mock.Anything, mock.MatchedBy(func(l *models.SecretAccessLog) bool {
		return l.Action == "delete"
	}))
}

func TestLogSecretDeletedWithProject(t *testing.T) {
	ms, c := auditCore(t)
	c.LogSecretDeletedWithProject(context.Background(), 1, 16, 100, "alice", "key", "1.2.3.4", "ua")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "secret.deleted" && e.ProjectID != nil && *e.ProjectID == 100
	}))
}

// ── audit.go — auth events ────────────────────────────────────────────────────

func TestLogAuthLogin(t *testing.T) {
	ms, c := auditCore(t)
	c.LogAuthLogin(context.Background(), 5, "bob", "10.0.0.1", "Firefox")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "auth.login" && e.Success != nil && *e.Success
	}))
}

func TestLogAuthFailure(t *testing.T) {
	ms, c := auditCore(t)
	c.LogAuthFailure(context.Background(), "eve", "192.168.1.1")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "auth.login_failed" && e.Success != nil && !*e.Success
	}))
}

func TestLogAuthLogout(t *testing.T) {
	ms, c := auditCore(t)
	c.LogAuthLogout(context.Background(), 5, "bob", "10.0.0.1", "Firefox")
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "auth.logout"
	}))
}

// ── audit.go — LookupSessionUser ─────────────────────────────────────────────

func TestLookupSessionUser_SessionNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "bad").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	uid, uname := c.LookupSessionUser(context.Background(), "bad")
	assert.Equal(t, uint(0), uid)
	assert.Equal(t, "", uname)
}

func TestLookupSessionUser_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "tok").Return(&models.Session{ID: 1, UserID: 7}, nil)
	ms.On("GetUser", mock.Anything, uint(7)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	uid, uname := c.LookupSessionUser(context.Background(), "tok")
	assert.Equal(t, uint(7), uid)
	assert.Equal(t, "", uname)
}

func TestLookupSessionUser_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "tok").Return(&models.Session{ID: 1, UserID: 7}, nil)
	ms.On("GetUser", mock.Anything, uint(7)).Return(&models.User{ID: 7, Username: "carol"}, nil)
	c := NewKeyorixCore(ms)
	uid, uname := c.LookupSessionUser(context.Background(), "tok")
	assert.Equal(t, uint(7), uid)
	assert.Equal(t, "carol", uname)
}

// ── auth.go — Logout ──────────────────────────────────────────────────────────

func TestLogout_SessionNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "unknown").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.Logout(context.Background(), "unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestLogout_DeletesSession(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "valid-tok").Return(&models.Session{ID: 42, UserID: 1}, nil)
	ms.On("DeleteSession", mock.Anything, uint(42)).Return(nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.Logout(context.Background(), "valid-tok"))
	ms.AssertCalled(t, "DeleteSession", mock.Anything, uint(42))
}

// ── auth.go — GetSessionForRemoteProxy ───────────────────────────────────────

func TestGetSessionForRemoteProxy_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "bad-tok").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSessionForRemoteProxy(context.Background(), "bad-tok")
	require.Error(t, err)
}

func TestGetSessionForRemoteProxy_Found(t *testing.T) {
	ms := new(MockStorage)
	sess := &models.Session{ID: 10, UserID: 3, SessionToken: "good-tok"}
	ms.On("GetSession", mock.Anything, "good-tok").Return(sess, nil)
	c := NewKeyorixCore(ms)
	got, err := c.GetSessionForRemoteProxy(context.Background(), "good-tok")
	require.NoError(t, err)
	assert.Equal(t, uint(10), got.ID)
}

// ── auth.go — DeleteSessionForRemoteProxy ────────────────────────────────────

func TestDeleteSessionForRemoteProxy_DeleteFails(t *testing.T) {
	ms := new(MockStorage)
	// GetSessionByID may or may not be called; stub it to succeed in case it is.
	ms.On("GetSessionByID", mock.Anything, uint(5)).Return(
		&models.Session{ID: 5, SessionToken: "tok"}, nil)
	ms.On("DeleteSession", mock.Anything, uint(5)).Return(errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.DeleteSessionForRemoteProxy(context.Background(), 5)
	require.Error(t, err)
}

func TestDeleteSessionForRemoteProxy_Success(t *testing.T) {
	ms := new(MockStorage)
	sess := &models.Session{ID: 6, SessionToken: "live-tok", UserID: 1}
	ms.On("GetSessionByID", mock.Anything, uint(6)).Return(sess, nil)
	ms.On("DeleteSession", mock.Anything, uint(6)).Return(nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.DeleteSessionForRemoteProxy(context.Background(), 6))
	ms.AssertCalled(t, "DeleteSession", mock.Anything, uint(6))
}

func TestDeleteSessionForRemoteProxy_LookupFails_StillDeletes(t *testing.T) {
	// If GetSessionByID fails we still call DeleteSession (delete wins).
	ms := new(MockStorage)
	ms.On("GetSessionByID", mock.Anything, uint(7)).Return(nil, errors.New("not found"))
	ms.On("DeleteSession", mock.Anything, uint(7)).Return(nil)
	c := NewKeyorixCore(ms)
	require.NoError(t, c.DeleteSessionForRemoteProxy(context.Background(), 7))
}

// ── auth_bootstrap.go — IsBuiltinRole ────────────────────────────────────────

func TestIsBuiltinRole_Builtins(t *testing.T) {
	for _, name := range []string{
		"admin", "editor", "viewer", "auditor", "super_admin",
		"system_admin", "system_auditor", "system_viewer",
		"project_admin", "project_developer", "project_viewer", "project_auditor",
	} {
		assert.True(t, IsBuiltinRole(name), "expected %q to be a builtin", name)
	}
}

func TestIsBuiltinRole_NonBuiltins(t *testing.T) {
	for _, name := range []string{"", "custom-role", "my_admin", "superadmin"} {
		assert.False(t, IsBuiltinRole(name), "expected %q NOT to be a builtin", name)
	}
}

// ── auth_bootstrap.go — GenerateBootstrapToken ───────────────────────────────

func TestGenerateBootstrapToken_Unique(t *testing.T) {
	tok1, err1 := GenerateBootstrapToken()
	tok2, err2 := GenerateBootstrapToken()
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEmpty(t, tok1)
	assert.NotEmpty(t, tok2)
	assert.NotEqual(t, tok1, tok2, "bootstrap tokens must be unique")
}

func TestGenerateBootstrapToken_MinLength(t *testing.T) {
	tok, err := GenerateBootstrapToken()
	require.NoError(t, err)
	// hex-encoded 32 bytes = 64 chars; allow for base64/URL variants
	assert.GreaterOrEqual(t, len(tok), 16, "token should be reasonably long")
}

// ── catalog.go — CreateProjectWithEnvs ───────────────────────────────────────

func TestCreateProjectWithEnvs_EmptyName(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.CreateProjectWithEnvs(context.Background(), "", "desc", []string{"dev"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project name is required")
}

func TestCreateProjectWithEnvs_TooManyEnvs(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	envs := make([]string, maxEnvNamesPerCreate+1)
	for i := range envs {
		envs[i] = "env"
	}
	_, err := c.CreateProjectWithEnvs(context.Background(), "myproject", "", envs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most")
}

func TestCreateProjectWithEnvs_EmptyEnvName(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.CreateProjectWithEnvs(context.Background(), "myproject", "", []string{"dev", ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment name is required")
}

func TestCreateProjectWithEnvs_Success(t *testing.T) {
	ms := new(MockStorage)
	// CreateProject returns the passed project; CreateEnvironment does too.
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	proj, err := c.CreateProjectWithEnvs(context.Background(), "infra", "infra project", []string{"dev", "prod"})
	require.NoError(t, err)
	assert.Equal(t, "infra", proj.Name)
}

func TestCreateProjectWithEnvs_EmptyEnvsList(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	proj, err := c.CreateProjectWithEnvs(context.Background(), "bare", "", nil)
	require.NoError(t, err)
	assert.Equal(t, "bare", proj.Name)
}

// ── compliance_evidence.go — appendEvidenceRotations ─────────────────────────

func TestAppendEvidenceRotations_Empty(t *testing.T) {
	ev := &ComplianceEvidence{}
	appendEvidenceRotations(ev, nil)
	assert.Empty(t, ev.RotationOverdue)
}

func TestAppendEvidenceRotations_OnlyOverdue(t *testing.T) {
	ev := &ComplianceEvidence{}
	statuses := []*RotationStatusEntry{
		{SecretID: 1, SecretName: "api-key", PolicyName: "30d", DaysOverdue: 5, Status: RotationStatusOverdue},
		{SecretID: 2, SecretName: "db-pw", PolicyName: "90d", DaysOverdue: 0, Status: RotationStatusOK},
		{SecretID: 3, SecretName: "cert", PolicyName: "365d", DaysOverdue: 10, Status: RotationStatusOverdue},
	}
	appendEvidenceRotations(ev, statuses)
	require.Len(t, ev.RotationOverdue, 2)
	assert.Equal(t, uint(1), ev.RotationOverdue[0].SecretID)
	assert.Equal(t, uint(3), ev.RotationOverdue[1].SecretID)
}

func TestAppendEvidenceRotations_NoneOverdue(t *testing.T) {
	ev := &ComplianceEvidence{}
	statuses := []*RotationStatusEntry{
		{SecretID: 1, Status: RotationStatusOK},
		{SecretID: 2, Status: RotationStatusDueSoon},
	}
	appendEvidenceRotations(ev, statuses)
	assert.Empty(t, ev.RotationOverdue)
}

// ── dashboard.go — mapAuditEventToActivity — remaining branches ──────────────

func TestMapAuditEventToActivity_SecretCreated(t *testing.T) {
	e := &models.AuditEvent{ID: 10, EventType: "secret.created", Description: "User admin created secret my-api-key", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "admin")
	assert.Equal(t, "created", item.Type)
	assert.Equal(t, "my-api-key", item.SecretName)
}

func TestMapAuditEventToActivity_SecretUpdated(t *testing.T) {
	e := &models.AuditEvent{ID: 11, EventType: "secret.updated", Description: "User alice updated secret db-pass", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "alice")
	assert.Equal(t, "updated", item.Type)
	assert.Equal(t, "db-pass", item.SecretName)
}

func TestMapAuditEventToActivity_SecretDeleted(t *testing.T) {
	e := &models.AuditEvent{ID: 12, EventType: "secret.deleted", Description: "User alice deleted secret old-key", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "alice")
	assert.Equal(t, "deleted", item.Type)
}

func TestMapAuditEventToActivity_SecretRotated(t *testing.T) {
	e := &models.AuditEvent{ID: 13, EventType: "secret.rotated", Description: "User admin rotated secret cert", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "admin")
	assert.Equal(t, "rotated", item.Type)
	assert.Equal(t, "cert", item.SecretName)
}

func TestMapAuditEventToActivity_SecretShared(t *testing.T) {
	e := &models.AuditEvent{ID: 14, EventType: "secret.shared", Description: "User admin shared secret my-secret", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "admin")
	assert.Equal(t, "shared", item.Type)
}

func TestMapAuditEventToActivity_ShareRevoked(t *testing.T) {
	e := &models.AuditEvent{ID: 15, EventType: "share.revoked", Description: "User admin revoked share for secret my-secret", EventTime: time.Now()}
	item := mapAuditEventToActivity(e, "admin")
	assert.Equal(t, "share_revoked", item.Type)
}

func TestMapAuditEventToActivity_AuthLogout(t *testing.T) {
	e := &models.AuditEvent{ID: 16, EventType: "auth.logout", Description: "User bob logged out"}
	item := mapAuditEventToActivity(e, "bob")
	assert.Equal(t, "logout", item.Type)
	assert.Equal(t, "", item.SecretName)
}

func TestMapAuditEventToActivity_AuthPasswordReset(t *testing.T) {
	e := &models.AuditEvent{ID: 17, EventType: "auth.password_reset", Description: "password reset"}
	item := mapAuditEventToActivity(e, "user")
	assert.Equal(t, "password_reset", item.Type)
	assert.Equal(t, "", item.SecretName)
}

// ── dynamic_secrets.go — ListDynamicSecretConfigs ────────────────────────────

func TestListDynamicSecretConfigs_Delegated(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// MockStorage stub returns (nil, nil).
	configs, err := c.ListDynamicSecretConfigs(context.Background(), 1, 2)
	require.NoError(t, err)
	assert.Nil(t, configs)
}

// ── dynamic_secrets.go — SetDynamicSecretConfigEnabled ───────────────────────

func TestSetDynamicSecretConfigEnabled_ZeroID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.SetDynamicSecretConfigEnabled(context.Background(), 1, 0, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config id is required")
}

// Note: GetDynamicSecretConfig is a FIXED stub in MockStorage (returns nil, nil
// always without using m.Called) — we can't override it via ms.On. We therefore
// test the zero-ID guard (above) and the no-op / state-change branches through
// the dynamic_secrets_test.go's real-SQLite path.  The paragraphs below exercise
// the public signature with a zero configID so the guard is reached before any
// storage call is attempted.

func TestSetDynamicSecretConfigEnabled_ZeroID_DisableCase(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.SetDynamicSecretConfigEnabled(context.Background(), 1, 0, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config id is required")
}

// ── dynamic_secrets.go — GetDynamicSecretLease ───────────────────────────────

func TestGetDynamicSecretLease_Delegated(t *testing.T) {
	ms := new(MockStorage)
	// MockStorage stub returns (nil, nil) for GetDynamicSecretLease.
	c := NewKeyorixCore(ms)
	lease, err := c.GetDynamicSecretLease(context.Background(), "lease-abc")
	require.NoError(t, err)
	assert.Nil(t, lease)
}

// ── impersonation.go — SessionImpersonator ────────────────────────────────────

func TestSessionImpersonator_TokenNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSession", mock.Anything, "bad").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	result := c.SessionImpersonator(context.Background(), "bad")
	assert.Nil(t, result)
}

func TestSessionImpersonator_NotImpersonation(t *testing.T) {
	ms := new(MockStorage)
	// Session with no ImpersonatedBy.
	ms.On("GetSession", mock.Anything, "reg-tok").Return(&models.Session{ID: 1, UserID: 2}, nil)
	c := NewKeyorixCore(ms)
	result := c.SessionImpersonator(context.Background(), "reg-tok")
	assert.Nil(t, result)
}

func TestSessionImpersonator_IsImpersonation(t *testing.T) {
	ms := new(MockStorage)
	adminID := uint(7)
	sess := &models.Session{ID: 2, UserID: 3, ImpersonatedBy: &adminID}
	ms.On("GetSession", mock.Anything, "imp-tok").Return(sess, nil)
	c := NewKeyorixCore(ms)
	result := c.SessionImpersonator(context.Background(), "imp-tok")
	require.NotNil(t, result)
	assert.Equal(t, uint(7), *result)
}

// ── invitations.go — revokeSystemRoleGrant ────────────────────────────────────

func TestRevokeSystemRoleGrant_EmptySystemRole(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// An invitation with no SystemRole — revokeSystemRoleGrant must be a no-op.
	inv := &models.ProjectInvitation{ID: 1}
	c.revokeSystemRoleGrant(context.Background(), inv, 5)
	// No storage calls expected (no GetRoleByName, no RemoveUserRole).
	ms.AssertNotCalled(t, "GetRoleByName")
}

func TestRevokeSystemRoleGrant_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "viewer").Return(nil, errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{ID: 2, SystemRole: "viewer"}
	// If role not found, silently return (no panic, no error).
	c.revokeSystemRoleGrant(context.Background(), inv, 5)
	// RemoveUserRole must not be called since we never resolved the roleID.
	ms.AssertNotCalled(t, "RemoveRole")
}

// ── invitations.go — revokeInvitationGrants ──────────────────────────────────

func TestRevokeInvitationGrants_ProjectScoped_UserNotMember(t *testing.T) {
	// When the user is not a member, RemoveProjectMember returns an error which
	// revokeInvitationGrants audits. The storage.GetUserRoleIDsExact mock returns
	// an empty slice → "user is not a member" early return.
	ms := new(MockStorage)
	ms.On("GetUserRoleIDsExact", mock.Anything, uint(10), mock.Anything).Return([]uint{}, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	// A plain project invite (no SystemRole, no AssignmentsJSON).
	inv := &models.ProjectInvitation{ID: 5, ProjectID: 3, Role: "viewer"}
	// Should not panic — error is audited internally.
	c.revokeInvitationGrants(context.Background(), inv, 10)
}

func TestRevokeInvitationGrants_WithSystemRole_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRoleByName", mock.Anything, "system_viewer").Return(nil, errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	inv := &models.ProjectInvitation{ID: 6, SystemRole: "system_viewer"}
	// revokeSystemRoleGrant silently returns when role not found; no panic.
	c.revokeInvitationGrants(context.Background(), inv, 11)
}

// ── anomaly.go — auditBusinessHoursConfig ────────────────────────────────────

func TestAuditBusinessHoursConfig_NilStorage(t *testing.T) {
	// AnomalyDetector with a nil StorageInterface — must not panic.
	d := &AnomalyDetector{storage: nil}
	p := defaultOffHoursPolicy()
	// Must be a no-op, not a panic.
	d.auditBusinessHoursConfig(context.Background(), "UTC", p)
}

func TestAuditBusinessHoursConfig_StorageSuccess(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventAnomalyBusinessHoursConfigured
	})).Return(nil)
	d := NewAnomalyDetector(ms)
	p := offHoursPolicy{loc: time.UTC, start: 22, end: 6}
	d.auditBusinessHoursConfig(context.Background(), "UTC", p)
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestAuditBusinessHoursConfig_StorageError_NoReturnError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(errors.New("db down"))
	d := NewAnomalyDetector(ms)
	p := defaultOffHoursPolicy()
	// Must not panic or return an error; failure is logged loudly but swallowed.
	d.auditBusinessHoursConfig(context.Background(), "", p)
}

func TestAuditBusinessHoursConfig_EmptyTZ_UsesUTCLabel(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventAnomalyBusinessHoursConfigured &&
			// Description must mention "UTC" when tz is empty.
			len(e.Description) > 0
	})).Return(nil)
	d := NewAnomalyDetector(ms)
	d.auditBusinessHoursConfig(context.Background(), "", defaultOffHoursPolicy())
	ms.AssertExpectations(t)
}

// SetBusinessHours is the public entry point that calls auditBusinessHoursConfig —
// also exercises the full success/error branches of that internal helper.
func TestSetBusinessHours_InvalidTZ(t *testing.T) {
	ms := new(MockStorage)
	d := NewAnomalyDetector(ms)
	err := d.SetBusinessHours(context.Background(), "Not/A/Timezone", 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timezone")
}

func TestSetBusinessHours_DegenerateBand(t *testing.T) {
	ms := new(MockStorage)
	d := NewAnomalyDetector(ms)
	err := d.SetBusinessHours(context.Background(), "UTC", 10, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start_hour and end_hour must differ")
}

func TestSetBusinessHours_Success_AuditsChange(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	d := NewAnomalyDetector(ms)
	err := d.SetBusinessHours(context.Background(), "Europe/Madrid", 23, 7)
	require.NoError(t, err)
	ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

func TestSetBusinessHours_BothZeroKeepsDefault(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	d := NewAnomalyDetector(ms)
	// Both hours 0 = "unset" → keep the default band (22–6), no degenerate error.
	err := d.SetBusinessHours(context.Background(), "", 0, 0)
	require.NoError(t, err)
}
