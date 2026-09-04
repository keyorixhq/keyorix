package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func riskCore(store *MockStorage, now time.Time) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return now }}
}

// Category "mfa" (unlike "sod") has no live-violation report to validate
// reference against, so this exercises plain create+audit behavior without
// needing to stand up a DetectSoDViolations fixture. See
// risk_exceptions_external_test.go for the "sod" category's live-reference
// enforcement (Wave 6 core-sod finding #3).
func TestCreateRiskException_ValidatesAndAudits(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("CreateRiskException", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.Title == "accept dormant access for migration" && e.Category == "mfa" && e.CreatedBy == 9
	})).Return(&models.RiskException{ID: 1, Title: "accept dormant access for migration"}, nil)
	var audited string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionCreated {
			audited = ev.EventType
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	_, err := c.CreateRiskException(context.Background(), 9, false, "accept dormant access for migration", "mfa", "alice@example.com", "temporary during cutover", now.AddDate(0, 0, 30))
	require.NoError(t, err)
	assert.Equal(t, EventRiskExceptionCreated, audited)
}

func TestCreateRiskException_Rejects(t *testing.T) {
	now := time.Now()
	c := riskCore(new(MockStorage), now)

	_, err := c.CreateRiskException(context.Background(), 1, false, "", "sod", "", "", now.Add(time.Hour))
	require.Error(t, err, "title + justification required")

	_, err = c.CreateRiskException(context.Background(), 1, false, "t", "bogus", "", "j", now.Add(time.Hour))
	require.Error(t, err, "invalid category")

	_, err = c.CreateRiskException(context.Background(), 1, false, "t", "sod", "", "j", now.Add(-time.Hour))
	require.Error(t, err, "expiry must be in the future")

	// Must sunset: an expiry beyond the max duration is refused (no effectively-forever
	// waiver).
	_, err = c.CreateRiskException(context.Background(), 1, false, "t", "sod", "", "j", now.AddDate(5, 0, 0))
	require.Error(t, err, "expiry beyond the cap is rejected")
	require.Contains(t, err.Error(), "must be within")
}

// #1529: a machine-authenticated actor (e.g. a node credential proxying a
// call from a downstream server, or a CI machine identity) can never propose
// a governed risk acceptance -- only a human principal may. The denial is
// audited (Success=false) via the SAME EventRiskExceptionCreated constant a
// successful create uses, matching this file's own creator-or-admin denial
// convention for Revoke/Approve below.
func TestCreateRiskException_DeniesMachineActor(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	var audited string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionCreated && ev.Success != nil && !*ev.Success {
			audited = ev.EventType
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	_, err := c.CreateRiskException(context.Background(), 9, true, "accept dormant access", "mfa", "alice@example.com", "justification", now.Add(time.Hour))
	require.Error(t, err)
	assert.Equal(t, EventRiskExceptionCreated, audited, "the denial must be audited")
	store.AssertNotCalled(t, "CreateRiskException", mock.Anything, mock.Anything)
}

func TestListRiskExceptions_ComputesStatusAndFilters(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	rows := []*models.RiskException{
		{ID: 1, Title: "active", ExpiresAt: now.AddDate(0, 0, 10)},  // active
		{ID: 2, Title: "expired", ExpiresAt: now.AddDate(0, 0, -1)}, // expired
	}
	store.On("ListRiskExceptions", mock.Anything, true).Return(rows, nil)

	c := riskCore(store, now)

	// activeOnly drops the expired one.
	active, err := c.ListRiskExceptions(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, ExceptionStatusActive, active[0].Status)
	assert.Equal(t, "active", active[0].Title)
}

func TestRevokeRiskException(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	// #1529: RevokeRiskException now requires creator-or-admin. CreatedBy: 3
	// makes actor 3 the creator, satisfying the check without needing to stand
	// up an RBAC mock chain for the admin branch.
	// FIX-5 (Part 2 regression audit): isGlobalAdminRoleName is now evaluated
	// unconditionally up front (needed to decide the not-found-vs-denied
	// classification below, see #1645 403-for-both) rather than only on the
	// non-creator path, so even this creator-only case now needs the RBAC
	// lookup mocked.
	store.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 3}, nil)
	store.On("RevokeRiskExceptionIfNotRevoked", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.ID == 5 && e.Revoked && e.RevokedBy == 3 && e.RevokedAt != nil
	})).Return(true, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := riskCore(store, now)
	require.NoError(t, c.RevokeRiskException(context.Background(), 3, 5))
}

// #1529: an actor who neither created the exception nor holds an admin-tier
// role must be denied -- proves the creator-or-admin gate actually rejects
// the negative case, not just accepts the positive one (TestRevokeRiskException
// above only exercises the creator branch).
func TestRevokeRiskException_DeniesNonCreatorNonAdmin(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 3}, nil)
	store.On("GetUserRoleIDsAt", mock.Anything, uint(7), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(7), Scope{}).Return([]uint{}, nil)
	var audited string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionRevoked && ev.Success != nil && !*ev.Success {
			audited = ev.EventType
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	err := c.RevokeRiskException(context.Background(), 7, 5)
	require.Error(t, err)
	assert.Equal(t, EventRiskExceptionRevoked, audited, "the denial must be audited")
	store.AssertNotCalled(t, "RevokeRiskExceptionIfNotRevoked", mock.Anything, mock.Anything)
}

// #1529: an admin-tier actor who did NOT create the exception may still
// revoke it -- the OTHER half of the creator-OR-admin gate, proving admin
// status alone is sufficient without being the creator.
func TestRevokeRiskException_AdminNonCreatorSucceeds(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 3}, nil)
	store.On("GetUserRoleIDsAt", mock.Anything, uint(8), Scope{}).Return([]uint{1}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(8), Scope{}).Return([]uint{}, nil)
	store.On("GetRole", mock.Anything, uint(1)).Return(&models.Role{ID: 1, Name: "system_admin"}, nil)
	store.On("RevokeRiskExceptionIfNotRevoked", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.ID == 5 && e.Revoked && e.RevokedBy == 8
	})).Return(true, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := riskCore(store, now)
	require.NoError(t, c.RevokeRiskException(context.Background(), 8, 5))
}

// StateTransitionMissingCAS.ql: a lost race — the row's persisted revoked flag
// moved to true between the GetRiskException read and this write (e.g. a
// concurrent racing RevokeRiskException/ApproveRiskException) — must surface as
// a clear error, not be silently swallowed or retried.
func TestRevokeRiskException_LostRaceReturnsError(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	// #1529: CreatedBy: 3 makes actor 3 the creator, satisfying the
	// creator-or-admin check so this test still exercises the lost-race path
	// it's actually about.
	// FIX-5: see TestRevokeRiskException above -- the admin-tier RBAC lookup
	// now runs unconditionally, before the creator check.
	store.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 3}, nil)
	store.On("RevokeRiskExceptionIfNotRevoked", mock.Anything, mock.Anything).Return(false, nil)

	c := riskCore(store, now)
	err := c.RevokeRiskException(context.Background(), 3, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrently revoked")
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// #170: the creator of a risk exception cannot approve their own exception — dual
// control. The audit trail records the denial distinctly (Success=false) and the
// exception is left unapproved (no UpdateRiskException call expected).
func TestApproveRiskException_DeniesSelfApproval(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 9, ExpiresAt: now.Add(24 * time.Hour)}, nil)
	var audited *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionApproved {
			audited = ev
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	err := c.ApproveRiskException(context.Background(), 9, false, 5) // actor 9 == creator 9
	require.Error(t, err, "the creator must not be able to approve their own exception")
	assert.Contains(t, err.Error(), "cannot approve it")
	require.NotNil(t, audited, "the denial must still be audited")
	require.NotNil(t, audited.Success)
	assert.False(t, *audited.Success)
	store.AssertNotCalled(t, "ApproveRiskExceptionIfPending", mock.Anything, mock.Anything)
}

// A DIFFERENT principal than the creator may approve — the exception is marked
// approved and attributed to the approver.
func TestApproveRiskException_DifferentActorSucceeds(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 9, ExpiresAt: now.Add(24 * time.Hour)}, nil)
	store.On("ApproveRiskExceptionIfPending", mock.Anything, mock.MatchedBy(func(e *models.RiskException) bool {
		return e.ID == 5 && e.Approved && e.ApprovedBy == 3 && e.ApprovedAt != nil
	})).Return(true, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := riskCore(store, now)
	require.NoError(t, c.ApproveRiskException(context.Background(), 3, false, 5))
}

// #1524 finding (c): a machine credential relaying a HUMAN-created exception
// (CreatedBy=9, actorID=0) does NOT collide with the self-approval comparison
// (actorID == e.CreatedBy) the way a node-created-and-node-approved exception
// would -- it must still be denied, unconditionally, because dual control
// requires a different HUMAN reviewed it, which a machine can never be.
// Companion to TestApproveRiskException_DifferentActorSucceeds (a real
// different human succeeds) and TestApproveRiskException_DeniesSelfApproval
// (the same human is refused) -- this is the third case neither of those
// covers: a non-human actor, regardless of whose exception it is.
func TestApproveRiskException_DeniesMachineActor(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 9, ExpiresAt: now.Add(24 * time.Hour)}, nil)
	var audited *models.AuditEvent
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(ev *models.AuditEvent) bool {
		if ev.EventType == EventRiskExceptionApproved {
			audited = ev
			return true
		}
		return false
	})).Return(nil)

	c := riskCore(store, now)
	err := c.ApproveRiskException(context.Background(), 0, true, 5) // actorID 0, actorIsMachine true, CreatedBy 9 -- no sentinel collision
	require.Error(t, err, "a machine credential must not be able to approve a risk exception, even one it did not create")
	assert.Contains(t, err.Error(), "human")
	require.NotNil(t, audited, "the denial must still be audited")
	require.NotNil(t, audited.Success)
	assert.False(t, *audited.Success)
	store.AssertNotCalled(t, "ApproveRiskExceptionIfPending", mock.Anything, mock.Anything)
}

// StateTransitionMissingCAS.ql: a lost race on approve — the row's persisted
// revoked/approved flags moved between the GetRiskException read and this
// write (e.g. a concurrent racing revoke or a racing approve that landed
// first) — must surface as a clear error, not be silently swallowed.
func TestApproveRiskException_LostRaceReturnsError(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 9, ExpiresAt: now.Add(24 * time.Hour)}, nil)
	store.On("ApproveRiskExceptionIfPending", mock.Anything, mock.Anything).Return(false, nil)

	c := riskCore(store, now)
	err := c.ApproveRiskException(context.Background(), 3, false, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrently revoked or approved")
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// An already-approved exception cannot be approved again.
func TestApproveRiskException_RejectsAlreadyApproved(t *testing.T) {
	now := time.Now()
	store := new(MockStorage)
	store.On("GetRiskException", mock.Anything, uint(5)).Return(&models.RiskException{ID: 5, Title: "x", CreatedBy: 9, Approved: true, ExpiresAt: now.Add(24 * time.Hour)}, nil)

	c := riskCore(store, now)
	err := c.ApproveRiskException(context.Background(), 3, false, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already approved")
}

func TestCountActiveRiskExceptions(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("ListRiskExceptions", mock.Anything, true).Return([]*models.RiskException{
		{ID: 1, ExpiresAt: now.AddDate(0, 0, 3)},  // active, expiring soon (<14d)
		{ID: 2, ExpiresAt: now.AddDate(0, 0, 60)}, // active, not soon
		{ID: 3, ExpiresAt: now.AddDate(0, 0, -1)}, // expired
	}, nil)

	c := riskCore(store, now)
	active, soon, err := c.CountActiveRiskExceptions(context.Background(), riskExpiringSoonWindow)
	require.NoError(t, err)
	assert.Equal(t, 2, active)
	assert.Equal(t, 1, soon)
}

// #395: an exception past its expiry but still non-revoked counts as expired,
// distinct from a genuinely-active one — it dropped out of the active tally with no
// other signal that its accepted risk is unmitigated again.
func TestCountExpiredRiskExceptions(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("ListRiskExceptions", mock.Anything, true).Return([]*models.RiskException{
		{ID: 1, ExpiresAt: now.AddDate(0, 0, 3)},   // active, not expired
		{ID: 2, ExpiresAt: now.AddDate(0, 0, -1)},  // expired, still non-revoked
		{ID: 3, ExpiresAt: now.AddDate(0, 0, -30)}, // expired, still non-revoked
	}, nil)

	c := riskCore(store, now)
	expired, err := c.CountExpiredRiskExceptions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, expired)
}

// Zero stored exceptions, or exceptions that are all current, count zero expired.
func TestCountExpiredRiskExceptions_NoneExpired(t *testing.T) {
	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	store.On("ListRiskExceptions", mock.Anything, true).Return([]*models.RiskException{
		{ID: 1, ExpiresAt: now.AddDate(0, 0, 3)},
	}, nil)

	c := riskCore(store, now)
	expired, err := c.CountExpiredRiskExceptions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, expired)
}
