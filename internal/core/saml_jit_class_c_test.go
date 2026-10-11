// saml_jit_class_c_test.go — the three conditions Andrei attached to accepting
// CompleteSAML's JIT provisioning as atomicity class C (#2839 item 1,
// 2026-10-09). Each is enforced here, red when broken, rather than asserted in
// a ledger row:
//
//  1. mintSession runs ONLY if provisionSSOUser AND reconcileSSOGroups/Roles
//     fully succeeded. Any error in them means no session. This one was a REAL
//     BUG: both reconcile calls returned nothing and swallowed every error, so
//     a failed REVOCATION — the IdP dropped a user from its admin group, the
//     removal errored or was refused — left the user holding the group or role
//     and still handed them a session.
//  2. Reconcile removes as well as adds, and derives roles only from the
//     validated assertion.
//  3. JIT account creation is audited even when the login then fails.
//
// Class C is "independent, self-healing steps": each reconciliation is
// idempotent and converges on the next successful login, so nothing here is
// compensated or rolled back. That is exactly why condition 1 matters — the
// only protection against a half-applied reconcile is refusing to mint the
// session over it.
package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// samlGroupSyncCore is samlTestCore with group sync and a role mapping on, and
// an assertion that carries groups — the shape that reaches the reconcile calls
// at all. groupRoleMap may be nil to exercise the group path alone.
func samlGroupSyncCore(t *testing.T, groups []string, groupRoleMap map[string]string) (*KeyorixCore, *MockStorage) {
	t.Helper()
	stub := &stubSAML{info: &ports.SAMLAssertion{Subject: "corp|123", Email: "ada@x.io", Name: "Ada", Groups: groups}}
	store := new(MockStorage)
	p := &SSOProvider{
		Name: "corp", Type: "saml", SAML: stub,
		AutoProvision: true, DefaultRole: "system_viewer",
		GroupSync: true, GroupRoleMap: groupRoleMap,
	}
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}

	store.On("ConsumeSSOLoginState", mock.Anything, "relay-1").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ReturnTo: "/home", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|123").Return(
		&models.User{ID: 7, IsActive: true, AccountState: AccountActive}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()
	store.On("UpdateLastLogin", mock.Anything, uint(7), mock.Anything).Return(nil).Maybe()
	return c, store
}

func postACS(t *testing.T, c *KeyorixCore) (*models.Session, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, _, _, err := c.CompleteSAML(context.Background(), "corp", req, "relay-1", "ua", "1.2.3.4")
	return session, err
}

// ── Condition 1: any reconcile error means no session ───────────────────────

// TestCompleteSAML_GroupReconcileReadFailureRefusesTheLogin covers the
// "unknown desired state" arm: without the native group list, which groups the
// assertion maps to is unknown, so a membership the IdP has revoked may still
// be in place. Unknown is not the same as reconciled.
//
// RED before the fix: reconcileSSOGroups returned nothing, CompleteSAML ignored
// it, CreateSession was called and a session handed back.
func TestCompleteSAML_GroupReconcileReadFailureRefusesTheLogin(t *testing.T) {
	t.Parallel()
	c, store := samlGroupSyncCore(t, []string{"engineers"}, nil)
	store.On("ListGroups", mock.Anything).Return(nil, errors.New("injected: groups table unavailable"))

	session, err := postACS(t, c)

	require.Error(t, err, "a reconcile that could not be applied must refuse the login")
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_FailedGroupRemovalRefusesTheLogin is the headline scenario
// from #2839 condition 1, stated there as "a user removed from an IdP admin
// group could keep a stale role and still log in": the assertion no longer
// carries a group the user still holds natively, the removal FAILS, and the old
// code minted a session anyway — handing the user a privilege the IdP had
// revoked, for the whole session lifetime.
//
// RED before the fix: no error, session returned, user still in group 42.
func TestCompleteSAML_FailedGroupRemovalRefusesTheLogin(t *testing.T) {
	t.Parallel()
	// The IdP asserts "engineers" only; the user also holds "idp-admins".
	c, store := samlGroupSyncCore(t, []string{"engineers"}, nil)
	store.On("ListGroups", mock.Anything).Return([]*models.Group{
		{ID: 41, Name: "engineers"},
		{ID: 42, Name: "idp-admins"},
	}, nil)
	store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{
		{ID: 41, Name: "engineers"},
		{ID: 42, Name: "idp-admins"},
	}, nil)
	// No admin-bypass role seeded, so both last-admin guards short-circuit and
	// the removal reaches storage — where it fails.
	store.On("ListAdminBypassRoleIDs", mock.Anything).Return([]uint{}, nil).Maybe()
	store.On("ListGroupRoleAssignments", mock.Anything, mock.Anything).Return([]storage.RoleAssignment{}, nil).Maybe()
	store.On("RemoveUserFromGroup", mock.Anything, uint(7), uint(42), uint(0)).Return(errors.New("injected: removal failed"))

	session, err := postACS(t, c)

	require.Error(t, err, "a membership the IdP revoked that could not be removed must refuse the login, not ride into a session")
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_RoleReconcileReadFailureRefusesTheLogin is the role-path
// counterpart: without the current grants, a mapped role the IdP no longer maps
// the user to may still be held.
func TestCompleteSAML_RoleReconcileReadFailureRefusesTheLogin(t *testing.T) {
	t.Parallel()
	c, store := samlGroupSyncCore(t, []string{"engineers"}, map[string]string{"engineers": "system_viewer"})
	store.On("ListGroups", mock.Anything).Return([]*models.Group{}, nil)
	store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{}, nil)
	store.On("GetUserRoles", mock.Anything, uint(7)).Return(nil, errors.New("injected: role read failed"))

	session, err := postACS(t, c)

	require.Error(t, err)
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_CleanReconcileStillMintsASession is the calibration that
// stops condition 1 being satisfied by refusing every login. Without it, a
// mutation that returned an error unconditionally from either reconcile would
// pass every test above.
func TestCompleteSAML_CleanReconcileStillMintsASession(t *testing.T) {
	t.Parallel()
	c, store := samlGroupSyncCore(t, []string{"engineers"}, map[string]string{"engineers": "system_viewer"})
	store.On("ListGroups", mock.Anything).Return([]*models.Group{{ID: 41, Name: "engineers"}}, nil)
	store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{{ID: 41, Name: "engineers"}}, nil)
	store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{{ID: 5, Name: "system_viewer"}}, nil)
	store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 5, Name: "system_viewer"}, nil)
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 7, SessionToken: "tok"}, nil)

	session, err := postACS(t, c)

	require.NoError(t, err, "a reconcile with nothing to change must still mint a session")
	require.NotNil(t, session)
	assert.Equal(t, "tok", session.SessionToken)
}

// TestReconcileSSORoles_UnknownRoleNameSkipsButLookupFailureDoesNot pins the
// distinction condition 1's soundness rests on. GroupRoleMap naming a role that
// does not exist is a CONFIGURATION fact and has always been skipped; a lookup
// that FAILED means whether that role should be revoked is unknown, which is
// the dangerous direction and must refuse.
//
// Before this change the two were indistinguishable: GetRoleByName returned a
// translated "role not found" message with no sentinel, and the caller skipped
// on any error at all — so a storage blip silently became "no such role, carry
// on". GetRoleByName now wraps storage.ErrRoleNotFound.
func TestReconcileSSORoles_UnknownRoleNameSkipsButLookupFailureDoesNot(t *testing.T) {
	t.Parallel()
	p := &SSOProvider{Name: "corp", GroupRoleMap: map[string]string{"engineers": "ghost_role"}}

	t.Run("unknown role name is skipped", func(t *testing.T) {
		store := new(MockStorage)
		c := &KeyorixCore{storage: store, now: time.Now}
		store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{}, nil)
		store.On("GetRoleByName", mock.Anything, "ghost_role").Return(nil,
			fmt.Errorf("role not found: %w", storage.ErrRoleNotFound))

		require.NoError(t, c.reconcileSSORoles(context.Background(), p, 7, []string{"engineers"}),
			"a GroupRoleMap entry naming a nonexistent role is a config fact, not a failure")
	})

	t.Run("a failed lookup refuses", func(t *testing.T) {
		store := new(MockStorage)
		c := &KeyorixCore{storage: store, now: time.Now}
		store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{}, nil)
		store.On("GetRoleByName", mock.Anything, "ghost_role").Return(nil, errors.New("injected: database unreachable"))

		err := c.reconcileSSORoles(context.Background(), p, 7, []string{"engineers"})
		require.Error(t, err, "a lookup FAILURE leaves it unknown whether a mapped role should be revoked")
		assert.ErrorIs(t, err, ErrSSOReconcileIncomplete)
	})
}

// ── Condition 2: removes as well as adds, from the assertion only ───────────

// TestCompleteSAML_ReconcileRemovesAsWellAsAdds asserts both directions in one
// login: the user gains the group the assertion carries and loses the one it
// does not. A reconcile that only ever ADDED would pass an add-only test and
// still leave every revoked membership in place forever.
func TestCompleteSAML_ReconcileRemovesAsWellAsAdds(t *testing.T) {
	t.Parallel()
	c, store := samlGroupSyncCore(t, []string{"engineers"}, nil)
	store.On("ListGroups", mock.Anything).Return([]*models.Group{
		{ID: 41, Name: "engineers"},   // asserted, not currently held -> ADD
		{ID: 42, Name: "contractors"}, // currently held, not asserted -> REMOVE
	}, nil)
	store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{{ID: 42, Name: "contractors"}}, nil)
	store.On("ListAdminBypassRoleIDs", mock.Anything).Return([]uint{}, nil).Maybe()
	store.On("ListGroupRoleAssignments", mock.Anything, mock.Anything).Return([]storage.RoleAssignment{}, nil).Maybe()
	store.On("ListGroupRoles", mock.Anything, mock.Anything).Return([]*models.Role{}, nil).Maybe()
	store.On("AddUserToGroup", mock.Anything, uint(7), uint(41), uint(0)).Return(nil)
	store.On("RemoveUserFromGroup", mock.Anything, uint(7), uint(42), uint(0)).Return(nil)
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 7, SessionToken: "tok"}, nil)

	_, err := postACS(t, c)
	require.NoError(t, err)

	store.AssertCalled(t, "AddUserToGroup", mock.Anything, uint(7), uint(41), uint(0))
	store.AssertCalled(t, "RemoveUserFromGroup", mock.Anything, uint(7), uint(42), uint(0))
}

// TestCompleteSAML_RolesDerivedOnlyFromTheValidatedAssertion is condition 2's
// second half. The role set must come from the assertion the SAML library
// validated and from the admin-configured GroupRoleMap — never from a group the
// user already holds natively.
//
// The user holds "contractors" natively and the map grants "system_admin" for
// it, but the ASSERTION carries only "engineers". So "system_admin" must not be
// granted, and "contractors" must be removed.
func TestCompleteSAML_RolesDerivedOnlyFromTheValidatedAssertion(t *testing.T) {
	t.Parallel()
	c, store := samlGroupSyncCore(t, []string{"engineers"}, map[string]string{
		"engineers":   "system_viewer",
		"contractors": "system_admin",
	})
	store.On("ListGroups", mock.Anything).Return([]*models.Group{
		{ID: 41, Name: "engineers"},
		{ID: 42, Name: "contractors"},
	}, nil)
	store.On("GetUserGroups", mock.Anything, uint(7)).Return([]*models.Group{{ID: 42, Name: "contractors"}}, nil)
	store.On("ListAdminBypassRoleIDs", mock.Anything).Return([]uint{}, nil).Maybe()
	store.On("ListGroupRoleAssignments", mock.Anything, mock.Anything).Return([]storage.RoleAssignment{}, nil).Maybe()
	store.On("AddUserToGroup", mock.Anything, uint(7), uint(41), uint(0)).Return(nil)
	store.On("RemoveUserFromGroup", mock.Anything, uint(7), uint(42), uint(0)).Return(nil)
	// The user currently holds neither mapped role, so nothing is revoked and
	// only the ASSERTED mapping may be granted.
	store.On("GetUserRoles", mock.Anything, uint(7)).Return([]*models.Role{}, nil)
	store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 5, Name: "system_viewer"}, nil)
	store.On("GetRoleByName", mock.Anything, "system_admin").Return(&models.Role{ID: 6, Name: "system_admin"}, nil)
	// idpAutoGrantOfRoleIsEscalation's backstop: system_viewer is neither
	// admin-bypass nor roles.assign-carrying, so the asserted mapping may be
	// granted. (system_admin never reaches here — it is not desired.)
	store.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	store.On("GetRole", mock.Anything, mock.Anything).Return(&models.Role{ID: 5, Name: "system_viewer"}, nil).Maybe()
	store.On("GetRolePermissions", mock.Anything, mock.Anything).Return([]*models.Permission{}, nil).Maybe()
	store.On("AssignRole", mock.Anything, uint(7), uint(5), mock.Anything).Return(nil).Maybe()
	store.On("GetUserRoleIDsAt", mock.Anything, mock.Anything, mock.Anything).Return([]uint{}, nil).Maybe()
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 7, SessionToken: "tok"}, nil)

	_, err := postACS(t, c)
	require.NoError(t, err)

	// The role mapped from the natively-held-but-unasserted group must never be
	// granted: that would let a stale native membership, rather than the IdP,
	// decide privileges.
	store.AssertNotCalled(t, "AssignRole", mock.Anything, uint(7), uint(6), mock.Anything)
}

// ── Condition 3: the JIT account creation is audited even if login fails ────

// TestCompleteSAML_JITProvisionIsAuditedEvenWhenTheLoginThenFails is condition
// 3, and it matters precisely BECAUSE this is class C: a JIT-provisioned
// account that exists before its owner ever successfully logged in is a real
// state, so the trail has to show where it came from. If the audit were written
// only on a fully successful login, every account created by a login that then
// failed would be unexplained.
//
// Here the account is created, then mintSession fails. The
// auth.sso_jit_provision event must still have landed.
func TestCompleteSAML_JITProvisionIsAuditedEvenWhenTheLoginThenFails(t *testing.T) {
	t.Parallel()
	stub := &stubSAML{info: &ports.SAMLAssertion{Subject: "corp|new", Email: "new@x.io", Name: "New"}}
	c, store := samlTestCore(stub)
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-1").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	// No account matches, either by external id or by email -> JIT provision.
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|new").Return(nil, userNotFound())
	store.On("GetUserByEmail", mock.Anything, "new@x.io").Return(nil, userNotFound())
	store.On("GetUserByUsername", mock.Anything, mock.Anything).Return(nil, userNotFound()).Maybe()
	store.On("FindSCIMUser", mock.Anything, mock.Anything, mock.Anything).Return(nil, userNotFound()).Maybe()
	store.On("CreateUser", mock.Anything, mock.Anything).Return(&models.User{
		ID: 9, Email: "new@x.io", IsActive: true, AccountState: AccountActive,
	}, nil)
	store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 5, Name: "system_viewer"}, nil)
	store.On("AssignRole", mock.Anything, uint(9), uint(5), mock.Anything).Return(nil)
	// The login then fails at the very last fallible step.
	store.On("CreateSession", mock.Anything, mock.Anything).Return(nil, errors.New("injected: session mint failed"))

	var audited []string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		audited = append(audited, e.EventType)
		return true
	})).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, _, _, err := c.CompleteSAML(context.Background(), "corp", req, "relay-1", "ua", "1.2.3.4")

	require.Error(t, err, "the mint failure must still fail the login")
	assert.Nil(t, session)
	assert.Contains(t, audited, EventSSOJITProvision,
		"the JIT account exists, so its creation must be in the audit trail even though the login failed — "+
			"otherwise an account created by a failed login is unexplained. Got: %v", audited)
	assert.NotContains(t, audited, EventSSOLogin, "no login event may be written for a login that failed")
}
