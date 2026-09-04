// authz_guard_functions_test.go — coverage for a cluster of authorization/
// session-liveness guard functions that sat at 0% (or near it): the
// escalation-by-proxy ceilings (RequireMachinePrivilegeCeiling,
// RequireAdminAuthorityAt, ValidateRoleGrantAuthority,
// requireUserCredentialsRevokeAuthority), the machine-lifecycle legality
// check (IsValidMachineTransition), the session/account liveness re-checks
// #G18 added for the long-lived-stream cache-hit path (SessionStillLive,
// AccountStillUsable), the last-admin lockout guard (GuardLastAdminDeactivation),
// and the two /system proxy entry points built on the revoke ceiling
// (RevokeAllPersonalAccessTokensForUser, DeleteSessionsForUserExcept). These
// are exactly the security-boundary functions where an untested allow/deny
// edge is a privilege-escalation risk, so each gets its allow case, its deny
// case, and the boundary the function's own name implies.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── RequireMachinePrivilegeCeiling (MACH-001) ───────────────────────────────

func TestRequireMachinePrivilegeCeiling_AdminTargetActorGlobalAdmin_Allowed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineRoles", mock.Anything, uint(7)).Return([]*models.Role{{ID: 50, Name: "admin"}}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{50}).Return(true, nil)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{99}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{99}).Return(true, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeUser, 3, 2, 7)
	require.NoError(t, err, "a global admin may mint a credential for an admin-tier machine identity")
}

func TestRequireMachinePrivilegeCeiling_AdminTargetActorNotGlobalAdmin_Denied(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineRoles", mock.Anything, uint(7)).Return([]*models.Role{{ID: 50, Name: "admin"}}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{50}).Return(true, nil)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{11}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{11}).Return(false, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeUser, 3, 2, 7)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

// ADR-030: a machine is never a global admin, so a machine actor can never
// clear the admin-tier-target branch regardless of what permissions it
// bundles -- IsGlobalAdmin must not even be consulted for a machine actor.
func TestRequireMachinePrivilegeCeiling_AdminTarget_MachineActorAlwaysDenied(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineRoles", mock.Anything, uint(7)).Return([]*models.Role{{ID: 50, Name: "admin"}}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{50}).Return(true, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeMachine, 3, 2, 7)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

// machineID==0: the identity doesn't exist yet (creation-time check), so the
// ceiling falls to the actor's own roles.assign authority at the target
// project scope -- the SAME authority the human-facing creation route
// requires.
func TestRequireMachinePrivilegeCeiling_NewIdentity_ActorHasRolesAssign_Allowed(t *testing.T) {
	ms := new(MockStorage)
	stubAuthorizedPrincipal(ms, 3, Scope{ProjectID: 2}, permRolesAssign)

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeUser, 3, 2, 0)
	require.NoError(t, err)
}

func TestRequireMachinePrivilegeCeiling_NewIdentity_ActorLacksRolesAssign_Denied(t *testing.T) {
	ms := new(MockStorage)
	stubUnauthorizedPrincipal(ms, 3, Scope{ProjectID: 2})

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeUser, 3, 2, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

// A machine identity that exists but doesn't (yet) hold an admin-tier role
// falls through to the SAME roles.assign check as machineID==0 -- an actor
// without it must still be refused, even though the target itself isn't
// admin-tier.
func TestRequireMachinePrivilegeCeiling_NonAdminTarget_ActorLacksRolesAssign_Denied(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineRoles", mock.Anything, uint(7)).Return([]*models.Role{{ID: 12, Name: "project_viewer"}}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{12}).Return(false, nil)
	stubUnauthorizedPrincipal(ms, 3, Scope{ProjectID: 2})

	c := NewKeyorixCore(ms)
	err := c.RequireMachinePrivilegeCeiling(context.Background(), ActorTypeUser, 3, 2, 7)
	require.Error(t, err)
}

// ── RequireAdminAuthorityAt ──────────────────────────────────────────────

func TestRequireAdminAuthorityAt_Allowed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{ProjectID: 2}).Return([]uint{50}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{ProjectID: 2}).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{50}).Return(true, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireAdminAuthorityAt(context.Background(), 3, 2)
	require.NoError(t, err)
}

func TestRequireAdminAuthorityAt_Denied(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{ProjectID: 2}).Return([]uint{11}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{ProjectID: 2}).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{11}).Return(false, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireAdminAuthorityAt(context.Background(), 3, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin authority is required")
}

// projectID 0 means global scope -- a distinct Scope{} lookup, not just
// Scope{ProjectID: 0} coincidentally matching.
func TestRequireAdminAuthorityAt_GlobalScopeAllowed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{50}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(3), Scope{}).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{50}).Return(true, nil)

	c := NewKeyorixCore(ms)
	err := c.RequireAdminAuthorityAt(context.Background(), 3, 0)
	require.NoError(t, err)
}

// ── ValidateRoleGrantAuthority ───────────────────────────────────────────

func TestValidateRoleGrantAuthority_Allowed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "custom"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(5)).Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	stubAuthorizedPrincipal(ms, 1, Scope{ProjectID: 2}, "secrets.read")

	c := NewKeyorixCore(ms)
	grants := []storage.RoleGrant{{RoleID: 5, Scope: storage.Scope{ProjectID: 2}}}
	err := c.ValidateRoleGrantAuthority(context.Background(), 1, false, grants)
	require.NoError(t, err)
}

func TestValidateRoleGrantAuthority_DeniedWhenActorLacksBundledPermission(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "custom"}, nil)
	ms.On("GetRolePermissions", mock.Anything, uint(5)).Return([]*models.Permission{{Name: "secrets.read"}}, nil)
	stubUnauthorizedPrincipal(ms, 1, Scope{ProjectID: 2})

	c := NewKeyorixCore(ms)
	grants := []storage.RoleGrant{{RoleID: 5, Scope: storage.Scope{ProjectID: 2}}}
	err := c.ValidateRoleGrantAuthority(context.Background(), 1, false, grants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "you do not hold permission")
}

func TestValidateRoleGrantAuthority_RejectsOversizedBatch(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	grants := make([]storage.RoleGrant, maxUserCreateAssignments+1)
	err := c.ValidateRoleGrantAuthority(context.Background(), 1, false, grants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the maximum batch size")
}

func TestValidateRoleGrantAuthority_UnknownRoleID(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(999)).Return(nil, errors.New("record not found"))

	c := NewKeyorixCore(ms)
	grants := []storage.RoleGrant{{RoleID: 999, Scope: storage.Scope{ProjectID: 2}}}
	err := c.ValidateRoleGrantAuthority(context.Background(), 1, false, grants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown role id")
}

// ── IsValidMachineTransition ─────────────────────────────────────────────

func TestIsValidMachineTransition(t *testing.T) {
	cases := []struct {
		name      string
		from, to  string
		wantLegal bool
	}{
		{"pending to active", MachinePending, MachineActive, true},
		{"pending to revoked", MachinePending, MachineRevoked, true},
		{"pending to suspended is illegal", MachinePending, MachineSuspended, false},
		{"active to suspended", MachineActive, MachineSuspended, true},
		{"active to revoked", MachineActive, MachineRevoked, true},
		{"active back to pending is illegal", MachineActive, MachinePending, false},
		{"suspended to active", MachineSuspended, MachineActive, true},
		{"suspended to revoked", MachineSuspended, MachineRevoked, true},
		{"revoked is terminal: to active illegal", MachineRevoked, MachineActive, false},
		{"revoked is terminal: to pending illegal", MachineRevoked, MachinePending, false},
		{"revoked is terminal: to suspended illegal", MachineRevoked, MachineSuspended, false},
		{"self-transition is illegal", MachineActive, MachineActive, false},
		{"unknown state is illegal", "bogus", MachineActive, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantLegal, IsValidMachineTransition(tc.from, tc.to))
		})
	}
}

// ── SessionStillLive (#G18) ──────────────────────────────────────────────

func TestSessionStillLive(t *testing.T) {
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	newCore := func(sess *models.Session, err error) *KeyorixCore {
		ms := new(MockStorage)
		ms.On("GetSessionByID", mock.Anything, uint(1)).Return(sess, err)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		return c
	}

	t.Run("live session", func(t *testing.T) {
		exp := fixed.Add(time.Hour)
		abs := fixed.Add(24 * time.Hour)
		c := newCore(&models.Session{ID: 1, ExpiresAt: &exp, AbsoluteExpiresAt: &abs}, nil)
		live, err := c.SessionStillLive(context.Background(), 1)
		require.NoError(t, err)
		assert.True(t, live)
	})

	t.Run("rotated away is not live", func(t *testing.T) {
		rotated := fixed.Add(-time.Minute)
		c := newCore(&models.Session{ID: 1, RotatedAt: &rotated}, nil)
		live, err := c.SessionStillLive(context.Background(), 1)
		require.NoError(t, err)
		assert.False(t, live, "a rotated session must never be reported live regardless of its expiry fields")
	})

	t.Run("access window expired", func(t *testing.T) {
		exp := fixed.Add(-time.Minute)
		c := newCore(&models.Session{ID: 1, ExpiresAt: &exp}, nil)
		live, err := c.SessionStillLive(context.Background(), 1)
		require.NoError(t, err)
		assert.False(t, live)
	})

	t.Run("absolute lifetime ceiling expired even within the access window", func(t *testing.T) {
		exp := fixed.Add(time.Hour)
		abs := fixed.Add(-time.Minute)
		c := newCore(&models.Session{ID: 1, ExpiresAt: &exp, AbsoluteExpiresAt: &abs}, nil)
		live, err := c.SessionStillLive(context.Background(), 1)
		require.NoError(t, err)
		assert.False(t, live)
	})

	t.Run("no expiry fields set at all is live", func(t *testing.T) {
		c := newCore(&models.Session{ID: 1}, nil)
		live, err := c.SessionStillLive(context.Background(), 1)
		require.NoError(t, err)
		assert.True(t, live)
	})

	t.Run("storage error fails closed", func(t *testing.T) {
		c := newCore(nil, errors.New("connection reset"))
		live, err := c.SessionStillLive(context.Background(), 1)
		require.Error(t, err)
		assert.False(t, live)
	})
}

// ── AccountStillUsable (#G18) ─────────────────────────────────────────────

func TestAccountStillUsable(t *testing.T) {
	newCore := func(user *models.User, err error) *KeyorixCore {
		ms := new(MockStorage)
		ms.On("GetUser", mock.Anything, uint(1)).Return(user, err)
		return NewKeyorixCore(ms)
	}

	t.Run("active account is usable", func(t *testing.T) {
		c := newCore(&models.User{ID: 1, IsActive: true, AccountState: AccountActive}, nil)
		ok, err := c.AccountStillUsable(context.Background(), 1)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("deactivated (is_active=false) account is not usable even with AccountState active", func(t *testing.T) {
		c := newCore(&models.User{ID: 1, IsActive: false, AccountState: AccountActive}, nil)
		ok, err := c.AccountStillUsable(context.Background(), 1)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("suspended account is not usable even with IsActive true", func(t *testing.T) {
		c := newCore(&models.User{ID: 1, IsActive: true, AccountState: AccountSuspended}, nil)
		ok, err := c.AccountStillUsable(context.Background(), 1)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("storage error fails closed", func(t *testing.T) {
		c := newCore(nil, errors.New("connection reset"))
		ok, err := c.AccountStillUsable(context.Background(), 1)
		require.Error(t, err)
		assert.False(t, ok)
	})
}

// ── GuardLastAdminDeactivation ────────────────────────────────────────────
// Reuses newSCIMGuardCore (scim_guards_test.go), a real-SQLite fixture, since
// this guard's own resolution (resolveGlobalAdminHolders, group-aware) is
// awkward to hand-mock faithfully and the fixture already exists for exactly
// this purpose.

func TestGuardLastAdminDeactivation_RefusesLastAdmin(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)

	err := c.GuardLastAdminDeactivation(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")
}

func TestGuardLastAdminDeactivation_AllowsWhenAnotherAdminRemains(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "second", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	err := c.GuardLastAdminDeactivation(ctx, 1)
	require.NoError(t, err, "a second admin survives, so deactivating the first must be allowed")
}

func TestGuardLastAdminDeactivation_AllowsNonAdminTarget(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "viewer", IsActive: true, AccountState: AccountActive}).Error)

	err := c.GuardLastAdminDeactivation(ctx, 1)
	require.NoError(t, err, "a non-admin target is never the last-admin case")
}

// ── requireUserCredentialsRevokeAuthority / RevokeAllPersonalAccessTokensForUser / DeleteSessionsForUserExcept ──

func TestRevokeAllPersonalAccessTokensForUser(t *testing.T) {
	t.Run("authorized actor revokes and audits", func(t *testing.T) {
		ms := new(MockStorage)
		stubAuthorizedPrincipal(ms, 9, Scope{}, permUsersWrite)
		ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, uint(5)).Return([]string{"hash-1"}, nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		c := NewKeyorixCore(ms)
		hashes, err := c.RevokeAllPersonalAccessTokensForUser(context.Background(), ActorTypeUser, 9, 5)
		require.NoError(t, err)
		assert.Equal(t, []string{"hash-1"}, hashes)
	})

	t.Run("actor without users.write is refused before any revocation", func(t *testing.T) {
		ms := new(MockStorage)
		stubUnauthorizedPrincipal(ms, 9, Scope{})

		c := NewKeyorixCore(ms)
		_, err := c.RevokeAllPersonalAccessTokensForUser(context.Background(), ActorTypeUser, 9, 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "users.write authority")
		// No RevokeAllPersonalAccessTokensForUser/LogAuditEvent stub was set up above:
		// if the ceiling check didn't short-circuit, the unmet mock expectation
		// below would fail the test on AssertExpectations.
		ms.AssertNotCalled(t, "RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything)
	})

	t.Run("machine actor without users.write is refused", func(t *testing.T) {
		ms := new(MockStorage)
		ms.On("GetMachineRoleIDsAt", mock.Anything, uint(9), Scope{}).Return([]uint{}, nil)

		c := NewKeyorixCore(ms)
		_, err := c.RevokeAllPersonalAccessTokensForUser(context.Background(), ActorTypeMachine, 9, 5)
		require.Error(t, err)
	})
}

func TestDeleteSessionsForUserExcept(t *testing.T) {
	t.Run("authorized actor deletes and audits", func(t *testing.T) {
		ms := new(MockStorage)
		stubAuthorizedPrincipal(ms, 9, Scope{}, permUsersWrite)
		ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(5)).Return([]string{"hash-1"}, nil)
		ms.On("DeleteSessionsForUserExcept", mock.Anything, uint(5), uint(3)).Return(nil)
		ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		c := NewKeyorixCore(ms)
		err := c.DeleteSessionsForUserExcept(context.Background(), ActorTypeUser, 9, 5, 3)
		require.NoError(t, err)
	})

	t.Run("actor without users.write is refused before any deletion", func(t *testing.T) {
		ms := new(MockStorage)
		stubUnauthorizedPrincipal(ms, 9, Scope{})

		c := NewKeyorixCore(ms)
		err := c.DeleteSessionsForUserExcept(context.Background(), ActorTypeUser, 9, 5, 3)
		require.Error(t, err)
		ms.AssertNotCalled(t, "DeleteSessionsForUserExcept", mock.Anything, mock.Anything, mock.Anything)
	})
}

// ── RequireGranterHoldsRolePermissions ────────────────────────────────────
// This is the escalation-by-proxy ceiling every role-GRANT choke point uses
// (InviteToProject, CreateUserWithAssignments, ValidateRoleGrantAuthority
// above, ...): the granter must already hold, themselves, every permission
// the role being granted bundles -- the modern, permission-derived successor
// to the old fixed-name requireAuthorityForRole (see invitations.go's REMOVED
// doc comment). RequireGranterHoldsRolePermissions is its /system-proxy-layer
// export, for a caller outside internal/core (server/http/handlers) that
// needs to re-derive the SAME ceiling a matching core method already enforced
// locally before relaying a state change.

func TestRequireGranterHoldsRolePermissions_Allowed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRolePermissions", mock.Anything, uint(5)).Return([]*models.Permission{{Name: "secrets.read"}, {Name: "secrets.write"}}, nil)
	stubAuthorizedPrincipal(ms, 1, Scope{ProjectID: 2}, "secrets.read")
	stubAuthorizedPrincipal(ms, 1, Scope{ProjectID: 2}, "secrets.write")

	c := NewKeyorixCore(ms)
	err := c.RequireGranterHoldsRolePermissions(context.Background(), 1, 5, Scope{ProjectID: 2}, false)
	require.NoError(t, err)
}

func TestRequireGranterHoldsRolePermissions_DeniedWhenMissingOneBundledPermission(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRolePermissions", mock.Anything, uint(5)).Return([]*models.Permission{{Name: "secrets.read"}, {Name: "secrets.write"}}, nil)
	// The actor holds secrets.read but not secrets.write -- the role grant must
	// still be refused, since it would hand them the write permission by proxy.
	const roleID = uint(10)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), Scope{ProjectID: 2}).Return([]uint{roleID}, nil).Maybe()
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), Scope{ProjectID: 2}).Return([]uint{}, nil).Maybe()
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	ms.On("RoleSetHasPermission", mock.Anything, []uint{roleID}, "secrets.read").Return(true, nil).Maybe()
	ms.On("RoleSetHasPermission", mock.Anything, []uint{roleID}, "secrets.write").Return(false, nil).Maybe()

	c := NewKeyorixCore(ms)
	err := c.RequireGranterHoldsRolePermissions(context.Background(), 1, 5, Scope{ProjectID: 2}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "you do not hold permission")
}

// actorID==0 with actorIsMachine==false is the bootstrap/system-initiated
// grant case (no human/machine actor to check authority against) -- the
// ceiling is a deliberate no-op here, not an oversight, so GetRolePermissions
// must never even be consulted.
func TestRequireGranterHoldsRolePermissions_BootstrapActorBypasses(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.RequireGranterHoldsRolePermissions(context.Background(), 0, 5, Scope{ProjectID: 2}, false)
	require.NoError(t, err)
	ms.AssertNotCalled(t, "GetRolePermissions", mock.Anything, mock.Anything)
}

func TestRequireGranterHoldsRolePermissions_RoleLookupErrorFailsClosed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRolePermissions", mock.Anything, uint(5)).Return(nil, errors.New("connection reset"))
	c := NewKeyorixCore(ms)
	err := c.RequireGranterHoldsRolePermissions(context.Background(), 1, 5, Scope{ProjectID: 2}, false)
	require.Error(t, err)
}

// ── remaining branches: requireUserCredentialsRevokeAuthority's own
// AuthorizePrincipal-error path, and the underlying storage-error paths in
// RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept ─────────

func TestRequireUserCredentialsRevokeAuthority_StorageErrorFailsClosed(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(9), Scope{}).Return(nil, errors.New("connection reset"))
	c := NewKeyorixCore(ms)
	_, err := c.RevokeAllPersonalAccessTokensForUser(context.Background(), ActorTypeUser, 9, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve actor authority")
}

func TestRevokeAllPersonalAccessTokensForUser_StorageErrorPropagates(t *testing.T) {
	ms := new(MockStorage)
	stubAuthorizedPrincipal(ms, 9, Scope{}, permUsersWrite)
	ms.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, uint(5)).Return(nil, errors.New("db down"))

	c := NewKeyorixCore(ms)
	_, err := c.RevokeAllPersonalAccessTokensForUser(context.Background(), ActorTypeUser, 9, 5)
	require.Error(t, err)
}

func TestDeleteSessionsForUserExcept_StorageErrorPropagates(t *testing.T) {
	ms := new(MockStorage)
	stubAuthorizedPrincipal(ms, 9, Scope{}, permUsersWrite)
	ms.On("ListSessionTokenHashesForUser", mock.Anything, uint(5)).Return([]string{}, nil)
	ms.On("DeleteSessionsForUserExcept", mock.Anything, uint(5), uint(3)).Return(errors.New("db down"))

	c := NewKeyorixCore(ms)
	err := c.DeleteSessionsForUserExcept(context.Background(), ActorTypeUser, 9, 5, 3)
	require.Error(t, err)
}
