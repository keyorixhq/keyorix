package core

// machine_token_ceiling_actor_kind_test.go — regression coverage for the authzdiff
// cross-layer differential harness's known-03 finding (server/authzdiff/REPORT.md,
// internal historical name D3): IssueMachineToken's MACH-001 privilege-ceiling check
// (requireMachinePrivilegeCeiling) used to hardcode (ActorTypeUser, actorID) as the
// AUTHORIZING principal, even though requireMachinePrivilegeCeiling itself is already
// actor-kind-aware. Both the HTTP and gRPC routes in front of this call already admit a
// machine actor holding roles.assign (RequireScopedPermission/authorizeScoped), but
// actorID for a real machine caller is always 0 (ADR-030, UserID is never set for a
// machine principal) -- so the ceiling evaluated "user 0", which holds no roles, and
// refused every machine actor unconditionally. Fails closed (no escalation ever
// occurred), but contradicts the route gate it sits behind.
//
// The fix threads the real authorizing principal (actor.ActorKind(), actor.PrincipalID())
// through two new parameters, actorKind/actorPrincipalID, instead of reusing actorID
// (which stays exactly what it always was: audit attribution only, 0 for a machine
// caller). These two cases are this file's whole point: a machine actor holding
// roles.assign now succeeds (the fix); the same call shape the OLD code always made --
// (ActorTypeUser, principalID 0) -- still correctly denies, proving the fix didn't
// accidentally loosen anything for the shape the bug actually produced.
import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIssueMachineToken_CeilingUsesRealActorKind(t *testing.T) {
	t.Parallel()
	scope := Scope{ProjectID: 2}

	newStore := func() *MockStorage {
		store := new(MockStorage)
		// Target machine (being issued a token): active, in project 2, holds no
		// roles of its own (not admin-tier) -- so requireMachinePrivilegeCeiling
		// falls through to the actor-authority check both subtests exercise.
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
		store.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{}, nil)
		store.On("CreateMachineIdentityCredential", mock.Anything, mock.AnythingOfType("*models.MachineIdentityCredential")).
			Return(&models.MachineIdentityCredential{ID: 9}, nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
		return store
	}

	t.Run("machine actor holding roles.assign succeeds (the fix)", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		// The calling machine identity (principal 50) holds roles.assign at
		// project 2 via a plain, non-admin RBAC role grant -- exactly the
		// authority the route gate (RequireScopedPermission/authorizeScoped) in
		// front of this call already required before letting the request through.
		store.On("GetMachineRoleIDsAt", mock.Anything, uint(50), scope).Return([]uint{77}, nil)
		store.On("RoleSetHasPermission", mock.Anything, []uint{77}, permRolesAssign).Return(true, nil)
		c := NewKeyorixCore(store)

		// actorID (audit attribution) stays 0, exactly what a real machine
		// caller's UserID always is (ADR-030) -- only actorKind/actorPrincipalID
		// carry the real authorizing principal now.
		res, err := c.IssueMachineToken(context.Background(), 2, 1, 0, ActorTypeMachine, 50, IssueMachineTokenParams{Name: "ci"})
		require.NoError(t, err, "a machine actor holding roles.assign at the target's project must be able to issue a token for it")
		require.NotNil(t, res)
	})

	t.Run("the old hardcoded call shape (ActorTypeUser, principal 0) still denies", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		// This is exactly what every pre-fix call site produced for a real
		// machine actor: (ActorTypeUser, actorID) with actorID==0. Proves the
		// fix is additive -- it does not also loosen what the bug's own call
		// shape would have evaluated to.
		store.On("GetUserRoleIDsAt", mock.Anything, uint(0), scope).Return([]uint{}, nil)
		store.On("GetUserGroupRoleIDsAt", mock.Anything, uint(0), scope).Return([]uint{}, nil)
		c := NewKeyorixCore(store)

		_, err := c.IssueMachineToken(context.Background(), 2, 1, 0, ActorTypeUser, 0, IssueMachineTokenParams{Name: "ci"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	})
}
