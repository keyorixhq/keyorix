package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The invitation shapes #4507 named beyond the project-scoped one that
// TestCompleteInvitationAccept_SuspendedInviterGrantsNothing covers: a global
// invite with project assignments and no system role (its grants never reach the
// exported AssignUserRole, whose own check refused a system-role invite even
// before #4507), the re-check inside applyInvitationGrants on its own (an inviter
// suspended after completeInvitationAccept's pre-check), and a machine inviter,
// which has no user account and must still be accepted.

// TestCompleteInvitationAccept_SuspendedInviterGlobalAssignmentsGrantNothing: a
// global invitation carrying only project assignments, from an inviter suspended
// since, grants no membership and no role, creates no account, and leaves the
// link and the invitation as they were.
func TestCompleteInvitationAccept_SuspendedInviterGlobalAssignmentsGrantNothing(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const email = "suspended-global-inviter-invitee@example.com"
	const rawToken = setupPrefix + "invite-accept-suspended-global-inviter-1"
	const inviterID = 1 // the bootstrap administrator

	project, err := st.CreateProject(ctx, &models.Project{Name: "inviter-state-global-project"})
	require.NoError(t, err)
	assignments, err := json.Marshal([]ProjectAssignment{{ProjectID: project.ID, Role: "project_developer"}})
	require.NoError(t, err)
	now := c.now()
	future := now.Add(24 * time.Hour)
	inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 0, Email: email, State: InvitationPending, AssignmentsJSON: string(assignments),
		InvitedBy: inviterID, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: now,
	})
	require.NoError(t, err)
	_, err = st.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: sha256Hex(rawToken), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
		InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: future, CreatedBy: inviterID,
	})
	require.NoError(t, err)
	require.NoError(t, st.SetAccountState(ctx, inviterID, AccountSuspended, now))

	_, err = c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPermissionDenied), "refused as a permission decision, got %v", err)
	members, merr := st.ListProjectMemberships(ctx, project.ID)
	require.NoError(t, merr)
	assert.Empty(t, members, "no membership may come from a suspended inviter's authority")
	_, uerr := st.GetUserByEmail(ctx, email)
	assert.Error(t, uerr, "no account is created, so no role row can exist for it")
	tok, terr := st.GetSetupTokenByHash(ctx, sha256Hex(rawToken))
	require.NoError(t, terr)
	assert.Equal(t, SetupTokenActive, tok.State, "the link is not spent by the refusal")
	reloaded, ierr := st.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, ierr)
	assert.Equal(t, InvitationPending, reloaded.State)
}

// TestApplyInvitationGrants_SuspendedInviterGrantsNothing exercises the re-check
// in applyInvitationGrants by itself: an inviter suspended after the accept's
// pre-check (the account already exists) still grants nothing, for a
// project-scoped invite and for a global invite with assignments only. The active
// arm is the positive control on the same fixture.
func TestApplyInvitationGrants_SuspendedInviterGrantsNothing(t *testing.T) {
	t.Parallel()
	shapes := []struct {
		name   string
		global bool
	}{{"project invite", false}, {"global invite, assignments only", true}}
	for _, shape := range shapes {
		for _, suspended := range []bool{true, false} {
			name := fmt.Sprintf("%s, active inviter", shape.name)
			if suspended {
				name = fmt.Sprintf("%s, suspended inviter", shape.name)
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				c, st := newBootstrappedCore(t)
				ctx := context.Background()
				inviterID := seedUserWithRole(t, st, "grant-recheck-inviter", "admin", storage.Scope{})
				invitee, err := st.CreateUser(ctx, foldedTestUser(t, "grant-recheck-invitee", "grant-recheck-invitee@example.com"))
				require.NoError(t, err)
				project, err := st.CreateProject(ctx, &models.Project{Name: "grant-recheck-project"})
				require.NoError(t, err)
				inv := &models.ProjectInvitation{
					ID: 1, ProjectID: project.ID, Email: invitee.Email, Role: "project_developer",
					InvitedBy: inviterID, ValidationModeAtInvite: ValidationModeOpen,
				}
				if shape.global {
					b, err := json.Marshal([]ProjectAssignment{{ProjectID: project.ID, Role: "project_developer"}})
					require.NoError(t, err)
					inv.ProjectID, inv.Role, inv.AssignmentsJSON = 0, "", string(b)
				}
				if suspended {
					require.NoError(t, st.SetAccountState(ctx, inviterID, AccountSuspended, c.now()))
				}

				err = c.applyInvitationGrants(ctx, inv, invitee.ID)
				members, merr := st.ListProjectMemberships(ctx, project.ID)
				require.NoError(t, merr)
				roles, rerr := st.GetUserRoleIDsAt(ctx, invitee.ID, storage.Scope{ProjectID: project.ID})
				require.NoError(t, rerr)
				if !suspended {
					require.NoError(t, err)
					assert.Len(t, members, 1, "an active inviter's invitation grants the membership")
					assert.Len(t, roles, 1, "and the role")
					return
				}
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrPermissionDenied), "refused as a permission decision, got %v", err)
				assert.Empty(t, members, "no membership row")
				assert.Empty(t, roles, "no role row")
			})
		}
	}
}

// TestApplyInvitationGrants_MachineInviterIsNotAccountChecked: a machine inviter
// (InvitedBy 0, the machine in InvitedByMachineIdentityID) has no user account,
// so the #4507 check skips it, as requireActorActive skips every machine actor;
// its own role ceiling still applies. The mock has no GetUser expectation, so an
// account read for the inviter fails the test.
func TestApplyInvitationGrants_MachineInviterIsNotAccountChecked(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()

	store.On("GetRoleByName", mock.Anything, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	store.On("GetMachineRoleIDsAt", mock.Anything, uint(42), storage.Scope{ProjectID: 1}).Return([]uint{200}, nil)
	store.On("RoleSetHasPermission", mock.Anything, []uint{200}, "roles.assign").Return(true, nil)
	store.On("GetActiveProjectMembership", mock.Anything, uint(1), uint(2)).Return(nil, fmt.Errorf("not found"))
	store.On("CreateProjectMembership", mock.Anything, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.InvitedBy == 0 && m.InvitedByMachineIdentityID == 42
	})).Return(&models.ProjectMembership{ID: 51, ProjectID: 1, UserID: 2, State: MembershipInvited}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	inv := &models.ProjectInvitation{
		ID: 1, ProjectID: 1, Email: "machine-invitee@example.com", Role: "project_developer",
		InvitedBy: 0, InvitedByMachineIdentityID: 42, ValidationModeAtInvite: ValidationModeAllowlist,
	}
	require.NoError(t, c.applyInvitationGrants(ctx, inv, 2))
	store.AssertExpectations(t)
	store.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
}
