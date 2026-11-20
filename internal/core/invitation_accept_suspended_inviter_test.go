package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompleteInvitationAccept_SuspendedInviterGrantsNothing is #4507: a pending
// project-scoped invitation from an inviter who has since been suspended must not
// grant the role when the invitee consumes the (unauthenticated) setup link. The
// account-state check sat only on the exported InviteMember, while accept-time
// grants call inviteMemberWithMode directly, so the suspended inviter's role rows
// were taken at face value. The refusal comes before anything is written, so the
// link still works once the inviter is reactivated.
//
// The active-inviter arm is the positive control: the same fixture is accepted.
func TestCompleteInvitationAccept_SuspendedInviterGrantsNothing(t *testing.T) {
	t.Parallel()
	for _, suspended := range []bool{true, false} {
		name := "active inviter accepted"
		if suspended {
			name = "suspended inviter refused"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			const email = "suspended-inviter-invitee@example.com"
			const rawToken = setupPrefix + "invite-accept-suspended-inviter-1"
			const inviterID = 1 // the bootstrap administrator

			project, err := st.CreateProject(ctx, &models.Project{Name: "inviter-state-project"})
			require.NoError(t, err)
			now := c.now()
			future := now.Add(24 * time.Hour)
			inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
				ProjectID: project.ID, Email: email, Role: "project_developer", State: InvitationPending,
				InvitedBy: inviterID, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: now,
			})
			require.NoError(t, err)
			_, err = st.CreateSetupToken(ctx, &models.SetupToken{
				TokenHash: sha256Hex(rawToken), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
				InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: future, CreatedBy: inviterID,
			})
			require.NoError(t, err)
			if suspended {
				// Straight to storage: suspension keeps the role rows and the invitation.
				require.NoError(t, st.SetAccountState(ctx, inviterID, AccountSuspended, now))
			}

			_, err = c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
			members, merr := st.ListProjectMemberships(ctx, project.ID)
			require.NoError(t, merr)

			if !suspended {
				require.NoError(t, err)
				assert.Len(t, members, 1, "an active inviter's invitation grants the membership")
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrPermissionDenied), "refused as a permission decision, got %v", err)
			assert.Empty(t, members, "no membership may come from a suspended inviter's authority")
			_, uerr := st.GetUserByEmail(ctx, email)
			assert.Error(t, uerr, "no account is created")
			tok, terr := st.GetSetupTokenByHash(ctx, sha256Hex(rawToken))
			require.NoError(t, terr)
			assert.Equal(t, SetupTokenActive, tok.State, "the link is not spent by the refusal")
			reloaded, ierr := st.GetProjectInvitation(ctx, inv.ID)
			require.NoError(t, ierr)
			assert.Equal(t, InvitationPending, reloaded.State)
		})
	}
}
