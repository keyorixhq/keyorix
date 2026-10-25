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

// TestCompleteInvitationAccept_LegacyGlobalProjectRoleRefusedBeforeAnyWrite is
// #3554 review follow-up 2: a global invitation created before #3546 can name a
// project role as its system role (granted at the global scope). Accepting it
// used to create the account, spend the single-use token, and only then have
// the grant refused, deleting the account again: every resend repeated that.
// The role-scope check now runs before anything is written.
func TestCompleteInvitationAccept_LegacyGlobalProjectRoleRefusedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const email = "legacy-invitee@example.com"
	const rawToken = setupPrefix + "invite-accept-legacy-scope-1"

	now := c.now()
	future := now.Add(24 * time.Hour)
	// Written straight to storage, the way a pre-#3546 InviteGlobal left it.
	inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		Email: email, SystemRole: "project_developer", State: InvitationPending,
		InvitedBy: 1, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: now,
	})
	require.NoError(t, err)
	_, err = st.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: sha256Hex(rawToken), Purpose: SetupPurposeInvitationAccept, SubjectEmail: email,
		InvitationID: &inv.ID, State: SetupTokenActive, ExpiresAt: future, CreatedBy: 1,
	})
	require.NoError(t, err)

	_, err = c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRoleScopeInvalid), "refused by the role-scope check, got %v", err)

	// The effect: nothing was written.
	_, uerr := st.GetUserByEmail(ctx, email)
	assert.Error(t, uerr, "no account may be created for an invitation that cannot be accepted")
	tok, terr := st.GetSetupTokenByHash(ctx, sha256Hex(rawToken))
	require.NoError(t, terr)
	assert.Equal(t, SetupTokenActive, tok.State, "the link must not be spent by a refusal")
	reloaded, ierr := st.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, ierr)
	assert.Equal(t, InvitationPending, reloaded.State)
}
