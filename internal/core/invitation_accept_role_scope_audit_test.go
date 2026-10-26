package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompleteInvitationAccept_RoleScopeRefusalIsAudited is the #3610 review
// finding: ConsumeSetup answers a role-scope refusal with the generic setup-link
// 400, and on v0.96 its handler audits nothing (main's LogSetupConsumeFailure
// does not exist here), so a refused pre-#3546 invitation left no trace. The
// refusal is now written as setup_token.consume_failed (Success=false) by core,
// with the reason, the project and the caller's IP.
func TestCompleteInvitationAccept_RoleScopeRefusalIsAudited(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const email = "legacy-invitee-audit@example.com"
	const rawToken = setupPrefix + "invite-accept-legacy-scope-audit-1"

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
	require.ErrorIs(t, err, ErrRoleScopeInvalid)

	action := "setup_token.consume_failed"
	events, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action})
	require.NoError(t, err)
	require.Len(t, events, 1, "the role-scope refusal must leave exactly one audit row")
	ev := events[0]
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success)
	assert.Nil(t, ev.UserID, "no account exists, so there is no actor")
	assert.Equal(t, "1.2.3.4", ev.IPAddress)
	assert.True(t, strings.Contains(ev.Description, "project_developer"),
		"the audit row must carry the refusal reason, got %q", ev.Description)
}
