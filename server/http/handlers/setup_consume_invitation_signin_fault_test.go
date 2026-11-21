package handlers

// setup_consume_invitation_signin_fault_test.go — #4409 shape 2 (INVITE-ACCEPT-NOV-1
// item 2). An invitation accept that committed (account, grants, accepted invitation)
// and then failed to mint the login session was answered with the dead-link 400 ("ask
// your administrator for a new one"), which sends the invitee back to the inviter for
// an accept that worked and whose link is now spent. It now says to log in with the
// new password, and the account, its grant and the accepted invitation stay.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestConsumeSetup_InvitationSignInFault_SaysLogInWithTheNewPassword(t *testing.T) {
	h, _, fs, st, adminID := newUndeliveredSetupFixture(t)
	ctx := context.Background()
	const password = "Kx#Vr9$Mn2!Zp4@Qw!accept"
	proj, err := st.CreateProject(ctx, &models.Project{Name: "inv-signin-fault", Description: "d"})
	require.NoError(t, err)

	post := func(raw string) (int, string) {
		body := fmt.Sprintf(`{"token":%q,"password":%q}`, raw, password)
		req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.10:1234"
		w := httptest.NewRecorder()
		throughProductionRecovery(h.ConsumeSetup).ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	_, deadBody := post("kx_setup_no-such-link")

	for i, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		t.Run(kind.String(), func(t *testing.T) {
			email := fmt.Sprintf("signin-fault-%d@example.com", i)
			raw := fmt.Sprintf("kx_setup_invite-signin-fault-%d", i)
			future := time.Now().Add(24 * time.Hour)
			inv, err := st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
				ProjectID: proj.ID, Email: email, Role: "project_developer", State: core.InvitationPending,
				InvitedBy: adminID, ValidationModeAtInvite: core.ValidationModeOpen, ExpiresAt: &future, CreatedAt: time.Now(),
			})
			require.NoError(t, err)
			sum := sha256.Sum256([]byte(raw))
			_, err = st.CreateSetupToken(ctx, &models.SetupToken{
				TokenHash: hex.EncodeToString(sum[:]), Purpose: core.SetupPurposeInvitationAccept, SubjectEmail: email,
				InvitationID: &inv.ID, State: core.SetupTokenActive, ExpiresAt: future, CreatedBy: adminID,
			})
			require.NoError(t, err)

			fs.Arm(&faultstorage.FaultSpec{Method: "CreateSession", NthCall: 1, Kind: kind, Err: errInjectedInviteFault})
			status, body := post(raw)
			require.True(t, fs.Fired(), "the CreateSession fault must be reached")
			fs.Arm(nil)

			assert.Equal(t, http.StatusBadRequest, status, body)
			assert.NotEqual(t, deadBody, body, "the accept committed: the dead-link answer would send the invitee back for a new link")
			assert.Contains(t, body, "Log in with your new password")
			assert.NotContains(t, body, errInjectedInviteFault.Error())

			u, err := st.GetUserByEmail(ctx, email)
			require.NoError(t, err, "the account stays: the accept committed")
			grants, err := st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj.ID})
			require.NoError(t, err)
			assert.NotEmpty(t, grants, "the invitation's project role stays")
			got, err := st.GetProjectInvitation(ctx, inv.ID)
			require.NoError(t, err)
			assert.Equal(t, core.InvitationAccepted, got.State)
		})
	}
}
