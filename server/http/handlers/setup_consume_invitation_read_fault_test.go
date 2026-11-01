package handlers

// setup_consume_invitation_read_fault_test.go — AUTH-ENDPOINT-OUTAGE-1 item 2 (REST).
//
// POST /auth/setup/consume with an invitation_accept link: a storage READ fault on the
// invitation (or on the existing-account probe) happens only after the token was found
// valid, so the client must get exactly the dead-link answer (a 503 here would confirm
// the token; INV-CORE-setup-consume-all-or-nothing). What changes is the audit: core now
// types the fault ErrSetupPostVerdict, so the operator sees setup_token.consume_error
// (a fault, the link still works) instead of setup_token.consume_failed (a dead-link
// attempt).

import (
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
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestConsumeSetup_InvitationReadFault_DeadLinkAnswer_AuditedAsError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxinvreadfault_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	require.NoError(t, db.Create(&models.Project{Name: "inv-read-fault"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "inviter", Email: "inviter@example.com"}).Error)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	h := NewAuthHandler(core.NewKeyorixCore(faulty), false)

	post := func(raw string) (int, string) {
		body := fmt.Sprintf(`{"token":%q,"password":%q}`, raw, "Kx#Vr9$Mn2!Zp4@Qw!invite")
		req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.9:1234"
		w := httptest.NewRecorder()
		throughProductionRecovery(h.ConsumeSetup).ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	auditCount := func(action string) int64 {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", action).Count(&n).Error)
		return n
	}

	deadStatus, deadBody := post("kx_setup_no-such-link")
	require.Equal(t, http.StatusBadRequest, deadStatus, deadBody)
	require.Eventually(t, func() bool { return auditCount("setup_token.consume_failed") == 1 }, 5*time.Second, 10*time.Millisecond)

	for i, method := range []string{"GetProjectInvitation", "GetUserByEmail"} {
		t.Run(method, func(t *testing.T) {
			email := fmt.Sprintf("invitee-%d@example.com", i)
			future := time.Now().Add(24 * time.Hour)
			inv := &models.ProjectInvitation{ProjectID: 1, Email: email, Role: "project_developer", State: core.InvitationPending,
				InvitedBy: 1, ValidationModeAtInvite: core.ValidationModeOpen, ExpiresAt: &future, CreatedAt: time.Now()}
			require.NoError(t, db.Create(inv).Error)
			raw := fmt.Sprintf("kx_setup_invite-read-fault-%d", i)
			sum := sha256.Sum256([]byte(raw))
			require.NoError(t, db.Create(&models.SetupToken{TokenHash: hex.EncodeToString(sum[:]), Purpose: core.SetupPurposeInvitationAccept,
				SubjectEmail: email, InvitationID: &inv.ID, State: core.SetupTokenActive, ExpiresAt: future, CreatedBy: 1}).Error)

			errorsBefore, failedBefore := auditCount("setup_token.consume_error"), auditCount("setup_token.consume_failed")
			faulty.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: errInjectedInviteFault})
			status, body := post(raw)
			require.True(t, faulty.Fired(), "the %s fault must be reached", method)
			faulty.Arm(nil)

			assert.Equal(t, deadStatus, status, "a post-verdict read fault answers exactly like a dead link")
			assert.Equal(t, deadBody, body, "same body as a dead link: the answer must not confirm the token")
			assert.NotContains(t, body, errInjectedInviteFault.Error())
			require.Eventually(t, func() bool { return auditCount("setup_token.consume_error") == errorsBefore+1 }, 5*time.Second, 10*time.Millisecond,
				"the fault is audited as a consume error (link still works), not as a dead-link attempt")
			assert.Equal(t, failedBefore, auditCount("setup_token.consume_failed"))
		})
	}
}
