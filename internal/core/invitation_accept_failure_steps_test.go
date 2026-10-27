package core

// invitation_accept_failure_steps_test.go — CORE-REVOCATION-TAILS-1 item 4 (ATOMIC-OWED-1
// leftover). completeInvitationAccept creates the account, spends the setup token,
// grants the invitation's roles (a global invite: one commit per grant), marks the
// invitation accepted and signs the user in. A failure after the account exists used
// to leave a half-done accept behind and say something untrue about it:
//
//   - a failed token spend returned with the new account left in place, so the retry
//     of the SAME link hit "an account already exists";
//   - a global invite whose system-role grant committed before a later grant failed
//     (an audit outage: "could not record the change in the audit log; nothing was
//     changed, retry") soft-deleted the account but left the system-role grant on it
//     (a RestoreUser brings it back), and answered "nothing was changed, retry"
//     although the account was created and deleted and the link was spent;
//   - a failed "mark accepted" write left the account and its grants live behind a
//     still-pending invitation and a spent link.
//
// Now every failure after the account exists undoes the accept (abandonInvitationAccept):
// the grants made so far are reverted, the account is removed, the invitation stays
// pending, and the error (ErrInvitationAcceptAbandoned) says which step failed, what was
// undone and what the invitee must do. A failed automatic sign-in after everything
// committed says the accept succeeded. One fault at each step.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type inviteAcceptStepWorld struct {
	c       *KeyorixCore
	st      *store.LocalStorage
	proj    *models.Project
	inv     *models.ProjectInvitation
	email   string
	rawTok  string
	sysRole *models.Role
}

// newInviteAcceptStepWorld builds a pending invitation and a live accept link. global
// makes it a global invite (system_auditor at the global scope plus one project
// assignment: two grant commits); otherwise a project invite (one).
func newInviteAcceptStepWorld(t *testing.T, global bool) *inviteAcceptStepWorld {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	w := &inviteAcceptStepWorld{c: c, st: st, email: "invitee@example.com", rawTok: setupPrefix + "invite-accept-steps"}
	var err error
	w.proj, err = st.CreateProject(ctx, &models.Project{Name: "invite-steps", Description: "d"})
	require.NoError(t, err)
	if !global {
		w.inv = inviteAcceptFixture(t, c, st, w.proj.ID, 1, w.email, w.rawTok)
		return w
	}
	w.sysRole, err = st.GetRoleByName(ctx, "system_auditor")
	require.NoError(t, err)
	assignments, err := json.Marshal([]ProjectAssignment{{ProjectID: w.proj.ID, Role: "project_developer"}})
	require.NoError(t, err)
	future := c.now().Add(24 * time.Hour)
	w.inv, err = st.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		Email: w.email, SystemRole: "system_auditor", AssignmentsJSON: string(assignments), State: InvitationPending,
		InvitedBy: 1, ValidationModeAtInvite: ValidationModeOpen, ExpiresAt: &future, CreatedAt: c.now(),
	})
	require.NoError(t, err)
	w.newLink(t, w.rawTok)
	return w
}

func (w *inviteAcceptStepWorld) newLink(t *testing.T, raw string) {
	t.Helper()
	_, err := w.st.CreateSetupToken(context.Background(), &models.SetupToken{
		TokenHash: sha256Hex(raw), Purpose: SetupPurposeInvitationAccept, SubjectEmail: w.email,
		InvitationID: &w.inv.ID, State: SetupTokenActive, ExpiresAt: w.c.now().Add(24 * time.Hour), CreatedBy: 1,
	})
	require.NoError(t, err)
}

// accountRows returns every account ever created for the invitee, soft-deleted
// ones included.
func (w *inviteAcceptStepWorld) accountRows(t *testing.T) []models.User {
	t.Helper()
	var users []models.User
	require.NoError(t, w.st.DB().Unscoped().Where("email = ?", w.email).Find(&users).Error)
	return users
}

// requireNothingKept: the accept was undone. No live account, no grant left on the
// removed one (a RestoreUser must not bring any back), the invitation still pending.
func (w *inviteAcceptStepWorld) requireNothingKept(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := w.st.GetUserByEmail(ctx, w.email)
	require.Error(t, err, "the account created for the failed accept must be removed")
	for _, u := range w.accountRows(t) {
		require.True(t, u.DeletedAt.Valid, "account %d must be removed", u.ID)
		global, err := w.st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{})
		require.NoError(t, err)
		if w.sysRole != nil {
			assert.NotContains(t, global, w.sysRole.ID, "the invitation's system role must be reverted on the removed account %d", u.ID)
		}
		project, err := w.st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: w.proj.ID})
		require.NoError(t, err)
		assert.Empty(t, project, "the invitation's project role must be reverted on the removed account %d", u.ID)
	}
	inv, err := w.st.GetProjectInvitation(ctx, w.inv.ID)
	require.NoError(t, err)
	assert.Equal(t, InvitationPending, inv.State, "the invitation stays pending so the inviter can resend it")
}

func (w *inviteAcceptStepWorld) tokenState(t *testing.T, raw string) string {
	t.Helper()
	tok, err := w.st.GetSetupTokenByHash(context.Background(), sha256Hex(raw))
	require.NoError(t, err)
	return tok.State
}

// requireAcceptSucceeds: a later accept (the same link or a resent one) completes
// cleanly and grants what the invitation names.
func (w *inviteAcceptStepWorld) requireAcceptSucceeds(t *testing.T, raw string) {
	t.Helper()
	ctx := context.Background()
	w.c.storage = w.st
	res, err := w.c.CompleteSetup(ctx, raw, strongPw, "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, res.Session)
	u, err := w.st.GetUserByEmail(ctx, w.email)
	require.NoError(t, err)
	project, err := w.st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: w.proj.ID})
	require.NoError(t, err)
	assert.NotEmpty(t, project)
	inv, err := w.st.GetProjectInvitation(ctx, w.inv.ID)
	require.NoError(t, err)
	assert.Equal(t, InvitationAccepted, inv.State)
}

// requireAbandonMessage: the error says what happened, never the failing grant's own
// "nothing was changed, retry".
func requireAbandonMessage(t *testing.T, err error, step string, linkUsed bool) {
	t.Helper()
	require.ErrorIs(t, err, ErrInvitationAcceptAbandoned)
	require.NotErrorIs(t, err, ErrMutationAuditUnavailable, "the grant's own sentinel must not reach callers that map it to 'nothing was changed'")
	msg := err.Error()
	assert.NotContains(t, msg, "nothing was changed")
	assert.Contains(t, msg, step+" failed")
	assert.Contains(t, msg, "was removed")
	if linkUsed {
		assert.Contains(t, msg, "the inviter must resend the invitation")
	} else {
		assert.Contains(t, msg, "Retry the setup link")
	}
}

func TestCompleteInvitationAccept_FailureAtEachStep_UndoesAndSaysWhatHappened(t *testing.T) {
	ctx := context.Background()
	injected := errors.New("injected fault")

	// fault runs CompleteSetup with fs armed; the fault must fire.
	fault := func(t *testing.T, w *inviteAcceptStepWorld, spec *faultstorage.FaultSpec) error {
		t.Helper()
		fs := faultstorage.NewFaultyStorage(w.st, spec)
		w.c.storage = fs
		_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
		require.True(t, fs.Fired(), "the %s fault must have fired", spec.Method)
		w.c.storage = w.st
		require.Error(t, err)
		return err
	}

	t.Run("token spend fails: account removed, the same link still works", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		err := fault(t, w, &faultstorage.FaultSpec{Method: "MarkSetupTokenConsumed", NthCall: 1, Kind: faultstorage.KindError, Err: injected})
		requireAbandonMessage(t, err, invitationAcceptStepConsume, false)
		w.requireNothingKept(t)
		assert.Equal(t, SetupTokenActive, w.tokenState(t, w.rawTok), "a failed spend leaves the link live")
		w.requireAcceptSucceeds(t, w.rawTok) // before: "an account already exists"
	})

	t.Run("project grant fails: account removed, resend works", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		err := fault(t, w, &faultstorage.FaultSpec{Method: "CreateProjectMembership", NthCall: 1, Kind: faultstorage.KindError, Err: injected})
		requireAbandonMessage(t, err, invitationAcceptStepGrant, true)
		w.requireNothingKept(t)
		assert.NotEqual(t, SetupTokenActive, w.tokenState(t, w.rawTok))
		w.newLink(t, w.rawTok+"-resend")
		w.requireAcceptSucceeds(t, w.rawTok+"-resend")
	})

	t.Run("global invite: second grant fails after the system role committed", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, true)
		err := fault(t, w, &faultstorage.FaultSpec{Method: "CreateProjectMembership", NthCall: 1, Kind: faultstorage.KindError, Err: injected})
		requireAbandonMessage(t, err, invitationAcceptStepGrant, true)
		assert.Contains(t, err.Error(), "Every role it had granted was reverted")
		w.requireNothingKept(t) // before: system_auditor stayed on the removed account
		w.newLink(t, w.rawTok+"-resend")
		w.requireAcceptSucceeds(t, w.rawTok+"-resend")
	})

	t.Run("global invite: audit log refuses the second grant", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, true)
		// The project assignment's role.assigned row is refused: that grant is fail
		// closed (ErrMutationAuditUnavailable), the system role before it committed.
		dev, err := w.st.GetRoleByName(ctx, "project_developer")
		require.NoError(t, err)
		refused := false
		w.c.storage = hooked(w.st, &storeHooks{
			WrapTx: true, // the grant writes its row through its transaction
			LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
				if e.EventType == EventRoleAssigned && strings.Contains(e.Diff, fmt.Sprintf(`"role_id":%d,`, dev.ID)) {
					refused = true
					return errors.New("injected audit outage")
				}
				return next.LogAuditEvent(ctx, e)
			},
		})
		_, err = w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
		w.c.storage = w.st
		require.True(t, refused, "the project grant's audit row must have been refused")
		require.Error(t, err)
		requireAbandonMessage(t, err, invitationAcceptStepGrant, true) // before: "... nothing was changed, retry"
		assert.Contains(t, err.Error(), "the audit log could not record the grant")
		w.requireNothingKept(t)
	})

	t.Run("marking the invitation accepted fails: grants reverted, account removed", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		err := fault(t, w, &faultstorage.FaultSpec{Method: "UpdateProjectInvitation", NthCall: 1, Kind: faultstorage.KindError, Err: injected})
		requireAbandonMessage(t, err, invitationAcceptStepAccept, true)
		w.requireNothingKept(t) // before: account + project role live, invitation pending
		w.newLink(t, w.rawTok+"-resend")
		w.requireAcceptSucceeds(t, w.rawTok+"-resend")
	})

	t.Run("sign-in fails after everything committed: says the accept succeeded", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		err := fault(t, w, &faultstorage.FaultSpec{Method: "CreateSession", NthCall: 1, Kind: faultstorage.KindError, Err: injected})
		require.NotErrorIs(t, err, ErrInvitationAcceptAbandoned)
		assert.Contains(t, err.Error(), "was accepted")
		assert.Contains(t, err.Error(), "log in with the new password")
		u, uerr := w.st.GetUserByEmail(ctx, w.email)
		require.NoError(t, uerr, "the account stays: the accept committed")
		project, rerr := w.st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: w.proj.ID})
		require.NoError(t, rerr)
		assert.NotEmpty(t, project)
		inv, ierr := w.st.GetProjectInvitation(ctx, w.inv.ID)
		require.NoError(t, ierr)
		assert.Equal(t, InvitationAccepted, inv.State)
	})
}
