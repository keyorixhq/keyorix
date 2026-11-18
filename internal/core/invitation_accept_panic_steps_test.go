package core

// invitation_accept_panic_steps_test.go — #4409 shape 1 (INVITE-ACCEPT-NOV-1 item 1).
// A panic in a step of completeInvitationAccept after the account was created (the
// token spend, the grants, marking the invitation accepted) used to be recovered only
// by completeValidSetupToken, which answered the dead-link error but never ran
// abandonInvitationAccept: the account stayed live with the new password, usually with
// its project membership, behind a spent link and a still-pending invitation whose
// resend met "an account already exists". Each step now turns its panic into its
// error, so the accept is undone exactly as for the error
// (invitation_accept_failure_steps_test.go). One panic at each step.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestCompleteInvitationAccept_PanicAtEachStep_UndoesTheAccept(t *testing.T) {
	ctx := context.Background()
	injected := errors.New("injected panic")

	// panicAt runs CompleteSetup, the full public path, with one panic armed.
	panicAt := func(t *testing.T, w *inviteAcceptStepWorld, method string, nth int) error {
		t.Helper()
		fs := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{Method: method, NthCall: nth, Kind: faultstorage.KindPanic, Err: injected})
		w.c.storage = fs
		var err error
		require.NotPanics(t, func() { _, err = w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4") })
		require.True(t, fs.Fired(), "the %s#%d panic must have fired", method, nth)
		w.c.storage = w.st
		require.Error(t, err)
		return err
	}

	cases := []struct {
		name     string
		global   bool
		method   string
		nth      int
		step     string
		linkUsed bool
	}{
		{"token spend panics", false, "MarkSetupTokenConsumed", 1, invitationAcceptStepConsume, false},
		{"membership create panics", false, "CreateProjectMembership", 1, invitationAcceptStepGrant, true},
		// AssignRole#1 is the account's baseline role inside CreateUser; #2 is the
		// project role, after the membership row was written.
		{"project role grant panics after the membership", false, "AssignRole", 2, invitationAcceptStepGrant, true},
		{"global invite: assignment panics after the system role committed", true, "CreateProjectMembership", 1, invitationAcceptStepGrant, true},
		{"marking the invitation accepted panics", false, "UpdateProjectInvitation", 1, invitationAcceptStepAccept, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newInviteAcceptStepWorld(t, tc.global)
			err := panicAt(t, w, tc.method, tc.nth)
			// Before: the outer recover answered "setup completion panicked" with the
			// account live, so none of these held.
			w.requireNothingKept(t)
			requireAbandonMessage(t, err, tc.step, tc.linkUsed)
			assert.Contains(t, err.Error(), "panicked")
			if tc.linkUsed {
				assert.NotEqual(t, SetupTokenActive, w.tokenState(t, w.rawTok))
				w.newLink(t, w.rawTok+"-resend")
				w.requireAcceptSucceeds(t, w.rawTok+"-resend")
				return
			}
			assert.Equal(t, SetupTokenActive, w.tokenState(t, w.rawTok), "a spend that panicked leaves the link live")
			w.requireAcceptSucceeds(t, w.rawTok)
		})
	}
}
