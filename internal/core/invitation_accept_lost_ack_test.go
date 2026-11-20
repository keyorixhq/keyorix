package core

// invitation_accept_lost_ack_test.go — #4409 shape 3 (INVITE-ACCEPT-NOV-1 item 3).
// Marking the invitation accepted can commit and still report an error (a lost
// acknowledgement). completeInvitationAccept used to undo the accept on any error, so
// the invitation read accepted with no account and no grant behind it, and the
// inviter could not resend it. It now reads the invitation back: accepted means the
// accept committed and stands; pending means it did not, and it is undone; a read-back
// that fails too is undone (fail closed: no live account behind an invitation nobody
// marked accepted).

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestCompleteInvitationAccept_AcceptWriteLostAck_KeepsTheAccept(t *testing.T) {
	ctx := context.Background()
	w := newInviteAcceptStepWorld(t, false)
	fs := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{
		Method: "UpdateProjectInvitation", NthCall: 1, Kind: faultstorage.KindEffectThenError, Err: errors.New("injected lost ack"),
	})
	w.c.storage = fs
	res, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
	w.c.storage = w.st
	require.True(t, fs.Fired())

	// Before: ErrInvitationAcceptAbandoned, account and grant removed, invitation accepted.
	require.NoError(t, err, "the accept committed: it is delivered, not undone")
	require.NotNil(t, res.Session)
	u, err := w.st.GetUserByEmail(ctx, w.email)
	require.NoError(t, err, "the account stays")
	grants, err := w.st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: w.proj.ID})
	require.NoError(t, err)
	assert.NotEmpty(t, grants, "the invitation's project role stays")
	inv, err := w.st.GetProjectInvitation(ctx, w.inv.ID)
	require.NoError(t, err)
	assert.Equal(t, InvitationAccepted, inv.State)
}

// Calibration for the read-back: when the accept write commits AND the read-back
// fails, the outcome is unknown and the accept is undone (fail closed), not kept.
func TestCompleteInvitationAccept_AcceptWriteLostAckAndReadBackFails_FailsClosed(t *testing.T) {
	ctx := context.Background()
	w := newInviteAcceptStepWorld(t, false)
	lostAck := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{
		Method: "UpdateProjectInvitation", NthCall: 1, Kind: faultstorage.KindEffectThenError, Err: errors.New("injected lost ack"),
	})
	// GetProjectInvitation#1 is the accept's own first read; #2 is the read-back.
	readBack := faultstorage.NewFaultyStorage(lostAck, &faultstorage.FaultSpec{
		Method: "GetProjectInvitation", NthCall: 2, Kind: faultstorage.KindError, Err: errors.New("injected read-back fault"),
	})
	w.c.storage = readBack
	_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
	w.c.storage = w.st
	require.True(t, lostAck.Fired())
	require.True(t, readBack.Fired())

	require.ErrorIs(t, err, ErrInvitationAcceptAbandoned)
	assert.Contains(t, err.Error(), "reading the invitation back failed")
	_, uerr := w.st.GetUserByEmail(ctx, w.email)
	require.Error(t, uerr, "no live account is left when whether the accept landed is unknown")
}
