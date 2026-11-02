package core

// invitation_accept_read_fault_test.go — AUTH-ENDPOINT-OUTAGE-1 item 2.
//
// completeInvitationAccept reads the invitation and probes for an existing account
// before it creates anything. A storage READ fault on the invitation read was folded
// into "invitation not found" (the folded-read guard's exception row), and a fault on
// the account probe came back as a plain storage error: both reached the setup handler
// as an ordinary refusal and were audited setup_token.consume_failed, the dead-link
// event. They are now ErrSetupPostVerdict wrapping ErrStorageReadUnavailable (typed,
// no message text), so the handler audits setup_token.consume_error for an operator
// while the client keeps the dead-link answer (INV-CORE-setup-consume-all-or-nothing).
// A positive not-found keeps its verdict and is not a fault.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestCompleteInvitationAccept_ReadFaultIsTypedPostVerdict(t *testing.T) {
	ctx := context.Background()
	injected := errors.New("injected read fault")

	for _, method := range []string{"GetProjectInvitation", "GetUserByEmail"} {
		t.Run(method+" fault", func(t *testing.T) {
			w := newInviteAcceptStepWorld(t, false)
			fs := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: injected})
			w.c.storage = fs
			_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
			w.c.storage = w.st
			require.True(t, fs.Fired(), "the %s fault must have fired", method)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSetupPostVerdict, "a read fault after the token was validated is post-verdict: %v", err)
			assert.True(t, IsStorageReadUnavailable(err), "a read fault is typed as a storage fault, not a verdict: %v", err)
			assert.ErrorIs(t, err, injected, "the cause stays in the chain for the server log")

			_, uerr := w.st.GetUserByEmail(ctx, w.email)
			assert.True(t, storage.IsUserNotFound(uerr), "nothing was created: %v", uerr)
			assert.Equal(t, SetupTokenActive, w.tokenState(t, w.rawTok), "the link is still live")
			w.requireAcceptSucceeds(t, w.rawTok)
		})
	}

	t.Run("a deleted invitation is a verdict, not a fault", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		require.NoError(t, w.st.DB().Delete(w.inv).Error)
		_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrSetupPostVerdict)
		assert.False(t, IsStorageReadUnavailable(err), "a positive not-found is not a fault: %v", err)
	})
}
