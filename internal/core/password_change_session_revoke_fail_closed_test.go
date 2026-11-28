// password_change_session_revoke_fail_closed_test.go — AUDIT-DISCLOSURE-NOV-1 item 3
// (R1.16) red/green proof.
//
// ChangePassword and the setup/reset-link consume ended the account's OTHER sessions
// after their transaction committed, and a failed purge was only logged and audited:
// the caller was told the password had changed while a stolen session stayed live.
// Same class as #4537. The purge now runs inside the password transaction, so a
// failed purge refuses the change (the old password stays valid, the link stays
// usable) and a change reported as successful never leaves another session behind.
//
// The fault is a DeleteSessionsForUserExcept hook re-wrapped inside transactions
// (WrapTx), so it fires wherever the purge runs, before and after the fix.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func failSessionPurge(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		DeleteSessionsForUserExcept: func(next storage.Storage, ctx context.Context, userID, keepID uint) error {
			return errors.New("fault-injected: session purge failed")
		},
	})
}

// plantSession stores a live session for user 1 under the raw token raw.
func plantSession(t *testing.T, c *KeyorixCore, raw string) {
	t.Helper()
	exp := time.Now().Add(time.Hour)
	_, err := c.storage.CreateSession(context.Background(), &models.Session{
		UserID: 1, SessionToken: raw, ExpiresAt: &exp,
	})
	require.NoError(t, err)
}

func sessionLive(t *testing.T, c *KeyorixCore, raw string) bool {
	t.Helper()
	_, err := c.storage.GetSession(context.Background(), raw)
	if err == nil {
		return true
	}
	require.ErrorIs(t, err, storage.ErrSessionNotFound)
	return false
}

func TestChangePassword_SessionPurgeFails_ChangeRefusedOtherSessionCannotSurvive(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	ctx := context.Background()
	plantSession(t, c, "raw-callers-own-session")
	plantSession(t, c, "raw-stolen-session")

	base := c.storage
	c.storage = failSessionPurge(base)
	err := c.ChangePassword(ctx, 1, curPwOld, curPwNew, "raw-callers-own-session")
	c.storage = base

	if err == nil {
		assert.False(t, sessionLive(t, c, "raw-stolen-session"),
			"R1.16: a password change reported as successful must not leave another session live")
	}
	require.Error(t, err, "a change whose session purge failed must be reported as failed")
	assert.True(t, passwordIs(t, db, curPwOld), "the refused change leaves the old password valid")
	assert.False(t, passwordIs(t, db, curPwNew))

	// The retry goes through and ends every other session; the caller's own stays.
	require.NoError(t, c.ChangePassword(ctx, 1, curPwOld, curPwNew, "raw-callers-own-session"))
	assert.True(t, passwordIs(t, db, curPwNew))
	assert.False(t, sessionLive(t, c, "raw-stolen-session"))
	assert.True(t, sessionLive(t, c, "raw-callers-own-session"))
}

func TestCompleteSetup_SessionPurgeFails_ResetRefusedOldSessionCannotSurvive(t *testing.T) {
	t.Parallel()
	for _, mfa := range []bool{false, true} {
		name := "no-second-factor"
		if mfa {
			name = "second-factor"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, db := newSetupAtomicCore(t, mfa)
			plantSession(t, c, "raw-stolen-session")
			before := readSetupState(t, db)

			base := c.storage
			c.storage = failSessionPurge(base)
			res, err := completeSetupRecovering(c)
			c.storage = base

			if err == nil || errors.Is(err, ErrMFARequired) {
				assert.False(t, sessionLive(t, c, "raw-stolen-session"),
					"R1.16: a reset reported as successful must not leave an old session live")
			}
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrMFARequired, "a reset whose session purge failed must be refused")
			assert.Nil(t, res)
			assert.Equal(t, before, readSetupState(t, db), "the refused reset leaves nothing behind")
			assert.True(t, sessionLive(t, c, "raw-stolen-session"), "rolled back with the rest")

			// The same link works once the purge does, and ends the old session.
			res, err = completeSetupRecovering(c)
			if mfa {
				require.ErrorIs(t, err, ErrMFARequired)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res.Session)
			}
			assert.False(t, sessionLive(t, c, "raw-stolen-session"))
			assert.False(t, readSetupState(t, db).oldPassword)
		})
	}
}
