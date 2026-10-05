// audit_labelling_storage_error_test.go — #2744, #2745, #2746.
//
// The last three sites in the family #2398 / #2740 / #2743 established: a
// STORAGE failure during credential verification must not be recorded as a
// confirmed wrong credential. None of these three carries a lockout or
// availability impact (no recordFailedLogin is reachable at any of them), so the
// defect is audit-trail accuracy — a DB hiccup during a legitimate sign-in
// reading, on review, exactly like a bad-credential guess. That is still real:
// an incident reviewer counting auth.login_failed / mfa.failed /
// webauthn.failed against an account cannot otherwise distinguish an attack
// from an outage.
//
// Every test asserts the EFFECT — which audit event actually landed in the
// table, or which error class the caller can act on — rather than a message
// string. And every one also pins the half that must NOT change: a confirmed
// replay stays mfa.failed, an absent account stays indistinguishable from a
// wrong password, and an attacker-supplied user handle naming no user stays a
// failed attempt. Those are the assertions that stop the fix over-correcting
// into a new oracle.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var errAuditLabellingStorageDown = errors.New("pq: connection reset by peer")

// markStepUsedErrStub wraps a real storage.Storage and overrides exactly
// MarkTOTPStepUsed, mirroring mfaSecretReadErrStub's pattern. errOnly makes it
// return (false, err) — a storage failure; replay makes it return (false, nil) —
// the step genuinely already consumed. Those two are what #2744 is about
// telling apart.
type markStepUsedErrStub struct {
	corestorage.Storage
	err    error
	replay bool
}

func (s *markStepUsedErrStub) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.replay {
		return false, nil
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

// TestActivateMFA_StorageErrorAuditsMFAError_NotMFAFailed is #2744.
func TestActivateMFA_StorageErrorAuditsMFAError_NotMFAFailed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error audits mfa.error and never mfa.failed", func(t *testing.T) {
		c, db, fixed := newMFATestCore(t)
		_, secret, err := c.BeginMFAEnrollment(ctx, 1)
		require.NoError(t, err)
		code, err := totp.GenerateCode(secret, fixed)
		require.NoError(t, err)

		real := c.storage
		c.storage = &markStepUsedErrStub{Storage: real, err: errAuditLabellingStorageDown}
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMFAVerificationStorageFailure,
			"the caller must be able to tell this apart from a wrong code")

		var failed, errored int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.failed").Count(&failed).Error)
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.error").Count(&errored).Error)
		assert.Equal(t, int64(1), errored, "the attempt must be recorded as not-evaluated")
		assert.Zero(t, failed,
			"a storage error must not be recorded as a failed MFA attempt — that is the whole defect (#2744)")

		// And the correct code must still work once the fault clears: a storage
		// error must not have consumed the step.
		c.storage = real
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.NoError(t, err, "the same correct code must still activate once storage recovers")
	})

	t.Run("a confirmed replay still audits mfa.failed", func(t *testing.T) {
		c, db, fixed := newMFATestCore(t)
		_, secret, err := c.BeginMFAEnrollment(ctx, 1)
		require.NoError(t, err)
		code, err := totp.GenerateCode(secret, fixed)
		require.NoError(t, err)

		// fresh == false with NO error: the step really was already used.
		c.storage = &markStepUsedErrStub{Storage: c.storage, replay: true}
		_, err = c.ActivateMFA(ctx, 1, code, mfaTestPassword, "")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrMFAVerificationStorageFailure)

		var failed, errored int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.failed").Count(&failed).Error)
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.error").Count(&errored).Error)
		assert.Equal(t, int64(1), failed,
			"a replay IS a failed attempt and must stay labelled as one — the fix must not over-correct")
		assert.Zero(t, errored)
	})
}

// usernameLookupErrStub overrides exactly GetUserByUsername.
type usernameLookupErrStub struct {
	corestorage.Storage
	err error
}

func (s *usernameLookupErrStub) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetUserByUsername(ctx, username)
}

// TestVerifyPasswordCredentials_StorageErrorIsDistinguishableFromNoSuchUser is
// #2745. The second subtest is the one that matters most: the anti-enumeration
// property must survive the fix.
func TestVerifyPasswordCredentials_StorageErrorIsDistinguishableFromNoSuchUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error is reported as not-evaluated", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		c.storage = &usernameLookupErrStub{Storage: c.storage, err: errAuditLabellingStorageDown}

		_, err := c.VerifyPasswordCredentials(ctx, "alice", mfaTestPassword)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrLoginNotEvaluated)
		assert.NotErrorIs(t, err, errAuditLabellingStorageDown,
			"the storage error's detail must not reach an unauthenticated caller")
	})

	t.Run("no such user stays an ordinary invalid-credentials result", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)

		_, err := c.VerifyPasswordCredentials(ctx, "nobody-at-all", mfaTestPassword)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrLoginNotEvaluated,
			"an absent account must NOT be distinguishable from a wrong password — the anti-enumeration property "+
				"the dummy-bcrypt spend exists for, and the reason this site was left out of #2398/#2740/#2743")
		assert.EqualError(t, err, "invalid credentials")
	})

	t.Run("a wrong password for a real account is the same class as no such user", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)

		_, err := c.VerifyPasswordCredentials(ctx, "alice", "not-the-password")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid credentials",
			"wrong-password and no-such-user must remain the same observable outcome")
	})
}

// userReadErrStub overrides exactly GetUser, which is what loadWebAuthnUser
// reads first.
type userReadErrStub struct {
	corestorage.Storage
	err error
}

func (s *userReadErrStub) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetUser(ctx, id)
}

// TestLoadWebAuthnUser_PreservesNotFoundVsStorageError is #2746's enabling half.
//
// loadWebAuthnUser used to flatten GetUser's error to a bare "user not found"
// string, which destroyed the distinction the PASSWORDLESS caller needs: its
// user handle is attacker-supplied and there is no first factor, so a handle
// naming no user IS a credential guess (webauthn.failed), while a DB failure is
// not (webauthn.error). The non-passwordless FinishWebAuthnLogin treats both as
// not-evaluated and is right to — its user id comes from a challenge whose
// first factor already passed.
func TestLoadWebAuthnUser_PreservesNotFoundVsStorageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a storage error does not masquerade as not-found", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)
		c.storage = &userReadErrStub{Storage: c.storage, err: errAuditLabellingStorageDown}

		_, err := c.loadWebAuthnUser(ctx, 1)
		require.Error(t, err)
		assert.False(t, corestorage.IsUserNotFound(err),
			"the passwordless caller decides webauthn.error vs webauthn.failed on exactly this distinction (#2746)")
	})

	t.Run("a genuinely absent user stays not-found", func(t *testing.T) {
		c, _, _ := newMFATestCore(t)

		_, err := c.loadWebAuthnUser(ctx, 9999)
		require.Error(t, err)
		assert.True(t, corestorage.IsUserNotFound(err),
			"an absent account is a genuine negative result on the passwordless path (the handle is "+
				"attacker-supplied) and must stay audited as a failed attempt")
	})
}
