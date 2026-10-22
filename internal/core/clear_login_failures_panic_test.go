package core

// #3556: clearLoginFailures runs after an authentication's effect committed (a
// delivered session, a step-up grant, a consumed re-auth grant), so a panic in
// its UpdateLoginLockoutState write must not escape: it used to answer the
// Recovery 500 over a session cookie or a grant the client nevertheless held,
// unaudited. The HTTP-level proof for the login transports is
// server/http/handlers TestLoginDelivery_LockoutClearPanicKeepsTheLoginDelivered;
// this file proves the primitive itself (so every caller is covered) and the
// step-up caller, which only this package can drive.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// panicOnLockoutClear panics once in UpdateLoginLockoutState, either in place
// of the write or after it committed. (release/v0.96.x has no hooked()/storeHooks
// helper; this is the embedded-Storage decorator its own #3277 tests use.)
func panicOnLockoutClear(inner corestorage.Storage, afterCommit bool, fired *atomic.Bool) corestorage.Storage {
	return &lockoutClearPanicStorage{Storage: inner, afterCommit: afterCommit, fired: fired}
}

type lockoutClearPanicStorage struct {
	corestorage.Storage
	afterCommit bool
	fired       *atomic.Bool
}

func (s *lockoutClearPanicStorage) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error {
	if s.fired.CompareAndSwap(false, true) {
		if s.afterCommit {
			_ = s.Storage.UpdateLoginLockoutState(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
		}
		panic("injected panic: UpdateLoginLockoutState")
	}
	return s.Storage.UpdateLoginLockoutState(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
}

func TestClearLoginFailures_PanicIsRecovered(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(commitLabel(afterCommit), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			c, db, _, _ := newActivatedMFACore(t)
			c.loginLockout = postVerdictParityPolicy
			putAtThresholdMinusOne(t, db, 1)
			var u models.User
			require.NoError(t, db.First(&u, 1).Error)
			require.NotZero(t, u.FailedLoginAttempts, "setup: the clear must have something to write")

			var fired atomic.Bool
			c.storage = panicOnLockoutClear(c.storage, afterCommit, &fired)
			require.NotPanics(t, func() { c.clearLoginFailures(ctx, &u) },
				"the clear runs after the authentication committed; its panic must not escape")
			require.True(t, fired.Load())
			assert.Equal(t, postVerdictParityPolicy.MaxAttempts-1, u.FailedLoginAttempts,
				"the caller's struct is only reset when the clear is known to have landed")
		})
	}
}

func TestVerifyMFAStepUp_LockoutClearPanicStillDeliversTheGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _, good := newActivatedMFACore(t)
	c.loginLockout = postVerdictParityPolicy
	putAtThresholdMinusOne(t, db, 1)

	var fired atomic.Bool
	base := c.storage
	c.storage = panicOnLockoutClear(base, false, &fired)
	var err error
	require.NotPanics(t, func() { err = c.VerifyMFAStepUp(ctx, 1, good) })
	c.storage = base
	require.True(t, fired.Load(), "the clear must actually have been faulted")

	require.NoError(t, err, "the grant committed, so the step-up is delivered, not reported failed")
	assert.EqualValues(t, 1, liveStepUpGrants(t, db), "the delivered grant stays live")
	assert.EqualValues(t, 1, auditCount(t, db, "mfa.stepup_verified"), "and the step-up is audited")
}
