// unlock_user_audit_fail_closed_test.go — UNLOCK-AUDIT-1 (AUTH-AUDIT-1 follow-up).
//
// UnlockUser lifts a brute-force refusal, so it must never happen without a
// record (the same rule server/admin's clear-login-lockout already enforces by
// auditing first): the lockout clear and the account.unlocked row commit in one
// transaction, and an audit write that errors or panics leaves the lockout set.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func lockedLockoutTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, func() *models.User) {
	t.Helper()
	c, db, _ := newLockoutTestCore(t, true)
	for range 3 {
		_ = login(c, "wrong")
	}
	require.NotNil(t, reloadUser(t, db).LoginLockedUntil, "precondition: the account is locked")
	return c, db, func() *models.User { return reloadUser(t, db) }
}

func countUnlockAuditRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", EventAccountUnlocked).Count(&n).Error)
	return n
}

func TestUnlockUser_AuditWriteError_LeavesLockoutSet(t *testing.T) {
	t.Parallel()
	c, _, user := lockedLockoutTestCore(t)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LogAuditEvent"),
	})
	c.storage = fs
	err := c.UnlockUser(context.Background(), 99, 1)
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.Error(t, err, "an unrecorded unlock must fail")
	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	u := user()
	assert.NotNil(t, u.LoginLockedUntil, "the lockout must stay set when the audit write failed")
	assert.NotZero(t, u.LoginLockoutCount)
	require.ErrorContains(t, login(c, lockoutTestPassword), "temporarily locked")
}

func TestUnlockUser_AuditWritePanic_LeavesLockoutSet(t *testing.T) {
	t.Parallel()
	c, _, user := lockedLockoutTestCore(t)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindPanic,
		Err: errors.New("injected: LogAuditEvent panic"),
	})
	c.storage = fs
	var err error
	require.NotPanics(t, func() { err = c.UnlockUser(context.Background(), 99, 1) })
	c.storage = base

	require.True(t, fs.Fired(), "the audit write must have been attempted and faulted")
	require.Error(t, err, "an unrecorded unlock must fail")
	assert.NotNil(t, user().LoginLockedUntil, "the lockout must stay set when the audit write panicked")
}

func TestUnlockUser_AuditSucceeds_ClearsAndRecords(t *testing.T) {
	t.Parallel()
	c, db, user := lockedLockoutTestCore(t)

	require.NoError(t, c.UnlockUser(context.Background(), 99, 1))
	u := user()
	assert.Nil(t, u.LoginLockedUntil)
	assert.Zero(t, u.LoginLockoutCount)
	assert.EqualValues(t, 1, countUnlockAuditRows(t, db), "exactly one account.unlocked row")
	require.NoError(t, login(c, lockoutTestPassword))
}

// A clear that fails after the audit row was appended in the same transaction
// rolls the row back: the chain never claims an unlock that did not happen.
func TestUnlockUser_ClearFails_NoUnlockedAuditRow(t *testing.T) {
	t.Parallel()
	c, db, user := lockedLockoutTestCore(t)

	base := c.storage
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "UpdateLoginLockoutState", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: UpdateLoginLockoutState"),
	})
	c.storage = fs
	err := c.UnlockUser(context.Background(), 99, 1)
	c.storage = base

	require.True(t, fs.Fired())
	require.Error(t, err)
	assert.NotNil(t, user().LoginLockedUntil)
	assert.EqualValues(t, 0, countUnlockAuditRows(t, db), "no account.unlocked row for an unlock that failed")
}
