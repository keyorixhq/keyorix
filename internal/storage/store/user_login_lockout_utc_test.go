package store

// UTC-STORE-SCAN-1 item 1: UpdateLoginLockoutState persists last_failed_login_at and
// login_locked_until through a map Updates (no hook, no NowFunc). login_locked_until is the cutoff
// the lockout decision compares with "now", so a host-offset text on SQLite is a lockout that does
// not order (or a user row that no longer scans back, locking everyone out of that account).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateLoginLockoutState_StoresUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.user()
		failedAt, lockedUntil := at, at.Add(15*time.Minute)
		require.NoError(t, w.ls.UpdateLoginLockoutState(ctx, id, 5, &failedAt, &lockedUntil, 1))
		requireStoredUTC(w, "users", "last_failed_login_at", id, failedAt)
		requireStoredUTC(w, "users", "login_locked_until", id, lockedUntil)

		u, err := w.ls.GetUser(ctx, id)
		require.NoError(t, err, "the row must scan back")
		require.NotNil(t, u.LoginLockedUntil)
		require.WithinDuration(t, lockedUntil, *u.LoginLockedUntil, time.Millisecond)
	})
}
