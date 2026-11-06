package store

// UTC-STORE-SCAN-1 item 1: SetPasswordHash writes password_changed_at and updated_at through a map
// Updates (no hook, no NowFunc). Core passes its clock in the host zone.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetPasswordHash_StoresUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.user()
		require.NoError(t, w.ls.SetPasswordHash(ctx, id, "hash", at))
		requireStoredUTC(w, "users", "password_changed_at", id, at)
		requireStoredUTC(w, "users", "updated_at", id, at)

		u, err := w.ls.GetUser(ctx, id)
		require.NoError(t, err, "the row must scan back")
		require.NotNil(t, u.PasswordChangedAt)
	})
}
