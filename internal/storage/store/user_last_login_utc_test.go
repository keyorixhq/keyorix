package store

// UTC-STORE-SCAN-1 item 1: UpdateLastLogin writes last_login_at through UpdateColumn, which runs no
// hook and no NowFunc. ListInactiveUsers / ListUsers(InactiveSince) compare the column with a UTC
// cutoff, so a host-offset text breaks the inactive-account suspend sweep on SQLite.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateLastLogin_StoresUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.user()
		require.NoError(t, w.ls.UpdateLastLogin(ctx, id, at))
		requireStoredUTC(w, "users", "last_login_at", id, at)

		u, err := w.ls.GetUser(ctx, id)
		require.NoError(t, err, "the row must scan back")
		require.NotNil(t, u.LastLoginAt)

		// The sweep's own comparison: a login a minute ago is not inactive for an hour-old cutoff.
		inactive, err := w.ls.ListInactiveUsers(ctx, at.Add(-time.Hour))
		require.NoError(t, err)
		for _, x := range inactive {
			require.NotEqual(t, id, x.ID, "a user who just logged in must not be inactive")
		}
	})
}
