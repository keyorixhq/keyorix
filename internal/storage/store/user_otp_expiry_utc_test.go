package store

// UTC-STORE-SCAN-1 item 1: SetOneTimePasswordExpiry writes one_time_password_expires_at (the expiry
// the login path compares with "now") and updated_at through a map Updates (no hook, no NowFunc).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetOneTimePasswordExpiry_StoresUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.user()
		expiresAt := at.Add(24 * time.Hour)
		require.NoError(t, w.ls.SetOneTimePasswordExpiry(ctx, id, &expiresAt, at))
		requireStoredUTC(w, "users", "one_time_password_expires_at", id, expiresAt)
		requireStoredUTC(w, "users", "updated_at", id, at)

		u, err := w.ls.GetUser(ctx, id)
		require.NoError(t, err, "the row must scan back")
		require.NotNil(t, u.OneTimePasswordExpiresAt)

		// Clearing the expiry still writes NULL, not a zero time.
		require.NoError(t, w.ls.SetOneTimePasswordExpiry(ctx, id, nil, at))
		u, err = w.ls.GetUser(ctx, id)
		require.NoError(t, err)
		require.Nil(t, u.OneTimePasswordExpiresAt)
	})
}
