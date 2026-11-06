package store

// UTC-STORE-SCAN-1 item 1: ClaimUserExternalIDIfUnset stores the caller's updated_at through a map Updates (no hook,
// no NowFunc), so a host-zone time reached the column with its offset. Core passes c.now().

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClaimUserExternalIDIfUnset_StoresUpdatedAtInUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.user()
		ok, err := w.ls.ClaimUserExternalIDIfUnset(ctx, id, w.name("ext"), at)
		require.NoError(t, err)
		require.True(t, ok)
		requireStoredUTC(w, "users", "updated_at", id, at)
		_, err = w.ls.GetUser(ctx, id)
		require.NoError(t, err, "the row must scan back")
	})
}
