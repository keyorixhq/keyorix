package store

// UTC-STORE-SCAN-1 item 1: SetAccountState stores the caller's updated_at through a map Updates (no hook,
// no NowFunc), so a host-zone time reached the column with its offset. Core passes c.now().

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetAccountState_StoresUpdatedAtInUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		id := w.user()
		require.NoError(t, w.ls.SetAccountState(context.Background(), id, "password_reset_required", at))
		requireStoredUTC(w, "users", "updated_at", id, at)
		_, err := w.ls.GetUser(context.Background(), id)
		require.NoError(t, err, "the row must scan back")
	})
}
