package store

// UTC-STORE-SCAN-1 item 1: UpdateGroupFields stores the caller's updated_at through a map Updates
// (no hook, no NowFunc), like UpdateProjectFields and UpdateSecretTemplateFields, which normalise it.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateGroupFields_StoresUpdatedAtInUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		id := w.group()
		desc := "d"
		ok, err := w.ls.UpdateGroupFields(ctx, id, nil, nil, &desc, at)
		require.NoError(t, err)
		require.True(t, ok)
		requireStoredUTC(w, "groups", "updated_at", id, at)
		_, err = w.ls.GetGroup(ctx, id)
		require.NoError(t, err, "the row must scan back")
	})
}
