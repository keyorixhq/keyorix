package store

// UTC-STORE-SCAN-1 item 2: the HTTP and gRPC secret-update handlers pass the client's expiry (RFC 3339
// with the client's offset, a protobuf Timestamp) to core, and core to UpdateSecretFields, which stores
// it through a map Updates (no hook, no NowFunc). TestEveryServerExpiryWriteIsUTC
// (internal/core/guards) lists those hand-offs as exceptions on the strength of this test: the store
// normalises the expiry, so the handler need not. Not red on any tree: it pins an existing fix.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestUpdateSecretFields_StoresExpirationInUTCForAnyCallerZone(t *testing.T) {
	eachCallerZone(t, func(t *testing.T, w ppWorld, at time.Time) {
		ctx := context.Background()
		require.NoError(t, w.ls.db.AutoMigrate(&models.SecretNode{}))
		s := seedSecret(w)
		expiration := at.Add(48 * time.Hour)
		ok, err := w.ls.UpdateSecretFields(ctx, s.ID, storage.SecretFieldUpdate{SetExpiration: true, Expiration: &expiration})
		require.NoError(t, err)
		require.True(t, ok)
		requireStoredUTC(w, "secret_nodes", "expiration", s.ID, expiration)
	})
}
