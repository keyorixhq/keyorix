package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// cappedShareFetchStorage answers the caller's share fetch with a list at the
// 10000-row storage cap, which core refuses as possibly truncated.
func cappedShareFetchStorage(inner storage.Storage) storage.Storage {
	return storagetest.Hooked(inner, &storagetest.StoreHooks{
		ListSharesByUser: func(storage.Storage, context.Context, uint, time.Time) ([]*models.ShareRecord, error) {
			const atCap = 10000 // core.maxShareViewBatchSize, and the storage list cap
			shares := make([]*models.ShareRecord, atCap)
			for i := range shares {
				shares[i] = &models.ShareRecord{SecretID: 1, OwnerID: 1, RecipientID: 2, Permission: "read"}
			}
			return shares, nil
		},
	})
}

// STORAGE-ERR-CLASS-5: ListSecrets over a share fetch at the row cap answers the
// typed FailedPrecondition HTTP's 422 ShareListOverCap has, not Internal.
func TestSecretService_ListSecrets_OverCapIsFailedPrecondition(t *testing.T) {
	rig := newSecretTestRig(t)
	svc := NewSecretService(core.NewKeyorixCore(cappedShareFetchStorage(store.NewLocalStorage(rig.db))))

	resp, err := svc.ListSecrets(ownerCtx(), &pb.ListSecretsRequest{})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "over-cap must be a typed refusal, not Internal: %v", err)
}
