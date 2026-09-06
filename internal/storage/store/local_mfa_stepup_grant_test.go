package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newMFAStepUpGrantStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MFAStepUpGrant{}))
	return NewLocalStorage(db)
}

func TestMFAStepUpGrant_CreateAndDeleteFor(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(10 * time.Minute),
	}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(20 * time.Minute),
	}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID: 2, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	g, err := ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, uint(1), g.UserID)

	require.NoError(t, ls.DeleteMFAStepUpGrantsFor(ctx, 1))

	g, err = ls.GetActiveMFAStepUpGrant(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	assert.Nil(t, g, "all of user 1's grants were deleted")

	// User 2's grant must be untouched.
	g2, err := ls.GetActiveMFAStepUpGrant(ctx, 2, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g2)
}

func TestMFAStepUpGrant_PruneRemovesOnlyExpired(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: past}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 2, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: past}))
	require.NoError(t, ls.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: 3, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: future}))

	deleted, err := ls.PruneMFAStepUpGrants(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	g3, err := ls.GetActiveMFAStepUpGrant(ctx, 3, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	require.NotNil(t, g3, "the not-yet-expired grant must survive the prune")
}

func TestMFAStepUpGrant_GetActiveNoneReturnsNilNil(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	g, err := ls.GetActiveMFAStepUpGrant(context.Background(), 99, models.MFAStepUpPurposeRestrictedSecretRead, time.Now())
	require.NoError(t, err)
	assert.Nil(t, g)
}

func TestMFAStepUpGrant_DeleteForNoneIsNoop(t *testing.T) {
	ls := newMFAStepUpGrantStore(t)
	require.NoError(t, ls.DeleteMFAStepUpGrantsFor(context.Background(), 404))
}
