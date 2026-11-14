package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLiftLegalHold_LostReleaseIsRefusedAndUnaudited pins the core half of #4210:
// when the conditional ReleaseLegalHold matches no row (another lift released the
// hold after this lift's read), LiftLegalHold returns ErrLegalHoldAlreadyReleased
// and commits no lift audit row. The cross-replica interleaving itself is
// TestLegalHoldLift_SecondLifterRefused_CrossReplicaSQLite / _Postgres.
func TestLiftLegalHold_LostReleaseIsRefusedAndUnaudited(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	hold, err := c.PlaceLegalHold(ctx, 1, "litigation INC-5")
	require.NoError(t, err)

	calls := 0
	c.storage = hooked(st, &storeHooks{
		WrapTx: true,
		ReleaseLegalHold: func(_ storage.Storage, _ context.Context, id, releasedBy uint, _ time.Time, reason string) (bool, error) {
			calls++
			assert.Equal(t, hold.ID, id)
			assert.Equal(t, uint(1), releasedBy)
			assert.Equal(t, "INC-5 settled", reason)
			return false, nil // the row was already released by a racing lift
		},
	})

	err = c.LiftLegalHold(ctx, 1, "INC-5 settled")
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrLegalHoldAlreadyReleased), "want the typed refusal, got %v", err)
	assert.Equal(t, 1, calls)

	var lifts int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).Where("event_type = ?", EventLegalHoldLifted).Count(&lifts).Error)
	assert.Zero(t, lifts, "a refused lift wrote a lift audit row")
}
