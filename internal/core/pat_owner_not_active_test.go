// pat_owner_not_active_test.go — CurrentPATRestriction's owner re-check: a
// token whose owning account is gone or no longer usable is the DEFINITIVE
// ErrPATOwnerNotActive (the auth cache-hit path denies and evicts on it), and a
// failed read is not. The HTTP half is
// server/middleware/pat_cache_hit_owner_recheck_test.go.
package core_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCurrentPATRestriction_OwnerNotUsable_ReturnsOwnerNotActive(t *testing.T) {
	t.Parallel()
	for name, column := range map[string]map[string]any{
		"suspended":     {"account_state": core.AccountSuspended},
		"deprovisioned": {"account_state": core.AccountDeprovisioned},
		"unrecognized":  {"account_state": "not-a-state"},
		"inactive":      {"is_active": false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, raw, db := newPATWorld(t)
			require.NoError(t, db.Model(&models.User{}).Where("id = ?", 7).Updates(column).Error)

			_, err := c.CurrentPATRestriction(context.Background(), raw)

			require.Error(t, err)
			assert.ErrorIs(t, err, core.ErrPATOwnerNotActive)
			assert.NotErrorIs(t, err, core.ErrPATRevoked, "the token row itself is fine; the owner is the reason")
		})
	}
}

func TestCurrentPATRestriction_OwnerGone_ReturnsOwnerNotActive(t *testing.T) {
	t.Parallel()
	for name, del := range map[string]bool{"soft-deleted": false, "hard-deleted": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, raw, db := newPATWorld(t)
			q := db
			if del {
				q = db.Unscoped()
			}
			require.NoError(t, q.Delete(&models.User{}, 7).Error)

			_, err := c.CurrentPATRestriction(context.Background(), raw)

			assert.ErrorIs(t, err, core.ErrPATOwnerNotActive)
		})
	}
}

// The other direction: the owner read failing is indeterminate, so it must not
// be the definitive sentinel (the caller refuses 503 and keeps the entry).
func TestCurrentPATRestriction_OwnerReadFailure_IsNotTheSentinel(t *testing.T) {
	t.Parallel()
	c, raw, db := newPATWorld(t)
	require.NoError(t, db.Migrator().DropTable(&models.User{}))

	_, err := c.CurrentPATRestriction(context.Background(), raw)

	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrPATOwnerNotActive)
	assert.NotErrorIs(t, err, core.ErrPATRevoked)
}
