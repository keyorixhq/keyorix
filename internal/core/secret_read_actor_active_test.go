package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const notActiveRefusal = "the acting account is not active"

// TestGetSecretForRead_RefusesInactiveActor: the per-secret read entry points refuse a
// suspended human actor in core itself, typed ErrPermissionDenied, as the mutating
// entry points do (#4159 known-02 for reads, #4336). Both the value read
// (GetSecretForValueRead) and the metadata read (GetSecretForRead withValue=false) are
// covered; the refusal comes before any permission lookup, so the actor needs no roles.
func TestGetSecretForRead_RefusesInactiveActor(t *testing.T) {
	c, db := newMaxReadsCore(t)
	secretID := seedMaxReadsSecret(t, c, 5)
	const actor uint = 2
	ensureActiveActor(t, c.storage, actor)
	var u models.User
	require.NoError(t, db.First(&u, actor).Error)
	u.AccountState = AccountSuspended
	require.NoError(t, db.Save(&u).Error)

	ctx := context.Background()
	for name, read := range map[string]func(context.Context) error{
		"value":    func(ctx context.Context) error { _, err := c.GetSecretForValueRead(ctx, secretID, actor); return err },
		"metadata": func(ctx context.Context) error { _, err := c.GetSecretForRead(ctx, secretID, actor, false); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := read(ctx)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrPermissionDenied)
			assert.Contains(t, err.Error(), notActiveRefusal)
		})
	}

	t.Run("machine actor is not checked", func(t *testing.T) {
		// A machine's own lifecycle is enforced by machine authentication; actor 0 and a
		// machine-tagged ctx never reach the account read.
		_, err := c.GetSecretForValueRead(WithActorType(ctx, ActorTypeMachine), secretID, actor)
		if err != nil {
			assert.NotContains(t, err.Error(), notActiveRefusal)
		}
	})
}
