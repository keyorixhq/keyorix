package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestGetSecretForRead_GateAllowedReadSkipsAccountRead: a request whose transport gate
// already allowed this read was authenticated there, so GetSecretForRead does not read
// the account again (#4336: no extra statement on the hot read path, OPT-READPATH-2).
// Whatever the read answers next, it is not the account refusal. The peek that decides
// this does not consume the memo and covers only the user and secret the gate allowed.
func TestGetSecretForRead_GateAllowedReadSkipsAccountRead(t *testing.T) {
	c, db := newMaxReadsCore(t)
	secretID := seedMaxReadsSecret(t, c, 5)
	const actor uint = 2
	ensureActiveActor(t, c.storage, actor)
	var u models.User
	require.NoError(t, db.First(&u, actor).Error)
	u.AccountState = AccountSuspended
	require.NoError(t, db.Save(&u).Error)

	ctx := context.Background()
	secret, err := c.storage.GetSecret(ctx, secretID)
	require.NoError(t, err)
	gctx := withGateReadDecision(ctx)
	noteGateReadAllow(gctx, actor, secret, permSecretsRead, "")

	require.True(t, gateAllowedRead(gctx, actor, secretID))
	assert.True(t, gateAllowedRead(gctx, actor, secretID), "peeking must not consume the memo")
	assert.False(t, gateAllowedRead(gctx, actor+1, secretID), "another user's read is not covered")
	assert.False(t, gateAllowedRead(gctx, actor, secretID+1), "another secret's read is not covered")

	_, err = c.GetSecretForValueRead(gctx, secretID, actor)
	if err != nil {
		assert.NotContains(t, err.Error(), notActiveRefusal)
	}
}
