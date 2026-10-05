package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestTransitionMachineIdentityState_StaleFromStateIsRejectedAndNoOp is the
// machine-identity half of INV-STORE-14's stale-fromState proof (the secret half
// is TestTransitionSecretStatus_ClosesRace). Two callers both read the row as
// 'active'; the first writes 'suspended'. The second, still conditioned on the
// now-stale 'active', must report matched=false AND leave the row exactly as the
// winner wrote it — in particular must not stamp its own RevokedAt/Description.
// A second assertion pins the `Select("*")` half: every field the winner mutated
// is persisted in the one statement, not a hardcoded column subset.
func TestTransitionMachineIdentityState_StaleFromStateIsRejectedAndNoOp(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	now := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)

	created, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 1, Name: "ci", IdentityType: "ci", State: "active", Description: "orig",
		CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	winner := *created
	winner.State = "suspended"
	winner.Description = "winner-wrote-this"
	loser := *created
	loser.State = "revoked"
	loser.Description = "loser-wrote-this"
	revokedAt := now.Add(time.Minute)
	loser.RevokedAt = &revokedAt

	matched, err := ls.TransitionMachineIdentityState(ctx, &winner, "active")
	require.NoError(t, err)
	require.True(t, matched, "the first writer, still on the state it read, must win")

	matched, err = ls.TransitionMachineIdentityState(ctx, &loser, "active")
	require.NoError(t, err)
	assert.False(t, matched, "a second writer on the stale fromState must lose, not clobber")

	got, err := ls.GetMachineIdentity(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", got.State)
	assert.Equal(t, "winner-wrote-this", got.Description, "full row (Select(\"*\")) of the winner persisted, nothing of the loser")
	assert.Nil(t, got.RevokedAt, "the rejected write must not have stamped revoked_at")

	// Conditioned on the current state, the transition works again: the guard
	// tracks persisted state, it is not permanently stuck.
	next := *got
	next.State = "revoked"
	matched, err = ls.TransitionMachineIdentityState(ctx, &next, "suspended")
	require.NoError(t, err)
	assert.True(t, matched)
}
