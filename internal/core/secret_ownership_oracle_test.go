package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// OWNERSHIP-ORACLE-1: transferOwnership authorizes the ACTOR before it looks at
// newOwnerID. It used to check "already owned by that user" and GetUser(newOwnerID)
// first, so a caller with no right to the secret could learn from the refusal
// whether a user ID exists and who owns the secret. An unauthorized actor must get
// the identical refusal (same sentinel, same text) for every newOwnerID.

// TestTransferOwnership_UnauthorizedActorGetsIdenticalRefusal covers both refusal
// branches: a non-owner on a live-owned secret, and a non-roles.assign actor on an
// orphaned one.
func TestTransferOwnership_UnauthorizedActorGetsIdenticalRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name     string
		orphan   bool
		sentinel error
		targets  map[string]uint
	}{
		{
			// Fixture: user 1 owns the secret; actor 2 (alice) holds secrets.write but
			// is not the owner.
			name: "live owner, non-owner actor", sentinel: ErrSecretNotOwner,
			targets: map[string]uint{"existing user": 3, "missing user": 999, "current owner": 1},
		},
		{
			// Orphaned secret: actor 2 lacks roles.assign. "current owner" is 0 here,
			// which the ID check rejects before anything else, so the third case is
			// the actor naming themselves.
			name: "orphaned secret, actor without roles.assign", orphan: true, sentinel: ErrPermissionDenied,
			targets: map[string]uint{"existing user": 3, "missing user": 999, "self": 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var refusals []string
			for label, newOwner := range tc.targets {
				c, id := newOwnershipFixture(t)
				if tc.orphan {
					s, err := c.storage.GetSecret(ctx, id)
					require.NoError(t, err)
					s.OwnerID = 0
					_, err = c.storage.UpdateSecret(ctx, s)
					require.NoError(t, err)
				}
				_, err := c.TransferSecretOwnership(ctx, id, newOwner, 2, ActorTypeUser)
				require.Error(t, err, label)
				assert.ErrorIs(t, err, tc.sentinel, "%s: %v", label, err)
				// Both refusals are authorization refusals, so transports map them
				// through ErrPermissionDenied (403 / PermissionDenied) by errors.Is.
				assert.ErrorIs(t, err, ErrPermissionDenied, "%s: %v", label, err)
				assert.False(t, errors.Is(err, coreStorage.ErrUserNotFound), "%s: refusal reveals the user lookup: %v", label, err)
				assert.False(t, errors.Is(err, ErrSecretInvalidInput), "%s: refusal reveals the current owner: %v", label, err)
				refusals = append(refusals, err.Error())
			}
			for _, r := range refusals[1:] {
				assert.Equal(t, refusals[0], r, "refusal text differs by newOwnerID: %q", refusals)
			}
		})
	}
}

// TestTransferOwnership_AuthorizedActorKeepsSpecificErrors pins the other half: the
// owner still gets the specific validation answers.
func TestTransferOwnership_AuthorizedActorKeepsSpecificErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c, id := newOwnershipFixture(t)
	_, err := c.TransferSecretOwnership(ctx, id, 999, 1, ActorTypeUser)
	require.Error(t, err)
	assert.ErrorIs(t, err, coreStorage.ErrUserNotFound)
	assert.Contains(t, err.Error(), "new owner 999 not found")

	_, err = c.TransferSecretOwnership(ctx, id, 1, 1, ActorTypeUser)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretInvalidInput)
	assert.Contains(t, err.Error(), "already owned")
}
