package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SetAccountStateIfMatches (C-RACE-FIX-B2) is the conditional account_state
// write the SCIM lifecycle paths use: it must apply only while the row still
// holds the state the caller read, and must touch nothing but account_state
// and updated_at.

func TestSetAccountStateIfMatches_AppliesWhenStateUnchanged(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)
	u, err := ls.CreateUser(ctx, &models.User{Username: "sam", UsernameFolded: "sam", Email: "sam@example.com", EmailFolded: "sam@example.com", IsActive: true, AccountState: "active", PasswordHash: "h1"})
	require.NoError(t, err)

	matched, err := ls.SetAccountStateIfMatches(ctx, u.ID, "active", "deprovisioned", time.Now())
	require.NoError(t, err)
	assert.True(t, matched)

	got, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "deprovisioned", got.AccountState)
	assert.True(t, got.IsActive, "only account_state/updated_at are written")
	assert.Equal(t, "h1", got.PasswordHash, "only account_state/updated_at are written")
}

// The lost-race shape: the row moved to "suspended" after the caller read
// "deprovisioned"; a SCIM reactivation must not turn it into "active".
func TestSetAccountStateIfMatches_RefusesWhenStateMoved(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)
	u, err := ls.CreateUser(ctx, &models.User{Username: "sue", UsernameFolded: "sue", Email: "sue@example.com", EmailFolded: "sue@example.com", AccountState: "deprovisioned"})
	require.NoError(t, err)
	require.NoError(t, ls.SetAccountState(ctx, u.ID, "suspended", time.Now())) // the concurrent writer

	matched, err := ls.SetAccountStateIfMatches(ctx, u.ID, "deprovisioned", "active", time.Now())
	require.NoError(t, err)
	assert.False(t, matched)

	got, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", got.AccountState, "the concurrent suspension must survive")
}

func TestSetAccountStateIfMatches_MissingOrDeletedRowDoesNotMatch(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	matched, err := ls.SetAccountStateIfMatches(ctx, 999999, "active", "suspended", time.Now())
	require.NoError(t, err)
	assert.False(t, matched)

	u, err := ls.CreateUser(ctx, &models.User{Username: "del", UsernameFolded: "del", Email: "del@example.com", EmailFolded: "del@example.com", AccountState: "active"})
	require.NoError(t, err)
	require.NoError(t, ls.DeleteUser(ctx, u.ID))
	matched, err = ls.SetAccountStateIfMatches(ctx, u.ID, "active", "suspended", time.Now())
	require.NoError(t, err)
	assert.False(t, matched, "a soft-deleted row is never written")
}
