package store

// pat_revoke_not_found_typed_test.go -- CORE-FAULT-TAILS-1 item 3: RevokePersonalAccessToken
// returned an untyped i18n "not found" when no row matched, so core could not tell a token
// deleted mid-revoke from a failed write. The no-row case now matches
// storage.ErrPersonalAccessTokenNotFound (text unchanged); a driver failure never does.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRevokePersonalAccessToken_NoRowIsTypedNotFound(t *testing.T) {
	ls := newS25Store(t, &models.PersonalAccessToken{})
	err := ls.RevokePersonalAccessToken(context.Background(), 9999)
	require.ErrorIs(t, err, storage.ErrPersonalAccessTokenNotFound)
	assert.Equal(t, i18n.T("ErrorNotFound", nil), err.Error(), "the rendered text is unchanged")

	broken := newBrokenDB(t).RevokePersonalAccessToken(context.Background(), 1)
	require.Error(t, broken)
	assert.NotErrorIs(t, broken, storage.ErrPersonalAccessTokenNotFound, "a driver failure is never a not-found")
}
