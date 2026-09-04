// local_auth_cascade_sweep_test.go — partial-coverage sweep for
// local_auth.go: RotateSession's post-CAS-win Create failure,
// EnforceSessionLimit's Delete failure, and
// RevokeAllPersonalAccessTokensForUser's Update failure.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestRotateSession_CreateFailsAfterWinningCAS(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Session{})
	old := &models.Session{UserID: 1, SessionToken: "old-hash"}
	require.NoError(t, ls.db.Create(old).Error)

	dropTableAfterUpdates(t, ls.db, 1, "sessions")

	_, _, err := ls.RotateSession(context.Background(), old.ID, &models.Session{UserID: 1, SessionToken: "new-plaintext"}, time.Now())
	require.Error(t, err)
}

func TestEnforceSessionLimit_DeleteFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Session{})
	require.NoError(t, ls.db.Create(&models.Session{UserID: 1, SessionToken: "s1"}).Error)

	dropTableAfterQueries(t, ls.db, 1, "sessions")

	err := ls.EnforceSessionLimit(context.Background(), 1, 1)
	require.Error(t, err)
}

func TestRevokeAllPersonalAccessTokensForUser_UpdateFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.PersonalAccessToken{})
	require.NoError(t, ls.db.Create(&models.PersonalAccessToken{
		UserID: 1, Name: "tok", TokenHash: "hash1",
	}).Error)

	dropTableAfterQueries(t, ls.db, 1, "personal_access_tokens")

	_, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	require.Error(t, err)
}
