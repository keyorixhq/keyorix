package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ExpiresBefore filter returns only secrets with a non-null expiration before
// the cutoff (already expired or expiring within the window), excluding
// later-expiring and never-expiring secrets.
func TestListSecrets_ExpiresBeforeFilter(t *testing.T) {
	ls := newSecretScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 5, Name: "dev"}).Error)

	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	cutoff := now.Add(30 * 24 * time.Hour)
	mk := func(name string, exp *time.Time) {
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 5, EnvironmentID: 1, Name: name, IsSecret: true, Type: "api_key", Status: "active",
			Expiration: exp,
		}).Error)
	}
	expired := now.Add(-24 * time.Hour)
	soon := now.Add(10 * 24 * time.Hour)
	far := now.Add(60 * 24 * time.Hour)
	mk("expired", &expired)
	mk("soon", &soon)
	mk("far", &far)
	mk("no-expiry", nil)

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ExpiresBefore: &cutoff, Page: 1, PageSize: 100,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.ElementsMatch(t, []string{"expired", "soon"}, secretNames(got),
		"only secrets expiring before the cutoff match; far-future and never-expiring are excluded")
}
