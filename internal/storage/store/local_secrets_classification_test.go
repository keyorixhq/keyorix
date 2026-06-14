package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The classification filter returns only secrets with the requested label, and
// "unclassified" matches secrets with an empty classification (ISO A.5.12).
func TestListSecrets_ClassificationFilter(t *testing.T) {
	ls := newSecretScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 5, Name: "dev"}).Error)

	mk := func(name, classification string) {
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 5, EnvironmentID: 1, Name: name, IsSecret: true, Type: "api_key", Status: "active",
			Classification: classification,
		}).Error)
	}
	mk("r1", "restricted")
	mk("r2", "restricted")
	mk("c1", "confidential")
	mk("u1", "") // unclassified

	level := "restricted"
	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{Classification: &level, Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.ElementsMatch(t, []string{"r1", "r2"}, secretNames(got))

	unclassified := "unclassified"
	got, total, err = ls.ListSecrets(ctx, &storage.SecretFilter{Classification: &unclassified, Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.ElementsMatch(t, []string{"u1"}, secretNames(got))
}
