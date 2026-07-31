// local_search_test.go — tests for the Search filter on ListSecrets.
// Uses a real in-memory SQLite database (no mocks) to verify that the
// LOWER/LIKE predicate wired in local_secrets.go actually filters rows.
package store

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var searchTestCounter atomic.Int64

func newSearchTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	n := searchTestCounter.Add(1)
	dsn := fmt.Sprintf("file:kxsearch_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretDependency{},
		&models.ShareRecord{},
	))
	return NewLocalStorage(db)
}

// seedSearchSecrets creates a project+environment and inserts the given secret
// names, returning the LocalStorage so callers can run additional queries.
func seedSearchSecrets(t *testing.T, names ...string) (*LocalStorage, uint) {
	t.Helper()
	ls := newSearchTestStore(t)
	ctx := context.Background()

	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	for _, name := range names {
		_, err := ls.CreateSecret(ctx, &models.SecretNode{
			ProjectID:     1,
			EnvironmentID: 1,
			Name:          name,
			IsSecret:      true,
			Type:          "generic",
			Status:        "active",
		})
		require.NoError(t, err, "seeding secret %q", name)
	}
	return ls, 1
}

func strPtr(s string) *string { return &s }

// TestListSecrets_Search_CaseInsensitive verifies that the search filter is
// case-insensitive: "mysecret" must match "MySecret", "mysecret-backup", and
// "another-MYSECRET" but not "other-secret".
func TestListSecrets_Search_CaseInsensitive(t *testing.T) {
	ls, projectID := seedSearchSecrets(t, "MySecret", "other-secret", "mysecret-backup", "another-MYSECRET")
	ctx := context.Background()

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Search:    strPtr("mysecret"),
		Page:      1,
		PageSize:  50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 3, total, "expected 3 matching secrets")
	require.Len(t, got, 3)

	names := make(map[string]bool, len(got))
	for _, s := range got {
		names[s.Name] = true
	}
	assert.True(t, names["MySecret"], "MySecret must match")
	assert.True(t, names["mysecret-backup"], "mysecret-backup must match")
	assert.True(t, names["another-MYSECRET"], "another-MYSECRET must match")
	assert.False(t, names["other-secret"], "other-secret must NOT match")
}

// TestListSecrets_Search_NoMatch verifies that a search term with no
// matching secrets returns an empty result (not an error).
func TestListSecrets_Search_NoMatch(t *testing.T) {
	ls, projectID := seedSearchSecrets(t, "alpha", "beta", "gamma")
	ctx := context.Background()

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Search:    strPtr("zzznomatch"),
		Page:      1,
		PageSize:  50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)
	assert.Empty(t, got)
}

// TestListSecrets_Search_Nil verifies that a nil Search returns all secrets
// with no filtering applied.
func TestListSecrets_Search_Nil(t *testing.T) {
	ls, projectID := seedSearchSecrets(t, "x", "y", "z")
	ctx := context.Background()

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Search:    nil,
		Page:      1,
		PageSize:  50,
	})
	require.NoError(t, err)
	assert.EqualValues(t, 3, total)
	assert.Len(t, got, 3)
}

// TestListSecrets_Search_SpecialChars verifies that SQL wildcard characters in
// the search term do not cause injection or unexpected results: GORM's
// parameterized query wraps the value in '%...%' safely, so "%" alone should
// match every secret (the LIKE '%' || '%' || '%' expands to '%') — rather than
// error or execute arbitrary SQL. We assert on no-error and a deterministic
// result (either all match or none — never a panic / driver error).
func TestListSecrets_Search_SpecialChars(t *testing.T) {
	ls, projectID := seedSearchSecrets(t, "normal-secret", "another-secret")
	ctx := context.Background()

	// A bare "%" is a valid LIKE wildcard; GORM's parameterization wraps it in
	// '%' + value + '%', producing '%%%' which matches every row. The important
	// guarantee is that no SQL injection or driver error occurs.
	_, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Search:    strPtr("%"),
		Page:      1,
		PageSize:  50,
	})
	require.NoError(t, err, "SQL wildcard characters in search must not cause errors")

	// A value that cannot appear in any secret name must return zero rows safely.
	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID,
		Search:    strPtr("'; DROP TABLE secret_nodes; --"),
		Page:      1,
		PageSize:  50,
	})
	require.NoError(t, err, "SQL injection attempt must not cause errors")
	assert.EqualValues(t, 0, total)
	assert.Empty(t, got)
}
