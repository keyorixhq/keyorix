package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestParseSecretRef(t *testing.T) {
	cases := []struct {
		ref                        string
		project, environment, name string
		wantErr                    bool
	}{
		{"app/prod/db-password", "app", "prod", "db-password", false},
		{"app/prod/path/like/name", "app", "prod", "path/like/name", false}, // name may contain slashes
		{"  app/prod/db  ", "app", "prod", "db", false},                     // trimmed
		{"app/prod", "", "", "", true},                                      // too few parts
		{"app", "", "", "", true},
		{"app//db", "", "", "", true},   // empty environment
		{"/prod/db", "", "", "", true},  // empty project
		{"app/prod/", "", "", "", true}, // empty name
		{"", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			p, e, n, err := ParseSecretRef(c.ref)
			if c.wantErr {
				require.ErrorIs(t, err, ErrSecretRefInvalid)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.project, p)
			assert.Equal(t, c.environment, e)
			assert.Equal(t, c.name, n)
		})
	}
}

func newRefTestCore(t *testing.T) *KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}))

	// Two projects, each with an environment named "prod" — the case that makes a bare
	// "prod/name" ambiguous and forces the three-level reference.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "beta"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, ProjectID: 2, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 10, ProjectID: 1, EnvironmentID: 1, Name: "db", IsSecret: true}).Error)
	require.NoError(t, db.Create(&models.SecretNode{ID: 20, ProjectID: 2, EnvironmentID: 2, Name: "db", IsSecret: true}).Error)
	return NewKeyorixCore(store.NewLocalStorage(db))
}

func TestResolveSecretRef(t *testing.T) {
	c := newRefTestCore(t)
	ctx := context.Background()

	// The project segment disambiguates two same-named env/secret pairs.
	s, err := c.ResolveSecretRef(ctx, "alpha/prod/db")
	require.NoError(t, err)
	assert.Equal(t, uint(10), s.ID)

	s, err = c.ResolveSecretRef(ctx, "beta/prod/db")
	require.NoError(t, err)
	assert.Equal(t, uint(20), s.ID)
}

func TestResolveSecretRef_NotFound(t *testing.T) {
	c := newRefTestCore(t)
	ctx := context.Background()
	for _, ref := range []string{"ghost/prod/db", "alpha/ghost/db", "alpha/prod/ghost"} {
		_, err := c.ResolveSecretRef(ctx, ref)
		require.ErrorIs(t, err, ErrSecretRefNotFound, "ref %q", ref)
	}
}

func TestResolveSecretRef_Invalid(t *testing.T) {
	_, err := newRefTestCore(t).ResolveSecretRef(context.Background(), "alpha/prod")
	require.ErrorIs(t, err, ErrSecretRefInvalid)
}
