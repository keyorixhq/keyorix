package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Project-name uniqueness and lookup use projects.name_folded (NFC + case fold,
// computed in Go), so SQLite and PostgreSQL accept the same set of names. The
// same checks run on SQLite always and on PostgreSQL when KEYORIX_TEST_PG_DSN is
// set. The index DDL is the one ensureProjectNameIndex creates.

const projectNameFoldedIndexSQL = "CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_name_active " +
	"ON projects (name_folded) WHERE deleted_at IS NULL AND name <> ''"

func runProjectNameFolded(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, ls.db.AutoMigrate(&models.Project{}))
	require.NoError(t, ls.db.Exec(projectNameFoldedIndexSQL).Error)

	first, err := ls.CreateProject(ctx, &models.Project{Name: "ÄÖ"})
	require.NoError(t, err)
	assert.Equal(t, "äö", first.NameFolded)

	// Case variants, including non-ASCII ones, are the same name.
	for _, dup := range []string{"äö", "ÄÖ", "äö", "Äö"} {
		_, err := ls.CreateProject(ctx, &models.Project{Name: dup})
		require.ErrorIs(t, err, storage.ErrDuplicateProjectName, "create %q", dup)
	}
	for _, name := range []string{"Straße", "ΟΔΟΣ", "İstanbul"} {
		_, err := ls.CreateProject(ctx, &models.Project{Name: name})
		require.NoError(t, err, name)
	}
	// Capital Greek sigma and the dotted capital I fold like their lower forms. (Final
	// sigma is not unified with medial sigma, the same as for usernames: the fold is
	// identity.NewFoldedName's.)
	for _, dup := range []string{"οδοσ", "i̇stanbul"} {
		_, err := ls.CreateProject(ctx, &models.Project{Name: dup})
		require.ErrorIs(t, err, storage.ErrDuplicateProjectName, "create %q", dup)
	}
	// Sharp s is not expanded to ss.
	_, err = ls.CreateProject(ctx, &models.Project{Name: "STRASSE"})
	require.NoError(t, err)

	// Lookup resolves to the one row the index allows.
	for _, q := range []string{"ÄÖ", "äö", "Äö", "äö"} {
		got, err := ls.GetProjectByName(ctx, q)
		require.NoError(t, err, q)
		assert.Equal(t, first.ID, got.ID, q)
	}
	_, err = ls.GetProjectByName(ctx, "zzz")
	require.ErrorIs(t, err, storage.ErrProjectNotFound)

	// Rename onto an existing folded name is refused; rename keeps name_folded in step.
	other, err := ls.CreateProject(ctx, &models.Project{Name: "Other"})
	require.NoError(t, err)
	_, err = ls.UpdateProjectFields(ctx, other.ID, "äÖ", "", nil, time.Now())
	require.ErrorIs(t, err, storage.ErrDuplicateProjectName)
	ok, err := ls.UpdateProjectFields(ctx, other.ID, "Renamed", "", nil, time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	got, err := ls.GetProjectByName(ctx, "RENAMED")
	require.NoError(t, err)
	assert.Equal(t, other.ID, got.ID)
	_, err = ls.GetProjectByName(ctx, "other")
	require.ErrorIs(t, err, storage.ErrProjectNotFound)

	// A soft-deleted project frees its name.
	require.NoError(t, ls.db.Delete(&models.Project{}, first.ID).Error)
	_, err = ls.GetProjectByName(ctx, "äö")
	require.ErrorIs(t, err, storage.ErrProjectNotFound)
	again, err := ls.CreateProject(ctx, &models.Project{Name: "äö"})
	require.NoError(t, err)
	assert.NotEqual(t, first.ID, again.ID)
}

func TestProjectNameFolded_SQLite(t *testing.T) {
	runProjectNameFolded(t, newFoldSQLiteStore(t))
}

func TestProjectNameFolded_Postgres(t *testing.T) {
	runProjectNameFolded(t, newFoldPGStore(t))
}
