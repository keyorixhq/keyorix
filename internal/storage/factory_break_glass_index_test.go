package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// The real migration path (CreateStorage → migrateDatabase → ensureBreakGlassActiveIndex)
// must actually create the partial unique index on break_glass_activations
// (project_id, user_id) WHERE state='active' — not just the isolated unit test that
// manually creates the index. A second active activation for the same (project, user)
// must be rejected at the DB level.
func TestBreakGlassActiveIndex_CreatedByMigration(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "break-glass-index.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = st.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.NoError(t, err)

	_, err = st.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: 2, UserID: 10, RoleID: 3, RoleName: "editor", State: "active",
	})
	require.Error(t, err, "a fresh install must already reject a second active activation for the same project+user")
}
