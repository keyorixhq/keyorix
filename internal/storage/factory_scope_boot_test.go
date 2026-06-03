package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFreshBootMigratesScopedRoles verifies that the full AutoMigrate path used
// on a fresh database creates the scoped user_roles schema (composite PK with the
// project/environment sentinel columns) and that the same role can be assigned to
// a user at two different scopes — the case the old (user_id, role_id) PK forbade.
func TestFreshBootMigratesScopedRoles(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "boot.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "fresh-DB AutoMigrate must succeed with the scoped role models")

	ctx := context.Background()

	// Same user, same role, two different project scopes must both persist.
	require.NoError(t, st.AssignRole(ctx, 1, 1, corestorage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRole(ctx, 1, 1, corestorage.Scope{ProjectID: 2}))

	// Re-assigning at an existing scope is rejected (idempotency guard).
	assert.Error(t, st.AssignRole(ctx, 1, 1, corestorage.Scope{ProjectID: 1}))

	idsP1, err := st.GetUserRoleIDsExact(ctx, 1, corestorage.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.Equal(t, []uint{1}, idsP1)

	// A global-scope query matches both project assignments (project sentinel).
	idsAt, err := st.GetUserRoleIDsAt(ctx, 1, corestorage.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.Equal(t, []uint{1}, idsAt)
}
